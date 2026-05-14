//! Linux platform implementation
//!
//! Uses Linux kernel primitives for sandboxing:
//!
//! - **Namespaces**: PID, mount, network, user, UTS, IPC isolation
//! - **Cgroups v2**: Resource limits (memory, CPU, PIDs)
//! - **Seccomp-BPF**: Syscall filtering
//! - **HTTP Proxy**: Domain whitelisting for proxied network mode

use crate::builder::{
    ExecutionPolicy, Mount, NetworkMode, Permission, ResourceEnforcement, SandboxConfig,
    SeccompProfile,
};
use crate::error::{Result, SandboxError};
use crate::network::ProxiedNetwork;
use crate::platform::PlatformExecutor;
use crate::result::{
    ExecutionDiagnostics, ExecutionReport, ExecutionResult, LimitDiagnostics, LimitStatus,
    MetricDiagnostics, MetricStatus,
};
use std::os::unix::io::{IntoRawFd, RawFd};
use std::time::{Duration, Instant};

mod cgroup;
mod namespace;
mod seccomp;

pub use cgroup::CgroupManager;
pub use cgroup::{is_cgroup_accessible, is_cgroup_v2_mounted};
pub use cgroup::{probe_cgroup_support, CgroupController, CgroupSupport};
pub use namespace::{MountNamespace, UserNamespace, UtsNamespace};
pub use seccomp::SeccompFilter;

/// RawFd version of close
fn close_raw(fd: RawFd) -> nix::Result<()> {
    let ret = unsafe { libc::close(fd) };
    nix::errno::Errno::result(ret).map(|_| ())
}

/// RawFd version of write
fn write_raw(fd: RawFd, data: &[u8]) -> nix::Result<usize> {
    let ret = unsafe { libc::write(fd, data.as_ptr() as _, data.len()) };
    nix::errno::Errno::result(ret).map(|r| r as usize)
}

/// RawFd version of read
fn read_raw(fd: RawFd, buf: &mut [u8]) -> nix::Result<usize> {
    let ret = unsafe { libc::read(fd, buf.as_mut_ptr() as _, buf.len()) };
    nix::errno::Errno::result(ret).map(|r| r as usize)
}

struct AutoCloseFd {
    fd: RawFd,
}

impl AutoCloseFd {
    fn new(fd: RawFd) -> Self {
        Self { fd }
    }

    fn raw(&self) -> RawFd {
        self.fd
    }

    fn write_byte_and_close(&mut self, byte: u8) -> nix::Result<()> {
        let fd = self.fd;
        write_raw(fd, &[byte])?;
        self.close()
    }

    fn close(&mut self) -> nix::Result<()> {
        if self.fd >= 0 {
            let fd = self.fd;
            self.fd = -1;
            close_raw(fd)?;
        }
        Ok(())
    }
}

impl Drop for AutoCloseFd {
    fn drop(&mut self) {
        let _ = self.close();
    }
}

fn abort_child_startup(
    child_pid: nix::unistd::Pid,
    ready_write: &mut AutoCloseFd,
    message: String,
) -> SandboxError {
    let _ = ready_write.close();
    let _ = nix::sys::wait::waitpid(child_pid, None);
    SandboxError::Internal(message)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum EnforcementMode {
    NotRequested,
    Strict,
    BestEffort,
}

#[derive(Clone, Copy, Debug)]
struct LimitPlan {
    memory: EnforcementMode,
    cpu: EnforcementMode,
    pids: EnforcementMode,
}

impl LimitPlan {
    fn from(config: &SandboxConfig, policy: &ExecutionPolicy) -> Self {
        Self {
            memory: limit_mode(
                config.memory_limit.is_some(),
                policy.cgroup_limit_requests.memory,
                policy.resource_enforcement.clone(),
            ),
            cpu: limit_mode(
                config.cpu_limit.is_some(),
                policy.cgroup_limit_requests.cpu,
                policy.resource_enforcement.clone(),
            ),
            pids: limit_mode(
                config.max_pids.is_some(),
                policy.cgroup_limit_requests.pids,
                policy.resource_enforcement.clone(),
            ),
        }
    }

    fn first_strict_limit(&self) -> Option<(&'static str, CgroupController)> {
        if self.memory == EnforcementMode::Strict {
            Some(("memory", CgroupController::Memory))
        } else if self.cpu == EnforcementMode::Strict {
            Some(("cpu", CgroupController::Cpu))
        } else if self.pids == EnforcementMode::Strict {
            Some(("pids", CgroupController::Pids))
        } else {
            None
        }
    }

    fn requested_controllers(&self) -> Vec<CgroupController> {
        let mut requested = Vec::new();
        if self.memory != EnforcementMode::NotRequested {
            requested.push(CgroupController::Memory);
        }
        if self.cpu != EnforcementMode::NotRequested {
            requested.push(CgroupController::Cpu);
        }
        if self.pids != EnforcementMode::NotRequested {
            requested.push(CgroupController::Pids);
        }
        requested
    }
}

fn limit_mode(
    configured: bool,
    explicit: bool,
    enforcement: ResourceEnforcement,
) -> EnforcementMode {
    if !configured {
        EnforcementMode::NotRequested
    } else if explicit && enforcement == ResourceEnforcement::Strict {
        EnforcementMode::Strict
    } else {
        EnforcementMode::BestEffort
    }
}

/// Check if Linux sandboxing is supported
pub fn is_supported() -> bool {
    // Check for user namespace support
    check_user_namespace_support()
}

fn check_user_namespace_support() -> bool {
    // Check if unprivileged user namespaces are enabled
    std::fs::read_to_string("/proc/sys/kernel/unprivileged_userns_clone")
        .map(|s| s.trim() == "1")
        .unwrap_or(true) // If file doesn't exist, assume enabled (newer kernels)
}

/// Linux sandbox executor
pub struct LinuxExecutor {
    _private: (),
}

impl LinuxExecutor {
    pub fn new() -> Self {
        Self { _private: () }
    }
}

impl Default for LinuxExecutor {
    fn default() -> Self {
        Self::new()
    }
}

impl PlatformExecutor for LinuxExecutor {
    fn execute(
        &self,
        config: &SandboxConfig,
        cmd: &str,
        args: &[&str],
        stdin: Option<&[u8]>,
    ) -> Result<ExecutionResult> {
        self.execute_detailed(config, &ExecutionPolicy::default(), cmd, args, stdin)
            .map(|report| report.result)
    }

    fn execute_detailed(
        &self,
        config: &SandboxConfig,
        policy: &ExecutionPolicy,
        cmd: &str,
        args: &[&str],
        stdin: Option<&[u8]>,
    ) -> Result<ExecutionReport> {
        use nix::sched::{clone, CloneFlags};
        use nix::sys::signal::Signal;
        use nix::unistd::{execvpe, pipe};
        use std::collections::HashMap;
        use std::ffi::CString;

        const STACK_SIZE: usize = 1024 * 1024;

        let start = Instant::now();

        // Setup proxy if using proxied network mode
        let _proxy = match &config.network_mode {
            NetworkMode::Proxied { allowed_domains } => {
                Some(ProxiedNetwork::setup(allowed_domains.clone())?)
            }
            _ => None,
        };

        // Create pipes for stdout, stderr, and synchronization
        let (r, w) = pipe()
            .map_err(|e| SandboxError::Internal(format!("create pipe for child stdout: {e}")))?;
        let stdout_read: RawFd = r.into_raw_fd();
        let stdout_write: RawFd = w.into_raw_fd();

        let (r, w) = pipe()
            .map_err(|e| SandboxError::Internal(format!("create pipe for child stderr: {e}")))?;
        let stderr_read: RawFd = r.into_raw_fd();
        let stderr_write: RawFd = w.into_raw_fd();

        let (r, w) = pipe().map_err(|e| {
            SandboxError::Internal(format!("create pipe for parent-child sync: {e}"))
        })?;
        let ready_read: RawFd = r.into_raw_fd();
        let mut ready_write = AutoCloseFd::new(w.into_raw_fd());

        let (stdin_read, stdin_write) = if stdin.is_some() {
            let (r, w) = pipe()
                .map_err(|e| SandboxError::Internal(format!("create pipe for child stdin: {e}")))?;
            (Some(r.into_raw_fd()), Some(w.into_raw_fd()))
        } else {
            (None, None)
        };

        // Build clone flags
        let mut clone_flags = CloneFlags::CLONE_NEWUSER
            | CloneFlags::CLONE_NEWPID
            | CloneFlags::CLONE_NEWNS
            | CloneFlags::CLONE_NEWUTS
            | CloneFlags::CLONE_NEWIPC;

        if matches!(config.network_mode, NetworkMode::None) {
            clone_flags |= CloneFlags::CLONE_NEWNET;
        }

        // Prepare command arguments
        let cmd_cstr = CString::new(cmd)?;
        let args_cstr: Vec<CString> = std::iter::once(cmd_cstr.clone())
            .chain(args.iter().map(|s| CString::new(*s).unwrap()))
            .collect();

        // Allocate stack for child
        let mut stack = vec![0u8; STACK_SIZE];

        // Clone config for child
        let child_config = config.clone();
        let default_path =
            std::env::var("PATH").unwrap_or_else(|_| "/usr/local/bin:/usr/bin:/bin".into());
        let mut env: HashMap<String, String> = if config.clear_env {
            HashMap::new()
        } else {
            std::env::vars().collect()
        };
        env.extend(config.env.clone());

        // Add proxy environment variables if using proxied network
        if let Some(ref proxy) = _proxy {
            for (key, value) in proxy.env_vars() {
                env.insert(key, value);
            }
        }
        if !env.contains_key("PATH") {
            env.insert("PATH".into(), default_path);
        }
        let env_cstr: Vec<CString> = env
            .iter()
            .map(|(key, value)| CString::new(format!("{key}={value}")))
            .collect::<std::result::Result<Vec<_>, _>>()?;

        let working_dir = config.working_dir.clone();
        let hostname = config.hostname.clone();
        let child_ready_write = ready_write.raw();

        // Create user namespace config
        let user_ns = UserNamespace::new(config.uid, config.gid);

        // Child process entry point
        let child_fn: Box<dyn FnMut() -> isize> = Box::new(move || {
            let _ = close_raw(child_ready_write);
            if let Some(stdin_fd) = stdin_write {
                let _ = close_raw(stdin_fd);
            }

            // Create a new process group with this process as leader
            // This allows us to kill all children with killpg
            unsafe {
                libc::setpgid(0, 0);
            }

            // Wait for parent to setup UID/GID mappings
            let mut buf = [0u8; 1];
            match read_raw(ready_read, &mut buf) {
                Ok(1) if buf[0] == 0 => {}
                _ => {
                    let _ = close_raw(ready_read);
                    return 1;
                }
            }
            let _ = close_raw(ready_read);

            // Setup stdin
            if let Some(stdin_fd) = stdin_read {
                unsafe {
                    libc::dup2(stdin_fd, libc::STDIN_FILENO);
                }
                let _ = close_raw(stdin_fd);
            }

            // Redirect stdout/stderr
            unsafe {
                libc::dup2(stdout_write, libc::STDOUT_FILENO);
                libc::dup2(stderr_write, libc::STDERR_FILENO);
            }
            let _ = close_raw(stdout_write);
            let _ = close_raw(stderr_write);
            let _ = close_raw(stdout_read);
            let _ = close_raw(stderr_read);

            // Setup hostname (UTS namespace)
            if let Err(e) = nix::unistd::sethostname(&hostname) {
                eprintln!("Failed to set hostname: {}", e);
            }

            // Setup mount namespace if needed
            if let Some(rootfs) = &child_config.rootfs {
                if let Err(e) =
                    setup_mount_namespace(rootfs, &child_config.mounts, &child_config.tmpfs_mounts)
                {
                    eprintln!("Mount setup failed: {}", e);
                    return 1;
                }
            } else if let Err(e) =
                setup_mount_overlays(&child_config.mounts, &child_config.tmpfs_mounts)
            {
                eprintln!("Mount setup failed: {}", e);
                return 1;
            }

            // Change working directory
            if working_dir.exists() {
                let _ = std::env::set_current_dir(&working_dir);
            }

            apply_resource_limits(&child_config);

            // Apply seccomp filter
            if !matches!(child_config.seccomp_profile, SeccompProfile::Disabled) {
                if let Err(e) = SeccompFilter::apply(&child_config.seccomp_profile) {
                    eprintln!("Seccomp setup failed: {}", e);
                }
            }

            // Execute
            let _ = execvpe(&cmd_cstr, &args_cstr, &env_cstr);
            eprintln!("execvp failed");
            127
        });

        // Clone child
        let child_pid = unsafe {
            clone(
                child_fn,
                &mut stack,
                clone_flags,
                Some(Signal::SIGCHLD as i32),
            )
        }
        .map_err(|e| SandboxError::Internal(format!("clone sandboxed process: {e}")))?;

        // Parent process

        // Close child's end of pipes
        close_raw(ready_read).map_err(|e| {
            abort_child_startup(
                child_pid,
                &mut ready_write,
                format!("close sync pipe read end in parent: {e}"),
            )
        })?;
        close_raw(stdout_write).map_err(|e| {
            abort_child_startup(
                child_pid,
                &mut ready_write,
                format!("close stdout pipe write end in parent: {e}"),
            )
        })?;
        close_raw(stderr_write).map_err(|e| {
            abort_child_startup(
                child_pid,
                &mut ready_write,
                format!("close stderr pipe write end in parent: {e}"),
            )
        })?;
        if let Some(fd) = stdin_read {
            close_raw(fd).map_err(|e| {
                abort_child_startup(
                    child_pid,
                    &mut ready_write,
                    format!("close stdin pipe read end in parent: {e}"),
                )
            })?;
        }

        // Write UID/GID mappings
        if let Err(e) = user_ns.write_mappings(child_pid.as_raw()) {
            drop(ready_write);
            let _ = nix::sys::wait::waitpid(child_pid, None);
            return Err(e);
        }

        let limit_plan = LimitPlan::from(config, policy);

        // Create and configure cgroup
        let sandbox_id = format!("nanobox-{}", child_pid.as_raw());
        let (cgroup, limit_diagnostics) = if needs_cgroup(config) {
            configure_cgroup(config, &limit_plan, &sandbox_id, child_pid.as_raw() as u32)?
        } else {
            (
                None,
                LimitDiagnostics {
                    memory: LimitStatus::NotRequested,
                    cpu: LimitStatus::NotRequested,
                    pids: LimitStatus::NotRequested,
                },
            )
        };

        // Write stdin if provided
        if let (Some(data), Some(fd)) = (stdin, stdin_write) {
            let _ = write_raw(fd, data);
            close_raw(fd).map_err(|e| {
                abort_child_startup(
                    child_pid,
                    &mut ready_write,
                    format!("close stdin pipe write end after writing: {e}"),
                )
            })?;
        }

        // Signal child to continue
        ready_write.write_byte_and_close(0).map_err(|e| {
            abort_child_startup(
                child_pid,
                &mut ready_write,
                format!("signal child to continue: {e}"),
            )
        })?;

        // Wait for child with timeout
        let timeout = config.wall_time_limit.unwrap_or(Duration::from_secs(3600));
        let (stdout, stderr, exit_code, killed_by_timeout, signal) =
            wait_with_timeout(child_pid, stdout_read, stderr_read, timeout)?;

        // Collect resource stats BEFORE cgroup cleanup
        let (peak_memory, cpu_time, killed_by_oom, metric_diagnostics) =
            collect_linux_metrics(cgroup.as_ref());

        // Cgroup will be cleaned up when dropped

        Ok(ExecutionReport {
            result: ExecutionResult {
                stdout,
                stderr,
                exit_code,
                duration: start.elapsed(),
                killed_by_timeout,
                killed_by_oom,
                signal,
                peak_memory,
                cpu_time,
            },
            diagnostics: ExecutionDiagnostics {
                limits: limit_diagnostics,
                metrics: metric_diagnostics,
            },
        })
    }

    fn check_support(&self, _config: &SandboxConfig) -> Result<()> {
        if !check_user_namespace_support() {
            return Err(SandboxError::UserNamespaceDisabled);
        }
        Ok(())
    }
}

fn needs_cgroup(config: &SandboxConfig) -> bool {
    config.memory_limit.is_some() || config.cpu_limit.is_some() || config.max_pids.is_some()
}

fn configure_cgroup(
    config: &SandboxConfig,
    limit_plan: &LimitPlan,
    sandbox_id: &str,
    child_pid: u32,
) -> Result<(Option<CgroupManager>, LimitDiagnostics)> {
    let support = probe_cgroup_support();
    let requested_controllers = limit_plan.requested_controllers();
    let require_rootless_memory = rootless_memory_required(config);
    let mut diagnostics = LimitDiagnostics {
        memory: limit_status(limit_plan.memory),
        cpu: limit_status(limit_plan.cpu),
        pids: limit_status(limit_plan.pids),
    };

    if !support.mounted || !support.accessible {
        if require_rootless_memory {
            return Err(SandboxError::ResourceLimitUnavailable {
                limit: "memory".into(),
                reason: support.unavailable_reason(Some(CgroupController::Memory)),
            });
        }
        if let Some((limit, controller)) = limit_plan.first_strict_limit() {
            return Err(SandboxError::ResourceLimitUnavailable {
                limit: limit.into(),
                reason: support.unavailable_reason(Some(controller)),
            });
        }

        let reason = support.unavailable_reason(None);
        set_best_effort_unavailable(&mut diagnostics, *limit_plan, &reason);
        return Ok((None, diagnostics));
    }

    let cg = match CgroupManager::create(sandbox_id, &requested_controllers) {
        Ok(cg) => cg,
        Err(e) => {
            let reason = format!("failed to create cgroup: {e}");
            if require_rootless_memory {
                return Err(SandboxError::ResourceLimitUnavailable {
                    limit: "memory".into(),
                    reason,
                });
            }
            if let Some((limit, _)) = limit_plan.first_strict_limit() {
                return Err(SandboxError::ResourceLimitUnavailable {
                    limit: limit.into(),
                    reason,
                });
            }

            set_best_effort_unavailable(&mut diagnostics, *limit_plan, &reason);
            return Ok((None, diagnostics));
        }
    };

    let mut memory_configured = false;
    let mut cpu_configured = false;
    let mut pids_configured = false;

    if let Some(memory) = config.memory_limit {
        match cg.set_memory_limit(memory) {
            Ok(()) => memory_configured = true,
            Err(e) => {
                if require_rootless_memory {
                    return Err(SandboxError::ResourceLimitUnavailable {
                        limit: "memory".into(),
                        reason: e.to_string(),
                    });
                }
                handle_limit_error(
                    &mut diagnostics.memory,
                    limit_plan.memory,
                    "memory",
                    e.to_string(),
                )?
            }
        }
    }

    if let Some(cpu) = config.cpu_limit {
        match cg.set_cpu_limit(cpu) {
            Ok(()) => cpu_configured = true,
            Err(e) => {
                handle_limit_error(&mut diagnostics.cpu, limit_plan.cpu, "cpu", e.to_string())?
            }
        }
    }

    if let Some(pids) = config.max_pids {
        match cg.set_pids_limit(pids) {
            Ok(()) => pids_configured = true,
            Err(e) => handle_limit_error(
                &mut diagnostics.pids,
                limit_plan.pids,
                "pids",
                e.to_string(),
            )?,
        }
    }

    if let Err(e) = cg.add_process(child_pid) {
        let reason = format!("failed to add process to cgroup: {e}");
        if require_rootless_memory {
            cg.cleanup();
            return Err(SandboxError::ResourceLimitUnavailable {
                limit: "memory".into(),
                reason,
            });
        }
        if let Some((limit, _)) = limit_plan.first_strict_limit() {
            cg.cleanup();
            return Err(SandboxError::ResourceLimitUnavailable {
                limit: limit.into(),
                reason,
            });
        }

        if memory_configured {
            diagnostics.memory = LimitStatus::NotEnforced {
                reason: reason.clone(),
            };
        }
        if cpu_configured {
            diagnostics.cpu = LimitStatus::NotEnforced {
                reason: reason.clone(),
            };
        }
        if pids_configured {
            diagnostics.pids = LimitStatus::NotEnforced { reason };
        }
        cg.cleanup();
        return Ok((None, diagnostics));
    }

    if memory_configured {
        diagnostics.memory = LimitStatus::Enforced;
    }
    if cpu_configured {
        diagnostics.cpu = LimitStatus::Enforced;
    }
    if pids_configured {
        diagnostics.pids = LimitStatus::Enforced;
    }

    Ok((Some(cg), diagnostics))
}

fn rootless_memory_required(config: &SandboxConfig) -> bool {
    config.memory_limit.is_some() && unsafe { libc::geteuid() } != 0
}

fn limit_status(mode: EnforcementMode) -> LimitStatus {
    match mode {
        EnforcementMode::NotRequested => LimitStatus::NotRequested,
        EnforcementMode::Strict | EnforcementMode::BestEffort => LimitStatus::Unknown {
            reason: "Limit requested but not evaluated yet".into(),
        },
    }
}

fn handle_limit_error(
    status: &mut LimitStatus,
    mode: EnforcementMode,
    limit: &'static str,
    reason: String,
) -> Result<()> {
    match mode {
        EnforcementMode::Strict => Err(SandboxError::ResourceLimitUnavailable {
            limit: limit.into(),
            reason,
        }),
        EnforcementMode::BestEffort => {
            *status = LimitStatus::NotEnforced { reason };
            Ok(())
        }
        EnforcementMode::NotRequested => Ok(()),
    }
}

fn set_best_effort_unavailable(
    diagnostics: &mut LimitDiagnostics,
    limit_plan: LimitPlan,
    reason: &str,
) {
    if limit_plan.memory == EnforcementMode::BestEffort {
        diagnostics.memory = LimitStatus::NotEnforced {
            reason: reason.into(),
        };
    }
    if limit_plan.cpu == EnforcementMode::BestEffort {
        diagnostics.cpu = LimitStatus::NotEnforced {
            reason: reason.into(),
        };
    }
    if limit_plan.pids == EnforcementMode::BestEffort {
        diagnostics.pids = LimitStatus::NotEnforced {
            reason: reason.into(),
        };
    }
}

fn collect_linux_metrics(
    cgroup: Option<&CgroupManager>,
) -> (Option<u64>, Option<Duration>, bool, MetricDiagnostics) {
    if let Some(cg) = cgroup {
        let (peak_memory, peak_status) = match cg.get_memory_stats() {
            Ok(stats) => (Some(stats.peak), MetricStatus::Collected),
            Err(e) => (
                None,
                MetricStatus::Unavailable {
                    reason: e.to_string(),
                },
            ),
        };
        let (cpu_time, cpu_status) = match cg.get_cpu_stats() {
            Ok(stats) => (
                Some(Duration::from_micros(stats.total_usec)),
                MetricStatus::Collected,
            ),
            Err(e) => (
                None,
                MetricStatus::Unavailable {
                    reason: e.to_string(),
                },
            ),
        };

        (
            peak_memory,
            cpu_time,
            cg.was_oom_killed(),
            MetricDiagnostics {
                peak_memory: peak_status,
                cpu_time: cpu_status,
            },
        )
    } else {
        (
            None,
            None,
            false,
            MetricDiagnostics {
                peak_memory: MetricStatus::Unavailable {
                    reason:
                        "peak memory collection requires a cgroup-backed execution path on Linux"
                            .into(),
                },
                cpu_time: MetricStatus::Unavailable {
                    reason: "cpu time collection requires a cgroup-backed execution path on Linux"
                        .into(),
                },
            },
        )
    }
}

fn apply_resource_limits(config: &SandboxConfig) {
    if let Some(max_files) = config.max_open_files {
        let rlim = libc::rlimit {
            rlim_cur: max_files as libc::rlim_t,
            rlim_max: max_files as libc::rlim_t,
        };
        unsafe {
            libc::setrlimit(libc::RLIMIT_NOFILE, &rlim);
        }
    }

    if let Some(max_file_size) = config.max_file_size {
        let rlim = libc::rlimit {
            rlim_cur: max_file_size as libc::rlim_t,
            rlim_max: max_file_size as libc::rlim_t,
        };
        unsafe {
            libc::setrlimit(libc::RLIMIT_FSIZE, &rlim);
        }
    }

    if let Some(cpu_time) = config.cpu_time_limit {
        let secs = cpu_time.as_secs();
        if secs > 0 {
            let rlim = libc::rlimit {
                rlim_cur: secs as libc::rlim_t,
                rlim_max: secs as libc::rlim_t,
            };
            unsafe {
                libc::setrlimit(libc::RLIMIT_CPU, &rlim);
            }
        }
    }
}

fn make_mounts_private() -> Result<()> {
    use nix::mount::{mount, MsFlags};

    mount::<str, str, str, str>(None, "/", None, MsFlags::MS_REC | MsFlags::MS_PRIVATE, None)
        .map_err(|e| SandboxError::Internal(format!("mark all mounts as private: {e}")))
}

fn bind_mount(
    source: &std::path::Path,
    target: &std::path::Path,
    permission: Permission,
) -> Result<()> {
    use nix::mount::{mount, MsFlags};

    if source.is_dir() {
        std::fs::create_dir_all(target)?;
    } else {
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent)?;
        }
        if !target.exists() {
            std::fs::File::create(target)?;
        }
    }

    mount(
        Some(source),
        target,
        None::<&str>,
        MsFlags::MS_BIND | MsFlags::MS_REC,
        None::<&str>,
    )
    .map_err(|e| {
        SandboxError::Internal(format!(
            "bind mount {} -> {}: {e}",
            source.display(),
            target.display()
        ))
    })?;

    if permission == Permission::ReadOnly {
        // Linux ignores MS_RDONLY on the initial bind mount. Enforce read-only
        // semantics with a separate remount step so caller-visible permissions
        // match the builder configuration.
        mount(
            None::<&str>,
            target,
            None::<&str>,
            MsFlags::MS_BIND | MsFlags::MS_REMOUNT | MsFlags::MS_RDONLY | MsFlags::MS_REC,
            None::<&str>,
        )
        .map_err(|e| {
            SandboxError::Internal(format!(
                "remount read-only {} -> {}: {e}",
                source.display(),
                target.display()
            ))
        })?;
    }

    Ok(())
}

fn mount_tmpfs(target: &std::path::Path, size: u64) -> Result<()> {
    use nix::mount::{mount, MsFlags};

    std::fs::create_dir_all(target)?;

    let options = format!("size={}", size);
    mount(
        None::<&str>,
        target,
        Some("tmpfs"),
        MsFlags::empty(),
        Some(options.as_str()),
    )
    .map_err(|e| {
        SandboxError::Internal(format!(
            "mount tmpfs at {} (size={}): {e}",
            target.display(),
            size
        ))
    })?;

    Ok(())
}

fn remount_procfs(target: &std::path::Path) -> Result<()> {
    use nix::mount::{mount, umount2, MntFlags, MsFlags};

    std::fs::create_dir_all(target)?;
    // /proc must be mounted from inside the new PID namespace; otherwise
    // /proc/1 and tools like ps can still reflect the host procfs view.
    let _ = umount2(target, MntFlags::MNT_DETACH);
    mount(
        Some("proc"),
        target,
        Some("proc"),
        MsFlags::empty(),
        None::<&str>,
    )
    .map_err(|e| SandboxError::Internal(format!("mount procfs at {}: {e}", target.display())))?;

    Ok(())
}

fn setup_mount_namespace(
    rootfs: &std::path::Path,
    mounts: &[Mount],
    tmpfs_mounts: &[(std::path::PathBuf, u64)],
) -> Result<()> {
    use nix::mount::{mount, MsFlags};

    make_mounts_private()?;

    // Bind mount rootfs
    mount(
        Some(rootfs),
        rootfs,
        None::<&str>,
        MsFlags::MS_BIND | MsFlags::MS_REC,
        None::<&str>,
    )
    .map_err(|e| {
        SandboxError::Internal(format!("bind mount rootfs at {}: {e}", rootfs.display()))
    })?;

    // Setup mounts
    for m in mounts {
        let target = rootfs.join(m.target.strip_prefix("/").unwrap_or(&m.target));
        bind_mount(&m.source, &target, m.permission.clone())?;
    }

    // Setup tmpfs mounts
    for (path, size) in tmpfs_mounts {
        let target = rootfs.join(path.strip_prefix("/").unwrap_or(path));
        mount_tmpfs(&target, *size)?;
    }

    // Pivot root
    let old_root = rootfs.join("old_root");
    std::fs::create_dir_all(&old_root)?;

    nix::unistd::pivot_root(rootfs, &old_root).map_err(|e| {
        SandboxError::Internal(format!(
            "pivot_root into sandbox at {}: {e}",
            rootfs.display()
        ))
    })?;
    std::env::set_current_dir("/")?;

    // Unmount old root
    mount::<str, str, str, str>(
        None,
        "/old_root",
        None,
        MsFlags::MS_REC | MsFlags::MS_PRIVATE,
        None,
    )
    .map_err(|e| SandboxError::Internal(format!("mark /old_root as private mount: {e}")))?;
    nix::mount::umount2("/old_root", nix::mount::MntFlags::MNT_DETACH)
        .map_err(|e| SandboxError::Internal(format!("detach /old_root mount: {e}")))?;
    std::fs::remove_dir("/old_root")?;
    remount_procfs(std::path::Path::new("/proc"))?;

    Ok(())
}

fn setup_mount_overlays(
    mounts: &[Mount],
    tmpfs_mounts: &[(std::path::PathBuf, u64)],
) -> Result<()> {
    // Even without a custom rootfs, mounts/tmpfs should still apply inside the
    // sandbox's private mount namespace.
    make_mounts_private()?;

    for m in mounts {
        bind_mount(&m.source, &m.target, m.permission.clone())?;
    }

    for (path, size) in tmpfs_mounts {
        mount_tmpfs(path, *size)?;
    }

    remount_procfs(std::path::Path::new("/proc"))?;

    Ok(())
}

fn wait_with_timeout(
    pid: nix::unistd::Pid,
    stdout_fd: RawFd,
    stderr_fd: RawFd,
    timeout: Duration,
) -> Result<(String, String, i32, bool, Option<i32>)> {
    use nix::sys::wait::{waitpid, WaitPidFlag, WaitStatus};

    let start = Instant::now();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let mut killed_by_timeout = false;

    // Set non-blocking
    unsafe {
        let flags = libc::fcntl(stdout_fd, libc::F_GETFL);
        libc::fcntl(stdout_fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
        let flags = libc::fcntl(stderr_fd, libc::F_GETFL);
        libc::fcntl(stderr_fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
    }

    loop {
        // Read available output
        let mut buf = [0u8; 4096];
        if let Ok(n) = read_raw(stdout_fd, &mut buf) {
            if n > 0 {
                stdout.extend_from_slice(&buf[..n]);
            }
        }
        if let Ok(n) = read_raw(stderr_fd, &mut buf) {
            if n > 0 {
                stderr.extend_from_slice(&buf[..n]);
            }
        }

        match waitpid(pid, Some(WaitPidFlag::WNOHANG))
            .map_err(|e| SandboxError::Internal(format!("waitpid for child {pid}: {e}")))?
        {
            WaitStatus::Exited(_, code) => {
                drain_fd(stdout_fd, &mut stdout);
                drain_fd(stderr_fd, &mut stderr);
                close_raw(stdout_fd).ok();
                close_raw(stderr_fd).ok();
                return Ok((
                    String::from_utf8_lossy(&stdout).to_string(),
                    String::from_utf8_lossy(&stderr).to_string(),
                    code,
                    killed_by_timeout,
                    None,
                ));
            }
            WaitStatus::Signaled(_, sig, _) => {
                drain_fd(stdout_fd, &mut stdout);
                drain_fd(stderr_fd, &mut stderr);
                close_raw(stdout_fd).ok();
                close_raw(stderr_fd).ok();
                return Ok((
                    String::from_utf8_lossy(&stdout).to_string(),
                    String::from_utf8_lossy(&stderr).to_string(),
                    128 + sig as i32,
                    killed_by_timeout,
                    Some(sig as i32),
                ));
            }
            WaitStatus::StillAlive => {
                if start.elapsed() > timeout && !killed_by_timeout {
                    // Kill the entire process group (negative PID)
                    // The child runs in a PID namespace where it's PID 1,
                    // but from our namespace we see the real PID.
                    // Use SIGKILL on the process - the PID namespace
                    // will ensure all children are killed when init (pid 1) dies.
                    let _ = nix::sys::signal::kill(pid, nix::sys::signal::Signal::SIGKILL);

                    // Also try to kill the process group just in case
                    unsafe {
                        libc::kill(-(pid.as_raw()), libc::SIGKILL);
                    }

                    killed_by_timeout = true;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            _ => {
                std::thread::sleep(Duration::from_millis(10));
            }
        }
    }
}

fn drain_fd(fd: RawFd, buf: &mut Vec<u8>) {
    let mut tmp = [0u8; 4096];
    loop {
        match read_raw(fd, &mut tmp) {
            Ok(n) if n > 0 => buf.extend_from_slice(&tmp[..n]),
            _ => break,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::builder::SandboxConfig;

    #[test]
    fn test_linux_executor_creation() {
        let executor = LinuxExecutor::new();
        let _ = executor;
    }

    #[test]
    fn test_limit_plan_requested_controllers() {
        let config = SandboxConfig {
            memory_limit: Some(1),
            max_pids: Some(5),
            ..SandboxConfig::default()
        };
        let plan = LimitPlan::from(
            &config,
            &ExecutionPolicy {
                resource_enforcement: ResourceEnforcement::BestEffort,
                cgroup_limit_requests: crate::builder::CgroupLimitRequests {
                    memory: true,
                    cpu: false,
                    pids: true,
                },
            },
        );

        assert_eq!(
            plan.requested_controllers(),
            vec![CgroupController::Memory, CgroupController::Pids]
        );
    }
}
