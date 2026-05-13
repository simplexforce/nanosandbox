//! Linux platform implementation
//!
//! Uses Linux kernel primitives for sandboxing:
//!
//! - **Namespaces**: PID, mount, network, user, UTS, IPC isolation
//! - **Cgroups v2**: Resource limits (memory, CPU, PIDs)
//! - **Seccomp-BPF**: Syscall filtering
//! - **HTTP Proxy**: Domain whitelisting for proxied network mode

use crate::builder::{Mount, NetworkMode, Permission, SandboxConfig, SeccompProfile};
use crate::error::{Result, SandboxError};
use crate::network::ProxiedNetwork;
use crate::platform::PlatformExecutor;
use crate::result::ExecutionResult;
use std::time::{Duration, Instant};

mod cgroup;
mod namespace;
mod seccomp;

pub use cgroup::CgroupManager;
pub use namespace::{MountNamespace, UserNamespace, UtsNamespace};
pub use seccomp::SeccompFilter;

/// Check if Linux sandboxing is supported
pub fn is_supported() -> bool {
    // Check for user namespace support
    check_user_namespace_support() && check_cgroup_v2_support()
}

fn check_user_namespace_support() -> bool {
    // Check if unprivileged user namespaces are enabled
    std::fs::read_to_string("/proc/sys/kernel/unprivileged_userns_clone")
        .map(|s| s.trim() == "1")
        .unwrap_or(true) // If file doesn't exist, assume enabled (newer kernels)
}

fn check_cgroup_v2_support() -> bool {
    // Check if cgroup v2 is mounted
    std::path::Path::new("/sys/fs/cgroup/cgroup.controllers").exists()
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
        use nix::sched::{clone, CloneFlags};
        use nix::sys::signal::Signal;
        use nix::sys::wait::{waitpid, WaitPidFlag, WaitStatus};
        use nix::unistd::{close, execvp, pipe, read, write, Pid};
        use std::ffi::CString;
        use std::os::unix::io::RawFd;

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
        let (stdout_read, stdout_write) = pipe()?;
        let (stderr_read, stderr_write) = pipe()?;
        let (ready_read, ready_write) = pipe()?;
        let (stdin_read, stdin_write) = if stdin.is_some() {
            let (r, w) = pipe()?;
            (Some(r), Some(w))
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
        let mut env = config.env.clone();

        // Add proxy environment variables if using proxied network
        if let Some(ref proxy) = _proxy {
            for (key, value) in proxy.env_vars() {
                env.insert(key, value);
            }
        }

        let working_dir = config.working_dir.clone();
        let hostname = config.hostname.clone();

        // Create user namespace config
        let user_ns = UserNamespace::new(config.uid, config.gid);

        // Clone child
        let child_pid = clone(
            Box::new(move || {
                // Create a new process group with this process as leader
                // This allows us to kill all children with killpg
                unsafe {
                    libc::setpgid(0, 0);
                }

                // Wait for parent to setup UID/GID mappings
                let mut buf = [0u8; 1];
                let _ = read(ready_read, &mut buf);
                let _ = close(ready_read);

                // Setup stdin
                if let Some(stdin_fd) = stdin_read {
                    unsafe {
                        libc::dup2(stdin_fd, libc::STDIN_FILENO);
                    }
                    let _ = close(stdin_fd);
                }

                // Redirect stdout/stderr
                unsafe {
                    libc::dup2(stdout_write, libc::STDOUT_FILENO);
                    libc::dup2(stderr_write, libc::STDERR_FILENO);
                }
                let _ = close(stdout_write);
                let _ = close(stderr_write);
                let _ = close(stdout_read);
                let _ = close(stderr_read);

                // Setup hostname (UTS namespace)
                if let Err(e) = nix::unistd::sethostname(&hostname) {
                    eprintln!("Failed to set hostname: {}", e);
                }

                // Setup mount namespace if needed
                if let Some(rootfs) = &child_config.rootfs {
                    if let Err(e) = setup_mount_namespace(rootfs, &child_config.mounts, &child_config.tmpfs_mounts) {
                        eprintln!("Mount setup failed: {}", e);
                        return 1;
                    }
                }

                // Set environment
                for (key, _) in std::env::vars() {
                    std::env::remove_var(&key);
                }
                for (key, value) in &env {
                    std::env::set_var(key, value);
                }
                if !env.contains_key("PATH") {
                    std::env::set_var("PATH", "/usr/local/bin:/usr/bin:/bin");
                }

                // Change working directory
                if working_dir.exists() {
                    let _ = std::env::set_current_dir(&working_dir);
                }

                // Apply seccomp filter
                if !matches!(child_config.seccomp_profile, SeccompProfile::Disabled) {
                    if let Err(e) = SeccompFilter::apply(&child_config.seccomp_profile) {
                        eprintln!("Seccomp setup failed: {}", e);
                    }
                }

                // Execute
                let _ = execvp(&cmd_cstr, &args_cstr);
                eprintln!("execvp failed");
                127
            }),
            &mut stack,
            clone_flags,
            Some(Signal::SIGCHLD as i32),
        )?;

        // Parent process

        // Close child's end of pipes
        close(ready_read)?;
        close(stdout_write)?;
        close(stderr_write)?;
        if let Some(fd) = stdin_read {
            close(fd)?;
        }

        // Write UID/GID mappings
        user_ns.write_mappings(child_pid.as_raw())?;

        // Create and configure cgroup
        let sandbox_id = format!("nanobox-{}", child_pid.as_raw());
        let cgroup = if needs_cgroup(config) {
            let cg = CgroupManager::create(&sandbox_id)?;
            if let Some(memory) = config.memory_limit {
                cg.set_memory_limit(memory)?;
            }
            if let Some(cpu) = config.cpu_limit {
                cg.set_cpu_limit(cpu)?;
            }
            if let Some(pids) = config.max_pids {
                cg.set_pids_limit(pids)?;
            }
            cg.add_process(child_pid.as_raw() as u32)?;
            Some(cg)
        } else {
            None
        };

        // Write stdin if provided
        if let (Some(data), Some(fd)) = (stdin, stdin_write) {
            let _ = write(fd, data);
            close(fd)?;
        }

        // Signal child to continue
        write(ready_write, &[0u8])?;
        close(ready_write)?;

        // Wait for child with timeout
        let timeout = config.wall_time_limit.unwrap_or(Duration::from_secs(3600));
        let (stdout, stderr, exit_code, killed_by_timeout, signal) =
            wait_with_timeout(child_pid, stdout_read, stderr_read, timeout)?;

        // Collect resource stats BEFORE cgroup cleanup
        let (peak_memory, cpu_time, killed_by_oom) = if let Some(ref cg) = cgroup {
            let peak = cg.get_memory_stats().ok().map(|s| s.peak);
            let cpu = cg.get_cpu_stats().ok().map(|s| Duration::from_micros(s.total_usec));
            let oom = cg.was_oom_killed();
            (peak, cpu, oom)
        } else {
            (None, None, false)
        };

        // Cgroup will be cleaned up when dropped

        Ok(ExecutionResult {
            stdout,
            stderr,
            exit_code,
            duration: start.elapsed(),
            killed_by_timeout,
            killed_by_oom,
            signal,
            peak_memory,
            cpu_time,
        })
    }

    fn check_support(&self, _config: &SandboxConfig) -> Result<()> {
        if !check_user_namespace_support() {
            return Err(SandboxError::UserNamespaceDisabled);
        }
        if !check_cgroup_v2_support() {
            return Err(SandboxError::CgroupV2Unavailable);
        }
        Ok(())
    }
}

fn needs_cgroup(config: &SandboxConfig) -> bool {
    config.memory_limit.is_some() || config.cpu_limit.is_some() || config.max_pids.is_some()
}

fn setup_mount_namespace(
    rootfs: &std::path::Path,
    mounts: &[Mount],
    tmpfs_mounts: &[(std::path::PathBuf, u64)],
) -> Result<()> {
    use nix::mount::{mount, MsFlags};

    // Make everything private
    mount::<str, str, str, str>(None, "/", None, MsFlags::MS_REC | MsFlags::MS_PRIVATE, None)?;

    // Bind mount rootfs
    mount(
        Some(rootfs),
        rootfs,
        None::<&str>,
        MsFlags::MS_BIND | MsFlags::MS_REC,
        None::<&str>,
    )?;

    // Setup mounts
    for m in mounts {
        let target = rootfs.join(m.target.strip_prefix("/").unwrap_or(&m.target));
        std::fs::create_dir_all(&target)?;

        let mut flags = MsFlags::MS_BIND;
        if m.permission == Permission::ReadOnly {
            flags |= MsFlags::MS_RDONLY;
        }

        mount(
            Some(&m.source),
            &target,
            None::<&str>,
            flags,
            None::<&str>,
        )?;
    }

    // Setup tmpfs mounts
    for (path, size) in tmpfs_mounts {
        let target = rootfs.join(path.strip_prefix("/").unwrap_or(path));
        std::fs::create_dir_all(&target)?;

        let options = format!("size={}", size);
        mount(
            None::<&str>,
            &target,
            Some("tmpfs"),
            MsFlags::empty(),
            Some(options.as_str()),
        )?;
    }

    // Pivot root
    let old_root = rootfs.join("old_root");
    std::fs::create_dir_all(&old_root)?;

    nix::unistd::pivot_root(rootfs, &old_root)?;
    std::env::set_current_dir("/")?;

    // Unmount old root
    mount::<str, str, str, str>(None, "/old_root", None, MsFlags::MS_REC | MsFlags::MS_PRIVATE, None)?;
    nix::mount::umount2("/old_root", nix::mount::MntFlags::MNT_DETACH)?;
    std::fs::remove_dir("/old_root")?;

    Ok(())
}

fn wait_with_timeout(
    pid: nix::unistd::Pid,
    stdout_fd: std::os::unix::io::RawFd,
    stderr_fd: std::os::unix::io::RawFd,
    timeout: Duration,
) -> Result<(String, String, i32, bool, Option<i32>)> {
    use nix::sys::wait::{waitpid, WaitPidFlag, WaitStatus};
    use nix::unistd::{close, read};

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
        if let Ok(n) = read(stdout_fd, &mut buf) {
            if n > 0 {
                stdout.extend_from_slice(&buf[..n]);
            }
        }
        if let Ok(n) = read(stderr_fd, &mut buf) {
            if n > 0 {
                stderr.extend_from_slice(&buf[..n]);
            }
        }

        match waitpid(pid, Some(WaitPidFlag::WNOHANG))? {
            WaitStatus::Exited(_, code) => {
                drain_fd(stdout_fd, &mut stdout);
                drain_fd(stderr_fd, &mut stderr);
                close(stdout_fd).ok();
                close(stderr_fd).ok();
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
                close(stdout_fd).ok();
                close(stderr_fd).ok();
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

fn drain_fd(fd: std::os::unix::io::RawFd, buf: &mut Vec<u8>) {
    let mut tmp = [0u8; 4096];
    loop {
        match nix::unistd::read(fd, &mut tmp) {
            Ok(n) if n > 0 => buf.extend_from_slice(&tmp[..n]),
            _ => break,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_linux_executor_creation() {
        let executor = LinuxExecutor::new();
        let _ = executor;
    }
}
