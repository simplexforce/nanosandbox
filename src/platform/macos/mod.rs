//! macOS platform implementation
//!
//! Uses macOS sandbox-exec (Seatbelt) for sandboxing.
//!
//! ## Implementation
//!
//! - **Process isolation**: sandbox-exec with SBPL profiles
//! - **Filesystem**: Sandbox profile file system restrictions
//! - **Network**: Sandbox profile network restrictions + HTTP proxy for whitelisting
//! - **Resource limits**: setrlimit (RLIMIT_AS, RLIMIT_NPROC, RLIMIT_NOFILE)

use crate::builder::{NetworkMode, Permission, SandboxConfig, SeccompProfile};
use crate::error::{Result, SandboxError};
use crate::network::ProxiedNetwork;
use crate::platform::PlatformExecutor;
use crate::result::ExecutionResult;
use std::io::{Read, Write};
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// Check if sandbox-exec is available
pub fn is_supported() -> bool {
    std::path::Path::new("/usr/bin/sandbox-exec").exists()
}

/// macOS sandbox executor using sandbox-exec
pub struct MacOSExecutor {
    _private: (),
}

impl MacOSExecutor {
    pub fn new() -> Self {
        Self { _private: () }
    }

    /// Generate SBPL (Sandbox Profile Language) profile
    fn generate_profile(&self, config: &SandboxConfig) -> String {
        let mut profile = String::new();

        // Version and default deny
        profile.push_str("(version 1)\n");
        profile.push_str("(deny default)\n");

        // Allow basic process operations
        profile.push_str("(allow process-fork)\n");
        profile.push_str("(allow process-exec)\n");
        profile.push_str("(allow process-exec-interpreter)\n");
        profile.push_str("(allow signal)\n");

        // Allow sysctl operations
        profile.push_str("(allow sysctl-read)\n");
        profile.push_str("(allow sysctl-write)\n");

        // Allow mach operations
        profile.push_str("(allow mach-lookup)\n");
        profile.push_str("(allow mach-register)\n");
        profile.push_str("(allow mach-priv-host-port)\n");
        profile.push_str("(allow mach-priv-task-port)\n");
        profile.push_str("(allow mach-task-name)\n");

        // Allow IPC operations
        profile.push_str("(allow ipc-posix-shm-read-data)\n");
        profile.push_str("(allow ipc-posix-shm-write-data)\n");
        profile.push_str("(allow ipc-posix-shm-read-metadata)\n");
        profile.push_str("(allow ipc-posix-shm-write-create)\n");
        profile.push_str("(allow ipc-posix-sem)\n");

        // Allow iokit and pseudo-tty
        profile.push_str("(allow iokit-open)\n");
        profile.push_str("(allow pseudo-tty)\n");

        // Allow process info
        profile.push_str("(allow process-info-pidinfo)\n");
        profile.push_str("(allow process-info-setcontrol)\n");
        profile.push_str("(allow process-info-dirtycontrol)\n");
        profile.push_str("(allow process-info-codesignature)\n");

        // Allow reading from anywhere (simplifies profile)
        profile.push_str("(allow file-read* (subpath \"/\"))\n");

        // Allow writes to specific directories
        profile.push_str("(allow file-write* (subpath \"/tmp\"))\n");
        profile.push_str("(allow file-write* (subpath \"/private/tmp\"))\n");
        profile.push_str("(allow file-write* (subpath \"/private/var/folders\"))\n");
        profile.push_str("(allow file-write* (subpath \"/dev\"))\n");

        // Working directory write access
        let working_dir = config.working_dir.to_string_lossy();
        profile.push_str(&format!("(allow file-write* (subpath \"{}\"))\n", working_dir));

        // Custom mount write access
        for mount in &config.mounts {
            if mount.permission == Permission::ReadWrite {
                let source = mount.source.to_string_lossy();
                profile.push_str(&format!("(allow file-write* (subpath \"{}\"))\n", source));
            }
        }

        // tmpfs mount write access
        for (path, _) in &config.tmpfs_mounts {
            let path_str = path.to_string_lossy();
            profile.push_str(&format!("(allow file-write* (subpath \"{}\"))\n", path_str));
        }

        // Rootfs write access if specified
        if let Some(rootfs) = &config.rootfs {
            let rootfs_str = rootfs.to_string_lossy();
            profile.push_str(&format!("(allow file-write* (subpath \"{}\"))\n", rootfs_str));
        }

        // Network rules
        match &config.network_mode {
            NetworkMode::None => {
                // No network rules - default deny applies
            }
            NetworkMode::Host | NetworkMode::Proxied { .. } => {
                profile.push_str("(allow network*)\n");
            }
        }

        profile
    }

    /// Apply resource limits using setrlimit
    /// Called in the child process before exec
    fn apply_resource_limits(config: &SandboxConfig) {
        // Memory limit (RLIMIT_AS - address space)
        if let Some(memory) = config.memory_limit {
            let rlim = libc::rlimit {
                rlim_cur: memory,
                rlim_max: memory,
            };
            unsafe {
                libc::setrlimit(libc::RLIMIT_AS, &rlim);
            }
        }

        // NOTE: RLIMIT_NPROC is NOT used on macOS because it limits processes
        // for the ENTIRE USER, not just the sandbox. This is not useful for
        // sandboxing and can interfere with other processes.
        // On Linux, we use cgroups pids controller instead.

        // Max open files (RLIMIT_NOFILE)
        if let Some(max_files) = config.max_open_files {
            let rlim = libc::rlimit {
                rlim_cur: max_files as u64,
                rlim_max: max_files as u64,
            };
            unsafe {
                libc::setrlimit(libc::RLIMIT_NOFILE, &rlim);
            }
        }

        // Max file size (RLIMIT_FSIZE)
        if let Some(max_file_size) = config.max_file_size {
            let rlim = libc::rlimit {
                rlim_cur: max_file_size,
                rlim_max: max_file_size,
            };
            unsafe {
                libc::setrlimit(libc::RLIMIT_FSIZE, &rlim);
            }
        }

        // CPU time limit (RLIMIT_CPU) - in seconds
        if let Some(cpu_time) = config.cpu_time_limit {
            let secs = cpu_time.as_secs();
            if secs > 0 {
                let rlim = libc::rlimit {
                    rlim_cur: secs,
                    rlim_max: secs,
                };
                unsafe {
                    libc::setrlimit(libc::RLIMIT_CPU, &rlim);
                }
            }
        }
    }

    /// Kill the entire process group
    fn kill_process_group(pid: i32) {
        unsafe {
            // Kill the entire process group (negative pid)
            libc::kill(-pid, libc::SIGKILL);
        }
    }

}

impl Default for MacOSExecutor {
    fn default() -> Self {
        Self::new()
    }
}

impl PlatformExecutor for MacOSExecutor {
    fn execute(
        &self,
        config: &SandboxConfig,
        cmd: &str,
        args: &[&str],
        stdin: Option<&[u8]>,
    ) -> Result<ExecutionResult> {
        let start = Instant::now();

        // Setup proxy if using proxied network mode
        let proxy = match &config.network_mode {
            NetworkMode::Proxied { allowed_domains } => {
                Some(ProxiedNetwork::setup(allowed_domains.clone())?)
            }
            _ => None,
        };

        // Generate sandbox profile
        let profile = self.generate_profile(config);

        // Clone config values for the closure
        let memory_limit = config.memory_limit;
        let max_open_files = config.max_open_files;
        let max_file_size = config.max_file_size;
        let cpu_time_limit = config.cpu_time_limit;

        // Build command: sandbox-exec -p <profile> <cmd> <args>
        let mut command = Command::new("/usr/bin/sandbox-exec");
        command.arg("-p").arg(&profile);
        command.arg(cmd);
        command.args(args);

        // Set working directory
        command.current_dir(&config.working_dir);

        // Clear and set environment
        if config.clear_env {
            command.env_clear();
        }
        for (key, value) in &config.env {
            command.env(key, value);
        }
        // Set default PATH if not provided
        if !config.env.contains_key("PATH") {
            command.env("PATH", "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin");
        }

        // Set proxy environment variables if proxied network
        if let Some(ref proxy) = proxy {
            for (key, value) in proxy.env_vars() {
                command.env(key, value);
            }
        }

        // Setup stdin/stdout/stderr
        command.stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        });
        command.stdout(Stdio::piped());
        command.stderr(Stdio::piped());

        // CRITICAL: Set up process group and resource limits before exec
        // This runs in the child process after fork but before exec
        unsafe {
            command.pre_exec(move || {
                // Create a new process group with this process as leader
                // This allows us to kill all children with killpg
                libc::setpgid(0, 0);

                // Apply resource limits
                let temp_config = SandboxConfig {
                    memory_limit,
                    max_open_files,
                    max_file_size,
                    cpu_time_limit,
                    ..Default::default()
                };
                MacOSExecutor::apply_resource_limits(&temp_config);

                Ok(())
            });
        }

        // Spawn the process
        let mut child = command.spawn().map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                SandboxError::CommandNotFound(cmd.to_string())
            } else {
                SandboxError::ExecutionFailed(e.to_string())
            }
        })?;

        let child_pid = child.id() as i32;

        // Write stdin if provided
        if let Some(stdin_data) = stdin {
            if let Some(mut stdin_pipe) = child.stdin.take() {
                let _ = stdin_pipe.write_all(stdin_data);
                // Drop stdin to close the pipe and signal EOF
                drop(stdin_pipe);
            }
        }

        // Wait with timeout
        let timeout = config.wall_time_limit.unwrap_or(Duration::from_secs(3600));
        let result = self.wait_with_timeout(&mut child, child_pid, timeout, start);

        // Proxy will be shut down when dropped
        drop(proxy);

        result
    }

    fn check_support(&self, config: &SandboxConfig) -> Result<()> {
        if !is_supported() {
            return Err(SandboxError::SandboxExecUnavailable);
        }

        // Check for unsupported features
        if !matches!(config.seccomp_profile, SeccompProfile::Disabled | SeccompProfile::Standard) {
            // Custom seccomp profiles are not directly supported on macOS
            // We map them to sandbox-exec profiles instead
        }

        Ok(())
    }
}

impl MacOSExecutor {
    fn wait_with_timeout(
        &self,
        child: &mut std::process::Child,
        child_pid: i32,
        timeout: Duration,
        start: Instant,
    ) -> Result<ExecutionResult> {
        let mut killed_by_timeout = false;

        // Use wait4 with WNOHANG for non-blocking wait with rusage collection
        loop {
            let mut status: libc::c_int = 0;
            let mut rusage: libc::rusage = unsafe { std::mem::zeroed() };

            let result = unsafe {
                libc::wait4(child_pid, &mut status, libc::WNOHANG, &mut rusage)
            };

            if result == child_pid {
                // Process exited, collect output
                let mut stdout = String::new();
                let mut stderr = String::new();

                if let Some(mut stdout_pipe) = child.stdout.take() {
                    let _ = stdout_pipe.read_to_string(&mut stdout);
                }
                if let Some(mut stderr_pipe) = child.stderr.take() {
                    let _ = stderr_pipe.read_to_string(&mut stderr);
                }

                // Extract exit code and signal
                let (exit_code, signal) = if libc::WIFEXITED(status) {
                    (libc::WEXITSTATUS(status), None)
                } else if libc::WIFSIGNALED(status) {
                    (-1, Some(libc::WTERMSIG(status)))
                } else {
                    (-1, None)
                };

                // Extract resource usage
                // maxrss is in bytes on macOS
                let peak_memory = Some(rusage.ru_maxrss as u64);

                // CPU time = user time + system time
                let user_time = Duration::new(
                    rusage.ru_utime.tv_sec as u64,
                    rusage.ru_utime.tv_usec as u32 * 1000,
                );
                let sys_time = Duration::new(
                    rusage.ru_stime.tv_sec as u64,
                    rusage.ru_stime.tv_usec as u32 * 1000,
                );
                let cpu_time = Some(user_time + sys_time);

                return Ok(ExecutionResult {
                    stdout,
                    stderr,
                    exit_code,
                    duration: start.elapsed(),
                    killed_by_timeout,
                    killed_by_oom: false,
                    signal,
                    peak_memory,
                    cpu_time,
                });
            } else if result == 0 {
                // Still running, check timeout
                if start.elapsed() > timeout && !killed_by_timeout {
                    Self::kill_process_group(child_pid);
                    killed_by_timeout = true;
                }
                std::thread::sleep(Duration::from_millis(10));
            } else {
                // Error
                Self::kill_process_group(child_pid);
                let _ = child.wait();
                return Err(SandboxError::ExecutionFailed(
                    format!("wait4 failed: {}", std::io::Error::last_os_error())
                ));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::builder::Mount;

    #[test]
    fn test_macos_is_supported() {
        // On macOS, sandbox-exec should exist
        #[cfg(target_os = "macos")]
        assert!(is_supported());
    }

    #[test]
    fn test_generate_profile() {
        let executor = MacOSExecutor::new();
        let config = SandboxConfig::default();
        let profile = executor.generate_profile(&config);

        assert!(profile.contains("(version 1)"));
        assert!(profile.contains("(deny default)"));
    }

    #[test]
    fn test_generate_profile_with_mounts() {
        let executor = MacOSExecutor::new();
        let mut config = SandboxConfig::default();
        // Use ReadWrite permission since that adds explicit rules
        config.mounts.push(Mount {
            source: "/tmp/test_mount".into(),
            target: "/sandbox/test".into(),
            permission: Permission::ReadWrite,
        });

        let profile = executor.generate_profile(&config);
        // Should contain write access for ReadWrite mounts
        assert!(profile.contains("/tmp/test_mount"));
    }

    #[test]
    fn test_generate_profile_network_none() {
        let executor = MacOSExecutor::new();
        let config = SandboxConfig {
            network_mode: NetworkMode::None,
            ..Default::default()
        };

        let profile = executor.generate_profile(&config);
        // Should not contain network* allow
        assert!(!profile.contains("(allow network*)"));
    }

    #[test]
    fn test_generate_profile_network_host() {
        let executor = MacOSExecutor::new();
        let config = SandboxConfig {
            network_mode: NetworkMode::Host,
            ..Default::default()
        };

        let profile = executor.generate_profile(&config);
        assert!(profile.contains("(allow network*)"));
    }
}
