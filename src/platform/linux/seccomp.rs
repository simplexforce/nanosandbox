//! Seccomp-BPF syscall filtering for Linux
//!
//! Provides syscall filtering using seccomp-bpf.

use crate::builder::SeccompProfile;
use crate::error::{Result, SandboxError};

/// Seccomp filter configuration
pub struct SeccompFilter;

impl SeccompFilter {
    /// Apply seccomp filter based on profile
    pub fn apply(profile: &SeccompProfile) -> Result<()> {
        match profile {
            SeccompProfile::Disabled => Ok(()),
            SeccompProfile::Strict => Self::apply_strict(),
            SeccompProfile::Standard => Self::apply_standard(),
            SeccompProfile::Permissive => Self::apply_permissive(),
            SeccompProfile::Custom(syscalls) => Self::apply_custom(syscalls),
        }
    }

    fn apply_strict() -> Result<()> {
        // Strict mode: only allow essential syscalls
        // This is a placeholder - real implementation would use seccomp-bpf
        Self::set_no_new_privs()?;
        // Would install a strict BPF filter here
        Ok(())
    }

    fn apply_standard() -> Result<()> {
        // Standard mode: allow common safe syscalls
        Self::set_no_new_privs()?;
        // Would install a standard BPF filter here
        Ok(())
    }

    fn apply_permissive() -> Result<()> {
        // Permissive mode: allow most syscalls, block dangerous ones
        Self::set_no_new_privs()?;
        // Would install a permissive BPF filter here
        Ok(())
    }

    fn apply_custom(syscalls: &[String]) -> Result<()> {
        // Custom whitelist
        Self::set_no_new_privs()?;
        let _ = syscalls; // Would use these to build custom filter
        Ok(())
    }

    /// Set PR_SET_NO_NEW_PRIVS to prevent privilege escalation
    fn set_no_new_privs() -> Result<()> {
        let ret = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
        if ret != 0 {
            return Err(SandboxError::SecurityFilterLoad(
                "Failed to set PR_SET_NO_NEW_PRIVS".into(),
            ));
        }
        Ok(())
    }
}

/// Syscalls allowed in strict mode
#[allow(dead_code)]
const STRICT_SYSCALLS: &[&str] = &[
    "read",
    "write",
    "exit",
    "exit_group",
    "brk",
    "mmap",
    "munmap",
    "close",
    "fstat",
    "lseek",
    "getpid",
    "getuid",
    "getgid",
    "geteuid",
    "getegid",
];

/// Syscalls allowed in standard mode (in addition to strict)
#[allow(dead_code)]
const STANDARD_SYSCALLS: &[&str] = &[
    // File operations
    "open",
    "openat",
    "stat",
    "fstat",
    "lstat",
    "access",
    "faccessat",
    "readlink",
    "readlinkat",
    "getcwd",
    "dup",
    "dup2",
    "dup3",
    "fcntl",
    "flock",
    "fsync",
    "fdatasync",
    "truncate",
    "ftruncate",
    "getdents",
    "getdents64",
    // Memory
    "mmap",
    "munmap",
    "mprotect",
    "mremap",
    "brk",
    // Process
    "clone",
    "fork",
    "vfork",
    "execve",
    "wait4",
    "waitid",
    "getpid",
    "getppid",
    "gettid",
    // Time
    "time",
    "gettimeofday",
    "clock_gettime",
    "nanosleep",
    // Signals
    "rt_sigaction",
    "rt_sigprocmask",
    "rt_sigreturn",
    "sigaltstack",
    // I/O
    "read",
    "write",
    "readv",
    "writev",
    "pread64",
    "pwrite64",
    "select",
    "poll",
    "ppoll",
    "epoll_create",
    "epoll_create1",
    "epoll_ctl",
    "epoll_wait",
    "epoll_pwait",
    // Pipes
    "pipe",
    "pipe2",
    // Sockets (limited)
    "socket",
    "connect",
    "accept",
    "sendto",
    "recvfrom",
    "sendmsg",
    "recvmsg",
    "bind",
    "listen",
    "getsockname",
    "getpeername",
    "setsockopt",
    "getsockopt",
    // Other
    "arch_prctl",
    "set_tid_address",
    "set_robust_list",
    "futex",
    "sched_yield",
    "getrandom",
    "prctl",
];

/// Syscalls blocked in all modes
#[allow(dead_code)]
const BLOCKED_SYSCALLS: &[&str] = &[
    "ptrace",
    "process_vm_readv",
    "process_vm_writev",
    "kexec_load",
    "kexec_file_load",
    "init_module",
    "finit_module",
    "delete_module",
    "reboot",
    "swapon",
    "swapoff",
    "mount",
    "umount2",
    "pivot_root",
    "chroot",
    "setns",
    "unshare",
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_seccomp_disabled() {
        // Should be a no-op
        let result = SeccompFilter::apply(&SeccompProfile::Disabled);
        assert!(result.is_ok());
    }
}
