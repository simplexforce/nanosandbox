//! Sandbox builder implementation
//!
//! Provides a fluent API for configuring and building sandboxes.

use crate::error::{Result, SandboxError};
use crate::sandbox::Sandbox;
use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Duration;

/// File/directory mount permission
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Permission {
    ReadOnly,
    ReadWrite,
}

/// Network access mode
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum NetworkMode {
    /// No network access (default, most secure)
    #[default]
    None,
    /// Use host network (not recommended, breaks isolation)
    Host,
    /// Network access through proxy with domain whitelist
    Proxied { allowed_domains: Vec<String> },
}

/// Seccomp security profile (syscall filtering)
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum SeccompProfile {
    /// Disable seccomp filtering (not recommended)
    Disabled,
    /// Allow only safe syscalls (most restrictive)
    Strict,
    /// Standard set of allowed syscalls
    #[default]
    Standard,
    /// More permissive, for interactive use
    Permissive,
    /// Custom syscall whitelist
    Custom(Vec<String>),
}

/// How strictly Linux cgroup-backed resource limits should be enforced.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum ResourceEnforcement {
    /// Fail closed when an explicitly requested cgroup-backed limit cannot be enforced.
    #[default]
    Strict,
    /// Continue execution and surface any skipped limits through diagnostics.
    BestEffort,
}

/// Tracks which cgroup-backed limits were explicitly requested by the caller.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CgroupLimitRequests {
    pub memory: bool,
    pub cpu: bool,
    pub pids: bool,
}

/// Execution policy derived from builder state.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ExecutionPolicy {
    pub resource_enforcement: ResourceEnforcement,
    pub cgroup_limit_requests: CgroupLimitRequests,
}

/// Mount configuration
#[derive(Clone, Debug)]
pub struct Mount {
    pub source: PathBuf,
    pub target: PathBuf,
    pub permission: Permission,
}

/// Sandbox configuration built by the builder
#[derive(Clone, Debug)]
pub struct SandboxConfig {
    // Filesystem
    pub mounts: Vec<Mount>,
    pub tmpfs_mounts: Vec<(PathBuf, u64)>,
    pub working_dir: PathBuf,
    pub rootfs: Option<PathBuf>,

    // Resource limits
    pub memory_limit: Option<u64>,
    pub cpu_limit: Option<f64>,
    pub wall_time_limit: Option<Duration>,
    pub cpu_time_limit: Option<Duration>,
    pub max_pids: Option<u32>,
    pub max_file_size: Option<u64>,
    pub max_open_files: Option<u32>,

    // Network
    pub network_mode: NetworkMode,

    // Security
    pub seccomp_profile: SeccompProfile,
    pub uid: Option<u32>,
    pub gid: Option<u32>,

    // Environment
    pub env: HashMap<String, String>,
    pub clear_env: bool,
    pub hostname: String,
}

impl Default for SandboxConfig {
    fn default() -> Self {
        Self {
            mounts: Vec::new(),
            tmpfs_mounts: Vec::new(),
            working_dir: PathBuf::from("/"),
            rootfs: None,

            memory_limit: None,
            cpu_limit: None,
            wall_time_limit: None,
            cpu_time_limit: None,
            max_pids: Some(64),
            max_file_size: None,
            max_open_files: None,

            network_mode: NetworkMode::None,
            seccomp_profile: SeccompProfile::Standard,
            uid: None,
            gid: None,

            env: HashMap::new(),
            clear_env: true,
            hostname: "sandbox".into(),
        }
    }
}

/// Sandbox builder with fluent API
#[derive(Clone)]
pub struct SandboxBuilder {
    config: SandboxConfig,
    resource_enforcement: ResourceEnforcement,
    cgroup_limit_requests: CgroupLimitRequests,
}

impl Default for SandboxBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl SandboxBuilder {
    /// Create a new SandboxBuilder with default settings
    pub fn new() -> Self {
        Self {
            config: SandboxConfig::default(),
            resource_enforcement: ResourceEnforcement::Strict,
            cgroup_limit_requests: CgroupLimitRequests::default(),
        }
    }

    /// Split the builder into config plus execution policy.
    pub(crate) fn into_parts(self) -> (SandboxConfig, ExecutionPolicy) {
        (
            self.config,
            ExecutionPolicy {
                resource_enforcement: self.resource_enforcement,
                cgroup_limit_requests: self.cgroup_limit_requests,
            },
        )
    }

    // ========== Filesystem ==========

    /// Mount a file or directory into the sandbox
    pub fn mount(
        mut self,
        source: impl Into<PathBuf>,
        target: impl Into<PathBuf>,
        permission: Permission,
    ) -> Self {
        self.config.mounts.push(Mount {
            source: source.into(),
            target: target.into(),
            permission,
        });
        self
    }

    /// Mount a tmpfs (memory filesystem)
    pub fn tmpfs(mut self, path: impl Into<PathBuf>, size_bytes: u64) -> Self {
        self.config.tmpfs_mounts.push((path.into(), size_bytes));
        self
    }

    /// Set the working directory inside the sandbox
    pub fn working_dir(mut self, path: impl Into<PathBuf>) -> Self {
        self.config.working_dir = path.into();
        self
    }

    /// Use a custom rootfs
    pub fn rootfs(mut self, path: impl Into<PathBuf>) -> Self {
        self.config.rootfs = Some(path.into());
        self
    }

    // ========== Resource Limits ==========

    /// Set memory limit in bytes
    pub fn memory_limit(mut self, bytes: u64) -> Self {
        self.config.memory_limit = Some(bytes);
        self.cgroup_limit_requests.memory = true;
        self
    }

    /// Set CPU limit (0.0 - N.0, where N is number of CPU cores)
    pub fn cpu_limit(mut self, cpus: f64) -> Self {
        self.config.cpu_limit = Some(cpus);
        self.cgroup_limit_requests.cpu = true;
        self
    }

    /// Set wall clock time limit (process will be killed after this duration)
    pub fn wall_time_limit(mut self, duration: Duration) -> Self {
        self.config.wall_time_limit = Some(duration);
        self
    }

    /// Set CPU time limit
    pub fn cpu_time_limit(mut self, duration: Duration) -> Self {
        self.config.cpu_time_limit = Some(duration);
        self
    }

    /// Set maximum number of processes/threads
    pub fn max_pids(mut self, n: u32) -> Self {
        self.config.max_pids = Some(n);
        self.cgroup_limit_requests.pids = true;
        self
    }

    /// Control whether explicitly requested Linux cgroup-backed limits fail closed
    /// or degrade best-effort when they cannot be enforced. In rootless Linux
    /// execution, explicitly requested memory limits still fail closed unless a
    /// usable delegated cgroup v2 parent is available.
    pub fn resource_enforcement(mut self, enforcement: ResourceEnforcement) -> Self {
        self.resource_enforcement = enforcement;
        self
    }

    /// Set maximum file size
    pub fn max_file_size(mut self, bytes: u64) -> Self {
        self.config.max_file_size = Some(bytes);
        self
    }

    /// Set maximum number of open files
    pub fn max_open_files(mut self, n: u32) -> Self {
        self.config.max_open_files = Some(n);
        self
    }

    // ========== Network ==========

    /// Disable network access (default)
    pub fn no_network(mut self) -> Self {
        self.config.network_mode = NetworkMode::None;
        self
    }

    /// Use host network (not recommended)
    pub fn host_network(mut self) -> Self {
        self.config.network_mode = NetworkMode::Host;
        self
    }

    /// Allow network access only to specified domains
    pub fn allow_network(mut self, domains: &[&str]) -> Self {
        self.config.network_mode = NetworkMode::Proxied {
            allowed_domains: domains.iter().map(|s| s.to_string()).collect(),
        };
        self
    }

    // ========== Security ==========

    /// Set seccomp profile
    pub fn seccomp_profile(mut self, profile: SeccompProfile) -> Self {
        self.config.seccomp_profile = profile;
        self
    }

    /// Set UID inside the sandbox
    pub fn uid(mut self, uid: u32) -> Self {
        self.config.uid = Some(uid);
        self
    }

    /// Set GID inside the sandbox
    pub fn gid(mut self, gid: u32) -> Self {
        self.config.gid = Some(gid);
        self
    }

    // ========== Environment ==========

    /// Set an environment variable
    pub fn env(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.config.env.insert(key.into(), value.into());
        self
    }

    /// Set multiple environment variables
    pub fn envs(mut self, envs: impl IntoIterator<Item = (String, String)>) -> Self {
        self.config.env.extend(envs);
        self
    }

    /// Whether to clear inherited environment variables (default: true)
    pub fn clear_env(mut self, clear: bool) -> Self {
        self.config.clear_env = clear;
        self
    }

    /// Set hostname inside the sandbox
    pub fn hostname(mut self, name: impl Into<String>) -> Self {
        self.config.hostname = name.into();
        self
    }

    // ========== Build ==========

    /// Build the sandbox
    pub fn build(self) -> Result<Sandbox> {
        self.validate()?;
        Sandbox::from_builder(self)
    }

    fn validate(&self) -> Result<()> {
        // Pre-check platform capabilities
        self.pre_check_platform()?;

        // Validate mount paths exist
        for mount in &self.config.mounts {
            if !mount.source.exists() {
                return Err(SandboxError::PathNotFound(mount.source.clone()));
            }
        }

        // Validate rootfs if specified
        if let Some(rootfs) = &self.config.rootfs {
            if !rootfs.exists() || !rootfs.is_dir() {
                return Err(SandboxError::PathNotFound(rootfs.clone()));
            }
        }

        Ok(())
    }

    /// Pre-check platform capabilities before building sandbox
    fn pre_check_platform(&self) -> Result<()> {
        #[cfg(target_os = "linux")]
        {
            let support = crate::platform::linux::probe_cgroup_support();

            if self.cgroup_limit_requests.memory && unsafe { libc::geteuid() } != 0 {
                if !support.can_enforce(crate::platform::linux::CgroupController::Memory) {
                    return Err(SandboxError::ResourceLimitUnavailable {
                        limit: "memory".into(),
                        reason: support.unavailable_reason(Some(
                            crate::platform::linux::CgroupController::Memory,
                        )),
                    });
                }
            }

            let strict_limits = [
                (
                    self.cgroup_limit_requests.memory,
                    crate::platform::linux::CgroupController::Memory,
                    "memory",
                ),
                (
                    self.cgroup_limit_requests.cpu,
                    crate::platform::linux::CgroupController::Cpu,
                    "cpu",
                ),
                (
                    self.cgroup_limit_requests.pids,
                    crate::platform::linux::CgroupController::Pids,
                    "pids",
                ),
            ];

            if self.resource_enforcement == ResourceEnforcement::Strict
                && strict_limits.iter().any(|(requested, _, _)| *requested)
            {
                for (requested, controller, name) in strict_limits {
                    if !requested {
                        continue;
                    }
                    if !support.can_enforce(controller) {
                        return Err(SandboxError::ResourceLimitUnavailable {
                            limit: name.into(),
                            reason: support.unavailable_reason(Some(controller)),
                        });
                    }
                }
            }

            // Check user namespace support
            if let Ok(content) =
                std::fs::read_to_string("/proc/sys/kernel/unprivileged_userns_clone")
            {
                if content.trim() == "0" {
                    return Err(SandboxError::Config(
                        "Unprivileged user namespaces disabled. Run: sudo sysctl kernel.unprivileged_userns_clone=1".into()
                    ));
                }
            }
        }

        #[cfg(target_os = "macos")]
        {
            // Check sandbox-exec availability
            if !std::path::Path::new("/usr/bin/sandbox-exec").exists() {
                return Err(SandboxError::Config(
                    "sandbox-exec not found at /usr/bin/sandbox-exec".into(),
                ));
            }
        }

        // Windows: Job Objects are always available, no pre-check needed

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_builder_default() {
        let builder = SandboxBuilder::new();
        let config = builder.config;
        assert!(config.mounts.is_empty());
        assert!(config.memory_limit.is_none());
        assert_eq!(config.max_pids, Some(64));
        assert!(matches!(config.network_mode, NetworkMode::None));
    }

    #[test]
    fn test_builder_memory_limit() {
        let builder = SandboxBuilder::new().memory_limit(512 * 1024 * 1024);
        assert_eq!(builder.config.memory_limit, Some(512 * 1024 * 1024));
        assert!(builder.cgroup_limit_requests.memory);
    }

    #[test]
    fn test_builder_env() {
        let builder = SandboxBuilder::new().env("FOO", "bar").env("BAZ", "qux");
        assert_eq!(builder.config.env.get("FOO"), Some(&"bar".to_string()));
        assert_eq!(builder.config.env.get("BAZ"), Some(&"qux".to_string()));
    }

    #[test]
    fn test_builder_tmpfs() {
        let builder = SandboxBuilder::new().tmpfs("/tmp", 64 * 1024 * 1024);
        assert_eq!(builder.config.tmpfs_mounts.len(), 1);
        assert_eq!(builder.config.tmpfs_mounts[0].1, 64 * 1024 * 1024);
    }

    #[test]
    fn test_builder_network_modes() {
        let builder = SandboxBuilder::new().no_network();
        assert!(matches!(builder.config.network_mode, NetworkMode::None));

        let builder = SandboxBuilder::new().host_network();
        assert!(matches!(builder.config.network_mode, NetworkMode::Host));

        let builder = SandboxBuilder::new().allow_network(&["example.com"]);
        assert!(matches!(
            builder.config.network_mode,
            NetworkMode::Proxied { .. }
        ));
    }

    #[test]
    fn test_seccomp_profile() {
        let builder = SandboxBuilder::new().seccomp_profile(SeccompProfile::Strict);
        assert!(matches!(
            builder.config.seccomp_profile,
            SeccompProfile::Strict
        ));
    }

    #[test]
    fn test_resource_enforcement_default() {
        let builder = SandboxBuilder::new();
        assert_eq!(builder.resource_enforcement, ResourceEnforcement::Strict);
        assert_eq!(
            builder.cgroup_limit_requests,
            CgroupLimitRequests::default()
        );
    }

    #[test]
    fn test_resource_enforcement_override() {
        let builder = SandboxBuilder::new().resource_enforcement(ResourceEnforcement::BestEffort);
        assert_eq!(
            builder.resource_enforcement,
            ResourceEnforcement::BestEffort
        );
    }
}
