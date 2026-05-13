//! Linux namespace management
//!
//! Handles user, mount, and UTS namespace setup.

use crate::error::{Result, SandboxError};
use std::fs;
use std::path::PathBuf;

/// User namespace configuration
#[derive(Debug, Clone)]
pub struct UserNamespace {
    /// UID inside the namespace
    inner_uid: u32,
    /// GID inside the namespace
    inner_gid: u32,
}

impl UserNamespace {
    /// Create a new user namespace configuration
    pub fn new(uid: Option<u32>, gid: Option<u32>) -> Self {
        Self {
            inner_uid: uid.unwrap_or(1000),
            inner_gid: gid.unwrap_or(1000),
        }
    }

    /// Set the inner UID
    pub fn with_inner_uid(mut self, uid: u32) -> Self {
        self.inner_uid = uid;
        self
    }

    /// Set the inner GID
    pub fn with_inner_gid(mut self, gid: u32) -> Self {
        self.inner_gid = gid;
        self
    }

    /// Write UID/GID mappings for the child process
    pub fn write_mappings(&self, child_pid: i32) -> Result<()> {
        let outer_uid = unsafe { libc::getuid() };
        let outer_gid = unsafe { libc::getgid() };

        // Disable setgroups to allow unprivileged gid_map writes
        let setgroups_path = format!("/proc/{}/setgroups", child_pid);
        fs::write(&setgroups_path, "deny").map_err(|e| {
            SandboxError::NamespaceCreation {
                ns_type: "user".into(),
                reason: format!("Failed to write setgroups: {}", e),
            }
        })?;

        // Write UID mapping: inner_uid outer_uid 1
        let uid_map = format!("{} {} 1", self.inner_uid, outer_uid);
        let uid_map_path = format!("/proc/{}/uid_map", child_pid);
        fs::write(&uid_map_path, &uid_map).map_err(|e| {
            SandboxError::NamespaceCreation {
                ns_type: "user".into(),
                reason: format!("Failed to write uid_map: {}", e),
            }
        })?;

        // Write GID mapping: inner_gid outer_gid 1
        let gid_map = format!("{} {} 1", self.inner_gid, outer_gid);
        let gid_map_path = format!("/proc/{}/gid_map", child_pid);
        fs::write(&gid_map_path, &gid_map).map_err(|e| {
            SandboxError::NamespaceCreation {
                ns_type: "user".into(),
                reason: format!("Failed to write gid_map: {}", e),
            }
        })?;

        Ok(())
    }
}

impl Default for UserNamespace {
    fn default() -> Self {
        Self::new(Some(1000), Some(1000))
    }
}

/// UTS namespace configuration (hostname)
#[derive(Debug, Clone)]
pub struct UtsNamespace {
    hostname: String,
}

impl UtsNamespace {
    /// Create a new UTS namespace with given hostname
    pub fn with_hostname(hostname: &str) -> Self {
        Self {
            hostname: hostname.to_string(),
        }
    }

    /// Setup hostname in child process
    pub fn setup_in_child(&self) -> Result<()> {
        nix::unistd::sethostname(&self.hostname).map_err(|e| {
            SandboxError::NamespaceCreation {
                ns_type: "uts".into(),
                reason: e.to_string(),
            }
        })?;
        Ok(())
    }
}

impl Default for UtsNamespace {
    fn default() -> Self {
        Self::with_hostname("sandbox")
    }
}

/// Mount namespace configuration
#[derive(Debug, Clone)]
pub struct MountNamespace {
    rootfs: PathBuf,
    bind_mounts: Vec<(PathBuf, PathBuf, bool)>, // (source, target, readonly)
    tmpfs_mounts: Vec<(PathBuf, u64)>,          // (path, size)
}

impl MountNamespace {
    /// Create a new mount namespace with the given rootfs
    pub fn new(rootfs: &std::path::Path) -> Self {
        Self {
            rootfs: rootfs.to_path_buf(),
            bind_mounts: Vec::new(),
            tmpfs_mounts: Vec::new(),
        }
    }

    /// Add a bind mount
    pub fn bind_mount(&mut self, source: &std::path::Path, target: &std::path::Path, readonly: bool) {
        self.bind_mounts
            .push((source.to_path_buf(), target.to_path_buf(), readonly));
    }

    /// Add a tmpfs mount
    pub fn tmpfs(&mut self, path: &std::path::Path, size: u64) {
        self.tmpfs_mounts.push((path.to_path_buf(), size));
    }

    /// Get the rootfs path
    pub fn rootfs(&self) -> &PathBuf {
        &self.rootfs
    }

    /// Get bind mounts
    pub fn bind_mounts(&self) -> &[(PathBuf, PathBuf, bool)] {
        &self.bind_mounts
    }

    /// Get tmpfs mounts
    pub fn tmpfs_mounts(&self) -> &[(PathBuf, u64)] {
        &self.tmpfs_mounts
    }
}

impl Default for MountNamespace {
    fn default() -> Self {
        Self::new(std::path::Path::new("/"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_user_namespace_default() {
        let ns = UserNamespace::default();
        assert_eq!(ns.inner_uid, 1000);
        assert_eq!(ns.inner_gid, 1000);
    }

    #[test]
    fn test_user_namespace_custom() {
        let ns = UserNamespace::new(Some(0), Some(0));
        assert_eq!(ns.inner_uid, 0);
        assert_eq!(ns.inner_gid, 0);
    }

    #[test]
    fn test_uts_namespace() {
        let ns = UtsNamespace::with_hostname("test-sandbox");
        assert_eq!(ns.hostname, "test-sandbox");
    }

    #[test]
    fn test_mount_namespace() {
        let mut ns = MountNamespace::new(std::path::Path::new("/tmp/rootfs"));
        ns.bind_mount(
            std::path::Path::new("/home/user/data"),
            std::path::Path::new("/data"),
            true,
        );
        ns.tmpfs(std::path::Path::new("/tmp"), 64 * 1024 * 1024);

        assert_eq!(ns.bind_mounts().len(), 1);
        assert_eq!(ns.tmpfs_mounts().len(), 1);
    }
}
