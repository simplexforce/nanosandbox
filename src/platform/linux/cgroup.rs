//! Cgroup v2 management for Linux
//!
//! Provides resource limiting using cgroups v2.

use crate::error::{Result, SandboxError};
use std::fs;
use std::path::PathBuf;
use std::time::Duration;

const CGROUP_ROOT: &str = "/sys/fs/cgroup";
const NANOBOX_CGROUP: &str = "nanobox";

/// Memory statistics from cgroup
#[derive(Debug, Clone)]
pub struct MemoryStats {
    pub current: u64,
    pub peak: u64,
}

/// CPU statistics from cgroup
#[derive(Debug, Clone)]
pub struct CpuStats {
    pub total_usec: u64,
    pub user_usec: u64,
    pub system_usec: u64,
}

/// Memory events from cgroup (for OOM detection)
#[derive(Debug, Clone, Default)]
pub struct MemoryEvents {
    pub oom: u64,
    pub oom_kill: u64,
    pub oom_group_kill: u64,
}

/// Cgroup v2 manager
pub struct CgroupManager {
    path: PathBuf,
}

impl CgroupManager {
    /// Create a new cgroup for a sandbox
    pub fn create(sandbox_id: &str) -> Result<Self> {
        let cgroup_base = PathBuf::from(CGROUP_ROOT).join(NANOBOX_CGROUP);

        // Create base nanobox cgroup if it doesn't exist
        if !cgroup_base.exists() {
            fs::create_dir_all(&cgroup_base).map_err(|e| {
                SandboxError::CgroupCreation(format!("Failed to create base cgroup: {}", e))
            })?;

            // Enable controllers
            let parent_controllers = fs::read_to_string(
                PathBuf::from(CGROUP_ROOT).join("cgroup.controllers"),
            )
            .unwrap_or_default();

            let subtree_control = parent_controllers
                .split_whitespace()
                .map(|c| format!("+{}", c))
                .collect::<Vec<_>>()
                .join(" ");

            if !subtree_control.is_empty() {
                let _ = fs::write(
                    PathBuf::from(CGROUP_ROOT).join("cgroup.subtree_control"),
                    &subtree_control,
                );
            }
        }

        let path = cgroup_base.join(sandbox_id);

        // Create sandbox-specific cgroup
        fs::create_dir_all(&path).map_err(|e| {
            SandboxError::CgroupCreation(format!("Failed to create cgroup {}: {}", sandbox_id, e))
        })?;

        Ok(Self { path })
    }

    /// Set memory limit in bytes
    pub fn set_memory_limit(&self, bytes: u64) -> Result<()> {
        let path = self.path.join("memory.max");
        fs::write(&path, bytes.to_string()).map_err(|e| SandboxError::CgroupSetting {
            controller: "memory".into(),
            setting: "max".into(),
            value: bytes.to_string(),
            reason: e.to_string(),
        })?;

        // Also set high limit for soft limit
        let high = (bytes as f64 * 0.9) as u64;
        let high_path = self.path.join("memory.high");
        let _ = fs::write(&high_path, high.to_string());

        Ok(())
    }

    /// Set CPU limit (0.0 - N.0 where N is number of cores)
    pub fn set_cpu_limit(&self, cpus: f64) -> Result<()> {
        // cpu.max format: "quota period"
        // quota in microseconds, period typically 100000
        let period = 100000u64;
        let quota = (cpus * period as f64) as u64;

        let value = format!("{} {}", quota, period);
        let path = self.path.join("cpu.max");

        fs::write(&path, &value).map_err(|e| SandboxError::CgroupSetting {
            controller: "cpu".into(),
            setting: "max".into(),
            value: value.clone(),
            reason: e.to_string(),
        })?;

        Ok(())
    }

    /// Set maximum number of PIDs
    pub fn set_pids_limit(&self, max: u32) -> Result<()> {
        let path = self.path.join("pids.max");
        fs::write(&path, max.to_string()).map_err(|e| SandboxError::CgroupSetting {
            controller: "pids".into(),
            setting: "max".into(),
            value: max.to_string(),
            reason: e.to_string(),
        })?;

        Ok(())
    }

    /// Add a process to this cgroup
    pub fn add_process(&self, pid: u32) -> Result<()> {
        let path = self.path.join("cgroup.procs");
        fs::write(&path, pid.to_string()).map_err(|e| {
            SandboxError::CgroupCreation(format!("Failed to add PID {} to cgroup: {}", pid, e))
        })?;

        Ok(())
    }

    /// Get memory statistics
    pub fn get_memory_stats(&self) -> Result<MemoryStats> {
        let current = fs::read_to_string(self.path.join("memory.current"))
            .map_err(|e| SandboxError::Internal(format!("Failed to read memory.current: {}", e)))?
            .trim()
            .parse::<u64>()
            .unwrap_or(0);

        let peak = fs::read_to_string(self.path.join("memory.peak"))
            .map_err(|e| SandboxError::Internal(format!("Failed to read memory.peak: {}", e)))?
            .trim()
            .parse::<u64>()
            .unwrap_or(0);

        Ok(MemoryStats { current, peak })
    }

    /// Get CPU statistics
    pub fn get_cpu_stats(&self) -> Result<CpuStats> {
        let stat = fs::read_to_string(self.path.join("cpu.stat"))
            .map_err(|e| SandboxError::Internal(format!("Failed to read cpu.stat: {}", e)))?;

        let mut usage_usec = 0u64;
        let mut user_usec = 0u64;
        let mut system_usec = 0u64;

        for line in stat.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                match parts[0] {
                    "usage_usec" => usage_usec = parts[1].parse().unwrap_or(0),
                    "user_usec" => user_usec = parts[1].parse().unwrap_or(0),
                    "system_usec" => system_usec = parts[1].parse().unwrap_or(0),
                    _ => {}
                }
            }
        }

        Ok(CpuStats {
            total_usec: usage_usec,
            user_usec,
            system_usec,
        })
    }

    /// Get memory events (for OOM detection)
    ///
    /// Returns the memory events including OOM kill counts.
    /// Check `oom_kill > 0` to detect if a process was killed due to OOM.
    pub fn get_memory_events(&self) -> Result<MemoryEvents> {
        let events_path = self.path.join("memory.events");
        let events = fs::read_to_string(&events_path)
            .map_err(|e| SandboxError::Internal(format!("Failed to read memory.events: {}", e)))?;

        let mut result = MemoryEvents::default();

        for line in events.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                match parts[0] {
                    "oom" => result.oom = parts[1].parse().unwrap_or(0),
                    "oom_kill" => result.oom_kill = parts[1].parse().unwrap_or(0),
                    "oom_group_kill" => result.oom_group_kill = parts[1].parse().unwrap_or(0),
                    _ => {}
                }
            }
        }

        Ok(result)
    }

    /// Check if any process in the cgroup was killed by OOM
    pub fn was_oom_killed(&self) -> bool {
        self.get_memory_events()
            .map(|e| e.oom_kill > 0 || e.oom_group_kill > 0)
            .unwrap_or(false)
    }

    /// Get all PIDs in this cgroup
    pub fn get_pids(&self) -> Vec<u32> {
        let procs_path = self.path.join("cgroup.procs");
        fs::read_to_string(&procs_path)
            .map(|s| {
                s.lines()
                    .filter_map(|line| line.trim().parse::<u32>().ok())
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Kill all processes in the cgroup
    ///
    /// Sends SIGKILL to all processes and waits for them to exit.
    pub fn kill_all(&self) {
        // First, freeze the cgroup if possible to prevent new forks
        let freeze_path = self.path.join("cgroup.freeze");
        let _ = fs::write(&freeze_path, "1");

        // Kill all processes
        for _ in 0..10 {
            let pids = self.get_pids();
            if pids.is_empty() {
                break;
            }

            for pid in &pids {
                unsafe {
                    libc::kill(*pid as i32, libc::SIGKILL);
                }
            }

            // Wait a bit for processes to die
            std::thread::sleep(Duration::from_millis(10));
        }

        // Unfreeze
        let _ = fs::write(&freeze_path, "0");
    }

    /// Get the cgroup path
    pub fn path(&self) -> &PathBuf {
        &self.path
    }

    /// Clean up the cgroup
    ///
    /// Kills all processes and removes the cgroup directory.
    pub fn cleanup(&self) {
        // Kill all processes first
        self.kill_all();

        // Wait for processes to actually exit
        for _ in 0..50 {
            if self.get_pids().is_empty() {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }

        // Now try to remove the directory
        let _ = fs::remove_dir(&self.path);
    }
}

impl Drop for CgroupManager {
    fn drop(&mut self) {
        // Clean up: kill all processes and remove cgroup
        self.cleanup();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cgroup_path() {
        // Just test path generation logic
        let path = PathBuf::from(CGROUP_ROOT)
            .join(NANOBOX_CGROUP)
            .join("test-sandbox");
        assert!(path.to_string_lossy().contains("nanobox"));
    }
}
