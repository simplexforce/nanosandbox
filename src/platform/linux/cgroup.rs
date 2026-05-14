//! Cgroup v2 management for Linux
//!
//! Provides resource limiting using cgroups v2 with rootless support.

use crate::error::{Result, SandboxError};
use std::fs::{self, OpenOptions};
use std::path::{Path, PathBuf};
use std::sync::{
    atomic::{AtomicU64, Ordering},
    OnceLock,
};
use std::time::Duration;

const CGROUP_ROOT: &str = "/sys/fs/cgroup";
const NANOBOX_DIR: &str = "nanobox";

// ---- Type-safe enums ----

/// Cgroup controllers used for resource limiting
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CgroupController {
    Memory,
    Cpu,
    Pids,
}

impl CgroupController {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Memory => "memory",
            Self::Cpu => "cpu",
            Self::Pids => "pids",
        }
    }
}

/// Well-known cgroup v2 control files
#[derive(Debug, Clone, Copy)]
enum CgroupFile {
    Procs,
    Controllers,
    SubtreeControl,
    MemoryMax,
    MemoryHigh,
    MemoryCurrent,
    MemoryPeak,
    MemoryEvents,
    CpuMax,
    CpuStat,
    PidsMax,
    Freeze,
}

impl CgroupFile {
    fn filename(&self) -> &'static str {
        match self {
            Self::Procs => "cgroup.procs",
            Self::Controllers => "cgroup.controllers",
            Self::SubtreeControl => "cgroup.subtree_control",
            Self::MemoryMax => "memory.max",
            Self::MemoryHigh => "memory.high",
            Self::MemoryCurrent => "memory.current",
            Self::MemoryPeak => "memory.peak",
            Self::MemoryEvents => "memory.events",
            Self::CpuMax => "cpu.max",
            Self::CpuStat => "cpu.stat",
            Self::PidsMax => "pids.max",
            Self::Freeze => "cgroup.freeze",
        }
    }
}

// ---- Strategy detection ----

/// How we access cgroup v2
#[derive(Debug, Clone)]
enum CgroupStrategy {
    /// Running as root: use /sys/fs/cgroup/nanobox/
    Root { base: PathBuf },
    /// Non-root with delegated subtree
    Delegated { base: PathBuf },
    /// No cgroup access possible
    Unavailable,
}

#[derive(Debug, Clone)]
struct DelegatedBaseProbe {
    base: PathBuf,
}

/// Detect the cgroup v2 access strategy for the current process.
fn detect_cgroup_strategy() -> CgroupStrategy {
    if unsafe { libc::geteuid() } == 0 {
        return CgroupStrategy::Root {
            base: PathBuf::from(CGROUP_ROOT).join(NANOBOX_DIR),
        };
    }

    let cgroup_self = match fs::read_to_string("/proc/self/cgroup") {
        Ok(s) => s,
        Err(_) => return CgroupStrategy::Unavailable,
    };

    // cgroup v2 format: "0::/path\n"
    let cgroup_path = match cgroup_self
        .lines()
        .find(|l| l.starts_with("0::"))
        .map(|l| l.trim_start_matches("0::").trim())
    {
        Some(p) if p != "/" && !p.is_empty() => p,
        _ => return CgroupStrategy::Unavailable,
    };

    let base = PathBuf::from(CGROUP_ROOT).join(cgroup_path.trim_start_matches('/'));

    if !base.exists() {
        return CgroupStrategy::Unavailable;
    }

    // Without threaded subtree support, rootless delegation needs an empty,
    // writable "domain" cgroup before we can safely fan out resource control to
    // child sandboxes.
    let base = match find_usable_cgroup_base(&base) {
        Some(probe) => probe.base,
        None => return CgroupStrategy::Unavailable,
    };

    CgroupStrategy::Delegated { base }
}

/// Find a usable delegated base, walking up until we find a writable, empty
/// domain cgroup suitable for spawning managed child cgroups.
fn find_usable_cgroup_base(initial: &Path) -> Option<DelegatedBaseProbe> {
    let mut candidate = initial.to_path_buf();

    loop {
        if let Some(probe) = probe_delegated_base(&candidate) {
            return Some(probe);
        }

        candidate = candidate.parent()?.to_path_buf();
        if !candidate.starts_with(CGROUP_ROOT) || candidate == Path::new(CGROUP_ROOT) {
            return None;
        }
    }
}

static CGROUP_STRATEGY: OnceLock<CgroupStrategy> = OnceLock::new();
static PROBE_COUNTER: AtomicU64 = AtomicU64::new(0);

fn get_cgroup_strategy() -> CgroupStrategy {
    // Delegation and our current cgroup path are effectively process-wide for
    // the lifetime of the test binary / application, so probing on every
    // sandbox creation only adds filesystem churn and more race surface.
    CGROUP_STRATEGY.get_or_init(detect_cgroup_strategy).clone()
}

fn probe_cgroup_writable(path: &Path) -> bool {
    let probe_id = PROBE_COUNTER.fetch_add(1, Ordering::Relaxed);
    let probe = path.join(format!(
        ".nanobox_probe_{}_{}",
        std::process::id(),
        probe_id
    ));
    match fs::create_dir(&probe) {
        Ok(()) => {
            let _ = fs::remove_dir(&probe);
            true
        }
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => match fs::remove_dir(&probe) {
            Ok(()) => true,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => true,
            Err(_) => false,
        },
        Err(_) => false,
    }
}

fn file_writable(path: &Path) -> bool {
    OpenOptions::new().write(true).open(path).is_ok()
}

fn read_cgroup_type(path: &Path) -> String {
    fs::read_to_string(path.join("cgroup.type"))
        .unwrap_or_default()
        .trim()
        .to_string()
}

fn cgroup_is_populated(path: &Path) -> bool {
    let events = fs::read_to_string(path.join("cgroup.events")).unwrap_or_default();
    for line in events.lines() {
        let mut parts = line.split_whitespace();
        if matches!(parts.next(), Some("populated")) {
            return matches!(parts.next(), Some("1"));
        }
    }

    fs::read_to_string(path.join(CgroupFile::Procs.filename()))
        .map(|procs| !procs.trim().is_empty())
        .unwrap_or(false)
}

fn probe_delegated_base(path: &Path) -> Option<DelegatedBaseProbe> {
    if !probe_cgroup_writable(path) {
        return None;
    }

    if !file_writable(&path.join(CgroupFile::Procs.filename()))
        || !file_writable(&path.join(CgroupFile::SubtreeControl.filename()))
    {
        return None;
    }

    if read_cgroup_type(path) != "domain" || cgroup_is_populated(path) {
        return None;
    }

    Some(DelegatedBaseProbe {
        base: path.to_path_buf(),
    })
}

/// Read the list of controllers available at a given cgroup path
fn read_controllers(path: &Path) -> Vec<CgroupController> {
    let controllers_file = path.join(CgroupFile::Controllers.filename());
    let raw = fs::read_to_string(&controllers_file).unwrap_or_default();
    let mut controllers = Vec::new();
    for c in raw.split_whitespace() {
        match c {
            "memory" => controllers.push(CgroupController::Memory),
            "cpu" => controllers.push(CgroupController::Cpu),
            "pids" => controllers.push(CgroupController::Pids),
            _ => {}
        }
    }
    controllers
}

/// Try to enable controllers in cgroup.subtree_control at the given path
fn try_enable_controllers(
    path: &Path,
    controllers: &[CgroupController],
) -> Vec<(CgroupController, std::io::Result<()>)> {
    let subtree = path.join(CgroupFile::SubtreeControl.filename());
    let mut results = Vec::with_capacity(controllers.len());

    for controller in controllers {
        let enabled = fs::read_to_string(&subtree).unwrap_or_default();
        let already_enabled = enabled
            .split_whitespace()
            .any(|name| name == controller.as_str());
        if already_enabled {
            results.push((*controller, Ok(())));
            continue;
        }

        results.push((
            *controller,
            fs::write(&subtree, format!("+{}", controller.as_str())),
        ));
    }

    results
}

// ---- Public types ----

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

/// Cgroup v2 manager with rootless support
pub struct CgroupManager {
    path: PathBuf,
    available_controllers: Vec<CgroupController>,
    _strategy: CgroupStrategy,
}

/// Snapshot of cgroup support for the current process.
#[derive(Debug, Clone)]
pub struct CgroupSupport {
    pub mounted: bool,
    pub accessible: bool,
    pub available_controllers: Vec<CgroupController>,
}

impl CgroupSupport {
    pub fn controller_available(&self, controller: CgroupController) -> bool {
        self.available_controllers.contains(&controller)
    }

    pub fn can_enforce(&self, controller: CgroupController) -> bool {
        self.mounted && self.accessible && self.controller_available(controller)
    }

    pub fn available_controllers_string(&self) -> String {
        self.available_controllers
            .iter()
            .map(CgroupController::as_str)
            .collect::<Vec<_>>()
            .join(", ")
    }

    pub fn unavailable_reason(&self, controller: Option<CgroupController>) -> String {
        if !self.mounted {
            return "cgroups v2 not available. Resource limits require cgroup v2".into();
        }

        if !self.accessible {
            return "cgroup not writable or delegated base is unsuitable. Non-root requires a writable, empty delegated cgroup v2 parent or root access".into();
        }

        if let Some(controller) = controller {
            return format!(
                "cgroup controller '{}' not available. Available: {}",
                controller.as_str(),
                self.available_controllers_string()
            );
        }

        "cgroup support unavailable".into()
    }
}

impl CgroupManager {
    // ---- Internal helpers ----

    fn read_file(&self, file: CgroupFile) -> std::io::Result<String> {
        fs::read_to_string(self.path.join(file.filename()))
    }

    fn write_file(&self, file: CgroupFile, value: &str) -> std::io::Result<()> {
        fs::write(self.path.join(file.filename()), value)
    }

    fn require_controller(&self, controller: CgroupController) -> Result<()> {
        if self.available_controllers.contains(&controller) {
            Ok(())
        } else {
            let available = self
                .available_controllers
                .iter()
                .map(|c| c.as_str())
                .collect::<Vec<_>>()
                .join(", ");
            Err(SandboxError::CgroupControllerUnavailable {
                controller: controller.as_str().into(),
                available,
            })
        }
    }

    // ---- Creation ----

    /// Create a new cgroup for a sandbox.
    /// Automatically detects root vs delegated cgroup path.
    pub fn create(sandbox_id: &str, requested: &[CgroupController]) -> Result<Self> {
        let strategy = get_cgroup_strategy();
        match &strategy {
            CgroupStrategy::Root { base } => {
                Self::create_root(base, sandbox_id, requested, strategy.clone())
            }
            CgroupStrategy::Delegated { base } => {
                Self::create_delegated(base, sandbox_id, requested, strategy.clone())
            }
            CgroupStrategy::Unavailable => Err(SandboxError::CgroupCreation(
                "No usable cgroup access. Non-root requires a writable, empty delegated \
                 cgroup v2 parent (for example a pre-prepared scope), or run as root, or omit \
                 unsupported resource limits."
                    .into(),
            )),
        }
    }

    fn create_root(
        base: &Path,
        sandbox_id: &str,
        requested: &[CgroupController],
        strategy: CgroupStrategy,
    ) -> Result<Self> {
        fs::create_dir_all(base).map_err(|e| {
            SandboxError::CgroupCreation(format!("Failed to create base cgroup: {}", e))
        })?;

        let _ = try_enable_controllers(Path::new(CGROUP_ROOT), requested);
        let _ = try_enable_controllers(base, requested);

        let path = base.join(sandbox_id);
        fs::create_dir_all(&path).map_err(|e| {
            SandboxError::CgroupCreation(format!("Failed to create cgroup {}: {}", sandbox_id, e))
        })?;

        let controllers = read_controllers(&path);
        Ok(Self {
            path,
            available_controllers: controllers,
            _strategy: strategy,
        })
    }

    fn create_delegated(
        base: &Path,
        sandbox_id: &str,
        requested: &[CgroupController],
        strategy: CgroupStrategy,
    ) -> Result<Self> {
        let _ = try_enable_controllers(base, requested);

        let nanobox_dir = base.join(NANOBOX_DIR);
        match fs::create_dir(&nanobox_dir) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => {
                return Err(SandboxError::CgroupCreation(format!(
                    "Failed to create nanobox dir: {}",
                    e
                )));
            }
        }
        // Always ensure controllers are enabled in nanobox/, even if another
        // concurrent sandbox created it and hasn't finished enabling yet.
        let _ = try_enable_controllers(&nanobox_dir, requested);

        let path = nanobox_dir.join(sandbox_id);
        fs::create_dir(&path).map_err(|e| {
            SandboxError::CgroupCreation(format!("Failed to create cgroup {}: {}", sandbox_id, e))
        })?;

        let controllers = read_controllers(&path);
        Ok(Self {
            path,
            available_controllers: controllers,
            _strategy: strategy,
        })
    }

    // ---- Resource limits ----

    /// Set memory limit in bytes
    pub fn set_memory_limit(&self, bytes: u64) -> Result<()> {
        self.require_controller(CgroupController::Memory)?;

        self.write_file(CgroupFile::MemoryMax, &bytes.to_string())
            .map_err(|e| SandboxError::CgroupSetting {
                controller: "memory".into(),
                setting: "max".into(),
                value: bytes.to_string(),
                reason: e.to_string(),
            })?;

        // Soft limit at 90%
        let high = (bytes as f64 * 0.9) as u64;
        let _ = self.write_file(CgroupFile::MemoryHigh, &high.to_string());

        Ok(())
    }

    /// Set CPU limit (0.0 - N.0 where N is number of cores)
    pub fn set_cpu_limit(&self, cpus: f64) -> Result<()> {
        self.require_controller(CgroupController::Cpu)?;

        let period = 100_000u64;
        let quota = (cpus * period as f64) as u64;
        let value = format!("{} {}", quota, period);

        self.write_file(CgroupFile::CpuMax, &value)
            .map_err(|e| SandboxError::CgroupSetting {
                controller: "cpu".into(),
                setting: "max".into(),
                value: value.clone(),
                reason: e.to_string(),
            })?;

        Ok(())
    }

    /// Set maximum number of PIDs
    pub fn set_pids_limit(&self, max: u32) -> Result<()> {
        self.require_controller(CgroupController::Pids)?;

        self.write_file(CgroupFile::PidsMax, &max.to_string())
            .map_err(|e| SandboxError::CgroupSetting {
                controller: "pids".into(),
                setting: "max".into(),
                value: max.to_string(),
                reason: e.to_string(),
            })?;

        Ok(())
    }

    // ---- Process management ----

    /// Add a process to this cgroup
    pub fn add_process(&self, pid: u32) -> Result<()> {
        self.write_file(CgroupFile::Procs, &pid.to_string())
            .map_err(|e| {
                SandboxError::CgroupCreation(format!("Failed to add PID {} to cgroup: {}", pid, e))
            })
    }

    // ---- Statistics ----

    /// Get memory statistics
    pub fn get_memory_stats(&self) -> Result<MemoryStats> {
        let current = self
            .read_file(CgroupFile::MemoryCurrent)
            .map_err(|e| SandboxError::Internal(format!("Failed to read memory.current: {}", e)))?
            .trim()
            .parse::<u64>()
            .unwrap_or(0);

        let peak = self
            .read_file(CgroupFile::MemoryPeak)
            .map_err(|e| SandboxError::Internal(format!("Failed to read memory.peak: {}", e)))?
            .trim()
            .parse::<u64>()
            .unwrap_or(0);

        Ok(MemoryStats { current, peak })
    }

    /// Get CPU statistics
    pub fn get_cpu_stats(&self) -> Result<CpuStats> {
        let stat = self
            .read_file(CgroupFile::CpuStat)
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
    pub fn get_memory_events(&self) -> Result<MemoryEvents> {
        let events = self
            .read_file(CgroupFile::MemoryEvents)
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
        self.read_file(CgroupFile::Procs)
            .map(|s| {
                s.lines()
                    .filter_map(|line| line.trim().parse::<u32>().ok())
                    .collect()
            })
            .unwrap_or_default()
    }

    // ---- Lifecycle ----

    /// Kill all processes in the cgroup
    pub fn kill_all(&self) {
        let _ = self.write_file(CgroupFile::Freeze, "1");

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
            std::thread::sleep(Duration::from_millis(10));
        }

        let _ = self.write_file(CgroupFile::Freeze, "0");
    }

    /// Get the cgroup path
    pub fn path(&self) -> &PathBuf {
        &self.path
    }

    /// Clean up the cgroup
    pub fn cleanup(&self) {
        self.kill_all();

        for _ in 0..50 {
            if self.get_pids().is_empty() {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }

        let _ = fs::remove_dir(&self.path);

        // Keep the shared delegated nanobox/ parent in place. Removing it when
        // it temporarily looks empty races with concurrent sandbox creation.
    }
}

impl Drop for CgroupManager {
    fn drop(&mut self) {
        self.cleanup();
    }
}

// ---- Public helpers ----

/// Check if cgroup v2 is accessible (either as root or via delegation)
pub fn is_cgroup_accessible() -> bool {
    matches!(
        get_cgroup_strategy(),
        CgroupStrategy::Root { .. } | CgroupStrategy::Delegated { .. }
    )
}

/// Check if cgroup v2 is mounted on the system
pub fn is_cgroup_v2_mounted() -> bool {
    Path::new(CGROUP_ROOT)
        .join(CgroupFile::Controllers.filename())
        .exists()
}

/// Probe cgroup support and available controllers for the current process.
pub fn probe_cgroup_support() -> CgroupSupport {
    if !is_cgroup_v2_mounted() {
        return CgroupSupport {
            mounted: false,
            accessible: false,
            available_controllers: Vec::new(),
        };
    }

    match get_cgroup_strategy() {
        CgroupStrategy::Root { .. } => CgroupSupport {
            mounted: true,
            accessible: true,
            available_controllers: read_controllers(Path::new(CGROUP_ROOT)),
        },
        CgroupStrategy::Delegated { base } => CgroupSupport {
            mounted: true,
            accessible: true,
            available_controllers: read_controllers(&base),
        },
        CgroupStrategy::Unavailable => CgroupSupport {
            mounted: true,
            accessible: false,
            available_controllers: Vec::new(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cgroup_controller_as_str() {
        assert_eq!(CgroupController::Memory.as_str(), "memory");
        assert_eq!(CgroupController::Cpu.as_str(), "cpu");
        assert_eq!(CgroupController::Pids.as_str(), "pids");
    }

    #[test]
    fn test_cgroup_file_filenames() {
        assert_eq!(CgroupFile::Procs.filename(), "cgroup.procs");
        assert_eq!(CgroupFile::MemoryMax.filename(), "memory.max");
        assert_eq!(CgroupFile::CpuMax.filename(), "cpu.max");
        assert_eq!(CgroupFile::PidsMax.filename(), "pids.max");
        assert_eq!(CgroupFile::Controllers.filename(), "cgroup.controllers");
        assert_eq!(
            CgroupFile::SubtreeControl.filename(),
            "cgroup.subtree_control"
        );
    }

    #[test]
    fn test_detect_strategy_root_path() {
        if unsafe { libc::geteuid() } == 0 {
            let strategy = detect_cgroup_strategy();
            assert!(matches!(strategy, CgroupStrategy::Root { .. }));
        }
    }

    #[test]
    fn test_detect_strategy_nonroot() {
        if unsafe { libc::geteuid() } != 0 {
            let strategy = detect_cgroup_strategy();
            match &strategy {
                CgroupStrategy::Delegated { base } => {
                    assert!(base.starts_with(CGROUP_ROOT));
                    assert!(base.exists());
                }
                CgroupStrategy::Unavailable => {}
                CgroupStrategy::Root { .. } => {
                    panic!("Non-root should not get Root strategy")
                }
            }
        }
    }

    #[test]
    fn test_delegated_cgroup_flow() {
        if unsafe { libc::geteuid() } != 0 {
            let strategy = detect_cgroup_strategy();
            let CgroupStrategy::Delegated { base } = &strategy else {
                return;
            };

            let cgroup_type = fs::read_to_string(base.join("cgroup.type")).unwrap_or_default();

            assert_eq!(
                cgroup_type.trim(),
                "domain",
                "base must be 'domain' type, got: {:?}",
                cgroup_type.trim()
            );

            // Create a child cgroup and verify we can write processes to it
            let child = base.join(format!("test_leaf_{}", std::process::id()));
            fs::create_dir(&child).expect("create child cgroup");

            let mut fds = [0; 2];
            assert_eq!(
                unsafe { libc::pipe(fds.as_mut_ptr()) },
                0,
                "create sync pipe"
            );
            let pid = unsafe { libc::fork() };
            if pid == 0 {
                unsafe {
                    libc::close(fds[1]);
                }
                let mut buf = [0u8; 1];
                unsafe {
                    libc::read(fds[0], buf.as_mut_ptr() as *mut _, 1);
                    libc::close(fds[0]);
                    libc::_exit(0);
                }
            } else if pid > 0 {
                unsafe {
                    libc::close(fds[0]);
                }
                let procs_res = fs::write(child.join("cgroup.procs"), pid.to_string());
                unsafe {
                    libc::close(fds[1]);
                }
                assert!(
                    procs_res.is_ok(),
                    "should be able to add process to cgroup: {:?}",
                    procs_res
                );

                let mut status: i32 = 0;
                unsafe {
                    libc::waitpid(pid, &mut status, 0);
                }
            }

            let _ = fs::remove_dir(&child);
        }
    }
}
