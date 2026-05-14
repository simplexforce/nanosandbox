//! # Nanobox
//!
//! A lightweight cross-platform sandbox for secure code execution.
//!
//! ## Platform Support
//!
//! | Platform | Implementation | Status |
//! |----------|----------------|--------|
//! | Linux | namespaces, cgroups v2, seccomp | ✅ Full support |
//! | macOS | sandbox-exec, App Sandbox | ✅ Full support |
//! | Windows | Job Objects, CreateRestrictedToken | ✅ Full support |
//!
//! ## Quick Start
//!
//! ```rust,no_run
//! use nanosandbox::{Sandbox, Permission, MB};
//! use std::time::Duration;
//!
//! let sandbox = Sandbox::builder()
//!     .mount("/data/input", "/input", Permission::ReadOnly)
//!     .memory_limit(512 * MB)
//!     .wall_time_limit(Duration::from_secs(30))
//!     .build()
//!     .unwrap();
//!
//! let result = sandbox.run("python3", &["-c", "print('hello')"]).unwrap();
//! println!("{}", result.stdout);
//! ```
//!
//! On Linux, explicitly requested cgroup-backed limits fail closed by default.
//! `ResourceEnforcement::BestEffort` only relaxes controllers that can still be
//! honestly provisioned on the current execution path. Rootless memory limits
//! continue to fail closed unless a usable delegated cgroup v2 parent is
//! available; inspect `Sandbox::run_detailed()` diagnostics for degraded
//! non-memory limits.

pub mod builder;
pub mod error;
pub mod network;
pub mod platform;
pub mod result;
pub mod sandbox;

// Re-exports
pub use builder::{
    CgroupLimitRequests, ExecutionPolicy, NetworkMode, Permission, ResourceEnforcement,
    SandboxBuilder, SeccompProfile,
};
pub use error::{Result, SandboxError};
pub use result::{
    ExecutionDiagnostics, ExecutionReport, ExecutionResult, LimitDiagnostics, LimitStatus,
    MetricDiagnostics, MetricStatus,
};
pub use sandbox::Sandbox;

/// 1 KB in bytes
pub const KB: u64 = 1024;
/// 1 MB in bytes
pub const MB: u64 = 1024 * 1024;
/// 1 GB in bytes
pub const GB: u64 = 1024 * 1024 * 1024;

/// Check if the current platform supports sandboxing
pub fn is_platform_supported() -> bool {
    platform::is_supported()
}

/// Get the current platform name
pub fn platform_name() -> &'static str {
    platform::name()
}
