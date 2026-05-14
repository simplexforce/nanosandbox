//! Execution result types
//!
//! This module defines the result types returned from sandbox execution.

use crate::builder::ExecutionPolicy;
use std::time::Duration;

/// Result of executing a command in the sandbox
#[derive(Debug, Clone)]
pub struct ExecutionResult {
    /// Standard output captured from the process
    pub stdout: String,

    /// Standard error captured from the process
    pub stderr: String,

    /// Exit code of the process (0 typically means success)
    pub exit_code: i32,

    /// Wall-clock duration of execution
    pub duration: Duration,

    /// Whether the process was killed due to timeout
    pub killed_by_timeout: bool,

    /// Whether the process was killed due to out-of-memory
    pub killed_by_oom: bool,

    /// Signal that killed the process, if any
    pub signal: Option<i32>,

    /// Peak memory usage in bytes (if available)
    pub peak_memory: Option<u64>,

    /// CPU time consumed (if available)
    pub cpu_time: Option<Duration>,
}

/// Detailed execution report including diagnostics.
#[derive(Debug, Clone)]
pub struct ExecutionReport {
    pub result: ExecutionResult,
    pub diagnostics: ExecutionDiagnostics,
}

/// Structured execution diagnostics.
#[derive(Debug, Clone)]
pub struct ExecutionDiagnostics {
    pub limits: LimitDiagnostics,
    pub metrics: MetricDiagnostics,
}

/// Status for limit enforcement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LimitStatus {
    NotRequested,
    Enforced,
    NotEnforced { reason: String },
    Unknown { reason: String },
}

/// Status for metric collection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MetricStatus {
    Collected,
    Unavailable { reason: String },
    Unknown { reason: String },
}

/// Diagnostics for limit enforcement.
#[derive(Debug, Clone)]
pub struct LimitDiagnostics {
    pub memory: LimitStatus,
    pub cpu: LimitStatus,
    pub pids: LimitStatus,
}

/// Diagnostics for metric availability.
#[derive(Debug, Clone)]
pub struct MetricDiagnostics {
    pub peak_memory: MetricStatus,
    pub cpu_time: MetricStatus,
}

impl ExecutionResult {
    /// Create a new ExecutionResult with default values
    pub fn new() -> Self {
        Self {
            stdout: String::new(),
            stderr: String::new(),
            exit_code: 0,
            duration: Duration::ZERO,
            killed_by_timeout: false,
            killed_by_oom: false,
            signal: None,
            peak_memory: None,
            cpu_time: None,
        }
    }

    /// Check if execution was successful
    pub fn success(&self) -> bool {
        self.exit_code == 0
            && !self.killed_by_timeout
            && !self.killed_by_oom
            && self.signal.is_none()
    }

    /// Get failure reason if any
    pub fn failure_reason(&self) -> Option<String> {
        if self.killed_by_timeout {
            Some("Execution timed out".into())
        } else if self.killed_by_oom {
            Some("Out of memory".into())
        } else if let Some(sig) = self.signal {
            Some(format!("Killed by signal {}", sig))
        } else if self.exit_code != 0 {
            Some(format!("Exit code {}", self.exit_code))
        } else {
            None
        }
    }
}

impl ExecutionReport {
    pub fn from_result(policy: &ExecutionPolicy, result: ExecutionResult) -> Self {
        let diagnostics = ExecutionDiagnostics::from_result(policy, &result);
        Self {
            result,
            diagnostics,
        }
    }
}

impl ExecutionDiagnostics {
    pub fn from_result(policy: &ExecutionPolicy, result: &ExecutionResult) -> Self {
        let unknown_limit_reason =
            "Detailed limit enforcement status is not reported on this platform".to_string();
        let unknown_metric_reason =
            "Metric availability is not reported on this platform or execution path".to_string();

        Self {
            limits: LimitDiagnostics {
                memory: if policy.cgroup_limit_requests.memory {
                    LimitStatus::Unknown {
                        reason: unknown_limit_reason.clone(),
                    }
                } else {
                    LimitStatus::NotRequested
                },
                cpu: if policy.cgroup_limit_requests.cpu {
                    LimitStatus::Unknown {
                        reason: unknown_limit_reason.clone(),
                    }
                } else {
                    LimitStatus::NotRequested
                },
                pids: if policy.cgroup_limit_requests.pids {
                    LimitStatus::Unknown {
                        reason: unknown_limit_reason,
                    }
                } else {
                    LimitStatus::NotRequested
                },
            },
            metrics: MetricDiagnostics {
                peak_memory: if result.peak_memory.is_some() {
                    MetricStatus::Collected
                } else {
                    MetricStatus::Unknown {
                        reason: unknown_metric_reason.clone(),
                    }
                },
                cpu_time: if result.cpu_time.is_some() {
                    MetricStatus::Collected
                } else {
                    MetricStatus::Unknown {
                        reason: unknown_metric_reason,
                    }
                },
            },
        }
    }

    pub fn degradation_summary(&self) -> Option<String> {
        let mut items = Vec::new();

        if let LimitStatus::NotEnforced { reason } = &self.limits.memory {
            items.push(format!("memory limit not enforced ({reason})"));
        }
        if let LimitStatus::NotEnforced { reason } = &self.limits.cpu {
            items.push(format!("cpu limit not enforced ({reason})"));
        }
        if let LimitStatus::NotEnforced { reason } = &self.limits.pids {
            items.push(format!("pids limit not enforced ({reason})"));
        }

        if let MetricStatus::Unavailable { reason } = &self.metrics.peak_memory {
            items.push(format!("peak memory unavailable ({reason})"));
        }
        if let MetricStatus::Unavailable { reason } = &self.metrics.cpu_time {
            items.push(format!("cpu time unavailable ({reason})"));
        }

        if items.is_empty() {
            None
        } else {
            Some(items.join("; "))
        }
    }
}

impl Default for ExecutionResult {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_execution_result_success() {
        let result = ExecutionResult {
            stdout: "hello".into(),
            stderr: String::new(),
            exit_code: 0,
            duration: Duration::from_millis(100),
            killed_by_timeout: false,
            killed_by_oom: false,
            signal: None,
            peak_memory: None,
            cpu_time: None,
        };
        assert!(result.success());
        assert!(result.failure_reason().is_none());
    }

    #[test]
    fn test_execution_result_failure() {
        let result = ExecutionResult {
            stdout: String::new(),
            stderr: "error".into(),
            exit_code: 1,
            duration: Duration::from_millis(100),
            killed_by_timeout: false,
            killed_by_oom: false,
            signal: None,
            peak_memory: None,
            cpu_time: None,
        };
        assert!(!result.success());
        assert_eq!(result.failure_reason(), Some("Exit code 1".into()));
    }

    #[test]
    fn test_execution_result_timeout() {
        let result = ExecutionResult {
            stdout: String::new(),
            stderr: String::new(),
            exit_code: 137,
            duration: Duration::from_secs(5),
            killed_by_timeout: true,
            killed_by_oom: false,
            signal: Some(9),
            peak_memory: None,
            cpu_time: None,
        };
        assert!(!result.success());
        assert_eq!(result.failure_reason(), Some("Execution timed out".into()));
    }

    #[test]
    fn test_execution_result_oom() {
        let result = ExecutionResult {
            stdout: String::new(),
            stderr: String::new(),
            exit_code: 137,
            duration: Duration::from_secs(1),
            killed_by_timeout: false,
            killed_by_oom: true,
            signal: Some(9),
            peak_memory: Some(512 * 1024 * 1024),
            cpu_time: None,
        };
        assert!(!result.success());
        assert_eq!(result.failure_reason(), Some("Out of memory".into()));
    }

    #[test]
    fn test_execution_result_signal() {
        let result = ExecutionResult {
            stdout: String::new(),
            stderr: String::new(),
            exit_code: 137,
            duration: Duration::from_secs(1),
            killed_by_timeout: false,
            killed_by_oom: false,
            signal: Some(9),
            peak_memory: None,
            cpu_time: None,
        };
        assert!(!result.success());
        assert_eq!(result.failure_reason(), Some("Killed by signal 9".into()));
    }

    #[test]
    fn test_diagnostics_ignore_implicit_default_pids() {
        let diagnostics = ExecutionDiagnostics::from_result(
            &ExecutionPolicy::default(),
            &ExecutionResult::default(),
        );

        assert!(matches!(diagnostics.limits.pids, LimitStatus::NotRequested));
    }

    #[test]
    fn test_degradation_summary_reports_limit_and_metric_failures() {
        let diagnostics = ExecutionDiagnostics {
            limits: LimitDiagnostics {
                memory: LimitStatus::NotEnforced {
                    reason: "memory controller unavailable".into(),
                },
                cpu: LimitStatus::NotRequested,
                pids: LimitStatus::NotRequested,
            },
            metrics: MetricDiagnostics {
                peak_memory: MetricStatus::Unavailable {
                    reason: "memory stats missing".into(),
                },
                cpu_time: MetricStatus::Collected,
            },
        };

        let summary = diagnostics
            .degradation_summary()
            .expect("summary should exist");
        assert!(summary.contains("memory limit not enforced"));
        assert!(summary.contains("peak memory unavailable"));
    }
}
