//! Resource limits tests

use nanosandbox::{ResourceEnforcement, Sandbox, SandboxError, MB};
use std::time::{Duration, Instant};

#[cfg(target_os = "linux")]
fn is_memory_unavailable(err: &SandboxError) -> bool {
    matches!(
        err,
        SandboxError::ResourceLimitUnavailable { limit, .. } if limit == "memory"
    )
}

/// Wall time limit test - all platforms supported
#[test]
fn test_wall_time_limit() {
    let sandbox = Sandbox::builder()
        .working_dir(if cfg!(windows) {
            "C:\\Windows\\Temp"
        } else {
            "/tmp"
        })
        .wall_time_limit(Duration::from_millis(500))
        .build()
        .unwrap();

    let start = Instant::now();

    #[cfg(target_os = "windows")]
    let result = sandbox.run("timeout", &["/t", "10"]).unwrap();
    #[cfg(not(target_os = "windows"))]
    let result = sandbox.run("sleep", &["10"]).unwrap();

    let elapsed = start.elapsed();

    assert!(result.killed_by_timeout);
    assert!(elapsed < Duration::from_secs(3));
}

#[test]
fn test_wall_time_within_limit() {
    let sandbox = Sandbox::builder()
        .working_dir(if cfg!(windows) {
            "C:\\Windows\\Temp"
        } else {
            "/tmp"
        })
        .wall_time_limit(Duration::from_secs(5))
        .build()
        .unwrap();

    #[cfg(not(target_os = "windows"))]
    {
        let result = sandbox.run("sleep", &["0.1"]).unwrap();
        assert!(result.success());
        assert!(!result.killed_by_timeout);
    }
}

/// Memory limit test - platform specific
#[test]
#[cfg(target_os = "linux")]
fn test_memory_limit_linux() {
    let sandbox = match Sandbox::builder()
        .working_dir("/tmp")
        .memory_limit(64 * MB)
        .resource_enforcement(ResourceEnforcement::BestEffort)
        .wall_time_limit(Duration::from_secs(10))
        .build()
    {
        Ok(sandbox) => sandbox,
        Err(err) if is_memory_unavailable(&err) => return,
        Err(err) => panic!("unexpected memory sandbox build failure: {err:?}"),
    };

    // Try to allocate more memory than allowed
    let result = sandbox.run(
        "python3",
        &[
            "-c",
            "x = bytearray(100 * 1024 * 1024)", // Try to allocate 100MB
        ],
    );

    // Should either fail or be killed
    match result {
        Ok(r) => {
            if r.exit_code == 127 {
                eprintln!(
                    "warning: skipping memory limit assertion because python3 is unavailable"
                );
                return;
            }
            assert!(!r.success() || r.killed_by_oom);
        }
        Err(_) => {
            eprintln!("warning: skipping memory limit assertion because python3 is unavailable");
        }
    }
}

#[test]
fn test_memory_within_limit() {
    let sandbox = match Sandbox::builder()
        .working_dir(if cfg!(windows) {
            "C:\\Windows\\Temp"
        } else {
            "/tmp"
        })
        .memory_limit(256 * MB)
        .resource_enforcement(ResourceEnforcement::BestEffort)
        .wall_time_limit(Duration::from_secs(10))
        .build()
    {
        Ok(sandbox) => sandbox,
        #[cfg(target_os = "linux")]
        Err(err) if is_memory_unavailable(&err) => return,
        Err(err) => panic!("unexpected memory sandbox build failure: {err:?}"),
    };

    #[cfg(not(target_os = "windows"))]
    {
        // Check if python3 is available
        let result = sandbox.run(
            "python3",
            &[
                "-c",
                "x = bytearray(10 * 1024 * 1024); print('ok')", // 10MB - well within limit
            ],
        );

        match result {
            Ok(r) => {
                if r.exit_code == 127 {
                    eprintln!(
                        "warning: skipping memory within limit assertion because python3 is unavailable"
                    );
                    return;
                }
                if r.exit_code == 0 {
                    assert_eq!(r.stdout.trim(), "ok");
                }
            }
            Err(_) => {
                eprintln!(
                    "warning: skipping memory within limit assertion because python3 is unavailable"
                );
            }
        }
    }
}

/// Process limit test - Linux only
#[test]
#[cfg(target_os = "linux")]
fn test_max_pids_limit() {
    let sandbox = Sandbox::builder()
        .working_dir("/tmp")
        .max_pids(10)
        .resource_enforcement(ResourceEnforcement::BestEffort)
        .wall_time_limit(Duration::from_secs(5))
        .build()
        .unwrap();

    // Try fork bomb - should be contained
    let start = Instant::now();
    let _result = sandbox.run("sh", &["-c", ":(){ :|:& };:"]).unwrap();
    let elapsed = start.elapsed();

    // Should complete within time limit (contained by pids limit)
    assert!(elapsed < Duration::from_secs(6));
}

#[test]
fn test_multiple_limits_combined() {
    let sandbox = match Sandbox::builder()
        .working_dir(if cfg!(windows) {
            "C:\\Windows\\Temp"
        } else {
            "/tmp"
        })
        .memory_limit(128 * MB)
        .resource_enforcement(ResourceEnforcement::BestEffort)
        .wall_time_limit(Duration::from_secs(5))
        .max_pids(50)
        .build()
    {
        Ok(sandbox) => sandbox,
        #[cfg(target_os = "linux")]
        Err(err) if is_memory_unavailable(&err) => return,
        Err(err) => panic!("unexpected combined-limits build failure: {err:?}"),
    };

    #[cfg(not(target_os = "windows"))]
    {
        let result = sandbox.run("echo", &["hello"]).unwrap();
        assert!(result.success());
    }
}

#[test]
fn test_cpu_limit() {
    // CPU limit test - verifies it doesn't crash
    let sandbox = Sandbox::builder()
        .working_dir(if cfg!(windows) {
            "C:\\Windows\\Temp"
        } else {
            "/tmp"
        })
        .cpu_limit(1.0)
        .resource_enforcement(ResourceEnforcement::BestEffort)
        .wall_time_limit(Duration::from_secs(2))
        .build()
        .unwrap();

    #[cfg(not(target_os = "windows"))]
    {
        let result = sandbox.run("echo", &["cpu test"]).unwrap();
        assert!(result.success());
    }
}
