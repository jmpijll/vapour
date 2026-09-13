//! Internal same-executable entry point; it never starts Tauri or requests UAC.
use std::{ffi::OsString, io::Write};

const SWITCH: &str = "--vapour-dns-watchdog";

struct Request {
    pid: u32,
    creation: u64,
}

fn parse(args: &[OsString]) -> Option<Result<Request, &'static str>> {
    if args.first().is_none_or(|arg| arg != SWITCH) {
        return None;
    }
    Some((|| {
        if args.len() != 3 {
            return Err("invalid watchdog arguments");
        }
        let pid = args[1]
            .to_str()
            .and_then(|v| v.parse::<u32>().ok())
            .filter(|v| *v != 0)
            .ok_or("invalid parent PID")?;
        let creation = args[2]
            .to_str()
            .and_then(|v| v.parse::<u64>().ok())
            .filter(|v| *v != 0)
            .ok_or("invalid parent creation time")?;
        Ok(Request { pid, creation })
    })())
}

pub(crate) fn dispatch(args: &[OsString]) -> Option<i32> {
    let request = match parse(args)? {
        Ok(value) => value,
        Err(error) => {
            eprintln!("{error}");
            return Some(2);
        }
    };
    // Never accept a recovery path from command-line input. The storage module
    // verifies the fixed machine location and its ownership before readiness.
    let journal = match super::dns_storage::trusted_journal_path() {
        Ok(path) => path,
        Err(error) => {
            eprintln!("{}", error.chars().take(1024).collect::<String>());
            return Some(2);
        }
    };
    let result =
        super::dns_watchdog::run_with_ready(request.pid, request.creation, &journal, || {
            let mut stdout = std::io::stdout().lock();
            stdout
                .write_all(b"{\"status\":\"ready\"}\n")
                .and_then(|_| stdout.flush())
                .map_err(|e| e.to_string())
        });
    let (code, status) = completion_status(result);
    let mut stdout = std::io::stdout().lock();
    if serde_json::to_writer(&mut stdout, &status).is_err()
        || stdout
            .write_all(b"\n")
            .and_then(|_| stdout.flush())
            .is_err()
    {
        return Some(1);
    }
    Some(code)
}

fn completion_status(
    result: Result<super::dns_watchdog::DnsWatchdogOutcome, super::dns_watchdog::DnsWatchdogError>,
) -> (i32, serde_json::Value) {
    use super::dns_watchdog::DnsWatchdogOutcome;
    use serde_json::json;
    let bounded = |text: String| text.chars().take(1024).collect::<String>();
    match result {
        Ok(DnsWatchdogOutcome::Restored { attempts, result }) => (
            0,
            json!({"status":"restored", "attempts":attempts, "restored_stacks":result.restored_stack_count}),
        ),
        Ok(DnsWatchdogOutcome::ParentExitedWithoutJournal) => {
            (0, json!({"status":"stopped", "journal_present":false}))
        }
        Ok(DnsWatchdogOutcome::ParentIdentityMismatch) => (2, json!({"status":"parent_mismatch"})),
        Ok(DnsWatchdogOutcome::PersistentRestoreFailure {
            attempts,
            last_error,
        }) => (
            1,
            json!({"status":"recovery_failed", "attempts":attempts, "error":bounded(last_error)}),
        ),
        Err(error) => (
            1,
            json!({"status":"error", "error":bounded(error.to_string())}),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn args(values: &[&str]) -> Vec<OsString> {
        values.iter().map(OsString::from).collect()
    }
    #[test]
    fn recovery_failure_is_reported_with_bounded_details() {
        let (code, status) = completion_status(Ok(
            super::super::dns_watchdog::DnsWatchdogOutcome::PersistentRestoreFailure {
                attempts: 8,
                last_error: "é".repeat(2048),
            },
        ));
        assert_eq!(code, 1);
        assert_eq!(status["status"], "recovery_failed");
        assert_eq!(status["attempts"], 8);
        assert_eq!(status["error"].as_str().unwrap().chars().count(), 1024);
        let (code, status) = completion_status(Ok(
            super::super::dns_watchdog::DnsWatchdogOutcome::ParentIdentityMismatch,
        ));
        assert_eq!(code, 2);
        assert_eq!(status["status"], "parent_mismatch");
    }
    #[test]
    fn ordinary_app_launch_is_not_intercepted() {
        assert!(parse(&[]).is_none());
        assert!(parse(&args(&["--other"])).is_none());
    }
    #[test]
    fn watchdog_rejects_invalid_identity_and_journal_paths() {
        for values in [
            vec![SWITCH],
            vec![SWITCH, "0", "123"],
            vec![SWITCH, "1", "0"],
            vec![SWITCH, "bad", "123"],
            vec![SWITCH, "1", "18446744073709551616"],
            vec![SWITCH, "0", "123", "C:\\Vapour\\dns-recovery.json"],
            vec![SWITCH, "1", "0", "C:\\Vapour\\dns-recovery.json"],
            vec![SWITCH, "1", "123", "dns-recovery.json"],
            vec![SWITCH, "1", "123", "C:\\Vapour\\wrong.json"],
            vec![SWITCH, "1", "123", "C:\\Vapour\\..\\dns-recovery.json"],
            vec![SWITCH, "1", "123", "\\\\server\\share\\dns-recovery.json"],
        ] {
            assert!(parse(&args(&values)).unwrap().is_err());
        }
    }
    #[cfg(windows)]
    #[test]
    fn watchdog_accepts_only_parent_identity() {
        let input = args(&[SWITCH, "42", "123"]);
        let request = parse(&input).unwrap().unwrap();
        assert_eq!(request.pid, 42);
        assert_eq!(request.creation, 123);
        assert!(parse(&args(&[
            SWITCH,
            "42",
            "123",
            "C:\\Vapour Data\\dns-recovery.json"
        ]))
        .unwrap()
        .is_err());
    }
}
