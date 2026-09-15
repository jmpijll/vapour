use super::{
    enforcement,
    updater::{FeedUpdater, UpdateStatus},
};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

const INTENT_FORMAT_VERSION: u32 = 1;
const MAX_INTENT_FILE_BYTES: usize = 1024;

#[derive(Clone)]
pub struct ProtectionController {
    updater: FeedUpdater,
    intent_path: PathBuf,
    requested_enabled: Arc<Mutex<Option<bool>>>,
    operation: Arc<Mutex<()>>,
    stopped: Arc<AtomicBool>,
    update_error: Arc<Mutex<Option<String>>>,
}
#[derive(Serialize)]
pub struct ProtectionStatus {
    pub requested_enabled: bool,
    pub rules: enforcement::EnforcementStatus,
    pub feed: UpdateStatus,
    pub update_error: Option<String>,
}
impl ProtectionController {
    pub fn new(updater: FeedUpdater, intent_path: PathBuf) -> Self {
        Self {
            updater,
            intent_path,
            requested_enabled: Arc::new(Mutex::new(None)),
            operation: Arc::new(Mutex::new(())),
            stopped: Arc::new(AtomicBool::new(false)),
            update_error: Arc::new(Mutex::new(None)),
        }
    }
    pub fn start_updates(&self) -> Result<(), String> {
        let controller = self.clone();
        std::thread::Builder::new()
            .name("vapour-protection-scheduler".into())
            .spawn(move || {
                while !controller.stopped.load(Ordering::Acquire) {
                    let result = (|| {
                        let _guard = controller
                            .operation
                            .try_lock()
                            .ok_or("Protection change already in progress")?;
                        let status = controller.read_status()?;
                        match reconcile_action(status.requested_enabled, status.rules.enabled) {
                            ReconcileAction::Apply => {
                                controller.change_enabled(true)?;
                            }
                            ReconcileAction::Disable => {
                                controller.change_enabled(false)?;
                            }
                            ReconcileAction::None => {}
                        }
                        Ok::<(), String>(())
                    })();
                    *controller.update_error.lock() = result.err();
                    for _ in 0..900 {
                        if controller.stopped.load(Ordering::Acquire) {
                            return;
                        }
                        std::thread::sleep(Duration::from_secs(1));
                    }
                }
            })
            .map(|_| ())
            .map_err(|_| "Protection scheduler unavailable".into())
    }
    pub fn stop(&self) {
        self.stopped.store(true, Ordering::Release);
    }
    pub fn refresh(&self) -> Result<ProtectionStatus, String> {
        let _guard = self
            .operation
            .try_lock()
            .ok_or("Protection change already in progress")?;
        let status = self.read_status()?;
        self.updater.request(true);
        match reconcile_action(status.requested_enabled, status.rules.enabled) {
            ReconcileAction::Apply => self.change_enabled(true),
            ReconcileAction::Disable => self.change_enabled(false),
            ReconcileAction::None => self.read_status(),
        }
    }
    pub fn status(&self) -> Result<ProtectionStatus, String> {
        let _guard = self.operation.lock();
        self.read_status()
    }
    fn read_status(&self) -> Result<ProtectionStatus, String> {
        let rules = enforcement::status().map_err(|e| e.to_string())?;
        let requested_enabled = self.load_or_migrate_requested(rules.enabled)?;
        Ok(ProtectionStatus {
            requested_enabled,
            rules,
            feed: self.updater.status(),
            update_error: self.update_error.lock().clone(),
        })
    }
    /// Blocking operation: invoke only on a dedicated blocking worker.
    pub fn set_enabled(&self, enabled: bool) -> Result<ProtectionStatus, String> {
        let _guard = self
            .operation
            .try_lock()
            .ok_or("Protection change already in progress")?;
        self.persist_requested(enabled)?;
        self.change_enabled(enabled)
    }
    fn load_or_migrate_requested(&self, actual_enabled: bool) -> Result<bool, String> {
        if let Some(requested) = *self.requested_enabled.lock() {
            return Ok(requested);
        }

        let loaded = load_intent(&self.intent_path).map_err(|error| error.to_string())?;
        let requested = resolve_requested(loaded, actual_enabled);
        if loaded.is_none() {
            // A missing preference is the one-time migration case. Once this
            // value is persisted, firewall observations never change intent.
            *self.requested_enabled.lock() = Some(requested);
            persist_intent(&self.intent_path, requested)
                .map_err(|error| format!("could not persist protection preference: {error}"))?;
        }
        *self.requested_enabled.lock() = Some(requested);
        Ok(requested)
    }
    fn persist_requested(&self, requested: bool) -> Result<(), String> {
        persist_intent(&self.intent_path, requested)
            .map_err(|error| format!("could not persist protection preference: {error}"))?;
        *self.requested_enabled.lock() = Some(requested);
        Ok(())
    }
    fn change_enabled(&self, enabled: bool) -> Result<ProtectionStatus, String> {
        if !crate::firewall::FirewallManager::is_elevated() {
            return Err("Administrator access is required".into());
        }
        if enabled {
            self.updater.request(false);
            let deadline = Instant::now() + Duration::from_secs(40);
            while self.updater.status().refreshing && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(50));
            }
            if self.updater.status().refreshing {
                return Err("Threat feed refresh timed out".into());
            }
            let feed = self
                .updater
                .snapshot()
                .ok_or("No validated threat feed is available")?;
            let applied = enforcement::apply(&feed.endpoints).map_err(|e| e.to_string())?;
            if applied.cleanup_pending {
                return Err("Protection updated, but old rules still need cleanup".into());
            }
        } else {
            let result = enforcement::disable().map_err(|e| e.to_string())?;
            if !result.remaining_owned.is_empty() {
                return Err("Some protection rules could not be removed".into());
            }
        }
        self.read_status()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct IntentFile {
    format_version: u32,
    requested_enabled: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum IntentError {
    Io(String),
    Serialization(String),
    TooLarge { actual: u64, maximum: usize },
    Invalid(String),
    UnsupportedVersion { actual: u32, expected: u32 },
}

impl std::fmt::Display for IntentError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "preference I/O failed: {error}"),
            Self::Serialization(error) => {
                write!(formatter, "preference serialization failed: {error}")
            }
            Self::TooLarge { actual, maximum } => {
                write!(
                    formatter,
                    "preference is {actual} bytes; maximum is {maximum}"
                )
            }
            Self::Invalid(error) => write!(formatter, "preference is invalid: {error}"),
            Self::UnsupportedVersion { actual, expected } => write!(
                formatter,
                "preference format version {actual} is unsupported; expected {expected}"
            ),
        }
    }
}

impl std::error::Error for IntentError {}

fn load_intent(path: &Path) -> Result<Option<bool>, IntentError> {
    let Some(bytes) = read_intent_bounded(path)? else {
        return Ok(None);
    };
    let intent: IntentFile =
        serde_json::from_slice(&bytes).map_err(|error| IntentError::Invalid(error.to_string()))?;
    if intent.format_version != INTENT_FORMAT_VERSION {
        return Err(IntentError::UnsupportedVersion {
            actual: intent.format_version,
            expected: INTENT_FORMAT_VERSION,
        });
    }
    Ok(Some(intent.requested_enabled))
}

fn read_intent_bounded(path: &Path) -> Result<Option<Vec<u8>>, IntentError> {
    let mut file = match File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(IntentError::Io(error.to_string())),
    };
    if let Ok(metadata) = file.metadata() {
        let length = metadata.len();
        if length > MAX_INTENT_FILE_BYTES as u64 {
            return Err(IntentError::TooLarge {
                actual: length,
                maximum: MAX_INTENT_FILE_BYTES,
            });
        }
    }

    let read_limit = MAX_INTENT_FILE_BYTES.saturating_add(1) as u64;
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(read_limit)
        .read_to_end(&mut bytes)
        .map_err(|error| IntentError::Io(error.to_string()))?;
    if bytes.len() > MAX_INTENT_FILE_BYTES {
        return Err(IntentError::TooLarge {
            actual: bytes.len() as u64,
            maximum: MAX_INTENT_FILE_BYTES,
        });
    }
    Ok(Some(bytes))
}

fn persist_intent(path: &Path, requested_enabled: bool) -> Result<(), IntentError> {
    let bytes = serde_json::to_vec(&IntentFile {
        format_version: INTENT_FORMAT_VERSION,
        requested_enabled,
    })
    .map_err(|error| IntentError::Serialization(error.to_string()))?;
    if bytes.len() > MAX_INTENT_FILE_BYTES {
        return Err(IntentError::TooLarge {
            actual: bytes.len() as u64,
            maximum: MAX_INTENT_FILE_BYTES,
        });
    }

    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent).map_err(|error| IntentError::Io(error.to_string()))?;
    let file_name = path
        .file_name()
        .ok_or_else(|| IntentError::Io("preference path must contain a file name".to_owned()))?;

    static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(0);
    let mut temporary_path = None;
    let mut temporary_file = None;
    for _ in 0..32 {
        let id = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
        let candidate = parent.join(format!(
            ".{}.tmp-{}-{id}",
            file_name.to_string_lossy(),
            std::process::id()
        ));
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&candidate)
        {
            Ok(file) => {
                temporary_path = Some(candidate);
                temporary_file = Some(file);
                break;
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(IntentError::Io(error.to_string())),
        }
    }
    let temporary_path = temporary_path.ok_or_else(|| {
        IntentError::Io("could not allocate a unique preference temporary file".to_owned())
    })?;
    let mut temporary_file = temporary_file.expect("temporary path and file are paired");

    if let Err(error) = temporary_file.write_all(&bytes) {
        drop(temporary_file);
        let _ = fs::remove_file(&temporary_path);
        return Err(IntentError::Io(error.to_string()));
    }
    if let Err(error) = temporary_file.sync_all() {
        drop(temporary_file);
        let _ = fs::remove_file(&temporary_path);
        return Err(IntentError::Io(error.to_string()));
    }
    drop(temporary_file);

    let result = atomic_replace_intent(&temporary_path, path)
        .map_err(|error| IntentError::Io(error.to_string()));
    if result.is_err() {
        let _ = fs::remove_file(&temporary_path);
    }
    result
}

#[cfg(not(windows))]
fn atomic_replace_intent(temporary_path: &Path, destination: &Path) -> io::Result<()> {
    fs::rename(temporary_path, destination)
}

#[cfg(windows)]
fn atomic_replace_intent(temporary_path: &Path, destination: &Path) -> io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows::core::PCWSTR;
    use windows::Win32::Storage::FileSystem::{
        MoveFileExW, ReplaceFileW, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH,
        REPLACEFILE_WRITE_THROUGH,
    };

    fn wide(path: &Path) -> Vec<u16> {
        path.as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    }

    let temporary_wide = wide(temporary_path);
    let destination_wide = wide(destination);
    if destination.exists() {
        unsafe {
            ReplaceFileW(
                PCWSTR(destination_wide.as_ptr()),
                PCWSTR(temporary_wide.as_ptr()),
                PCWSTR::null(),
                REPLACEFILE_WRITE_THROUGH,
                None,
                None,
            )
        }
        .map_err(|_| io::Error::last_os_error())
    } else {
        unsafe {
            MoveFileExW(
                PCWSTR(temporary_wide.as_ptr()),
                PCWSTR(destination_wide.as_ptr()),
                MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
            )
        }
        .map_err(|_| io::Error::last_os_error())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ReconcileAction {
    Apply,
    Disable,
    None,
}

fn reconcile_action(requested_enabled: bool, actual_enabled: bool) -> ReconcileAction {
    match (requested_enabled, actual_enabled) {
        (true, _) => ReconcileAction::Apply,
        (false, true) => ReconcileAction::Disable,
        (false, false) => ReconcileAction::None,
    }
}

fn resolve_requested(stored: Option<bool>, observed_enabled: bool) -> bool {
    stored.unwrap_or(observed_enabled)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    struct TempDirectory {
        path: PathBuf,
    }

    impl TempDirectory {
        fn new() -> Self {
            static NEXT_ID: AtomicU64 = AtomicU64::new(0);
            let base = std::env::temp_dir();
            for _ in 0..128 {
                let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
                let path = base.join(format!(
                    "vapour-protection-intent-{}-{id}",
                    std::process::id()
                ));
                match fs::create_dir(&path) {
                    Ok(()) => return Self { path },
                    Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                    Err(error) => panic!("cannot create test directory: {error}"),
                }
            }
            panic!("could not allocate a unique test directory");
        }
    }

    impl Drop for TempDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    #[test]
    fn requested_enable_reconciles_even_when_the_feed_has_no_endpoints() {
        assert_eq!(
            reconcile_action(true, false),
            ReconcileAction::Apply,
            "an empty feed still represents an enabled requested state"
        );
    }

    #[test]
    fn persisted_request_survives_restart_and_ignores_later_rule_observation() {
        let directory = TempDirectory::new();
        let path = directory.path.join("intent.json");

        persist_intent(&path, true).unwrap();
        let after_restart = load_intent(&path).unwrap();
        assert_eq!(after_restart, Some(true));
        assert!(resolve_requested(after_restart, false));
    }

    #[test]
    fn missing_request_migrates_from_rules_once() {
        let directory = TempDirectory::new();
        let path = directory.path.join("intent.json");

        assert_eq!(load_intent(&path).unwrap(), None);
        let migrated = resolve_requested(None, true);
        persist_intent(&path, migrated).unwrap();
        assert!(migrated);
        assert_eq!(load_intent(&path).unwrap(), Some(true));
        assert!(resolve_requested(Some(migrated), false));
    }

    #[test]
    fn explicit_disable_is_persisted_as_false() {
        let directory = TempDirectory::new();
        let path = directory.path.join("intent.json");

        persist_intent(&path, false).unwrap();
        assert_eq!(load_intent(&path).unwrap(), Some(false));
        assert_eq!(reconcile_action(false, true), ReconcileAction::Disable);
    }

    #[test]
    fn preference_write_failure_is_reported_without_replacing_existing_file() {
        let directory = TempDirectory::new();
        let blocker = directory.path.join("not-a-directory");
        fs::write(&blocker, b"existing").unwrap();
        let path = blocker.join("intent.json");

        let error = persist_intent(&path, true).unwrap_err();
        assert!(matches!(error, IntentError::Io(_)));
        assert_eq!(fs::read(&blocker).unwrap(), b"existing");
    }

    #[test]
    fn oversized_preference_is_rejected_before_deserialization() {
        let directory = TempDirectory::new();
        let path = directory.path.join("intent.json");
        fs::write(&path, vec![b'x'; MAX_INTENT_FILE_BYTES + 1]).unwrap();

        assert!(matches!(
            load_intent(&path),
            Err(IntentError::TooLarge { .. })
        ));
    }
}
