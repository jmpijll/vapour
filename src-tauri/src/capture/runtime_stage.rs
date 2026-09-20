use std::{
    fs::{self, OpenOptions},
    io::{self, Write},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

const RUNTIME_DIRECTORY: &str = "windivert-2.2.2-A-x64";
static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(0);

const EMBEDDED_FILES: &[(&str, &[u8])] = &[
    (
        "WinDivert.dll",
        include_bytes!("../../vendor/windivert/WinDivert.dll"),
    ),
    (
        "WinDivert64.sys",
        include_bytes!("../../vendor/windivert/WinDivert64.sys"),
    ),
    ("LICENSE", include_bytes!("../../vendor/windivert/LICENSE")),
];

pub(super) fn stage(directory: &Path) -> Result<PathBuf, String> {
    // Embedded versioned files; never resolve DLLs via PATH or the working directory.
    let directory = directory.join(RUNTIME_DIRECTORY);
    fs::create_dir_all(&directory).map_err(|error| error.to_string())?;
    for (name, bytes) in EMBEDDED_FILES {
        install_file(&directory.join(name), bytes).map_err(|error| error.to_string())?;
    }
    Ok(directory.join("WinDivert.dll"))
}

fn install_file(path: &Path, bytes: &[u8]) -> io::Result<()> {
    match fs::read(path) {
        Ok(existing) => {
            return if existing == bytes {
                Ok(())
            } else {
                Err(integrity_error())
            };
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }

    let (temporary_path, mut temporary_file) = create_temporary_file(path)?;
    let cleanup = TemporaryFile::new(temporary_path.clone());
    let write_result = temporary_file
        .write_all(bytes)
        .and_then(|_| temporary_file.sync_all());
    drop(temporary_file);
    if let Err(error) = write_result {
        return Err(error);
    }

    match publish_new(&temporary_path, path) {
        Ok(()) => {
            cleanup.keep();
            verify_file(path, bytes)
        }
        Err(error) => {
            if path.exists() {
                return verify_file(path, bytes);
            }
            Err(error)
        }
    }
}

fn verify_file(path: &Path, bytes: &[u8]) -> io::Result<()> {
    match fs::read(path) {
        Ok(existing) if existing == bytes => Ok(()),
        Ok(_) => Err(integrity_error()),
        Err(error) => Err(error),
    }
}

fn create_temporary_file(path: &Path) -> io::Result<(PathBuf, fs::File)> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let name = path.file_name().ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "runtime path has no file name")
    })?;
    for _ in 0..32 {
        let id = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
        let candidate = parent.join(format!(
            ".{}.tmp-{}-{id}",
            name.to_string_lossy(),
            std::process::id()
        ));
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&candidate)
        {
            Ok(file) => return Ok((candidate, file)),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "could not allocate a runtime temporary file",
    ))
}

struct TemporaryFile {
    path: Option<PathBuf>,
}

impl TemporaryFile {
    fn new(path: PathBuf) -> Self {
        Self { path: Some(path) }
    }

    fn keep(mut self) {
        self.path = None;
    }
}

impl Drop for TemporaryFile {
    fn drop(&mut self) {
        if let Some(path) = self.path.take() {
            let _ = fs::remove_file(path);
        }
    }
}

fn integrity_error() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "Capture runtime integrity check failed",
    )
}

#[cfg(windows)]
fn publish_new(temporary_path: &Path, destination: &Path) -> io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows::{
        core::PCWSTR,
        Win32::Storage::FileSystem::{MoveFileExW, MOVEFILE_WRITE_THROUGH},
    };

    fn wide(path: &Path) -> Vec<u16> {
        path.as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    }

    let temporary = wide(temporary_path);
    let destination = wide(destination);
    unsafe {
        MoveFileExW(
            PCWSTR(temporary.as_ptr()),
            PCWSTR(destination.as_ptr()),
            MOVEFILE_WRITE_THROUGH,
        )
    }
    .map_err(|_| io::Error::last_os_error())
}

#[cfg(not(windows))]
fn publish_new(temporary_path: &Path, destination: &Path) -> io::Result<()> {
    // Hard-link creation is atomic and fails when the destination already exists;
    // unlike rename, it cannot replace a file on Unix.
    fs::hard_link(temporary_path, destination)?;
    fs::remove_file(temporary_path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs,
        sync::{
            atomic::{AtomicU64, Ordering},
            Arc, Barrier,
        },
        thread,
    };

    fn test_directory(label: &str) -> PathBuf {
        static NEXT_ID: AtomicU64 = AtomicU64::new(0);
        let root = std::env::temp_dir().join(format!(
            "vapour-{label}-{}-{}",
            std::process::id(),
            NEXT_ID.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).expect("create staging test directory");
        root
    }

    struct TestDirectory(PathBuf);

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn existing_corrupt_runtime_is_preserved_and_rejected() {
        let directory = TestDirectory(test_directory("stage-corrupt"));
        let runtime = directory.0.join(RUNTIME_DIRECTORY);
        fs::create_dir(&runtime).expect("create runtime directory");
        let dll = runtime.join("WinDivert.dll");
        fs::write(&dll, b"tampered").expect("seed corrupt runtime");

        let result = stage(&directory.0);

        assert!(result.is_err());
        assert_eq!(fs::read(&dll).unwrap(), b"tampered");
        assert_eq!(fs::read_dir(runtime).unwrap().count(), 1);
    }

    #[test]
    fn temporary_file_cleanup_removes_unpublished_file() {
        let directory = TestDirectory(test_directory("stage-cleanup"));
        let temporary = directory.0.join(".runtime.tmp-test");
        fs::write(&temporary, b"partial").expect("seed temporary file");

        {
            let _cleanup = TemporaryFile::new(temporary.clone());
        }

        assert!(!temporary.exists());
    }

    #[test]
    fn concurrent_stage_calls_publish_complete_runtime_without_temporary_files() {
        let directory = Arc::new(TestDirectory(test_directory("stage-concurrent")));
        let barrier = Arc::new(Barrier::new(32));
        let mut workers = Vec::new();
        for _ in 0..32 {
            let directory = Arc::clone(&directory);
            let barrier = Arc::clone(&barrier);
            workers.push(thread::spawn(move || {
                barrier.wait();
                stage(&directory.0)
            }));
        }
        for worker in workers {
            worker.join().unwrap().unwrap();
        }

        let runtime = directory.0.join(RUNTIME_DIRECTORY);
        for (name, bytes) in EMBEDDED_FILES {
            assert_eq!(fs::read(runtime.join(name)).unwrap(), *bytes);
        }
        let leftovers = fs::read_dir(runtime)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .filter(|name| name.to_string_lossy().contains(".tmp-"))
            .collect::<Vec<_>>();
        assert!(
            leftovers.is_empty(),
            "temporary files remain: {leftovers:?}"
        );
    }
}
