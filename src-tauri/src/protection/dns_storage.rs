//! Trusted storage for the DNS recovery journal.
//!
//! The journal is shared with an elevated crash-recovery helper, so a path
//! supplied by a user or an environment variable is not sufficient.  This
//! module derives the path from the Windows ProgramData known folder and
//! accepts an existing location only when every Vapour-owned component has an
//! explicit Administrators/SYSTEM-only security descriptor.

use std::path::{Component, Path, PathBuf};

const PRODUCT_DIRECTORY: &str = "Vapour";
const PROTECTION_DIRECTORY: &str = "Protection";
const JOURNAL_FILE: &str = "dns-recovery.json";

// FILE_ALL_ACCESS. Keeping this value local means the pure ACL policy tests
// do not depend on Windows-only newtype constants.
const FULL_CONTROL_MASK: u32 = 0x001F_01FF;
const OBJECT_INHERIT_ACE: u8 = 0x01;
const CONTAINER_INHERIT_ACE: u8 = 0x02;
const INHERITED_ACE: u8 = 0x10;
const DIRECTORY_ACE_FLAGS: u8 = OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE;
const SECURITY_DESCRIPTOR_REVISION: u32 = 1;
const MAX_SECURITY_DESCRIPTOR_BYTES: usize = 64 * 1024;
const MAX_PATH_UTF16_UNITS: usize = 32_767;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Principal {
    Administrators,
    LocalSystem,
    #[cfg(test)]
    Everyone,
    Other,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AceKind {
    Allow,
    Deny,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct AclEntryShape {
    principal: Principal,
    kind: AceKind,
    mask: u32,
    flags: u8,
    inherited: bool,
}

impl AclEntryShape {
    #[cfg(test)]
    fn allow(principal: Principal) -> Self {
        Self {
            principal,
            kind: AceKind::Allow,
            mask: FULL_CONTROL_MASK,
            flags: DIRECTORY_ACE_FLAGS,
            inherited: false,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct AclShape {
    owner: Principal,
    dacl_present: bool,
    dacl_protected: bool,
    entries: Vec<AclEntryShape>,
}

/// Validate the exact ACL policy used for Vapour storage directories. Existing
/// objects are never repaired in place: callers must reject this result and
/// ask an administrator to fix them out of band.
fn validate_acl_shape(shape: &AclShape) -> Result<(), &'static str> {
    validate_acl_shape_with_inheritance(shape, true)
}

/// Validate a journal file whose two allow ACEs may have been inherited from
/// the protected Protection directory. An inherited ACL is accepted only when
/// every ACE is still one of the two exact Administrators/SYSTEM full-control
/// entries.
fn validate_file_acl_shape(shape: &AclShape) -> Result<(), &'static str> {
    validate_acl_shape_with_inheritance(shape, false)
}

fn validate_acl_shape_with_inheritance(
    shape: &AclShape,
    directory: bool,
) -> Result<(), &'static str> {
    if !matches!(
        shape.owner,
        Principal::Administrators | Principal::LocalSystem
    ) {
        return Err("the storage owner is not Administrators or SYSTEM");
    }
    if !shape.dacl_present {
        return Err("the storage object has no DACL");
    }
    if shape.entries.len() != 2 {
        return Err("the storage DACL must contain exactly two entries");
    }
    if directory && !shape.dacl_protected {
        return Err("the storage directory DACL is not protected");
    }
    if !directory && !shape.dacl_protected && !shape.entries.iter().all(|entry| entry.inherited) {
        return Err("the inherited journal DACL contains explicit entries");
    }

    let mut administrators = false;
    let mut system = false;
    for entry in &shape.entries {
        if entry.kind != AceKind::Allow
            || entry.mask != FULL_CONTROL_MASK
            || (directory && entry.flags != DIRECTORY_ACE_FLAGS)
            || (!directory && entry.flags != 0 && entry.flags != DIRECTORY_ACE_FLAGS)
        {
            return Err("the storage DACL contains an unsafe entry");
        }
        if directory && entry.inherited {
            return Err("the storage directory DACL contains inherited entries");
        }
        match entry.principal {
            Principal::Administrators if !administrators => administrators = true,
            Principal::LocalSystem if !system => system = true,
            _ => return Err("the storage DACL contains an unexpected principal"),
        }
    }
    if administrators && system {
        Ok(())
    } else {
        Err("the storage DACL must grant only Administrators and SYSTEM")
    }
}

/// Build the only journal path accepted by this module from a known-folder
/// root. Keeping this helper pure makes the path policy testable without
/// touching ProgramData.
fn build_journal_path(program_data: &Path) -> Result<PathBuf, String> {
    validate_program_data_path(program_data)?;
    let mut path = program_data.to_owned();
    path.push(PRODUCT_DIRECTORY);
    path.push(PROTECTION_DIRECTORY);
    path.push(JOURNAL_FILE);
    Ok(path)
}

fn validate_program_data_path(program_data: &Path) -> Result<(), String> {
    // `Path::components` normalizes a textual `.` on Windows. Inspect the
    // original spelling as well so a future caller cannot smuggle a traversal
    // component through the pure path policy.
    if program_data
        .to_string_lossy()
        .split(['\\', '/'])
        .any(|component| component == "." || component == "..")
    {
        return Err("ProgramData contains traversal components".to_owned());
    }
    let mut components = program_data.components();
    match components.next() {
        Some(Component::Prefix(prefix)) => match prefix.kind() {
            std::path::Prefix::Disk(_) | std::path::Prefix::VerbatimDisk(_) => {}
            _ => return Err("ProgramData must be on a local drive".to_owned()),
        },
        _ => return Err("ProgramData must be an absolute local path".to_owned()),
    }
    if !matches!(components.next(), Some(Component::RootDir)) {
        return Err("ProgramData must have a rooted local path".to_owned());
    }

    let mut normal_count = 0usize;
    for component in components {
        match component {
            Component::Normal(name) if !name.is_empty() => normal_count += 1,
            Component::ParentDir | Component::CurDir => {
                return Err("ProgramData contains traversal components".to_owned())
            }
            Component::Prefix(_) | Component::RootDir => {
                return Err("ProgramData contains an unexpected path root".to_owned())
            }
            Component::Normal(_) => {
                return Err("ProgramData contains an empty component".to_owned())
            }
        }
    }
    if normal_count == 0 {
        return Err("ProgramData must name a directory".to_owned());
    }
    Ok(())
}

/// Resolve and validate the fixed DNS recovery journal location without
/// creating anything. A missing final journal is valid; its parent
/// directories must already exist and pass the security checks.
pub fn trusted_journal_path() -> Result<PathBuf, String> {
    #[cfg(windows)]
    {
        let program_data = windows_backend::program_data_path()?;
        let journal = build_journal_path(&program_data)?;
        windows_backend::validate_existing_layout(&program_data, &journal)?;
        return Ok(journal);
    }
    #[cfg(not(windows))]
    {
        Err("trusted DNS storage is available only on Windows".to_owned())
    }
}

/// Create the missing Vapour/Protection directories using an explicit
/// Administrators/SYSTEM-only security descriptor, then validate the entire
/// layout. Existing objects are checked and never have their permissions
/// changed by this function.
pub fn prepare_storage() -> Result<PathBuf, String> {
    #[cfg(windows)]
    {
        let program_data = windows_backend::program_data_path()?;
        let journal = build_journal_path(&program_data)?;
        windows_backend::prepare_layout(&program_data, &journal)?;
        return Ok(journal);
    }
    #[cfg(not(windows))]
    {
        Err("trusted DNS storage is available only on Windows".to_owned())
    }
}

#[cfg(windows)]
mod windows_backend {
    use super::*;
    use std::mem::size_of;
    use std::os::windows::ffi::OsStrExt;
    use std::ptr;

    use windows::core::PCWSTR;
    use windows::Win32::Foundation::{
        CloseHandle, GetLastError, BOOL, ERROR_ALREADY_EXISTS, ERROR_FILE_NOT_FOUND,
        ERROR_INSUFFICIENT_BUFFER, ERROR_PATH_NOT_FOUND, HANDLE,
    };
    use windows::Win32::Security::{
        AclSizeInformation, AddAccessAllowedAceEx, CreateWellKnownSid, GetAce, GetAclInformation,
        GetFileSecurityW, GetLengthSid, GetSecurityDescriptorControl, GetSecurityDescriptorDacl,
        GetSecurityDescriptorOwner, InitializeAcl, InitializeSecurityDescriptor, IsValidSid,
        SetSecurityDescriptorControl, SetSecurityDescriptorDacl, SetSecurityDescriptorOwner,
        WinBuiltinAdministratorsSid, WinLocalSystemSid, ACCESS_ALLOWED_ACE, ACE_FLAGS, ACE_HEADER,
        ACL, ACL_REVISION, DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION,
        PSECURITY_DESCRIPTOR, PSID, SECURITY_ATTRIBUTES, SECURITY_DESCRIPTOR, SE_DACL_PROTECTED,
    };
    use windows::Win32::Storage::FileSystem::{
        CreateDirectoryW, CreateFileW, FileAttributeTagInfo, GetFileAttributesW,
        GetFileInformationByHandleEx, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT,
        FILE_ATTRIBUTE_TAG_INFO, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
        FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
        INVALID_FILE_ATTRIBUTES, OPEN_EXISTING,
    };
    use windows::Win32::System::Com::CoTaskMemFree;
    use windows::Win32::UI::Shell::{FOLDERID_ProgramData, SHGetKnownFolderPath, KF_FLAG_DEFAULT};

    const SECURITY_INFORMATION: u32 = OWNER_SECURITY_INFORMATION.0 | DACL_SECURITY_INFORMATION.0;
    const ACE_ALLOWED_TYPE: u8 = 0;
    const ACL_MAX_ENTRIES: u32 = 32;

    struct SecureDescriptor {
        descriptor: SECURITY_DESCRIPTOR,
        // ACLs contain DWORD fields. A Vec<u8> is not guaranteed to provide
        // the alignment required by the native ACL structure.
        _acl: Vec<u32>,
        // The native descriptor stores pointers into these SIDs. Heap backing
        // keeps those addresses stable while the descriptor is passed to the
        // create call, including when this owner struct is moved.
        administrators: Box<[u32; 17]>,
        _system: Box<[u32; 17]>,
    }

    impl SecureDescriptor {
        fn new() -> Result<Self, String> {
            let mut descriptor = SECURITY_DESCRIPTOR::default();
            let mut acl = vec![0u32; 128];
            let mut administrators = Box::new([0u32; 17]);
            let mut system = Box::new([0u32; 17]);
            let administrators_sid =
                create_well_known_sid(WinBuiltinAdministratorsSid, &mut administrators)?;
            let system_sid = create_well_known_sid(WinLocalSystemSid, &mut system)?;

            unsafe {
                InitializeAcl(
                    acl.as_mut_ptr().cast::<ACL>(),
                    u32::try_from(acl.len().saturating_mul(size_of::<u32>()))
                        .map_err(|_| "ACL is too large".to_owned())?,
                    ACL_REVISION,
                )
                .map_err(|error| format!("InitializeAcl failed: {error}"))?;
                AddAccessAllowedAceEx(
                    acl.as_mut_ptr().cast::<ACL>(),
                    ACL_REVISION,
                    ACE_FLAGS(u32::from(DIRECTORY_ACE_FLAGS)),
                    FULL_CONTROL_MASK,
                    administrators_sid,
                )
                .map_err(|error| format!("AddAccessAllowedAce(Administrators) failed: {error}"))?;
                AddAccessAllowedAceEx(
                    acl.as_mut_ptr().cast::<ACL>(),
                    ACL_REVISION,
                    ACE_FLAGS(u32::from(DIRECTORY_ACE_FLAGS)),
                    FULL_CONTROL_MASK,
                    system_sid,
                )
                .map_err(|error| format!("AddAccessAllowedAce(SYSTEM) failed: {error}"))?;

                let descriptor_ptr =
                    PSECURITY_DESCRIPTOR((&mut descriptor as *mut SECURITY_DESCRIPTOR).cast());
                InitializeSecurityDescriptor(descriptor_ptr, SECURITY_DESCRIPTOR_REVISION)
                    .map_err(|error| format!("InitializeSecurityDescriptor failed: {error}"))?;
                SetSecurityDescriptorDacl(
                    descriptor_ptr,
                    BOOL(1),
                    Some(acl.as_mut_ptr().cast::<ACL>()),
                    BOOL(0),
                )
                .map_err(|error| format!("SetSecurityDescriptorDacl failed: {error}"))?;
                SetSecurityDescriptorControl(descriptor_ptr, SE_DACL_PROTECTED, SE_DACL_PROTECTED)
                    .map_err(|error| format!("SetSecurityDescriptorControl failed: {error}"))?;
            }

            Ok(Self {
                descriptor,
                _acl: acl,
                administrators,
                _system: system,
            })
        }

        fn security_attributes(&mut self) -> Result<SECURITY_ATTRIBUTES, String> {
            // Set the owner after `self` is fully constructed. Doing this in
            // `new` would leave an inline SID pointer dangling if the struct
            // moved on return.
            let administrators_sid = PSID(self.administrators.as_mut_ptr().cast());
            unsafe {
                SetSecurityDescriptorOwner(
                    PSECURITY_DESCRIPTOR((&mut self.descriptor as *mut SECURITY_DESCRIPTOR).cast()),
                    administrators_sid,
                    BOOL(0),
                )
                .map_err(|error| format!("SetSecurityDescriptorOwner failed: {error}"))?;
            }
            Ok(SECURITY_ATTRIBUTES {
                nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
                lpSecurityDescriptor: (&mut self.descriptor as *mut SECURITY_DESCRIPTOR).cast(),
                bInheritHandle: BOOL(0),
            })
        }
    }

    fn create_well_known_sid(
        kind: windows::Win32::Security::WELL_KNOWN_SID_TYPE,
        storage: &mut Box<[u32; 17]>,
    ) -> Result<PSID, String> {
        let mut length = u32::try_from(size_of::<[u32; 17]>())
            .map_err(|_| "SID buffer is too large".to_owned())?;
        let sid = PSID(storage.as_mut_ptr().cast());
        unsafe {
            CreateWellKnownSid(kind, PSID::default(), sid, &mut length)
                .map_err(|error| format!("CreateWellKnownSid failed: {error}"))?;
        }
        Ok(sid)
    }

    pub(super) fn program_data_path() -> Result<PathBuf, String> {
        let path = unsafe {
            SHGetKnownFolderPath(&FOLDERID_ProgramData, KF_FLAG_DEFAULT, HANDLE::default())
                .map_err(|error| format!("SHGetKnownFolderPath(ProgramData) failed: {error}"))?
        };
        if path.0.is_null() {
            return Err("SHGetKnownFolderPath returned a null path".to_owned());
        }
        let result = unsafe {
            path.to_string()
                .map(PathBuf::from)
                .map_err(|error| format!("ProgramData path is not valid UTF-16: {error}"))
        };
        unsafe {
            CoTaskMemFree(Some(path.0.cast()));
        }
        result
    }

    pub(super) fn validate_existing_layout(
        program_data: &Path,
        journal: &Path,
    ) -> Result<(), String> {
        validate_program_data_root(program_data)?;
        let product = program_data.join(PRODUCT_DIRECTORY);
        let protection = product.join(PROTECTION_DIRECTORY);
        require_secure_directory(&product, "Vapour")?;
        require_secure_directory(&protection, "Protection")?;
        validate_optional_journal(journal)
    }

    pub(super) fn prepare_layout(program_data: &Path, journal: &Path) -> Result<(), String> {
        validate_program_data_root(program_data)?;
        let product = program_data.join(PRODUCT_DIRECTORY);
        let protection = product.join(PROTECTION_DIRECTORY);
        ensure_secure_directory(&product, "Vapour")?;
        ensure_secure_directory(&protection, "Protection")?;
        validate_optional_journal(journal)
    }

    fn validate_program_data_root(program_data: &Path) -> Result<(), String> {
        let object =
            object_info(program_data)?.ok_or_else(|| "ProgramData does not exist".to_owned())?;
        if !object.directory {
            return Err("ProgramData is not a directory".to_owned());
        }
        if object.reparse {
            return Err("ProgramData is a reparse point".to_owned());
        }
        Ok(())
    }

    fn require_secure_directory(path: &Path, label: &str) -> Result<(), String> {
        let object =
            object_info(path)?.ok_or_else(|| format!("{label} storage directory is missing"))?;
        if !object.directory {
            return Err(format!("{label} storage component is not a directory"));
        }
        if object.reparse {
            return Err(format!("{label} storage directory is a reparse point"));
        }
        validate_security_descriptor(path, label, true)
    }

    fn ensure_secure_directory(path: &Path, label: &str) -> Result<(), String> {
        if let Some(object) = object_info(path)? {
            if !object.directory {
                return Err(format!("{label} storage component is not a directory"));
            }
            if object.reparse {
                return Err(format!("{label} storage directory is a reparse point"));
            }
            return validate_security_descriptor(path, label, true);
        }

        let mut descriptor = SecureDescriptor::new()?;
        let security_attributes = descriptor.security_attributes()?;
        let wide = wide_path(path)?;
        let create_result = unsafe {
            CreateDirectoryW(
                PCWSTR(wide.as_ptr()),
                Some(&security_attributes as *const SECURITY_ATTRIBUTES),
            )
        };
        if let Err(error) = create_result {
            if win32_code(&error) != ERROR_ALREADY_EXISTS.0 {
                return Err(format!(
                    "creating {label} storage directory failed: {error}"
                ));
            }
        }

        // ERROR_ALREADY_EXISTS can mean a file, directory, or a reparse point
        // won the race. Re-read and validate; never repair it.
        require_secure_directory(path, label)
    }

    fn validate_optional_journal(journal: &Path) -> Result<(), String> {
        let Some(object) = object_info(journal)? else {
            return Ok(());
        };
        if object.directory {
            return Err("DNS recovery journal path is a directory".to_owned());
        }
        if object.reparse {
            return Err("DNS recovery journal is a reparse point".to_owned());
        }
        validate_security_descriptor(journal, "DNS recovery journal", false)
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct ObjectInfo {
        directory: bool,
        reparse: bool,
    }

    fn object_info(path: &Path) -> Result<Option<ObjectInfo>, String> {
        let wide = wide_path(path)?;
        let attributes = unsafe { GetFileAttributesW(PCWSTR(wide.as_ptr())) };
        if attributes == INVALID_FILE_ATTRIBUTES {
            let code = unsafe { GetLastError().0 };
            if code == ERROR_FILE_NOT_FOUND.0 || code == ERROR_PATH_NOT_FOUND.0 {
                return Ok(None);
            }
            return Err(format!("reading storage path attributes failed ({code})"));
        }

        let directory = attributes & FILE_ATTRIBUTE_DIRECTORY.0 != 0;
        let reparse = attributes & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0;

        // Open the final component itself, rather than following a junction or
        // symbolic link, and confirm the tag returned by the kernel.
        let handle = unsafe {
            CreateFileW(
                PCWSTR(wide.as_ptr()),
                FILE_READ_ATTRIBUTES.0,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                None,
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
                HANDLE::default(),
            )
        }
        .map_err(|error| format!("opening storage path for validation failed: {error}"))?;

        let mut tag = FILE_ATTRIBUTE_TAG_INFO::default();
        let result = unsafe {
            GetFileInformationByHandleEx(
                handle,
                FileAttributeTagInfo,
                (&mut tag as *mut FILE_ATTRIBUTE_TAG_INFO).cast(),
                size_of::<FILE_ATTRIBUTE_TAG_INFO>() as u32,
            )
            .map_err(|error| format!("reading storage path attributes failed: {error}"))
        };
        let _ = unsafe { CloseHandle(handle) };
        result?;

        Ok(Some(ObjectInfo {
            directory,
            reparse: reparse || tag.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0,
        }))
    }

    fn validate_security_descriptor(
        path: &Path,
        label: &str,
        directory: bool,
    ) -> Result<(), String> {
        let buffer = read_security_descriptor(path)?;
        let descriptor = PSECURITY_DESCRIPTOR(buffer.as_ptr() as *mut _);
        let mut owner = PSID::default();
        let mut owner_defaulted = BOOL(0);
        let mut dacl_present = BOOL(0);
        let mut dacl = ptr::null_mut::<ACL>();
        let mut dacl_defaulted = BOOL(0);

        unsafe {
            GetSecurityDescriptorOwner(descriptor, &mut owner, &mut owner_defaulted)
                .map_err(|error| format!("reading {label} owner failed: {error}"))?;
            GetSecurityDescriptorDacl(
                descriptor,
                &mut dacl_present,
                &mut dacl,
                &mut dacl_defaulted,
            )
            .map_err(|error| format!("reading {label} DACL failed: {error}"))?;
        }
        if !sid_in_buffer(owner, &buffer) {
            return Err(format!("{label} has an invalid owner SID"));
        }

        let mut control = 0u16;
        let mut revision = 0u32;
        unsafe {
            GetSecurityDescriptorControl(descriptor, &mut control, &mut revision)
                .map_err(|error| format!("reading {label} DACL control failed: {error}"))?;
        }

        let mut administrators_storage = Box::new([0u32; 17]);
        let mut system_storage = Box::new([0u32; 17]);
        let administrators =
            create_well_known_sid(WinBuiltinAdministratorsSid, &mut administrators_storage)?;
        let system = create_well_known_sid(WinLocalSystemSid, &mut system_storage)?;
        let owner_principal = principal_for_sid(owner, administrators, system);
        let mut entries = Vec::new();
        if dacl_present.0 != 0 && !dacl.is_null() {
            let acl_length = acl_length_in_buffer(dacl, &buffer)
                .ok_or_else(|| format!("{label} DACL is outside its descriptor"))?;
            let mut info = windows::Win32::Security::ACL_SIZE_INFORMATION::default();
            unsafe {
                GetAclInformation(
                    dacl,
                    (&mut info as *mut windows::Win32::Security::ACL_SIZE_INFORMATION).cast(),
                    size_of::<windows::Win32::Security::ACL_SIZE_INFORMATION>() as u32,
                    AclSizeInformation,
                )
                .map_err(|error| format!("reading {label} DACL size failed: {error}"))?;
            }
            if info.AceCount > ACL_MAX_ENTRIES {
                return Err(format!("{label} DACL contains too many entries"));
            }
            for index in 0..info.AceCount {
                entries.push(read_ace_shape(
                    dacl,
                    acl_length,
                    index,
                    &buffer,
                    administrators,
                    system,
                )?);
            }
        }

        let shape = AclShape {
            owner: owner_principal,
            dacl_present: dacl_present.0 != 0 && !dacl.is_null(),
            dacl_protected: control & SE_DACL_PROTECTED.0 != 0,
            entries,
        };
        let result = if directory {
            validate_acl_shape(&shape)
        } else {
            validate_file_acl_shape(&shape)
        };
        result.map_err(|reason| format!("{label} ACL rejected: {reason}"))
    }

    struct SecurityDescriptorBuffer {
        // SECURITY_DESCRIPTOR and the structures it points at require native
        // alignment. A Vec<u8> only promises byte alignment, so keep the
        // backing allocation in DWORDs while tracking the exact byte length
        // returned by GetFileSecurityW.
        storage: Vec<u32>,
        byte_len: usize,
    }

    impl SecurityDescriptorBuffer {
        fn as_ptr(&self) -> *const u8 {
            self.storage.as_ptr().cast()
        }

        fn as_mut_ptr(&mut self) -> *mut u8 {
            self.storage.as_mut_ptr().cast()
        }
    }

    fn read_security_descriptor(path: &Path) -> Result<SecurityDescriptorBuffer, String> {
        let wide = wide_path(path)?;
        let mut needed = 0u32;
        let first = unsafe {
            GetFileSecurityW(
                PCWSTR(wide.as_ptr()),
                SECURITY_INFORMATION,
                PSECURITY_DESCRIPTOR(ptr::null_mut()),
                0,
                &mut needed,
            )
        };
        if first.0 != 0 {
            return Err("GetFileSecurityW unexpectedly succeeded with an empty buffer".to_owned());
        }
        let code = unsafe { GetLastError().0 };
        if code != ERROR_INSUFFICIENT_BUFFER.0 || needed == 0 {
            return Err(format!("GetFileSecurityW sizing failed ({code})"));
        }
        let length =
            usize::try_from(needed).map_err(|_| "security descriptor is too large".to_owned())?;
        if length > MAX_SECURITY_DESCRIPTOR_BYTES {
            return Err("security descriptor exceeds the validation limit".to_owned());
        }
        let word_count = length
            .checked_add(size_of::<u32>() - 1)
            .and_then(|value| value.checked_div(size_of::<u32>()))
            .ok_or_else(|| "security descriptor size overflow".to_owned())?;
        let capacity_bytes = word_count
            .checked_mul(size_of::<u32>())
            .ok_or_else(|| "security descriptor size overflow".to_owned())?;
        let capacity_u32 = u32::try_from(capacity_bytes)
            .map_err(|_| "security descriptor is too large".to_owned())?;
        let mut buffer = SecurityDescriptorBuffer {
            storage: vec![0u32; word_count],
            byte_len: 0,
        };
        let mut reported = capacity_u32;
        let success = unsafe {
            GetFileSecurityW(
                PCWSTR(wide.as_ptr()),
                SECURITY_INFORMATION,
                PSECURITY_DESCRIPTOR(buffer.as_mut_ptr().cast()),
                capacity_u32,
                &mut reported,
            )
        };
        if success.0 == 0 {
            return Err(format!("GetFileSecurityW read failed ({})", unsafe {
                GetLastError().0
            }));
        }
        let reported = usize::try_from(reported)
            .map_err(|_| "security descriptor reported an invalid length".to_owned())?;
        if reported == 0 || reported > capacity_bytes {
            return Err("GetFileSecurityW returned a length outside its buffer".to_owned());
        }
        buffer.byte_len = reported;
        Ok(buffer)
    }

    fn principal_for_sid(candidate: PSID, administrators: PSID, system: PSID) -> Principal {
        if unsafe { windows::Win32::Security::EqualSid(candidate, administrators).is_ok() } {
            Principal::Administrators
        } else if unsafe { windows::Win32::Security::EqualSid(candidate, system).is_ok() } {
            Principal::LocalSystem
        } else {
            Principal::Other
        }
    }

    fn sid_in_buffer(sid: PSID, descriptor: &SecurityDescriptorBuffer) -> bool {
        sid_length_in_buffer(sid, descriptor, descriptor.byte_len).is_some()
    }

    fn acl_length_in_buffer(
        acl: *const ACL,
        descriptor: &SecurityDescriptorBuffer,
    ) -> Option<usize> {
        if acl.is_null() || !range_in_buffer(acl.cast(), size_of::<ACL>(), descriptor) {
            return None;
        }
        let header = unsafe { ptr::read_unaligned(acl) };
        let length = usize::from(header.AclSize);
        (length >= size_of::<ACL>()
            && length % size_of::<u32>() == 0
            && range_in_buffer(acl.cast(), length, descriptor))
        .then_some(length)
    }

    fn read_ace_shape(
        dacl: *const ACL,
        dacl_length: usize,
        index: u32,
        descriptor: &SecurityDescriptorBuffer,
        administrators: PSID,
        system: PSID,
    ) -> Result<AclEntryShape, String> {
        let mut raw_ace = ptr::null_mut::<std::ffi::c_void>();
        unsafe {
            GetAce(dacl, index, &mut raw_ace)
                .map_err(|error| format!("reading storage DACL entry failed: {error}"))?;
        }
        if raw_ace.is_null()
            || !range_in_region(
                raw_ace.cast(),
                size_of::<ACE_HEADER>(),
                dacl.cast(),
                dacl_length,
            )
        {
            return Err("storage DACL entry is outside its descriptor".to_owned());
        }
        let header = unsafe { ptr::read_unaligned(raw_ace.cast::<ACE_HEADER>()) };
        let ace_size = usize::from(header.AceSize);
        if ace_size < size_of::<ACE_HEADER>()
            || ace_size % size_of::<u32>() != 0
            || !range_in_region(raw_ace.cast(), ace_size, dacl.cast(), dacl_length)
            || !range_in_buffer(raw_ace.cast(), ace_size, descriptor)
        {
            return Err("storage DACL entry has an invalid length".to_owned());
        }
        if header.AceType != ACE_ALLOWED_TYPE {
            return Ok(AclEntryShape {
                principal: Principal::Other,
                kind: AceKind::Deny,
                mask: 0,
                flags: header.AceFlags & !INHERITED_ACE,
                inherited: header.AceFlags & INHERITED_ACE != 0,
            });
        }
        if ace_size < size_of::<ACCESS_ALLOWED_ACE>() {
            return Err("storage allow DACL entry has an invalid length".to_owned());
        }
        let ace = unsafe { ptr::read_unaligned(raw_ace.cast::<ACCESS_ALLOWED_ACE>()) };
        let sid_offset = size_of::<ACE_HEADER>() + size_of::<u32>();
        let sid = PSID((raw_ace as *const u8).wrapping_add(sid_offset) as *mut _);
        let sid_length =
            sid_length_in_buffer(sid, descriptor, ace_size.saturating_sub(sid_offset)).unwrap_or(0);
        if sid_length == 0 {
            return Err("storage DACL entry has an invalid SID length".to_owned());
        }
        let principal = if unsafe { IsValidSid(sid).0 } == 0 {
            Principal::Other
        } else {
            principal_for_sid(sid, administrators, system)
        };
        Ok(AclEntryShape {
            principal,
            kind: AceKind::Allow,
            mask: ace.Mask,
            flags: header.AceFlags & !INHERITED_ACE,
            inherited: header.AceFlags & INHERITED_ACE != 0,
        })
    }

    fn sid_length_in_buffer(
        sid: PSID,
        descriptor: &SecurityDescriptorBuffer,
        max_length: usize,
    ) -> Option<usize> {
        let sid_pointer = sid.0.cast::<u8>();
        if sid.is_invalid() || max_length < 8 || !range_in_buffer(sid_pointer, 8, descriptor) {
            return None;
        }

        // Validate the fixed SID header and subauthority count before calling
        // IsValidSid/GetLengthSid. Those APIs dereference the SID structure;
        // the ACE's declared size must contain the complete SID first.
        let subauthority_count = unsafe { sid_pointer.add(1).read() };
        if subauthority_count > 15 {
            return None;
        }
        let sid_length = 8usize.checked_add(usize::from(subauthority_count).checked_mul(4)?)?;
        if sid_length > max_length || !range_in_buffer(sid_pointer, sid_length, descriptor) {
            return None;
        }
        if unsafe { IsValidSid(sid).0 } == 0 {
            return None;
        }
        let reported = unsafe { GetLengthSid(sid) as usize };
        (reported == sid_length).then_some(reported)
    }

    fn range_in_buffer(
        pointer: *const u8,
        length: usize,
        buffer: &SecurityDescriptorBuffer,
    ) -> bool {
        range_in_region(pointer, length, buffer.as_ptr(), buffer.byte_len)
    }

    fn range_in_region(
        pointer: *const u8,
        length: usize,
        region: *const u8,
        region_length: usize,
    ) -> bool {
        let start = region as usize;
        let Some(end) = start.checked_add(region_length) else {
            return false;
        };
        let address = pointer as usize;
        address >= start
            && address
                .checked_add(length)
                .is_some_and(|finish| finish <= end)
    }

    fn wide_path(path: &Path) -> Result<Vec<u16>, String> {
        let units: Vec<u16> = path.as_os_str().encode_wide().collect();
        if units.is_empty() || units.len() > MAX_PATH_UTF16_UNITS || units.contains(&0) {
            return Err("storage path has an invalid length or embedded NUL".to_owned());
        }
        let mut result = units;
        result.push(0);
        Ok(result)
    }

    fn win32_code(error: &windows::core::Error) -> u32 {
        let code = error.code().0 as u32;
        if code & 0xFFFF_0000 == 0x8007_0000 {
            code & 0xFFFF
        } else {
            code
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::{Path, PathBuf};

    #[cfg(windows)]
    #[test]
    fn builds_the_fixed_journal_leaf_beneath_program_data() {
        let path = build_journal_path(Path::new(r"C:\ProgramData")).unwrap();
        assert_eq!(
            path,
            PathBuf::from(r"C:\ProgramData\Vapour\Protection\dns-recovery.json")
        );
    }

    #[cfg(windows)]
    #[test]
    fn rejects_program_data_paths_that_are_not_local_absolute_roots() {
        for path in [
            Path::new("relative"),
            Path::new(r"\\server\share\ProgramData"),
            Path::new(r"C:\ProgramData\..\Other"),
            Path::new(r"C:\ProgramData\.\Other"),
        ] {
            assert!(build_journal_path(path).is_err(), "accepted {path:?}");
        }
    }

    #[test]
    fn acl_policy_allows_only_admin_and_system_full_control() {
        let shape = AclShape {
            owner: Principal::Administrators,
            dacl_present: true,
            dacl_protected: true,
            entries: vec![
                AclEntryShape::allow(Principal::Administrators),
                AclEntryShape::allow(Principal::LocalSystem),
            ],
        };
        assert!(validate_acl_shape(&shape).is_ok());
    }

    #[test]
    fn acl_policy_rejects_missing_protection_or_extra_principals() {
        let mut shape = AclShape {
            owner: Principal::Administrators,
            dacl_present: true,
            dacl_protected: false,
            entries: vec![
                AclEntryShape::allow(Principal::Administrators),
                AclEntryShape::allow(Principal::LocalSystem),
            ],
        };
        assert!(validate_acl_shape(&shape).is_err());

        shape.dacl_protected = true;
        shape
            .entries
            .push(AclEntryShape::allow(Principal::Everyone));
        assert!(validate_acl_shape(&shape).is_err());
    }

    #[test]
    fn acl_policy_rejects_denies_and_inherited_entries() {
        let mut shape = AclShape {
            owner: Principal::LocalSystem,
            dacl_present: true,
            dacl_protected: true,
            entries: vec![
                AclEntryShape::allow(Principal::Administrators),
                AclEntryShape::allow(Principal::LocalSystem),
            ],
        };
        shape.entries[0].kind = AceKind::Deny;
        assert!(validate_acl_shape(&shape).is_err());

        shape.entries[0].kind = AceKind::Allow;
        shape.entries[0].inherited = true;
        assert!(validate_acl_shape(&shape).is_err());
    }

    #[test]
    fn acl_policy_rejects_non_full_control_masks_and_inheritance_flags() {
        let mut shape = AclShape {
            owner: Principal::Administrators,
            dacl_present: true,
            dacl_protected: true,
            entries: vec![
                AclEntryShape::allow(Principal::Administrators),
                AclEntryShape::allow(Principal::LocalSystem),
            ],
        };
        shape.entries[0].mask = 0x120089;
        assert!(validate_acl_shape(&shape).is_err());
        shape.entries[0].mask = FULL_CONTROL_MASK;
        shape.entries[0].flags = 0;
        assert!(validate_acl_shape(&shape).is_err());
    }

    #[test]
    fn file_policy_accepts_only_inherited_admin_and_system_entries() {
        let mut shape = AclShape {
            owner: Principal::Administrators,
            dacl_present: true,
            dacl_protected: false,
            entries: vec![
                AclEntryShape::allow(Principal::Administrators),
                AclEntryShape::allow(Principal::LocalSystem),
            ],
        };
        shape.entries[0].flags = 0;
        shape.entries[1].flags = 0;
        shape.entries[0].inherited = true;
        shape.entries[1].inherited = true;
        assert!(validate_file_acl_shape(&shape).is_ok());

        shape.entries[1].inherited = false;
        assert!(validate_file_acl_shape(&shape).is_err());
    }

    #[cfg(windows)]
    #[test]
    #[ignore = "read-only host probe; ProgramData must already contain trusted storage"]
    fn read_only_host_probe_reports_trusted_storage_without_creating_it() {
        let path = trusted_journal_path().expect("trusted DNS storage must be provisioned");
        println!(
            "trusted DNS journal path resolved (leaf={:?})",
            path.file_name()
        );
    }
}
