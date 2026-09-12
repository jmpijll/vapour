use std::os::windows::process::CommandExt;
use std::process::Command;
use windows::Win32::Foundation::HANDLE;
use windows::Win32::Security::{GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

const CREATE_NO_WINDOW: u32 = 0x08000000;

pub struct FirewallManager;

fn validate_executable(path: &str) -> Result<String, String> {
    let candidate = std::path::Path::new(path);
    if path.is_empty()
        || !candidate.is_absolute()
        || !candidate.is_file()
        || !candidate
            .extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("exe"))
    {
        return Err("A valid executable path is required.".into());
    }
    let canonical = candidate
        .canonicalize()
        .map_err(|_| "Cannot resolve executable path.")?;
    Ok(canonical
        .to_string_lossy()
        .trim_start_matches(r"\\?\")
        .to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_missing_executable_before_any_system_action() {
        let result = validate_executable("");
        assert!(result.unwrap_err().contains("executable"));
    }
}

impl FirewallManager {
    pub fn is_elevated() -> bool {
        unsafe {
            let mut token: HANDLE = HANDLE::default();
            if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).is_err() {
                return false;
            }

            let mut elevation = TOKEN_ELEVATION::default();
            let mut return_length = 0u32;
            let success = GetTokenInformation(
                token,
                TokenElevation,
                Some(&mut elevation as *mut _ as *mut _),
                std::mem::size_of::<TOKEN_ELEVATION>() as u32,
                &mut return_length,
            );

            let _ = windows::Win32::Foundation::CloseHandle(token);

            if success.is_ok() {
                elevation.TokenIsElevated != 0
            } else {
                false
            }
        }
    }

    pub fn get_blocked_rules() -> std::collections::HashSet<String> {
        Self::read_blocked_rules().unwrap_or_default()
    }
    pub fn read_blocked_rules() -> Result<std::collections::HashSet<String>, String> {
        let out = Command::new("netsh")
            .args(["advfirewall", "firewall", "show", "rule", "name=all"])
            .creation_flags(CREATE_NO_WINDOW)
            .output()
            .map_err(|e| e.to_string())?;
        if !out.status.success() {
            return Err("Cannot read Windows Firewall rules.".into());
        }
        Ok(String::from_utf8_lossy(&out.stdout)
            .lines()
            .filter_map(|line| {
                let pos = line.find("Vapour-v2-")?;
                let name = line[pos..].trim();
                (name.len() == 74 && name[10..].bytes().all(|c| c.is_ascii_hexdigit()))
                    .then(|| name.to_owned())
            })
            .collect())
    }
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct BlockTarget {
    pub path: String,
    pub remote_ip: Option<String>,
    pub remote_port: Option<u16>,
    pub local_ip: Option<String>,
    pub local_port: Option<u16>,
    pub protocol: Option<String>,
}
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct BlockRule {
    pub id: String,
    pub target: BlockTarget,
}

pub fn rule_id(target: &BlockTarget) -> String {
    use sha2::{Digest, Sha256};
    let mut normalized = target.clone();
    normalized.path = normalized.path.to_lowercase();
    format!(
        "Vapour-v2-{:x}",
        Sha256::digest(serde_json::to_vec(&normalized).unwrap())
    )
}
fn target_args(target: &BlockTarget) -> Result<Vec<String>, String> {
    let mut args = vec![format!("program={}", target.path)];
    match (
        &target.remote_ip,
        target.remote_port,
        &target.local_ip,
        target.local_port,
        &target.protocol,
    ) {
        (None, None, None, None, None) => {}
        (Some(remote), Some(rport), Some(local), Some(lport), Some(protocol)) => {
            let rip: std::net::IpAddr = remote.parse().map_err(|_| "Invalid remote address")?;
            let lip: std::net::IpAddr = local.parse().map_err(|_| "Invalid local address")?;
            if rip.is_unspecified()
                || lip.is_unspecified()
                || rport == 0
                || lport == 0
                || !["TCP", "UDP"].contains(&protocol.as_str())
            {
                return Err("A complete connection is required.".into());
            }
            args.extend([
                format!("remoteip={rip}"),
                format!("remoteport={rport}"),
                format!("localip={lip}"),
                format!("localport={lport}"),
                format!("protocol={protocol}"),
            ]);
        }
        _ => return Err("Incomplete connection: refusing a broader rule.".into()),
    }
    Ok(args)
}

pub struct RuleStore {
    file: std::path::PathBuf,
}
impl RuleStore {
    pub fn new(file: std::path::PathBuf) -> Self {
        Self { file }
    }
    fn catalog(&self) -> Result<Vec<BlockRule>, String> {
        if !self.file.exists() {
            return Ok(vec![]);
        }
        serde_json::from_slice(&std::fs::read(&self.file).map_err(|e| e.to_string())?)
            .map_err(|e| format!("Cannot read block catalog: {e}"))
    }
    fn save(&self, rules: &[BlockRule]) -> Result<(), String> {
        if let Some(parent) = self.file.parent() {
            std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        use std::io::Write;
        let pending = self.file.with_extension("pending");
        let mut file = std::fs::File::create(&pending).map_err(|e| e.to_string())?;
        file.write_all(&serde_json::to_vec(rules).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?;
        file.sync_all().map_err(|e| e.to_string())?;
        drop(file);
        std::fs::rename(pending, &self.file).map_err(|e| e.to_string())
    }
    pub fn list(&self) -> Result<Vec<BlockRule>, String> {
        let installed = FirewallManager::read_blocked_rules()?;
        Ok(self
            .catalog()?
            .into_iter()
            .filter(|r| installed.contains(&r.id) && r.id == rule_id(&r.target))
            .collect())
    }
    pub fn change(&self, mut target: BlockTarget, block: bool) -> Result<Vec<BlockRule>, String> {
        if !FirewallManager::is_elevated() {
            return Err("Administrator access is required for firewall changes.".into());
        }
        if block {
            let environment = FirewallManager::environment()?;
            if !environment.enforcing {
                return Err(environment
                    .reason
                    .unwrap_or_else(|| "Windows Firewall is not enforcing rules.".into()));
            }
            target.path = validate_executable(&target.path)?;
        }
        let selectors = target_args(&target)?;
        let id = rule_id(&target);
        let mut catalog = self.catalog()?;
        if !block && !catalog.iter().any(|r| r.id == id) {
            return Err("This rule is not managed by Vapour.".into());
        }
        // Persist exact scope before touching the firewall, so a restart cannot orphan a block.
        if block && !catalog.iter().any(|r| r.id == id) {
            catalog.push(BlockRule {
                id: id.clone(),
                target: target.clone(),
            });
            self.save(&catalog)?;
        }
        let installed = FirewallManager::read_blocked_rules()?;
        if installed.contains(&id) != block {
            let mut args: Vec<String> = [
                "advfirewall",
                "firewall",
                if block { "add" } else { "delete" },
                "rule",
            ]
            .into_iter()
            .map(str::to_owned)
            .collect();
            args.push(format!("name={id}"));
            args.push("dir=out".into());
            if block {
                args.extend([
                    "action=block".into(),
                    "enable=yes".into(),
                    "profile=any".into(),
                ]);
            }
            args.extend(selectors);
            let out = Command::new("netsh")
                .args(args)
                .creation_flags(CREATE_NO_WINDOW)
                .output()
                .map_err(|e| e.to_string())?;
            if !out.status.success() {
                return Err(format!(
                    "Firewall change failed: {}",
                    String::from_utf8_lossy(&out.stdout).trim()
                ));
            }
        }
        if FirewallManager::read_blocked_rules()?.contains(&id) != block {
            return Err("Windows did not confirm the firewall change.".into());
        }
        if !block {
            catalog.retain(|r| r.id != id);
            self.save(&catalog)?;
        }
        self.list()
    }
}
#[cfg(test)]
mod scope_tests {
    use super::*;
    fn target() -> BlockTarget {
        BlockTarget {
            path: r"C:\One\app.exe".into(),
            remote_ip: None,
            remote_port: None,
            local_ip: None,
            local_port: None,
            protocol: None,
        }
    }
    #[test]
    fn same_filename_different_directories_never_share_rule() {
        let a = target();
        let mut b = a.clone();
        b.path = r"C:\Two\app.exe".into();
        assert_ne!(rule_id(&a), rule_id(&b));
    }
    #[test]
    fn incomplete_session_cannot_become_application_block() {
        let mut a = target();
        a.remote_ip = Some("1.1.1.1".into());
        assert!(target_args(&a).is_err());
    }
    #[test]
    fn session_rule_contains_every_endpoint_selector() {
        let mut a = target();
        a.remote_ip = Some("1.1.1.1".into());
        a.remote_port = Some(443);
        a.local_ip = Some("192.0.2.2".into());
        a.local_port = Some(51234);
        a.protocol = Some("TCP".into());
        let args = target_args(&a).unwrap();
        assert!(args.contains(&"remoteport=443".into()));
        assert!(args.contains(&"localport=51234".into()));
        assert_eq!(args.len(), 6);
    }
}

#[derive(Debug, serde::Serialize)]
pub struct FirewallEnvironment {
    pub enforcing: bool,
    pub reason: Option<String>,
}
fn assess_profiles(active: i32, enabled: i32, policy_override: bool) -> FirewallEnvironment {
    let reason = if active == 0 {
        Some("Cannot determine the active Windows Firewall profile.")
    } else if active & enabled != active {
        Some("Windows Firewall is off for an active network. Saved rules cannot reliably block traffic.")
    } else if policy_override {
        Some("Windows policy overrides local firewall rules.")
    } else {
        None
    };
    FirewallEnvironment {
        enforcing: reason.is_none(),
        reason: reason.map(str::to_owned),
    }
}
impl FirewallManager {
    pub fn environment() -> Result<FirewallEnvironment, String> {
        use windows::Win32::NetworkManagement::WindowsFirewall::*;
        use windows::Win32::System::Com::{
            CoCreateInstance, CoInitializeEx, CoUninitialize, CLSCTX_INPROC_SERVER,
            COINIT_MULTITHREADED,
        };
        unsafe {
            let initialized = CoInitializeEx(None, COINIT_MULTITHREADED);
            // A caller with an existing apartment can use it without taking ownership.
            if initialized.is_err() && initialized.0 != 0x80010106u32 as i32 {
                return Err(initialized.to_string());
            }
            let result = (|| -> windows::core::Result<FirewallEnvironment> {
                let policy: INetFwPolicy2 =
                    CoCreateInstance(&NetFwPolicy2, None, CLSCTX_INPROC_SERVER)?;
                let active = policy.CurrentProfileTypes()?;
                let mut enabled = 0;
                for profile in [
                    NET_FW_PROFILE2_DOMAIN,
                    NET_FW_PROFILE2_PRIVATE,
                    NET_FW_PROFILE2_PUBLIC,
                ] {
                    if policy.get_FirewallEnabled(profile)?.0 != 0 {
                        enabled |= profile.0;
                    }
                }
                Ok(assess_profiles(
                    active,
                    enabled,
                    policy.LocalPolicyModifyState()? == NET_FW_MODIFY_STATE_GP_OVERRIDE,
                ))
            })();
            if initialized.is_ok() {
                CoUninitialize();
            }
            result.map_err(|e| format!("Cannot verify Windows Firewall: {e}"))
        }
    }
}
#[cfg(test)]
mod environment_tests {
    use super::*;
    #[test]
    fn disabled_active_private_profile_is_not_protection() {
        assert!(!assess_profiles(2, 5, false).enforcing);
    }
    #[test]
    fn every_active_profile_must_enforce_local_rules() {
        assert!(!assess_profiles(6, 4, false).enforcing);
        assert!(!assess_profiles(2, 7, true).enforcing);
        assert!(assess_profiles(2, 7, false).enforcing);
    }
}
