#[cfg(test)]
mod tests {
    use super::*;
    use crate::protection::feeds::ThreatEndpoint;
    use std::collections::HashSet;
    use std::net::IpAddr;

    fn endpoint(ip: &str, port: u16) -> ThreatEndpoint {
        ThreatEndpoint {
            ip_address: ip.parse().unwrap(),
            port,
        }
    }

    #[test]
    fn plan_is_deterministic_and_deduplicates_endpoints() {
        let a = endpoint("8.8.8.8", 443);
        let b = endpoint("2001:4860:4860::8888", 443);
        let first = plan(&[a.clone(), b.clone(), a.clone()]).unwrap();
        let second = plan(&[b, a]).unwrap();

        assert_eq!(first, second);
        assert_eq!(first.rules.len(), 2);
        assert_eq!(first.rules[0].remote_port, 443);
        assert_eq!(first.rules[0].remote_addresses, "8.8.8.8,2001:4860:4860::8888");
        assert_eq!(first.rules[0].protocol, TransportProtocol::Tcp);
        assert_eq!(first.rules[1].protocol, TransportProtocol::Udp);
    }

    #[test]
    fn plan_never_mixes_addresses_from_different_ports() {
        let plan = plan(&[
            endpoint("8.8.8.8", 443),
            endpoint("1.1.1.1", 53),
            endpoint("2001:4860:4860::8888", 443),
        ])
        .unwrap();

        assert_eq!(plan.rules.len(), 4);
        for rule in &plan.rules {
            let addresses: HashSet<IpAddr> = rule
                .remote_addresses
                .split(',')
                .map(|value| value.parse().unwrap())
                .collect();
            if rule.remote_port == 443 {
                assert!(addresses.contains(&"8.8.8.8".parse().unwrap()));
                assert!(addresses.contains(&"2001:4860:4860::8888".parse().unwrap()));
                assert!(!addresses.contains(&"1.1.1.1".parse().unwrap()));
            } else {
                assert_eq!(rule.remote_port, 53);
                assert_eq!(addresses, HashSet::from(["1.1.1.1".parse().unwrap()]));
            }
        }
    }

    #[test]
    fn plan_enforces_explicit_limits_before_building_rules() {
        let endpoints = vec![endpoint("8.8.8.8", 443), endpoint("1.1.1.1", 53)];
        assert!(matches!(
            plan_with_limits(&endpoints, 1, MAX_RULES, MAX_ADDRESSES_PER_RULE),
            Err(EnforcementError::TooManyEndpoints { actual: 2, maximum: 1 })
        ));
    }

    #[test]
    fn update_operations_add_new_generation_before_removing_old() {
        let desired = plan(&[endpoint("8.8.8.8", 443)]).unwrap();
        let old = owned_rule(&format!(
            "{RULE_NAME_PREFIX}{}-tcp-00443-0000",
            "0".repeat(64)
        ), 443);
        let operations = update_operations(&[old], &desired).unwrap();

        assert!(matches!(operations.first(), Some(RuleOperation::Add(_))));
        assert!(matches!(operations.last(), Some(RuleOperation::Remove(name)) if name.starts_with(RULE_NAME_PREFIX) && name.ends_with("-tcp-00443-0000")));
    }

    #[test]
    fn add_failure_rolls_back_only_new_rules() {
        let old = owned_rule(&format!(
            "{RULE_NAME_PREFIX}{}-tcp-00443-0000",
            "0".repeat(64)
        ), 443);
        let mut backend = FakeBackend::new(vec![old.clone()]);
        backend.fail_add_at = Some(1);

        let result = apply_with_backend(
            &mut backend,
            &[endpoint("8.8.8.8", 443), endpoint("1.1.1.1", 53)],
        );
        assert!(matches!(result, Err(EnforcementError::ApplyFailed { .. })));
        assert_eq!(backend.owned, vec![old]);
        assert!(backend.removed.iter().all(|name| name.starts_with(RULE_NAME_PREFIX)));
    }

    #[test]
    fn remove_failure_rolls_back_new_rules_and_restores_removed_old_rules() {
        let old = owned_rule(&format!(
            "{RULE_NAME_PREFIX}{}-tcp-00443-0000",
            "0".repeat(64)
        ), 443);
        let mut backend = FakeBackend::new(vec![old.clone()]);
        backend.fail_remove_at = Some(0);

        let result = apply_with_backend(&mut backend, &[endpoint("8.8.8.8", 443)]);
        assert!(matches!(result, Err(EnforcementError::ApplyFailed { .. })));
        assert_eq!(backend.owned, vec![old]);
    }

    #[test]
    fn status_rejects_malformed_owned_namespace_instead_of_reporting_disabled() {
        let malformed = OwnedRule {
            name: format!("{RULE_NAME_PREFIX}malformed"),
            definition: RuleSpec {
                name: format!("{RULE_NAME_PREFIX}malformed"),
                group: RULE_GROUP.to_owned(),
                description: "malformed".to_owned(),
                remote_addresses: "192.0.2.1".to_owned(),
                remote_port: 443,
                protocol: TransportProtocol::Tcp,
            },
        };
        let mut backend = FakeBackend::new(vec![malformed]);

        assert!(matches!(
            status_with_backend(&mut backend),
            Err(EnforcementError::InvalidOwnedRule { .. })
        ));
    }

    #[test]
    fn status_marks_multiple_generations_as_cleanup_pending() {
        let first = owned_rule(&format!(
            "{RULE_NAME_PREFIX}{}-tcp-00443-0000",
            "0".repeat(64)
        ), 443);
        let second = owned_rule(&format!(
            "{RULE_NAME_PREFIX}{}-tcp-00053-0000",
            "1".repeat(64)
        ), 53);
        let mut backend = FakeBackend::new(vec![first, second]);

        let status = status_with_backend(&mut backend).unwrap();
        assert!(status.enabled);
        assert!(status.cleanup_pending);
        assert_eq!(status.owned_rule_count, 2);
        assert!(status.generation.is_none());
    }

    #[test]
    fn status_marks_single_generation_with_one_protocol_as_cleanup_pending() {
        let partial = owned_rule(&format!(
            "{RULE_NAME_PREFIX}{}-tcp-00443-0000",
            "0".repeat(64)
        ), 443);
        let mut backend = FakeBackend::new(vec![partial]);

        let status = status_with_backend(&mut backend).unwrap();
        assert!(status.enabled);
        assert!(status.cleanup_pending);
        assert_eq!(status.owned_rule_count, 1);
    }

    #[cfg(windows)]
    #[test]
    #[ignore = "read-only Windows firewall enumeration; run explicitly on an isolated host"]
    fn native_status_enumerates_without_mutating_firewall() {
        let status = super::status().expect("read-only firewall enumeration should succeed");
        eprintln!(
            "read-only threat rule status: enabled={}, cleanup_pending={}, owned_rule_count={}",
            status.enabled, status.cleanup_pending, status.owned_rule_count
        );
    }

    #[cfg(windows)]
    #[test]
    #[ignore = "mutates only the isolated Vapour threat-rule namespace; run through the privileged wrapper"]
    fn live_apply_disable_round_trip() {
        use std::net::{IpAddr, SocketAddr, TcpStream};
        use std::time::Duration;

        struct CleanupGuard;
        impl Drop for CleanupGuard {
            fn drop(&mut self) {
                if let Err(error) = super::disable() {
                    eprintln!("threat-rule cleanup failed: {error}");
                }
            }
        }

        fn tcp_connects(ip: &str) -> bool {
            let address = SocketAddr::new(ip.parse::<IpAddr>().unwrap(), 443);
            TcpStream::connect_timeout(&address, Duration::from_secs(3)).is_ok()
        }

        let baseline = super::list_owned().expect("baseline firewall enumeration should succeed");
        assert!(
            baseline.is_empty(),
            "isolated round trip requires no pre-existing owned threat rules"
        );
        let cleanup = CleanupGuard;
        let selected_baseline = tcp_connects("1.1.1.1");
        let control_baseline = tcp_connects("1.0.0.1");
        assert!(selected_baseline && control_baseline, "Both baseline endpoints must be reachable to verify enforcement");

        let selected = "1.1.1.1".parse().unwrap();
        let applied = super::apply(&[ThreatEndpoint {
            ip_address: selected,
            port: 443,
        }])
        .expect("isolated threat rule installation should succeed");
        assert_eq!(applied.rule_count, 2, "one TCP and one UDP rule expected");
        assert_eq!(applied.added_rule_count, 2);
        assert!(!applied.cleanup_pending);

        let status = super::status().expect("status after apply should succeed");
        assert!(status.enabled);
        assert!(!status.cleanup_pending);
        assert_eq!(status.owned_rule_count, 2);
        assert_eq!(status.generation.as_deref(), Some(applied.generation.as_str()));

        if selected_baseline && control_baseline {
            assert!(
                !tcp_connects("1.1.1.1"),
                "selected TCP endpoint remained reachable after apply"
            );
            assert!(
                tcp_connects("1.0.0.1"),
                "control TCP endpoint became unreachable after apply"
            );
        }

        let disabled = super::disable().expect("isolated threat rule disable should succeed");
        assert_eq!(disabled.remaining_owned, Vec::<String>::new());
        let status = super::status().expect("status after disable should succeed");
        assert!(!status.enabled);
        assert!(!status.cleanup_pending);
        assert_eq!(status.owned_rule_count, 0);
        if selected_baseline {
            assert!(
                tcp_connects("1.1.1.1"),
                "selected TCP endpoint was not restored after disable"
            );
        }
        drop(cleanup);
    }

    fn owned_rule(name: &str, port: u16) -> OwnedRule {
        OwnedRule {
            name: name.to_owned(),
            definition: RuleSpec {
                name: name.to_owned(),
                group: RULE_GROUP.to_owned(),
                description: "old".to_owned(),
                remote_addresses: "192.0.2.1".to_owned(),
                remote_port: port,
                protocol: TransportProtocol::Tcp,
            },
        }
    }

    struct FakeBackend {
        owned: Vec<OwnedRule>,
        added: Vec<String>,
        removed: Vec<String>,
        fail_add_at: Option<usize>,
        fail_remove_at: Option<usize>,
        remove_attempts: usize,
    }

    impl FakeBackend {
        fn new(owned: Vec<OwnedRule>) -> Self {
            Self {
                owned,
                added: Vec::new(),
                removed: Vec::new(),
                fail_add_at: None,
                fail_remove_at: None,
                remove_attempts: 0,
            }
        }
    }

    impl FirewallBackend for FakeBackend {
        fn list_owned(&mut self) -> Result<Vec<OwnedRule>, EnforcementError> {
            Ok(self.owned.clone())
        }

        fn add(&mut self, rule: &RuleSpec) -> Result<(), EnforcementError> {
            let index = self.added.len();
            if self.fail_add_at == Some(index) {
                return Err(EnforcementError::Backend("add failed".to_owned()));
            }
            self.added.push(rule.name.clone());
            self.owned.push(OwnedRule {
                name: rule.name.clone(),
                definition: rule.clone(),
            });
            Ok(())
        }

        fn remove(&mut self, name: &str) -> Result<(), EnforcementError> {
            let index = self.remove_attempts;
            self.remove_attempts += 1;
            if self.fail_remove_at == Some(index) {
                return Err(EnforcementError::Backend("remove failed".to_owned()));
            }
            self.removed.push(name.to_owned());
            self.owned.retain(|rule| rule.name != name);
            Ok(())
        }
    }
}
use super::feeds::ThreatEndpoint;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::net::IpAddr;

/// Prefix used by every rule created by this module. It is intentionally
/// separate from the application-block namespace in `crate::firewall`.
pub const RULE_NAME_PREFIX: &str = "Vapour-ThreatFeed-v1-";
/// Group marker used together with [`RULE_NAME_PREFIX`] to prove ownership.
pub const RULE_GROUP: &str = "Vapour Threat Feed";

/// Hard upper bounds for a single feed replacement. The feed parser has a
/// larger entry budget, so enforcement can fail closed before making a large
/// number of COM calls.
pub const MAX_ENDPOINTS: usize = 100_000;
pub const MAX_RULES: usize = 4_096;
pub const MAX_ADDRESSES_PER_RULE: usize = 128;
const MAX_REMOTE_ADDRESSES_BYTES: usize = 8 * 1024;
const MAX_FIREWALL_RULES_TO_ENUMERATE: usize = 100_000;
const MAX_RULE_NAME_BYTES: usize = 255;
const MAX_GROUP_BYTES: usize = 128;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum TransportProtocol {
    Tcp,
    Udp,
}

impl TransportProtocol {
    fn name(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
        }
    }

    #[cfg(windows)]
    fn number(self) -> i32 {
        match self {
            Self::Tcp => 6,
            Self::Udp => 17,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct RuleSpec {
    pub name: String,
    pub group: String,
    pub description: String,
    /// Comma-separated addresses. Every address in a spec has `remote_port`.
    pub remote_addresses: String,
    pub remote_port: u16,
    pub protocol: TransportProtocol,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct OwnedRule {
    pub name: String,
    pub definition: RuleSpec,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct EnforcementPlan {
    pub generation: String,
    pub rules: Vec<RuleSpec>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub enum RuleOperation {
    Add(RuleSpec),
    Remove(String),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ApplyResult {
    pub generation: String,
    pub rule_count: usize,
    pub added_rule_count: usize,
    pub removed_rule_count: usize,
    pub cleanup_pending: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct DisableResult {
    pub removed_rule_count: usize,
    pub remaining_owned: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct EnforcementStatus {
    pub enabled: bool,
    pub cleanup_pending: bool,
    pub owned_rule_count: usize,
    pub generation: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub enum EnforcementError {
    UnsupportedPlatform,
    InvalidEndpoint { ip: String, port: u16 },
    TooManyEndpoints { actual: usize, maximum: usize },
    TooManyRules { actual: usize, maximum: usize },
    TooManyFirewallRules { actual: usize, maximum: usize },
    InvalidOwnedRule { name: String, reason: String },
    Backend(String),
    ApplyFailed {
        operation: String,
        source: String,
        rollback_failures: Vec<String>,
        remaining_owned: Vec<String>,
    },
    CleanupIncomplete {
        remaining: Vec<String>,
        source: String,
    },
}

impl fmt::Display for EnforcementError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedPlatform => write!(f, "threat enforcement is supported on Windows only"),
            Self::InvalidEndpoint { ip, port } => {
                write!(f, "invalid threat endpoint {ip}:{port}")
            }
            Self::TooManyEndpoints { actual, maximum } => {
                write!(f, "feed has {actual} endpoints; maximum is {maximum}")
            }
            Self::TooManyRules { actual, maximum } => {
                write!(f, "feed needs {actual} firewall rules; maximum is {maximum}")
            }
            Self::TooManyFirewallRules { actual, maximum } => {
                write!(f, "Windows returned {actual} firewall rules; maximum is {maximum}")
            }
            Self::InvalidOwnedRule { name, reason } => {
                write!(f, "owned firewall rule {name:?} is invalid: {reason}")
            }
            Self::Backend(error) => write!(f, "firewall backend failed: {error}"),
            Self::ApplyFailed {
                operation,
                source,
                rollback_failures,
                remaining_owned,
            } => write!(
                f,
                "threat rule {operation} failed ({source}); rollback failures: {}; remaining owned rules: {}",
                rollback_failures.len(),
                remaining_owned.len()
            ),
            Self::CleanupIncomplete { remaining, source } => write!(
                f,
                "firewall cleanup failed ({source}); {} owned rules remain",
                remaining.len()
            ),
        }
    }
}

impl std::error::Error for EnforcementError {}

/// Build a deterministic, bounded set of outbound TCP and UDP rules.
pub fn plan(endpoints: &[ThreatEndpoint]) -> Result<EnforcementPlan, EnforcementError> {
    plan_with_limits(
        endpoints,
        MAX_ENDPOINTS,
        MAX_RULES,
        MAX_ADDRESSES_PER_RULE,
    )
}

fn plan_with_limits(
    endpoints: &[ThreatEndpoint],
    maximum_endpoints: usize,
    maximum_rules: usize,
    maximum_addresses_per_rule: usize,
) -> Result<EnforcementPlan, EnforcementError> {
    if endpoints.len() > maximum_endpoints {
        return Err(EnforcementError::TooManyEndpoints {
            actual: endpoints.len(),
            maximum: maximum_endpoints,
        });
    }
    if maximum_addresses_per_rule == 0 {
        return Err(EnforcementError::TooManyRules {
            actual: 1,
            maximum: maximum_rules,
        });
    }

    let mut normalized = endpoints.to_vec();
    for endpoint in &normalized {
        if endpoint.port == 0
            || endpoint.ip_address.is_unspecified()
            || endpoint.ip_address.is_multicast()
        {
            return Err(EnforcementError::InvalidEndpoint {
                ip: endpoint.ip_address.to_string(),
                port: endpoint.port,
            });
        }
    }
    normalized.sort_unstable();
    normalized.dedup();

    let generation = generation_for(&normalized);
    let mut by_port: BTreeMap<u16, Vec<IpAddr>> = BTreeMap::new();
    for endpoint in normalized {
        by_port
            .entry(endpoint.port)
            .or_default()
            .push(endpoint.ip_address);
    }

    let mut rules = Vec::new();
    for (port, addresses) in by_port {
        let chunks = address_chunks(&addresses, maximum_addresses_per_rule);
        for protocol in [TransportProtocol::Tcp, TransportProtocol::Udp] {
            for (chunk_index, chunk) in chunks.iter().enumerate() {
                let remote_addresses = chunk.join(",");
                let actual = rules.len().checked_add(1).ok_or(
                    EnforcementError::TooManyRules {
                        actual: usize::MAX,
                        maximum: maximum_rules,
                    },
                )?;
                if actual > maximum_rules {
                    return Err(EnforcementError::TooManyRules {
                        actual,
                        maximum: maximum_rules,
                    });
                }
                rules.push(RuleSpec {
                    name: rule_name(&generation, protocol, port, chunk_index),
                    group: RULE_GROUP.to_owned(),
                    description: format!(
                        "Vapour threat feed {generation} {} port {port}",
                        protocol.name()
                    ),
                    remote_addresses,
                    remote_port: port,
                    protocol,
                });
            }
        }
    }

    Ok(EnforcementPlan { generation, rules })
}

fn address_chunks(addresses: &[IpAddr], maximum_addresses_per_rule: usize) -> Vec<Vec<String>> {
    let mut chunks: Vec<Vec<String>> = Vec::new();
    let mut current = Vec::new();
    let mut current_bytes = 0usize;
    for address in addresses {
        let rendered = address.to_string();
        let separator = usize::from(!current.is_empty());
        let next_bytes = current_bytes
            .checked_add(separator)
            .and_then(|value| value.checked_add(rendered.len()));
        let must_flush = current.len() >= maximum_addresses_per_rule
            || next_bytes.is_none_or(|value| value > MAX_REMOTE_ADDRESSES_BYTES);
        if must_flush && !current.is_empty() {
            chunks.push(current);
            current = Vec::new();
            current_bytes = 0;
        }
        current_bytes = current_bytes
            .checked_add(usize::from(!current.is_empty()))
            .and_then(|value| value.checked_add(rendered.len()))
            .unwrap_or(MAX_REMOTE_ADDRESSES_BYTES + 1);
        current.push(rendered);
    }
    if !current.is_empty() {
        chunks.push(current);
    }
    chunks
}

fn generation_for(endpoints: &[ThreatEndpoint]) -> String {
    let mut canonical = String::new();
    for endpoint in endpoints {
        canonical.push_str(&endpoint.ip_address.to_string());
        canonical.push(':');
        canonical.push_str(&endpoint.port.to_string());
        canonical.push('\n');
    }
    format!("{:x}", Sha256::digest(canonical.as_bytes()))
}

fn rule_name(generation: &str, protocol: TransportProtocol, port: u16, chunk: usize) -> String {
    format!(
        "{RULE_NAME_PREFIX}{generation}-{}-{port:05}-{chunk:04}",
        protocol.name()
    )
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct OwnedIdentity {
    generation: String,
    protocol: TransportProtocol,
    port: u16,
    chunk: usize,
}

fn parse_owned_name(name: &str) -> Option<OwnedIdentity> {
    let rest = name.strip_prefix(RULE_NAME_PREFIX)?;
    let mut fields = rest.split('-');
    let generation = fields.next()?;
    if generation.len() != 64 || !generation.bytes().all(|value| value.is_ascii_hexdigit()) {
        return None;
    }
    let protocol = match fields.next()? {
        "tcp" => TransportProtocol::Tcp,
        "udp" => TransportProtocol::Udp,
        _ => return None,
    };
    let port_value = fields.next()?;
    if port_value.len() != 5 || !port_value.bytes().all(|value| value.is_ascii_digit()) {
        return None;
    }
    let port = port_value.parse::<u16>().ok()?.filter_nonzero()?;
    let chunk_value = fields.next()?;
    if chunk_value.len() != 4 || !chunk_value.bytes().all(|value| value.is_ascii_digit()) {
        return None;
    }
    let chunk = chunk_value.parse::<usize>().ok()?;
    if fields.next().is_some() {
        return None;
    }
    Some(OwnedIdentity {
        generation: generation.to_ascii_lowercase(),
        protocol,
        port,
        chunk,
    })
}

trait NonZeroPort {
    fn filter_nonzero(self) -> Option<Self>
    where
        Self: Sized;
}

impl NonZeroPort for u16 {
    fn filter_nonzero(self) -> Option<Self> {
        (self != 0).then_some(self)
    }
}

fn is_owned_rule(rule: &OwnedRule) -> bool {
    rule.name == rule.definition.name
        && rule.definition.group == RULE_GROUP
        && rule.name.len() <= MAX_RULE_NAME_BYTES
        && parse_owned_name(&rule.name).is_some()
}

fn owned_rules_only(rules: Vec<OwnedRule>) -> Vec<OwnedRule> {
    let mut by_name = BTreeMap::new();
    for rule in rules {
        if is_owned_rule(&rule) {
            by_name.entry(rule.name.clone()).or_insert(rule);
        }
    }
    by_name.into_values().collect()
}

fn validate_owned_rules(rules: Vec<OwnedRule>) -> Result<Vec<OwnedRule>, EnforcementError> {
    for rule in &rules {
        if rule.name.starts_with(RULE_NAME_PREFIX) && rule.definition.group == RULE_GROUP {
            let identity = parse_owned_name(&rule.name);
            if !is_owned_rule(rule) {
                return Err(EnforcementError::InvalidOwnedRule {
                    name: rule.name.clone(),
                    reason: "owned prefix/group pair has an invalid deterministic name".to_owned(),
                });
            }
            if let Some(identity) = identity {
                if rule.definition.remote_port != identity.port
                    || rule.definition.protocol != identity.protocol
                {
                    return Err(EnforcementError::InvalidOwnedRule {
                        name: rule.name.clone(),
                        reason: "rule selectors do not match its deterministic name".to_owned(),
                    });
                }
            }
        }
    }
    Ok(owned_rules_only(rules))
}

fn desired_names(plan: &EnforcementPlan) -> BTreeSet<String> {
    plan.rules.iter().map(|rule| rule.name.clone()).collect()
}

fn update_operations(
    existing: &[OwnedRule],
    desired: &EnforcementPlan,
) -> Result<Vec<RuleOperation>, EnforcementError> {
    let existing = validate_owned_rules(existing.to_vec())?;
    let existing_names: BTreeSet<String> = existing.iter().map(|rule| rule.name.clone()).collect();
    let desired_names = desired_names(desired);
    let mut operations = Vec::new();
    for rule in &desired.rules {
        if !existing_names.contains(&rule.name) {
            operations.push(RuleOperation::Add(rule.clone()));
        }
    }
    for rule in existing {
        if !desired_names.contains(&rule.name) {
            operations.push(RuleOperation::Remove(rule.name));
        }
    }
    Ok(operations)
}

trait FirewallBackend {
    fn list_owned(&mut self) -> Result<Vec<OwnedRule>, EnforcementError>;
    fn add(&mut self, rule: &RuleSpec) -> Result<(), EnforcementError>;
    fn remove(&mut self, name: &str) -> Result<(), EnforcementError>;
}

fn apply_with_backend<B: FirewallBackend>(
    backend: &mut B,
    endpoints: &[ThreatEndpoint],
) -> Result<ApplyResult, EnforcementError> {
    let desired = plan(endpoints)?;
    let existing = validate_owned_rules(backend.list_owned()?)?;
    let operations = update_operations(&existing, &desired)?;
    let desired_names = desired_names(&desired);
    let mut added = Vec::new();

    for operation in &operations {
        let RuleOperation::Add(rule) = operation else {
            continue;
        };
        if let Err(error) = backend.add(rule) {
            let rollback_failures = rollback_added(backend, &added);
            return Err(apply_failed(
                backend,
                "add",
                error,
                rollback_failures,
            ));
        }
        added.push(rule.clone());
    }

    if let Err(error) = verify_desired(backend, &desired_names) {
        let rollback_failures = rollback_added(backend, &added);
        return Err(apply_failed(
            backend,
            "verify additions",
            error,
            rollback_failures,
        ));
    }

    let mut removed = Vec::new();
    for operation in &operations {
        let RuleOperation::Remove(name) = operation else {
            continue;
        };
        let Some(previous) = existing.iter().find(|rule| &rule.name == name) else {
            continue;
        };
        if let Err(error) = backend.remove(name) {
            let mut rollback_failures = rollback_added(backend, &added);
            rollback_failures.extend(restore_removed(backend, &removed));
            return Err(apply_failed(
                backend,
                "remove old generation",
                error,
                rollback_failures,
            ));
        }
        removed.push(previous.clone());
    }

    if let Err(error) = verify_replacement(backend, &desired_names, &removed) {
        let mut rollback_failures = rollback_added(backend, &added);
        rollback_failures.extend(restore_removed(backend, &removed));
        return Err(apply_failed(
            backend,
            "verify replacement",
            error,
            rollback_failures,
        ));
    }

    Ok(ApplyResult {
        generation: desired.generation,
        rule_count: desired.rules.len(),
        added_rule_count: added.len(),
        removed_rule_count: removed.len(),
        cleanup_pending: false,
    })
}

fn verify_desired<B: FirewallBackend>(
    backend: &mut B,
    desired_names: &BTreeSet<String>,
) -> Result<(), EnforcementError> {
    let installed = validate_owned_rules(backend.list_owned()?)?;
    let installed_names: BTreeSet<String> = installed.into_iter().map(|rule| rule.name).collect();
    if desired_names.is_subset(&installed_names) {
        Ok(())
    } else {
        Err(EnforcementError::Backend(
            "Windows did not confirm every desired threat rule".to_owned(),
        ))
    }
}

fn verify_replacement<B: FirewallBackend>(
    backend: &mut B,
    desired_names: &BTreeSet<String>,
    removed: &[OwnedRule],
) -> Result<(), EnforcementError> {
    let installed = validate_owned_rules(backend.list_owned()?)?;
    let installed_names: BTreeSet<String> = installed.iter().map(|rule| rule.name.clone()).collect();
    if !desired_names.is_subset(&installed_names) {
        return Err(EnforcementError::Backend(
            "Windows did not confirm every desired threat rule".to_owned(),
        ));
    }
    if removed.iter().any(|rule| installed_names.contains(&rule.name)) {
        return Err(EnforcementError::Backend(
            "Windows did not remove every previous threat rule".to_owned(),
        ));
    }
    Ok(())
}

fn rollback_added<B: FirewallBackend>(backend: &mut B, added: &[RuleSpec]) -> Vec<String> {
    added
        .iter()
        .rev()
        .filter_map(|rule| {
            backend
                .remove(&rule.name)
                .err()
                .map(|error| format!("remove {}: {error}", rule.name))
        })
        .collect()
}

fn restore_removed<B: FirewallBackend>(backend: &mut B, removed: &[OwnedRule]) -> Vec<String> {
    removed
        .iter()
        .rev()
        .filter_map(|rule| {
            backend
                .add(&rule.definition)
                .err()
                .map(|error| format!("restore {}: {error}", rule.name))
        })
        .collect()
}

fn apply_failed<B: FirewallBackend>(
    backend: &mut B,
    operation: &str,
    source: EnforcementError,
    rollback_failures: Vec<String>,
) -> EnforcementError {
    let remaining_owned = backend
        .list_owned()
        .map(owned_rules_only)
        .map(|rules| rules.into_iter().map(|rule| rule.name).collect())
        .unwrap_or_default();
    EnforcementError::ApplyFailed {
        operation: operation.to_owned(),
        source: source.to_string(),
        rollback_failures,
        remaining_owned,
    }
}

fn disable_with_backend<B: FirewallBackend>(
    backend: &mut B,
) -> Result<DisableResult, EnforcementError> {
    let existing = validate_owned_rules(backend.list_owned()?)?;
    let mut removed_rule_count = 0usize;
    for rule in existing {
        if let Err(error) = backend.remove(&rule.name) {
            return Err(cleanup_incomplete(backend, error));
        }
        removed_rule_count = removed_rule_count.saturating_add(1);
    }
    let remaining_owned = owned_rule_names(backend.list_owned()?);
    if !remaining_owned.is_empty() {
        return Err(EnforcementError::CleanupIncomplete {
            remaining: remaining_owned,
            source: "Windows still reports owned threat rules after disable".to_owned(),
        });
    }
    Ok(DisableResult {
        removed_rule_count,
        remaining_owned: Vec::new(),
    })
}

fn cleanup_incomplete<B: FirewallBackend>(
    backend: &mut B,
    source: EnforcementError,
) -> EnforcementError {
    EnforcementError::CleanupIncomplete {
        remaining: backend
            .list_owned()
            .map(owned_rule_names)
            .unwrap_or_default(),
        source: source.to_string(),
    }
}

fn owned_rule_names(rules: Vec<OwnedRule>) -> Vec<String> {
    owned_rules_only(rules)
        .into_iter()
        .map(|rule| rule.name)
        .collect()
}

fn status_with_backend<B: FirewallBackend>(
    backend: &mut B,
) -> Result<EnforcementStatus, EnforcementError> {
    let owned = validate_owned_rules(backend.list_owned()?)?;
    let generations: BTreeSet<String> = owned
        .iter()
        .filter_map(|rule| parse_owned_name(&rule.name).map(|identity| identity.generation))
        .collect();
    Ok(EnforcementStatus {
        enabled: !owned.is_empty(),
        cleanup_pending: generations.len() > 1 || has_partial_generation(&owned),
        owned_rule_count: owned.len(),
        generation: (generations.len() == 1).then(|| generations.into_iter().next().unwrap()),
    })
}

fn has_partial_generation(rules: &[OwnedRule]) -> bool {
    let mut by_generation: BTreeMap<
        String,
        BTreeMap<u16, (BTreeSet<usize>, BTreeSet<usize>)>,
    > = BTreeMap::new();
    for rule in rules {
        let Some(identity) = parse_owned_name(&rule.name) else {
            return true;
        };
        let ports = by_generation
            .entry(identity.generation)
            .or_default();
        let (tcp, udp) = ports.entry(identity.port).or_default();
        match identity.protocol {
            TransportProtocol::Tcp => {
                tcp.insert(identity.chunk);
            }
            TransportProtocol::Udp => {
                udp.insert(identity.chunk);
            }
        }
    }
    by_generation.values().any(|ports| {
        ports.values().any(|(tcp, udp)| {
            tcp.is_empty()
                || tcp != udp
                || !is_contiguous(tcp)
                || !is_contiguous(udp)
        })
    })
}

fn is_contiguous(chunks: &BTreeSet<usize>) -> bool {
    let Some(last) = chunks.iter().next_back().copied() else {
        return false;
    };
    chunks.len() == last.saturating_add(1) && (0..=last).all(|chunk| chunks.contains(&chunk))
}

#[cfg(windows)]
mod windows_backend {
    use super::*;
    use windows::core::{BSTR, IUnknown, Interface, VARIANT};
    use windows::Win32::Foundation::VARIANT_BOOL;
    use windows::Win32::NetworkManagement::WindowsFirewall::{
        INetFwPolicy2, INetFwRule, INetFwRules, NET_FW_ACTION_BLOCK, NET_FW_PROFILE2_ALL,
        NET_FW_RULE_DIR_OUT, NetFwPolicy2, NetFwRule,
    };
    use windows::Win32::System::Com::{
        CoCreateInstance, CoInitializeEx, CoUninitialize, CLSCTX_INPROC_SERVER,
        COINIT_MULTITHREADED,
    };

    #[repr(transparent)]
    #[derive(Clone)]
    struct IEnumVariant(IUnknown);

    unsafe impl Interface for IEnumVariant {
        type Vtable = IEnumVariant_Vtbl;
        const IID: windows::core::GUID =
            windows::core::GUID::from_u128(0x00020404_0000_0000_c000_000000000046);
    }

    impl std::ops::Deref for IEnumVariant {
        type Target = IUnknown;

        fn deref(&self) -> &Self::Target {
            &self.0
        }
    }

    #[repr(C)]
    pub struct IEnumVariant_Vtbl {
        pub base__: windows::core::IUnknown_Vtbl,
        pub next: unsafe extern "system" fn(
            *mut core::ffi::c_void,
            u32,
            *mut VARIANT,
            *mut u32,
        ) -> windows::core::HRESULT,
        pub skip: usize,
        pub reset: usize,
        pub clone_: usize,
    }

    impl IEnumVariant {
        unsafe fn next(&self, values: &mut [VARIANT], fetched: &mut u32) -> windows::core::Result<()> {
            let count = values.len().try_into().map_err(|_| {
                windows::core::Error::new(
                    windows::core::HRESULT(0x80070057u32 as i32),
                    "too many COM variants requested",
                )
            })?;
            (windows::core::Interface::vtable(self).next)(
                windows::core::Interface::as_raw(self),
                count,
                values.as_mut_ptr(),
                fetched,
            )
            .ok()
        }
    }

    pub fn apply(endpoints: &[ThreatEndpoint]) -> Result<ApplyResult, EnforcementError> {
        with_com(|backend| super::apply_with_backend(backend, endpoints))
    }

    pub fn disable() -> Result<DisableResult, EnforcementError> {
        with_com(super::disable_with_backend)
    }

    pub fn list_owned() -> Result<Vec<OwnedRule>, EnforcementError> {
        with_com(|backend| backend.list_owned())
    }

    pub fn status() -> Result<EnforcementStatus, EnforcementError> {
        with_com(super::status_with_backend)
    }

    struct ComFirewallBackend {
        rules: INetFwRules,
    }

    impl ComFirewallBackend {
        fn connect() -> Result<Self, EnforcementError> {
            let policy: INetFwPolicy2 = unsafe {
                CoCreateInstance(&NetFwPolicy2, None, CLSCTX_INPROC_SERVER)
            }
            .map_err(com_error)?;
            let rules = unsafe { policy.Rules() }.map_err(com_error)?;
            Ok(Self { rules })
        }
    }

    impl FirewallBackend for ComFirewallBackend {
        fn list_owned(&mut self) -> Result<Vec<OwnedRule>, EnforcementError> {
            let count = unsafe { self.rules.Count() }.map_err(com_error)?;
            let count = usize::try_from(count).map_err(|_| {
                EnforcementError::Backend("Windows returned a negative firewall rule count".to_owned())
            })?;
            if count > MAX_FIREWALL_RULES_TO_ENUMERATE {
                return Err(EnforcementError::TooManyFirewallRules {
                    actual: count,
                    maximum: MAX_FIREWALL_RULES_TO_ENUMERATE,
                });
            }
            let unknown = unsafe { self.rules._NewEnum() }.map_err(com_error)?;
            let enumerator: IEnumVariant = unknown.cast().map_err(com_error)?;
            let mut owned = Vec::new();
            for _ in 0..count {
                let mut values = [VARIANT::new()];
                let mut fetched = 0u32;
                unsafe { enumerator.next(&mut values, &mut fetched) }.map_err(com_error)?;
                if fetched == 0 {
                    break;
                }
                if let Some(rule) = unsafe { rule_from_variant(&values[0]) }.map_err(com_error)? {
                    if let Some(owned_rule) = owned_rule_from_com(&rule)? {
                        owned.push(owned_rule);
                        if owned.len() > MAX_RULES {
                            return Err(EnforcementError::TooManyRules {
                                actual: owned.len(),
                                maximum: MAX_RULES,
                            });
                        }
                    }
                }
            }
            Ok(owned_rules_only(owned))
        }

        fn add(&mut self, definition: &RuleSpec) -> Result<(), EnforcementError> {
            let rule: INetFwRule = unsafe {
                CoCreateInstance(&NetFwRule, None, CLSCTX_INPROC_SERVER)
            }
            .map_err(com_error)?;
            let name = BSTR::from(definition.name.as_str());
            let group = BSTR::from(definition.group.as_str());
            let description = BSTR::from(definition.description.as_str());
            let addresses = BSTR::from(definition.remote_addresses.as_str());
            let port = BSTR::from(definition.remote_port.to_string().as_str());
            unsafe {
                rule.SetName(&name)
                    .map_err(|error| com_property_error("INetFwRule.SetName", error))?;
                rule.SetGrouping(&group)
                    .map_err(|error| com_property_error("INetFwRule.SetGrouping", error))?;
                rule.SetDescription(&description)
                    .map_err(|error| com_property_error("INetFwRule.SetDescription", error))?;
                rule.SetRemoteAddresses(&addresses).map_err(|error| {
                    com_property_error("INetFwRule.SetRemoteAddresses", error)
                })?;
                // Windows requires TCP/UDP before a port restriction can be set.
                rule.SetProtocol(definition.protocol.number())
                    .map_err(|error| com_property_error("INetFwRule.SetProtocol", error))?;
                rule.SetRemotePorts(&port)
                    .map_err(|error| com_property_error("INetFwRule.SetRemotePorts", error))?;
                rule.SetDirection(NET_FW_RULE_DIR_OUT)
                    .map_err(|error| com_property_error("INetFwRule.SetDirection", error))?;
                rule.SetAction(NET_FW_ACTION_BLOCK)
                    .map_err(|error| com_property_error("INetFwRule.SetAction", error))?;
                rule.SetProfiles(NET_FW_PROFILE2_ALL.0)
                    .map_err(|error| com_property_error("INetFwRule.SetProfiles", error))?;
                rule.SetEnabled(VARIANT_BOOL(-1))
                    .map_err(|error| com_property_error("INetFwRule.SetEnabled", error))?;
                self.rules
                    .Add(&rule)
                    .map_err(|error| com_property_error("INetFwRules.Add", error))?;
            }
            Ok(())
        }

        fn remove(&mut self, name: &str) -> Result<(), EnforcementError> {
            if parse_owned_name(name).is_none() {
                return Err(EnforcementError::InvalidOwnedRule {
                    name: name.to_owned(),
                    reason: "name is outside the owned namespace".to_owned(),
                });
            }
            let name = BSTR::from(name);
            let rule = unsafe { self.rules.Item(&name) }.map_err(com_error)?;
            let group = unsafe { rule.Grouping() }.map_err(com_error)?.to_string();
            if group != RULE_GROUP {
                return Err(EnforcementError::InvalidOwnedRule {
                    name: name.to_string(),
                    reason: "rule group no longer proves Vapour ownership".to_owned(),
                });
            }
            unsafe { self.rules.Remove(&name) }.map_err(com_error)
        }
    }

    unsafe fn rule_from_variant(variant: &VARIANT) -> windows::core::Result<Option<INetFwRule>> {
        let raw = variant.as_raw();
        let variant_type = raw.Anonymous.Anonymous.vt;
        if variant_type != 3 && variant_type != 9 {
            return Ok(None);
        }
        let pointer = raw.Anonymous.Anonymous.Anonymous.pdispVal;
        if pointer.is_null() {
            return Ok(None);
        }
        let unknown = IUnknown::from_raw_borrowed(&pointer).ok_or_else(|| {
            windows::core::Error::new(
                windows::core::HRESULT(0x80004003u32 as i32),
                "firewall enumerator returned a null rule",
            )
        })?;
        unknown.cast::<INetFwRule>().map(Some)
    }

    fn owned_rule_from_com(rule: &INetFwRule) -> Result<Option<OwnedRule>, EnforcementError> {
        let name = unsafe { rule.Name() }.map_err(com_error)?.to_string();
        if name.len() > MAX_RULE_NAME_BYTES {
            return Ok(None);
        }
        let group = unsafe { rule.Grouping() }.map_err(com_error)?.to_string();
        if group.len() > MAX_GROUP_BYTES || group != RULE_GROUP {
            return Ok(None);
        }
        let Some(identity) = parse_owned_name(&name) else {
            if name.starts_with(RULE_NAME_PREFIX) {
                return Err(EnforcementError::InvalidOwnedRule {
                    name,
                    reason: "owned prefix/group pair has an invalid deterministic name".to_owned(),
                });
            }
            return Ok(None);
        };
        let remote_addresses = unsafe { rule.RemoteAddresses() }
            .map_err(com_error)?
            .to_string();
        if remote_addresses.len() > MAX_REMOTE_ADDRESSES_BYTES {
            return Err(EnforcementError::InvalidOwnedRule {
                name,
                reason: "remote address list exceeds the bounded restore size".to_owned(),
            });
        }
        let description = unsafe { rule.Description() }
            .map_err(com_error)?
            .to_string();
        Ok(Some(OwnedRule {
            name: name.clone(),
            definition: RuleSpec {
                name,
                group,
                description,
                remote_addresses,
                remote_port: identity.port,
                protocol: identity.protocol,
            },
        }))
    }

    fn com_error(error: windows::core::Error) -> EnforcementError {
        EnforcementError::Backend(error.to_string())
    }

    fn com_property_error(
        property: &'static str,
        error: windows::core::Error,
    ) -> EnforcementError {
        EnforcementError::Backend(format!("{property}: {error}"))
    }

    fn with_com<T>(operation: impl FnOnce(&mut ComFirewallBackend) -> Result<T, EnforcementError>) -> Result<T, EnforcementError> {
        unsafe {
            let initialized = CoInitializeEx(None, COINIT_MULTITHREADED);
            if initialized.is_err() && initialized.0 != 0x80010106u32 as i32 {
                return Err(EnforcementError::Backend(format!(
                    "COM initialization failed: {initialized:?}"
                )));
            }
            let result = (|| {
                let mut backend = ComFirewallBackend::connect()?;
                operation(&mut backend)
            })();
            if initialized.is_ok() {
                CoUninitialize();
            }
            result
        }
    }
}

#[cfg(windows)]
pub fn apply(endpoints: &[ThreatEndpoint]) -> Result<ApplyResult, EnforcementError> {
    windows_backend::apply(endpoints)
}

#[cfg(not(windows))]
pub fn apply(_endpoints: &[ThreatEndpoint]) -> Result<ApplyResult, EnforcementError> {
    Err(EnforcementError::UnsupportedPlatform)
}

#[cfg(windows)]
pub fn disable() -> Result<DisableResult, EnforcementError> {
    windows_backend::disable()
}

#[cfg(not(windows))]
pub fn disable() -> Result<DisableResult, EnforcementError> {
    Err(EnforcementError::UnsupportedPlatform)
}

#[cfg(windows)]
pub fn list_owned() -> Result<Vec<OwnedRule>, EnforcementError> {
    windows_backend::list_owned()
}

#[cfg(not(windows))]
pub fn list_owned() -> Result<Vec<OwnedRule>, EnforcementError> {
    Err(EnforcementError::UnsupportedPlatform)
}

#[cfg(windows)]
pub fn status() -> Result<EnforcementStatus, EnforcementError> {
    windows_backend::status()
}

#[cfg(not(windows))]
pub fn status() -> Result<EnforcementStatus, EnforcementError> {
    Err(EnforcementError::UnsupportedPlatform)
}
