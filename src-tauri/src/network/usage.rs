use ferrisetw::parser::Parser;
use ferrisetw::provider::{
    kernel_providers::{KernelProvider, TCP_IP_PROVIDER},
    Provider,
};
use ferrisetw::trace::KernelTrace;
use ferrisetw::{EventRecord, SchemaLocator};
use parking_lot::Mutex;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

#[derive(Clone, Default, Debug)]
pub struct Usage {
    pub down: u64,
    pub up: u64,
    pub received: u64,
    pub sent: u64,
}
fn direction(opcode: u8) -> Option<bool> {
    match opcode {
        10 | 26 => Some(true),
        11 | 27 => Some(false),
        _ => None,
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn counts_only_ipv4_ipv6_send_receive_not_retransmits() {
        assert_eq!(direction(10), Some(true));
        assert_eq!(direction(26), Some(true));
        assert_eq!(direction(11), Some(false));
        assert_eq!(direction(27), Some(false));
        for opcode in [12, 13, 14, 18, 28, 29, 30] {
            assert_eq!(direction(opcode), None);
        }
    }
}

struct Counter {
    received: u64,
    sent: u64,
    previous_received: u64,
    previous_sent: u64,
    seen: Instant,
}
pub struct UsageCollector {
    counters: Arc<Mutex<HashMap<u32, Counter>>>,
    sampled: Mutex<Instant>,
    trace: Mutex<Option<KernelTrace>>,
    pub status: String,
}
impl UsageCollector {
    pub fn new() -> Self {
        let counters = Arc::new(Mutex::new(HashMap::<u32, Counter>::new()));
        let callback = |counters: Arc<Mutex<HashMap<u32, Counter>>>| {
            move |record: &EventRecord, locator: &SchemaLocator| {
                let Some(send) = direction(record.opcode()) else {
                    return;
                };
                let Ok(schema) = locator.event_schema(record) else {
                    return;
                };
                let parser = Parser::create(record, &schema);
                // Header PID may be a system worker. The event payload owns attribution.
                let (Ok(pid), Ok(size)) = (
                    parser.try_parse::<u32>("PID"),
                    parser.try_parse::<u32>("size"),
                ) else {
                    return;
                };
                if pid == 0 {
                    return;
                }
                let mut map = counters.lock();
                if map.len() >= 8192 && !map.contains_key(&pid) {
                    return;
                }
                let value = map.entry(pid).or_insert(Counter {
                    received: 0,
                    sent: 0,
                    previous_received: 0,
                    previous_sent: 0,
                    seen: Instant::now(),
                });
                if send {
                    value.sent = value.sent.saturating_add(size as u64);
                } else {
                    value.received = value.received.saturating_add(size as u64);
                }
                value.seen = Instant::now();
            }
        };
        let tcp = Provider::kernel(&TCP_IP_PROVIDER)
            .add_callback(callback(Arc::clone(&counters)))
            .build();
        let udp_id = Provider::by_guid("bf3a50c5-a9c9-4988-a005-2df0b7c80f80")
            .build()
            .guid();
        let udp = Provider::kernel(&KernelProvider::new(udp_id, TCP_IP_PROVIDER.flags))
            .add_callback(callback(Arc::clone(&counters)))
            .build();
        let (trace, status) = if !crate::firewall::FirewallManager::is_elevated() {
            (None, "administrator_required".into())
        } else {
            super::trace_cleanup::cleanup_orphans();
            match KernelTrace::new()
                .named(format!("Vapour-Network-{}", std::process::id()))
                .enable(tcp)
                .enable(udp)
                .start_and_process()
            {
                Ok(trace) => (Some(trace), "measured".into()),
                Err(error) => {
                    log::warn!("Network trace unavailable: {:?}", error);
                    (None, "unavailable".into())
                }
            }
        };
        Self {
            counters,
            sampled: Mutex::new(Instant::now()),
            trace: Mutex::new(trace),
            status,
        }
    }
    pub fn sample(&self) -> HashMap<u32, Usage> {
        let now = Instant::now();
        let mut sampled = self.sampled.lock();
        let elapsed = now.duration_since(*sampled).as_secs_f64().max(0.001);
        *sampled = now;
        let mut map = self.counters.lock();
        map.retain(|_, v| now.duration_since(v.seen).as_secs() < 60);
        map.iter_mut()
            .map(|(&pid, v)| {
                let usage = Usage {
                    down: ((v.received - v.previous_received) as f64 / elapsed) as u64,
                    up: ((v.sent - v.previous_sent) as f64 / elapsed) as u64,
                    received: v.received,
                    sent: v.sent,
                };
                v.previous_received = v.received;
                v.previous_sent = v.sent;
                (pid, usage)
            })
            .collect()
    }
    pub fn stop(&self) {
        self.trace.lock().take();
    }
}
