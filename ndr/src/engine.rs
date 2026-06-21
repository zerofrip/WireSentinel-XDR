use std::collections::HashMap;

use chrono::{DateTime, Duration, Utc};
use parking_lot::RwLock;
use shared_types::{
    BeaconingFinding, LateralMovementFinding, NetworkThreat, ServiceEventInner, XdrSeverity,
};
use uuid::Uuid;
use xdr_core::{XdrEventEmitter, XdrResult};

const BEACON_WINDOW: Duration = Duration::minutes(10);
const BEACON_MIN_CONNECTIONS: u32 = 5;
const BEACON_INTERVAL_TOLERANCE: f64 = 5.0;
const PORT_SCAN_THRESHOLD: u32 = 20;
const C2_PORTS: &[u16] = &[4444, 8443, 31337];

#[derive(Debug, Clone)]
pub struct DnsQuery {
    pub device_id: Uuid,
    pub query_name: String,
    pub resolved_ip: Option<String>,
    pub observed_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct NetworkFlow {
    pub device_id: Uuid,
    pub source_ip: String,
    pub dest_ip: String,
    pub dest_port: u16,
    pub protocol: String,
    pub bytes_sent: u64,
    pub observed_at: DateTime<Utc>,
}

struct NdrState {
    dns_queries: Vec<DnsQuery>,
    flows: Vec<NetworkFlow>,
    beacon_windows: HashMap<String, Vec<DateTime<Utc>>>,
    port_scan_counts: HashMap<String, u32>,
}

impl Default for NdrState {
    fn default() -> Self {
        Self {
            dns_queries: Vec::new(),
            flows: Vec::new(),
            beacon_windows: HashMap::new(),
            port_scan_counts: HashMap::new(),
        }
    }
}

/// Network threat detection engine.
pub struct NdrEngine<E: XdrEventEmitter> {
    emitter: E,
    state: RwLock<NdrState>,
}

impl<E: XdrEventEmitter> NdrEngine<E> {
    pub fn new(emitter: E) -> Self {
        Self {
            emitter,
            state: RwLock::new(NdrState::default()),
        }
    }

    pub fn ingest_dns(&self, query: DnsQuery) -> XdrResult<()> {
        self.analyze_dns(&query);
        self.state.write().dns_queries.push(query);
        Ok(())
    }

    pub fn ingest_flow(&self, flow: NetworkFlow) -> XdrResult<()> {
        self.analyze_beaconing(&flow);
        self.analyze_port_scan(&flow);
        self.analyze_c2(&flow);
        self.analyze_lateral_movement(&flow);
        self.state.write().flows.push(flow);
        Ok(())
    }

    pub fn flow_count(&self) -> usize {
        self.state.read().flows.len()
    }

    fn analyze_dns(&self, query: &DnsQuery) {
        let suspicious = query.query_name.len() > 60
            || query.query_name.matches('.').count() > 6
            || query
                .query_name
                .chars()
                .filter(|c| c.is_numeric())
                .count()
                > query.query_name.len() / 2;

        if suspicious {
            let threat = NetworkThreat {
                id: Uuid::new_v4(),
                device_id: query.device_id,
                threat_kind: "dns_anomaly".into(),
                source_ip: None,
                dest_ip: query.resolved_ip.clone(),
                dest_port: None,
                protocol: Some("dns".into()),
                severity: XdrSeverity::Medium,
                detected_at: Utc::now(),
            };
            self.emitter.emit(shared_types::ServiceEvent::now(
                ServiceEventInner::NetworkThreatDetected { threat },
            ));
        }
    }

    fn analyze_beaconing(&self, flow: &NetworkFlow) {
        let key = format!("{}:{}:{}", flow.device_id, flow.dest_ip, flow.dest_port);
        let mut state = self.state.write();
        let window = state
            .beacon_windows
            .entry(key.clone())
            .or_default();
        window.push(flow.observed_at);
        window.retain(|t| *t >= Utc::now() - BEACON_WINDOW);

        if window.len() as u32 >= BEACON_MIN_CONNECTIONS {
            let mut intervals = Vec::new();
            for pair in window.windows(2) {
                intervals.push((pair[1] - pair[0]).num_seconds() as f64);
            }
            let avg = intervals.iter().sum::<f64>() / intervals.len() as f64;
            let regular = intervals
                .iter()
                .all(|i| (i - avg).abs() <= BEACON_INTERVAL_TOLERANCE);

            if regular {
                let finding = BeaconingFinding {
                    id: Uuid::new_v4(),
                    device_id: flow.device_id,
                    dest_ip: flow.dest_ip.clone(),
                    dest_port: flow.dest_port,
                    interval_secs: avg,
                    connection_count: window.len() as u32,
                    detected_at: Utc::now(),
                };
                drop(state);
                self.emitter.emit(shared_types::ServiceEvent::now(
                    ServiceEventInner::BeaconingDetected { finding },
                ));
                self.state.write().beacon_windows.remove(&key);
            }
        }
    }

    fn analyze_port_scan(&self, flow: &NetworkFlow) {
        let key = format!("{}:{}", flow.source_ip, flow.dest_ip);
        let mut state = self.state.write();
        let count = state.port_scan_counts.entry(key).or_insert(0);
        *count += 1;

        if *count == PORT_SCAN_THRESHOLD {
            let threat = NetworkThreat {
                id: Uuid::new_v4(),
                device_id: flow.device_id,
                threat_kind: "port_scan".into(),
                source_ip: Some(flow.source_ip.clone()),
                dest_ip: Some(flow.dest_ip.clone()),
                dest_port: Some(flow.dest_port),
                protocol: Some(flow.protocol.clone()),
                severity: XdrSeverity::High,
                detected_at: Utc::now(),
            };
            drop(state);
            self.emitter.emit(shared_types::ServiceEvent::now(
                ServiceEventInner::NetworkThreatDetected { threat },
            ));
        }
    }

    fn analyze_c2(&self, flow: &NetworkFlow) {
        if C2_PORTS.contains(&flow.dest_port) && flow.bytes_sent > 0 {
            let threat = NetworkThreat {
                id: Uuid::new_v4(),
                device_id: flow.device_id,
                threat_kind: "c2_communication".into(),
                source_ip: Some(flow.source_ip.clone()),
                dest_ip: Some(flow.dest_ip.clone()),
                dest_port: Some(flow.dest_port),
                protocol: Some(flow.protocol.clone()),
                severity: XdrSeverity::Critical,
                detected_at: Utc::now(),
            };
            self.emitter.emit(shared_types::ServiceEvent::now(
                ServiceEventInner::NetworkThreatDetected { threat },
            ));
        }
    }

    fn analyze_lateral_movement(&self, flow: &NetworkFlow) {
        let internal = |ip: &str| {
            ip.starts_with("10.")
                || ip.starts_with("192.168.")
                || ip.starts_with("172.16.")
                || ip.starts_with("172.17.")
        };

        if internal(&flow.source_ip)
            && internal(&flow.dest_ip)
            && matches!(flow.dest_port, 135 | 139 | 445 | 3389 | 5985 | 5986)
        {
            let finding = LateralMovementFinding {
                id: Uuid::new_v4(),
                device_id: flow.device_id,
                source_host: flow.source_ip.clone(),
                target_host: flow.dest_ip.clone(),
                protocol: flow.protocol.clone(),
                severity: XdrSeverity::High,
                detected_at: Utc::now(),
            };
            self.emitter.emit(shared_types::ServiceEvent::now(
                ServiceEventInner::LateralMovementDetected { finding },
            ));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use xdr_core::CollectingEmitter;

    #[test]
    fn detects_dns_anomaly() {
        let emitter = CollectingEmitter::new();
        let engine = NdrEngine::new(&emitter);
        engine
            .ingest_dns(DnsQuery {
                device_id: Uuid::new_v4(),
                query_name: "a".repeat(80),
                resolved_ip: Some("1.2.3.4".into()),
                observed_at: Utc::now(),
            })
            .unwrap();
        assert_eq!(emitter.drain().len(), 1);
    }

    #[test]
    fn detects_c2_on_known_port() {
        let emitter = CollectingEmitter::new();
        let engine = NdrEngine::new(&emitter);
        engine
            .ingest_flow(NetworkFlow {
                device_id: Uuid::new_v4(),
                source_ip: "10.0.0.5".into(),
                dest_ip: "203.0.113.10".into(),
                dest_port: 4444,
                protocol: "tcp".into(),
                bytes_sent: 512,
                observed_at: Utc::now(),
            })
            .unwrap();
        assert_eq!(emitter.drain().len(), 1);
    }
}
