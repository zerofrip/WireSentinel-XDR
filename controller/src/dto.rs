use chrono::Utc;
use serde::{Deserialize, Serialize};
use shared_types::{
    DriverEvent, EdrServiceEvent, FileEvent, ProcessEvent, RegistryEvent, XdrIncidentBundle,
    XdrPolicyBundle, XdrTelemetryPayload,
};
use uuid::Uuid;

/// Controller ingest payload wrapping EDR/NDR/ITDR telemetry batches.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct XdrIngestPayload {
    pub tenant_id: Uuid,
    pub device_id: Uuid,
    pub agent_id: Uuid,
    pub process_events: Vec<ProcessEvent>,
    pub file_events: Vec<FileEvent>,
    pub registry_events: Vec<RegistryEvent>,
    pub service_events: Vec<EdrServiceEvent>,
    pub driver_events: Vec<DriverEvent>,
    pub network_events: Vec<serde_json::Value>,
    pub auth_events: Vec<serde_json::Value>,
    pub ingested_at: chrono::DateTime<Utc>,
}

impl XdrIngestPayload {
    pub fn empty(tenant_id: Uuid, device_id: Uuid, agent_id: Uuid) -> Self {
        Self {
            tenant_id,
            device_id,
            agent_id,
            process_events: Vec::new(),
            file_events: Vec::new(),
            registry_events: Vec::new(),
            service_events: Vec::new(),
            driver_events: Vec::new(),
            network_events: Vec::new(),
            auth_events: Vec::new(),
            ingested_at: Utc::now(),
        }
    }

    pub fn event_count(&self) -> u32 {
        (self.process_events.len()
            + self.file_events.len()
            + self.registry_events.len()
            + self.service_events.len()
            + self.driver_events.len()
            + self.network_events.len()
            + self.auth_events.len()) as u32
    }
}

/// Acknowledgement returned to Controller after ingest.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct XdrIngestResponse {
    pub accepted: bool,
    pub events_processed: u32,
    pub message: String,
}

pub fn parse_ingest_payload(json: &str) -> Result<XdrIngestPayload, serde_json::Error> {
    serde_json::from_str(json)
}

pub fn build_telemetry_payload(
    agent_id: Uuid,
    device_id: Uuid,
    process: u32,
    file: u32,
    network: u32,
    identity: u32,
    incidents: u32,
    detections: u32,
) -> XdrTelemetryPayload {
    XdrTelemetryPayload {
        agent_id,
        device_id,
        reported_at: Utc::now(),
        process_events: process,
        file_events: file,
        network_events: network,
        identity_threats: identity,
        active_incidents: incidents,
        detection_matches: detections,
    }
}

pub fn build_policy_bundle(bundle: XdrPolicyBundle) -> XdrPolicyBundle {
    bundle
}

pub fn build_incident_bundle(bundle: XdrIncidentBundle) -> XdrIncidentBundle {
    bundle
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_payload_has_zero_events() {
        let payload = XdrIngestPayload::empty(Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
        assert_eq!(payload.event_count(), 0);
    }

    #[test]
    fn roundtrips_json() {
        let payload = XdrIngestPayload::empty(Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
        let json = serde_json::to_string(&payload).unwrap();
        let parsed = parse_ingest_payload(&json).unwrap();
        assert_eq!(parsed.tenant_id, payload.tenant_id);
    }
}
