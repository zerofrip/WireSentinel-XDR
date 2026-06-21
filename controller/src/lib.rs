//! DTO helpers for WireSentinel-Controller XDR ingest.

mod dto;

pub use dto::{
    build_incident_bundle, build_policy_bundle, build_telemetry_payload, parse_ingest_payload,
    XdrIngestPayload, XdrIngestResponse,
};
