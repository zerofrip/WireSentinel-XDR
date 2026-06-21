use chrono::Utc;
use shared_types::{HuntQueryKind, ProcessEvent};
use uuid::Uuid;
use xdr_controller::XdrIngestPayload;
use xdr_sdk::XdrPlatform;

#[test]
fn end_to_end_ingest_and_hunt() {
    let platform = XdrPlatform::new();
    let tenant = Uuid::new_v4();
    let device = Uuid::new_v4();

    let payload = XdrIngestPayload {
        tenant_id: tenant,
        device_id: device,
        agent_id: Uuid::new_v4(),
        process_events: vec![ProcessEvent {
            id: Uuid::new_v4(),
            device_id: device,
            pid: 999,
            parent_pid: None,
            process_name: "powershell.exe".into(),
            command_line: Some("powershell -enc ABC".into()),
            user: Some("user".into()),
            observed_at: Utc::now(),
        }],
        ..XdrIngestPayload::empty(tenant, device, Uuid::new_v4())
    };

    for event in payload.process_events {
        platform.edr.ingest_process(event).unwrap();
    }

    platform
        .hunting
        .lake()
        .ingest(tenant, "process", serde_json::json!({"device_id": device}));
    let hunt = platform.hunting.create_hunt(
        tenant,
        "integration",
        HuntQueryKind::Historical,
        "process",
    );
    let results = platform.hunting.run_hunt(hunt.id).unwrap();
    assert!(!results.is_empty() || platform.drain_events().len() > 0);
}

#[test]
fn platform_modules_initialized() {
    let platform = XdrPlatform::new();
    assert_eq!(platform.soar.list_playbooks().len(), 6);
    assert!(platform.mitre.list_techniques().len() >= 6);
}
