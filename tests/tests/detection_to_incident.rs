use chrono::Utc;
use shared_types::{DetectionRule, DetectionRuleKind, XdrSeverity};
use uuid::Uuid;
use xdr_sdk::XdrPlatform;

#[test]
fn detection_triggers_incident() {
    let platform = XdrPlatform::new();
    let tenant = Uuid::new_v4();

    let rule = DetectionRule {
        id: Uuid::new_v4(),
        tenant_id: tenant,
        name: "Test rule".into(),
        rule_kind: DetectionRuleKind::SigmaInspired,
        enabled: true,
        conditions: serde_json::json!({
            "selection": { "event_kind": "alert", "severity": "high" }
        }),
        severity: XdrSeverity::High,
        mitre_technique_ids: vec!["T1059.001".into()],
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };

    platform.detections.add_rule(rule).unwrap();
    let triggers = platform
        .detections
        .ingest_event(serde_json::json!({
            "event_kind": "alert",
            "severity": "high"
        }))
        .unwrap();
    assert_eq!(triggers.len(), 1);

    let incident = platform
        .incidents
        .on_detection_triggered(&triggers[0], tenant);
    platform.analytics.record_incident(incident.clone());
    platform.analytics.record_detection(triggers[0].clone());

    let techniques = platform
        .mitre
        .on_detection_triggered(&triggers[0], &["T1059.001".into()]);
    for t in techniques {
        platform.analytics.record_technique(t);
    }

    let summary = platform
        .analytics
        .summarize(tenant, platform.mitre.coverage_pct());
    assert_eq!(summary.total_incidents, 1);
    assert!(summary.total_detections >= 1);
}

#[test]
fn case_links_to_incident() {
    let platform = XdrPlatform::new();
    let tenant = Uuid::new_v4();
    let incident =
        platform
            .incidents
            .create_incident(tenant, "Case link test", XdrSeverity::Medium, None);
    let case_record = platform
        .cases
        .create_case(tenant, "Investigation", Some(incident.id));
    platform
        .cases
        .assign_investigator(case_record.id, "lead-analyst")
        .unwrap();
    assert_eq!(
        platform
            .cases
            .get_case(case_record.id)
            .unwrap()
            .investigator,
        Some("lead-analyst".into())
    );
}
