//! Core XDR abstractions for WireSentinel Phase 17.

mod error;
mod emitter;
mod security;

pub use error::{XdrError, XdrResult};
pub use emitter::{CollectingEmitter, NullEmitter, XdrEventEmitter};
pub use security::XdrSecurityPolicyEngine;
pub use shared_types::{
    AttackGraphEdge, AttackGraphEdgeKind, AttackGraphNode, AttackGraphNodeKind, AttackPath,
    BeaconingFinding, Case, CaseComment, CaseEvidence, CaseWorkflowState, DetectionMatch,
    DetectionRule, DetectionRuleKind, DetectionTrigger, DriverEvent, FileEvent, Hunt,
    HuntQueryKind, HuntResult, HuntStatus, HuntTimeline, HuntTimelineEntry, IdentityRiskRecord,
    IdentityThreat, IdentityThreatKind, Incident, IncidentArtifact, IncidentStatus,
    IncidentTimelineEntry, LateralMovementFinding, MaliciousExecution, MitreDetectionMapping,
    MitreTechnique, NetworkThreat, PersistenceFinding, Playbook, PlaybookExecution, PlaybookKind,
    PlaybookStatus, ProcessAnomaly, ProcessEvent, RegistryEvent, ResponseActionKind,
    ResponseActionRequest, ResponseActionResult, ResponseActionStatus, EdrServiceEvent,
    TechniqueDetection, XdrAnalyticsSummary, XdrIncidentBundle, XdrPolicyBundle, XdrSecurityPolicy,
    XdrSeverity, XdrTelemetryPayload,
};
