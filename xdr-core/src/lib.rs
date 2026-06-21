//! Core XDR abstractions for WireSentinel Phase 17.

mod emitter;
mod error;
mod security;

pub use emitter::{CollectingEmitter, NullEmitter, XdrEventEmitter};
pub use error::{XdrError, XdrResult};
pub use security::XdrSecurityPolicyEngine;
pub use shared_types::{
    AttackGraphEdge, AttackGraphEdgeKind, AttackGraphNode, AttackGraphNodeKind, AttackPath,
    BeaconingFinding, Case, CaseComment, CaseEvidence, CaseWorkflowState, DetectionMatch,
    DetectionRule, DetectionRuleKind, DetectionTrigger, DriverEvent, EdrServiceEvent, FileEvent,
    Hunt, HuntQueryKind, HuntResult, HuntStatus, HuntTimeline, HuntTimelineEntry,
    IdentityRiskRecord, IdentityThreat, IdentityThreatKind, Incident, IncidentArtifact,
    IncidentStatus, IncidentTimelineEntry, LateralMovementFinding, MaliciousExecution,
    MitreDetectionMapping, MitreTechnique, NetworkThreat, PersistenceFinding, Playbook,
    PlaybookExecution, PlaybookKind, PlaybookStatus, ProcessAnomaly, ProcessEvent, RegistryEvent,
    ResponseActionKind, ResponseActionRequest, ResponseActionResult, ResponseActionStatus,
    TechniqueDetection, XdrAnalyticsSummary, XdrIncidentBundle, XdrPolicyBundle, XdrSecurityPolicy,
    XdrSeverity, XdrTelemetryPayload,
};
