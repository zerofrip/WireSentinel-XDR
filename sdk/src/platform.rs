use std::sync::Arc;

use analytics::XdrAnalyticsService;
use attack_graph::AttackGraphEngine;
use cases::CaseManagementEngine;
use datalake::SecurityDataLake;
use detections::DetectionEngine;
use edr::EdrEngine;
use hunting::ThreatHuntingEngine;
use incidents::IncidentManager;
use itdr::IdentityThreatEngine;
use mitre::MitreMappingEngine;
use ndr::NdrEngine;
use response::{MockBackend, ResponseEngine};
use shared_types::RetentionPolicy;
use soar::SoarEngine;
use xdr_core::CollectingEmitter;

/// Facade bundling all XDR engines behind a shared event emitter.
pub struct XdrPlatform {
    pub emitter: Arc<CollectingEmitter>,
    pub edr: EdrEngine<Arc<CollectingEmitter>>,
    pub ndr: NdrEngine<Arc<CollectingEmitter>>,
    pub itdr: IdentityThreatEngine<Arc<CollectingEmitter>>,
    pub hunting: ThreatHuntingEngine,
    pub detections: DetectionEngine<Arc<CollectingEmitter>>,
    pub incidents: IncidentManager<Arc<CollectingEmitter>>,
    pub cases: CaseManagementEngine,
    pub soar: SoarEngine,
    pub attack_graph: AttackGraphEngine,
    pub mitre: MitreMappingEngine<Arc<CollectingEmitter>>,
    pub response: Arc<ResponseEngine>,
    pub analytics: XdrAnalyticsService,
}

impl XdrPlatform {
    pub fn new() -> Self {
        let emitter = Arc::new(CollectingEmitter::new());
        let backend = Arc::new(MockBackend::new());

        Self {
            edr: EdrEngine::new(emitter.clone()),
            ndr: NdrEngine::new(emitter.clone()),
            itdr: IdentityThreatEngine::new(emitter.clone()),
            hunting: ThreatHuntingEngine::new(SecurityDataLake::new(RetentionPolicy::Days90)),
            detections: DetectionEngine::new(emitter.clone()),
            incidents: IncidentManager::new(emitter.clone()),
            cases: CaseManagementEngine::new(),
            soar: SoarEngine::new(emitter.clone(), Arc::new(MockBackend::new())),
            attack_graph: AttackGraphEngine::new(),
            mitre: MitreMappingEngine::new(emitter.clone()),
            response: Arc::new(ResponseEngine::new(emitter.clone(), backend)),
            analytics: XdrAnalyticsService::new(),
            emitter,
        }
    }

    pub fn drain_events(&self) -> Vec<shared_types::ServiceEvent> {
        self.emitter.drain()
    }
}

impl Default for XdrPlatform {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn platform_bundles_engines() {
        let platform = XdrPlatform::new();
        assert_eq!(platform.soar.list_playbooks().len(), 6);
        assert_eq!(platform.mitre.list_techniques().len(), 6);
    }

    #[test]
    fn shared_emitter_collects_events() {
        let platform = XdrPlatform::new();
        platform.cases.create_case(uuid::Uuid::new_v4(), "test", None);
        assert!(platform.drain_events().is_empty());
    }
}
