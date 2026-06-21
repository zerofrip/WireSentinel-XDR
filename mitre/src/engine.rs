use chrono::Utc;
use parking_lot::RwLock;
use shared_types::{
    DetectionTrigger, MitreDetectionMapping, MitreTechnique, ServiceEventInner, TechniqueDetection,
};
use uuid::Uuid;
use xdr_core::{XdrError, XdrEventEmitter, XdrResult};

fn builtin_techniques() -> Vec<MitreTechnique> {
    vec![
        MitreTechnique {
            technique_id: "T1059.001".into(),
            name: "PowerShell".into(),
            tactic: "Execution".into(),
            description: "Adversaries may abuse PowerShell commands and scripts.".into(),
        },
        MitreTechnique {
            technique_id: "T1071.001".into(),
            name: "Web Protocols".into(),
            tactic: "Command and Control".into(),
            description: "Adversaries may communicate using application layer protocols.".into(),
        },
        MitreTechnique {
            technique_id: "T1021.001".into(),
            name: "Remote Desktop Protocol".into(),
            tactic: "Lateral Movement".into(),
            description: "Adversaries may use RDP to move laterally.".into(),
        },
        MitreTechnique {
            technique_id: "T1110".into(),
            name: "Brute Force".into(),
            tactic: "Credential Access".into(),
            description: "Adversaries may use brute force techniques to gain access.".into(),
        },
        MitreTechnique {
            technique_id: "T1547.001".into(),
            name: "Registry Run Keys".into(),
            tactic: "Persistence".into(),
            description: "Adversaries may achieve persistence via run registry keys.".into(),
        },
        MitreTechnique {
            technique_id: "T1078".into(),
            name: "Valid Accounts".into(),
            tactic: "Defense Evasion".into(),
            description: "Adversaries may obtain and abuse credentials of existing accounts.".into(),
        },
    ]
}

struct MitreState {
    techniques: Vec<MitreTechnique>,
    mappings: Vec<MitreDetectionMapping>,
    detections: Vec<TechniqueDetection>,
}

impl Default for MitreState {
    fn default() -> Self {
        Self {
            techniques: builtin_techniques(),
            mappings: Vec::new(),
            detections: Vec::new(),
        }
    }
}

/// Maps detections to MITRE ATT&CK techniques and emits TechniqueDetected events.
pub struct MitreMappingEngine<E: XdrEventEmitter> {
    emitter: E,
    state: RwLock<MitreState>,
}

impl<E: XdrEventEmitter> MitreMappingEngine<E> {
    pub fn new(emitter: E) -> Self {
        Self {
            emitter,
            state: RwLock::new(MitreState::default()),
        }
    }

    pub fn list_techniques(&self) -> Vec<MitreTechnique> {
        self.state.read().techniques.clone()
    }

    pub fn map_detection(
        &self,
        detection_kind: impl Into<String>,
        technique_id: impl Into<String>,
        rule_id: Option<Uuid>,
    ) -> XdrResult<MitreDetectionMapping> {
        let technique_id = technique_id.into();
        let exists = self
            .state
            .read()
            .techniques
            .iter()
            .any(|t| t.technique_id == technique_id);
        if !exists {
            return Err(XdrError::Mitre(format!(
                "technique {technique_id} not in built-in subset"
            )));
        }

        let mapping = MitreDetectionMapping {
            id: Uuid::new_v4(),
            detection_kind: detection_kind.into(),
            technique_id: technique_id.clone(),
            rule_id,
        };
        self.state.write().mappings.push(mapping.clone());
        Ok(mapping)
    }

    pub fn on_detection_triggered(
        &self,
        trigger: &DetectionTrigger,
        technique_ids: &[String],
    ) -> Vec<TechniqueDetection> {
        let mut emitted = Vec::new();
        let techniques = self.state.read().techniques.clone();

        for tid in technique_ids {
            if let Some(technique) = techniques.iter().find(|t| &t.technique_id == tid) {
                let detection = TechniqueDetection {
                    id: Uuid::new_v4(),
                    technique_id: technique.technique_id.clone(),
                    technique_name: technique.name.clone(),
                    tactic: technique.tactic.clone(),
                    source_detection: trigger.title.clone(),
                    severity: trigger.severity,
                    detected_at: Utc::now(),
                };
                self.state.write().detections.push(detection.clone());
                self.emitter.emit(shared_types::ServiceEvent::now(
                    ServiceEventInner::TechniqueDetected {
                        detection: detection.clone(),
                    },
                ));
                emitted.push(detection);
            }
        }
        emitted
    }

    pub fn detection_count(&self) -> usize {
        self.state.read().detections.len()
    }

    pub fn coverage_pct(&self) -> f64 {
        let state = self.state.read();
        let mapped: std::collections::HashSet<_> = state
            .mappings
            .iter()
            .map(|m| m.technique_id.clone())
            .collect();
        if state.techniques.is_empty() {
            return 0.0;
        }
        (mapped.len() as f64 / state.techniques.len() as f64) * 100.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use shared_types::XdrSeverity;
    use xdr_core::CollectingEmitter;

    #[test]
    fn maps_known_technique() {
        let engine = MitreMappingEngine::new(xdr_core::NullEmitter);
        let mapping = engine
            .map_detection("process_anomaly", "T1059.001", None)
            .unwrap();
        assert_eq!(mapping.technique_id, "T1059.001");
    }

    #[test]
    fn emits_technique_detected() {
        let emitter = CollectingEmitter::new();
        let engine = MitreMappingEngine::new(&emitter);
        let trigger = DetectionTrigger {
            id: Uuid::new_v4(),
            rule_id: Uuid::new_v4(),
            match_id: Uuid::new_v4(),
            severity: XdrSeverity::High,
            title: "PowerShell execution".into(),
            triggered_at: Utc::now(),
        };
        let detections = engine.on_detection_triggered(&trigger, &["T1059.001".into()]);
        assert_eq!(detections.len(), 1);
        assert_eq!(emitter.drain().len(), 1);
    }
}
