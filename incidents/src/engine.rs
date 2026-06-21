use chrono::Utc;
use parking_lot::RwLock;
use shared_types::{
    DetectionTrigger, Incident, IncidentArtifact, IncidentStatus, IncidentTimelineEntry,
    ServiceEventInner, XdrSeverity,
};
use uuid::Uuid;
use xdr_core::{XdrError, XdrEventEmitter, XdrResult};

struct IncidentState {
    incidents: Vec<Incident>,
    timeline: Vec<IncidentTimelineEntry>,
    artifacts: Vec<IncidentArtifact>,
}

impl Default for IncidentState {
    fn default() -> Self {
        Self {
            incidents: Vec::new(),
            timeline: Vec::new(),
            artifacts: Vec::new(),
        }
    }
}

/// Manages incident severity, lifecycle, and auto-creation from detections.
pub struct IncidentManager<E: XdrEventEmitter> {
    emitter: E,
    state: RwLock<IncidentState>,
}

impl<E: XdrEventEmitter> IncidentManager<E> {
    pub fn new(emitter: E) -> Self {
        Self {
            emitter,
            state: RwLock::new(IncidentState::default()),
        }
    }

    pub fn create_incident(
        &self,
        tenant_id: Uuid,
        title: impl Into<String>,
        severity: XdrSeverity,
        detection_id: Option<Uuid>,
    ) -> Incident {
        let now = Utc::now();
        let incident = Incident {
            id: Uuid::new_v4(),
            tenant_id,
            title: title.into(),
            description: None,
            severity,
            status: IncidentStatus::Open,
            detection_id,
            assigned_to: None,
            created_at: now,
            updated_at: now,
            resolved_at: None,
        };

        self.record_timeline(&incident.id, "created", "Incident opened", None);
        self.state.write().incidents.push(incident.clone());
        self.emitter.emit(shared_types::ServiceEvent::now(
            ServiceEventInner::IncidentCreated {
                incident: incident.clone(),
            },
        ));
        incident
    }

    pub fn on_detection_triggered(&self, trigger: &DetectionTrigger, tenant_id: Uuid) -> Incident {
        self.create_incident(
            tenant_id,
            trigger.title.clone(),
            trigger.severity,
            Some(trigger.id),
        )
    }

    pub fn transition(
        &self,
        incident_id: Uuid,
        to: IncidentStatus,
        actor: Option<&str>,
    ) -> XdrResult<Incident> {
        let mut state = self.state.write();
        let incident = state
            .incidents
            .iter_mut()
            .find(|i| i.id == incident_id)
            .ok_or_else(|| XdrError::Incident(format!("incident {incident_id} not found")))?;

        let from = incident.status;
        validate_transition(from, to)?;

        incident.status = to;
        incident.updated_at = Utc::now();
        if to == IncidentStatus::Resolved || to == IncidentStatus::Closed {
            incident.resolved_at = Some(Utc::now());
        }

        let updated = incident.clone();
        drop(state);

        self.record_timeline(
            &incident_id,
            &format!("status_{to:?}"),
            &format!("Transitioned from {from:?} to {to:?}"),
            actor,
        );

        let event = match to {
            IncidentStatus::Resolved | IncidentStatus::Closed => {
                ServiceEventInner::IncidentResolved {
                    incident: updated.clone(),
                }
            }
            _ => ServiceEventInner::IncidentEscalated {
                incident: updated.clone(),
            },
        };
        self.emitter.emit(shared_types::ServiceEvent::now(event));
        Ok(updated)
    }

    pub fn add_artifact(
        &self,
        incident_id: Uuid,
        artifact_kind: impl Into<String>,
        content: impl Into<String>,
    ) -> XdrResult<IncidentArtifact> {
        if !self
            .state
            .read()
            .incidents
            .iter()
            .any(|i| i.id == incident_id)
        {
            return Err(XdrError::Incident(format!(
                "incident {incident_id} not found"
            )));
        }

        let artifact = IncidentArtifact {
            id: Uuid::new_v4(),
            incident_id,
            artifact_kind: artifact_kind.into(),
            content: content.into(),
            collected_at: Utc::now(),
        };
        self.state.write().artifacts.push(artifact.clone());
        Ok(artifact)
    }

    pub fn list_incidents(&self) -> Vec<Incident> {
        self.state.read().incidents.clone()
    }

    pub fn open_count(&self) -> usize {
        self.state
            .read()
            .incidents
            .iter()
            .filter(|i| {
                matches!(
                    i.status,
                    IncidentStatus::Open | IncidentStatus::Investigating
                )
            })
            .count()
    }

    fn record_timeline(
        &self,
        incident_id: &Uuid,
        entry_kind: &str,
        summary: &str,
        actor: Option<&str>,
    ) {
        self.state.write().timeline.push(IncidentTimelineEntry {
            id: Uuid::new_v4(),
            incident_id: *incident_id,
            entry_kind: entry_kind.into(),
            summary: summary.into(),
            actor: actor.map(str::to_string),
            recorded_at: Utc::now(),
        });
    }
}

fn validate_transition(from: IncidentStatus, to: IncidentStatus) -> XdrResult<()> {
    let valid = matches!(
        (from, to),
        (IncidentStatus::Open, IncidentStatus::Investigating)
            | (IncidentStatus::Investigating, IncidentStatus::Contained)
            | (IncidentStatus::Contained, IncidentStatus::Resolved)
            | (IncidentStatus::Resolved, IncidentStatus::Closed)
            | (IncidentStatus::Open, IncidentStatus::Closed)
    );
    if valid {
        Ok(())
    } else {
        Err(XdrError::Incident(format!(
            "invalid transition {from:?} -> {to:?}"
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use xdr_core::CollectingEmitter;

    #[test]
    fn auto_creates_from_detection() {
        let emitter = CollectingEmitter::new();
        let mgr = IncidentManager::new(&emitter);
        let trigger = DetectionTrigger {
            id: Uuid::new_v4(),
            rule_id: Uuid::new_v4(),
            match_id: Uuid::new_v4(),
            severity: XdrSeverity::High,
            title: "Malware detected".into(),
            triggered_at: Utc::now(),
        };
        let incident = mgr.on_detection_triggered(&trigger, Uuid::new_v4());
        assert_eq!(incident.detection_id, Some(trigger.id));
        assert_eq!(emitter.drain().len(), 1);
    }

    #[test]
    fn transitions_lifecycle() {
        let mgr = IncidentManager::new(xdr_core::NullEmitter);
        let incident = mgr.create_incident(Uuid::new_v4(), "Test", XdrSeverity::Low, None);
        mgr.transition(incident.id, IncidentStatus::Investigating, Some("analyst"))
            .unwrap();
        mgr.transition(incident.id, IncidentStatus::Contained, Some("analyst"))
            .unwrap();
        assert_eq!(mgr.open_count(), 0);
    }
}
