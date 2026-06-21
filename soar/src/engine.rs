use std::sync::Arc;

use chrono::Utc;
use parking_lot::RwLock;
use response::{ResponseActionBackend, ResponseEngine};
use shared_types::{
    Incident, Playbook, PlaybookExecution, PlaybookKind, PlaybookStatus, ResponseActionKind,
    ServiceEventInner,
};
use uuid::Uuid;
use xdr_core::{XdrError, XdrEventEmitter, XdrResult};

struct SoarState {
    playbooks: Vec<Playbook>,
    executions: Vec<PlaybookExecution>,
}

impl Default for SoarState {
    fn default() -> Self {
        Self {
            playbooks: Vec::new(),
            executions: Vec::new(),
        }
    }
}

/// SOAR engine with six built-in playbooks wired to ResponseEngine.
pub struct SoarEngine {
    emitter: Arc<dyn XdrEventEmitter>,
    response: Arc<ResponseEngine>,
    state: RwLock<SoarState>,
}

impl SoarEngine {
    pub fn new(emitter: Arc<dyn XdrEventEmitter>, backend: Arc<dyn ResponseActionBackend>) -> Self {
        let response = Arc::new(ResponseEngine::new(emitter.clone(), backend));
        let engine = Self {
            emitter,
            response,
            state: RwLock::new(SoarState::default()),
        };
        engine.register_builtin_playbooks();
        engine
    }

    pub fn list_playbooks(&self) -> Vec<Playbook> {
        self.state.read().playbooks.clone()
    }

    pub async fn run_playbook(
        &self,
        playbook_id: Uuid,
        tenant_id: Uuid,
        incident: Option<&Incident>,
        target: &str,
    ) -> XdrResult<PlaybookExecution> {
        let playbook = self
            .state
            .read()
            .playbooks
            .iter()
            .find(|p| p.id == playbook_id)
            .cloned()
            .ok_or_else(|| XdrError::Soar(format!("playbook {playbook_id} not found")))?;

        let mut execution = PlaybookExecution {
            id: Uuid::new_v4(),
            playbook_id,
            incident_id: incident.map(|i| i.id),
            status: PlaybookStatus::Running,
            started_at: Utc::now(),
            completed_at: None,
            error: None,
        };

        self.emitter.emit(shared_types::ServiceEvent::now(
            ServiceEventInner::PlaybookStarted {
                execution: execution.clone(),
            },
        ));

        let result = self
            .execute_playbook_kind(playbook.playbook_kind, tenant_id, incident, target)
            .await;

        execution.completed_at = Some(Utc::now());
        execution.status = if result.is_ok() {
            PlaybookStatus::Completed
        } else {
            PlaybookStatus::Failed
        };
        execution.error = result.as_ref().err().map(|e| e.to_string());

        self.state.write().executions.push(execution.clone());
        self.emitter.emit(shared_types::ServiceEvent::now(
            ServiceEventInner::PlaybookCompleted {
                execution: execution.clone(),
            },
        ));

        result.map(|_| execution)
    }

    async fn execute_playbook_kind(
        &self,
        kind: PlaybookKind,
        tenant_id: Uuid,
        incident: Option<&Incident>,
        target: &str,
    ) -> XdrResult<()> {
        let incident_id = incident.map(|i| i.id);
        let action = match kind {
            PlaybookKind::BlockHost => ResponseActionKind::BlockIp,
            PlaybookKind::BlockDomain => ResponseActionKind::BlockDomain,
            PlaybookKind::DisableIdentity => ResponseActionKind::DisableUser,
            PlaybookKind::QuarantineDevice => ResponseActionKind::QuarantineDevice,
            PlaybookKind::EscalateIncident => ResponseActionKind::ForceReauthentication,
            PlaybookKind::NotifyTeam => ResponseActionKind::ForceReauthentication,
        };

        let request = ResponseEngine::build_request(tenant_id, action, target, "soar", incident_id);
        self.response.execute_action(request).await?;
        Ok(())
    }

    fn register_builtin_playbooks(&self) {
        let tenant_id = Uuid::nil();
        let now = Utc::now();
        let kinds = [
            (PlaybookKind::BlockHost, "Block Host"),
            (PlaybookKind::BlockDomain, "Block Domain"),
            (PlaybookKind::DisableIdentity, "Disable Identity"),
            (PlaybookKind::QuarantineDevice, "Quarantine Device"),
            (PlaybookKind::EscalateIncident, "Escalate Incident"),
            (PlaybookKind::NotifyTeam, "Notify Team"),
        ];

        let playbooks = kinds
            .into_iter()
            .map(|(kind, name)| Playbook {
                id: Uuid::new_v4(),
                tenant_id,
                name: name.into(),
                playbook_kind: kind,
                enabled: true,
                steps: vec![serde_json::json!({"action": format!("{kind:?}")})],
                created_at: now,
            })
            .collect();

        self.state.write().playbooks = playbooks;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use response::MockBackend;
    use shared_types::XdrSeverity;
    use xdr_core::CollectingEmitter;

    #[tokio::test]
    async fn runs_builtin_playbooks() {
        let emitter = Arc::new(CollectingEmitter::new());
        let engine = SoarEngine::new(emitter, Arc::new(MockBackend::new()));
        assert_eq!(engine.list_playbooks().len(), 6);
        let playbook = engine.list_playbooks()[0].clone();
        let incident = Incident {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            title: "Test".into(),
            description: None,
            severity: XdrSeverity::High,
            status: shared_types::IncidentStatus::Open,
            detection_id: None,
            assigned_to: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            resolved_at: None,
        };
        let execution = engine
            .run_playbook(playbook.id, incident.tenant_id, Some(&incident), "10.0.0.5")
            .await
            .unwrap();
        assert_eq!(execution.status, PlaybookStatus::Completed);
    }

    #[test]
    fn registers_six_playbooks() {
        let engine = SoarEngine::new(
            Arc::new(CollectingEmitter::new()),
            Arc::new(MockBackend::new()),
        );
        assert_eq!(engine.list_playbooks().len(), 6);
    }
}
