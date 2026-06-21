use std::sync::Arc;

use async_trait::async_trait;
use chrono::Utc;
use parking_lot::RwLock;
use shared_types::{
    ResponseActionKind, ResponseActionRequest, ResponseActionResult, ResponseActionStatus,
    ServiceEventInner,
};
use uuid::Uuid;
use xdr_core::{XdrError, XdrEventEmitter, XdrResult};

/// Backend that executes response actions against external systems.
#[async_trait]
pub trait ResponseActionBackend: Send + Sync {
    async fn execute(&self, request: &ResponseActionRequest) -> XdrResult<String>;
}

/// In-memory mock backend for tests and development.
pub struct MockBackend {
    executed: RwLock<Vec<ResponseActionRequest>>,
}

impl MockBackend {
    pub fn new() -> Self {
        Self {
            executed: RwLock::new(Vec::new()),
        }
    }

    pub fn executed_count(&self) -> usize {
        self.executed.read().len()
    }
}

impl Default for MockBackend {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ResponseActionBackend for MockBackend {
    async fn execute(&self, request: &ResponseActionRequest) -> XdrResult<String> {
        self.executed.write().push(request.clone());
        Ok(format!("mock executed {:?}", request.action_kind))
    }
}

struct ResponseState {
    requests: Vec<ResponseActionRequest>,
    results: Vec<ResponseActionResult>,
}

impl Default for ResponseState {
    fn default() -> Self {
        Self {
            requests: Vec::new(),
            results: Vec::new(),
        }
    }
}

/// Executes the eight supported response actions via a pluggable backend.
pub struct ResponseEngine {
    emitter: Arc<dyn XdrEventEmitter>,
    backend: Arc<dyn ResponseActionBackend>,
    state: RwLock<ResponseState>,
}

impl ResponseEngine {
    pub fn new(emitter: Arc<dyn XdrEventEmitter>, backend: Arc<dyn ResponseActionBackend>) -> Self {
        Self {
            emitter,
            backend,
            state: RwLock::new(ResponseState::default()),
        }
    }

    pub async fn execute_action(
        &self,
        request: ResponseActionRequest,
    ) -> XdrResult<ResponseActionResult> {
        validate_action(&request.action_kind)?;
        self.state.write().requests.push(request.clone());

        let outcome = self.backend.execute(&request).await;
        let (status, detail) = match outcome {
            Ok(detail) => (ResponseActionStatus::Executed, detail),
            Err(err) => (ResponseActionStatus::Failed, err.to_string()),
        };

        let result = ResponseActionResult {
            request_id: request.id,
            status,
            detail,
            executed_at: Utc::now(),
        };

        self.state.write().results.push(result.clone());

        let event = match status {
            ResponseActionStatus::Executed => {
                ServiceEventInner::ResponseActionExecuted { result: result.clone() }
            }
            _ => ServiceEventInner::ResponseActionFailed { result: result.clone() },
        };
        self.emitter.emit(shared_types::ServiceEvent::now(event));

        if status == ResponseActionStatus::Failed {
            return Err(XdrError::Response(result.detail));
        }
        Ok(result)
    }

    pub fn request_count(&self) -> usize {
        self.state.read().requests.len()
    }

    pub fn build_request(
        tenant_id: Uuid,
        action_kind: ResponseActionKind,
        target: impl Into<String>,
        initiated_by: impl Into<String>,
        incident_id: Option<Uuid>,
    ) -> ResponseActionRequest {
        ResponseActionRequest {
            id: Uuid::new_v4(),
            tenant_id,
            action_kind,
            target: target.into(),
            initiated_by: initiated_by.into(),
            incident_id,
            requested_at: Utc::now(),
        }
    }
}

fn validate_action(kind: &ResponseActionKind) -> XdrResult<()> {
    match kind {
        ResponseActionKind::KillProcess
        | ResponseActionKind::BlockHash
        | ResponseActionKind::BlockDomain
        | ResponseActionKind::BlockIp
        | ResponseActionKind::DisableUser
        | ResponseActionKind::QuarantineDevice
        | ResponseActionKind::DisconnectVpn
        | ResponseActionKind::ForceReauthentication => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use xdr_core::CollectingEmitter;

    #[tokio::test]
    async fn executes_block_ip() {
        let emitter = Arc::new(CollectingEmitter::new());
        let backend = Arc::new(MockBackend::new());
        let engine = ResponseEngine::new(emitter.clone(), backend.clone());
        let request = ResponseEngine::build_request(
            Uuid::new_v4(),
            ResponseActionKind::BlockIp,
            "203.0.113.50",
            "soar",
            None,
        );
        let result = engine.execute_action(request).await.unwrap();
        assert_eq!(result.status, ResponseActionStatus::Executed);
        assert_eq!(backend.executed_count(), 1);
    }

    #[tokio::test]
    async fn supports_all_eight_actions() {
        let kinds = [
            ResponseActionKind::KillProcess,
            ResponseActionKind::BlockHash,
            ResponseActionKind::BlockDomain,
            ResponseActionKind::BlockIp,
            ResponseActionKind::DisableUser,
            ResponseActionKind::QuarantineDevice,
            ResponseActionKind::DisconnectVpn,
            ResponseActionKind::ForceReauthentication,
        ];
        for kind in kinds {
            validate_action(&kind).unwrap();
        }
    }
}
