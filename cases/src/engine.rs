use chrono::Utc;
use parking_lot::RwLock;
use shared_types::{Case, CaseComment, CaseEvidence, CaseWorkflowState};
use uuid::Uuid;
use xdr_core::{XdrError, XdrResult};

struct CaseState {
    cases: Vec<Case>,
    comments: Vec<CaseComment>,
    evidence: Vec<CaseEvidence>,
}

impl Default for CaseState {
    fn default() -> Self {
        Self {
            cases: Vec::new(),
            comments: Vec::new(),
            evidence: Vec::new(),
        }
    }
}

/// Case management with investigator assignment, comments, evidence, and workflow.
pub struct CaseManagementEngine {
    state: RwLock<CaseState>,
}

impl CaseManagementEngine {
    pub fn new() -> Self {
        Self {
            state: RwLock::new(CaseState::default()),
        }
    }

    pub fn create_case(
        &self,
        tenant_id: Uuid,
        title: impl Into<String>,
        linked_incident_id: Option<Uuid>,
    ) -> Case {
        let now = Utc::now();
        let case_record = Case {
            id: Uuid::new_v4(),
            tenant_id,
            title: title.into(),
            linked_incident_id,
            investigator: None,
            workflow_state: CaseWorkflowState::New,
            created_at: now,
            updated_at: now,
        };
        self.state.write().cases.push(case_record.clone());
        case_record
    }

    pub fn assign_investigator(&self, case_id: Uuid, investigator: impl Into<String>) -> XdrResult<Case> {
        let mut state = self.state.write();
        let case_record = state
            .cases
            .iter_mut()
            .find(|c| c.id == case_id)
            .ok_or_else(|| XdrError::Case(format!("case {case_id} not found")))?;

        case_record.investigator = Some(investigator.into());
        case_record.workflow_state = CaseWorkflowState::Assigned;
        case_record.updated_at = Utc::now();
        Ok(case_record.clone())
    }

    pub fn add_comment(
        &self,
        case_id: Uuid,
        author: impl Into<String>,
        body: impl Into<String>,
    ) -> XdrResult<CaseComment> {
        self.ensure_case_exists(case_id)?;
        let comment = CaseComment {
            id: Uuid::new_v4(),
            case_id,
            author: author.into(),
            body: body.into(),
            created_at: Utc::now(),
        };
        self.state.write().comments.push(comment.clone());
        Ok(comment)
    }

    pub fn add_evidence(
        &self,
        case_id: Uuid,
        evidence_kind: impl Into<String>,
        description: impl Into<String>,
        uri: Option<String>,
    ) -> XdrResult<CaseEvidence> {
        self.ensure_case_exists(case_id)?;
        let item = CaseEvidence {
            id: Uuid::new_v4(),
            case_id,
            evidence_kind: evidence_kind.into(),
            description: description.into(),
            uri,
            collected_at: Utc::now(),
        };
        self.state.write().evidence.push(item.clone());
        Ok(item)
    }

    pub fn transition(&self, case_id: Uuid, to: CaseWorkflowState) -> XdrResult<Case> {
        let mut state = self.state.write();
        let case_record = state
            .cases
            .iter_mut()
            .find(|c| c.id == case_id)
            .ok_or_else(|| XdrError::Case(format!("case {case_id} not found")))?;

        validate_case_transition(case_record.workflow_state, to)?;
        case_record.workflow_state = to;
        case_record.updated_at = Utc::now();
        Ok(case_record.clone())
    }

    pub fn get_case(&self, case_id: Uuid) -> Option<Case> {
        self.state
            .read()
            .cases
            .iter()
            .find(|c| c.id == case_id)
            .cloned()
    }

    pub fn comment_count(&self, case_id: Uuid) -> usize {
        self.state
            .read()
            .comments
            .iter()
            .filter(|c| c.case_id == case_id)
            .count()
    }

    fn ensure_case_exists(&self, case_id: Uuid) -> XdrResult<()> {
        if self.get_case(case_id).is_some() {
            Ok(())
        } else {
            Err(XdrError::Case(format!("case {case_id} not found")))
        }
    }
}

impl Default for CaseManagementEngine {
    fn default() -> Self {
        Self::new()
    }
}

fn validate_case_transition(from: CaseWorkflowState, to: CaseWorkflowState) -> XdrResult<()> {
    let valid = matches!(
        (from, to),
        (CaseWorkflowState::New, CaseWorkflowState::Assigned)
            | (CaseWorkflowState::Assigned, CaseWorkflowState::InReview)
            | (CaseWorkflowState::InReview, CaseWorkflowState::Closed)
            | (CaseWorkflowState::New, CaseWorkflowState::Closed)
    );
    if valid {
        Ok(())
    } else {
        Err(XdrError::Case(format!(
            "invalid case transition {from:?} -> {to:?}"
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn assigns_investigator_and_comments() {
        let engine = CaseManagementEngine::new();
        let case_record = engine.create_case(Uuid::new_v4(), "Investigation", None);
        engine
            .assign_investigator(case_record.id, "analyst-1")
            .unwrap();
        engine
            .add_comment(case_record.id, "analyst-1", "Initial triage complete")
            .unwrap();
        assert_eq!(engine.comment_count(case_record.id), 1);
    }

    #[test]
    fn workflow_transitions() {
        let engine = CaseManagementEngine::new();
        let case_record = engine.create_case(Uuid::new_v4(), "Case", None);
        engine
            .assign_investigator(case_record.id, "analyst")
            .unwrap();
        engine
            .transition(case_record.id, CaseWorkflowState::InReview)
            .unwrap();
        engine
            .transition(case_record.id, CaseWorkflowState::Closed)
            .unwrap();
        assert_eq!(
            engine.get_case(case_record.id).unwrap().workflow_state,
            CaseWorkflowState::Closed
        );
    }
}
