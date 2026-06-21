use shared_types::{
    CaseWorkflowState, DetectionRule, Hunt, IncidentStatus, Playbook, ResponseActionRequest,
    ServiceEvent, ServiceEventInner, XdrSecurityPolicy, XdrSecurityViolationDetail,
};

use crate::{XdrError, XdrEventEmitter, XdrResult};

/// Validates XDR mutations against tenant security policy.
pub struct XdrSecurityPolicyEngine<E: XdrEventEmitter> {
    emitter: E,
}

impl<E: XdrEventEmitter> XdrSecurityPolicyEngine<E> {
    pub fn new(emitter: E) -> Self {
        Self { emitter }
    }

    pub fn validate_detection_rule(
        &self,
        policy: &XdrSecurityPolicy,
        rule: &DetectionRule,
    ) -> XdrResult<()> {
        let cond_count = rule
            .conditions
            .as_array()
            .map(|a| a.len() as u32)
            .unwrap_or(1);
        if cond_count > policy.max_detection_rule_conditions {
            self.violation("detection_rule", "too many conditions", &rule.name);
            return Err(XdrError::Security(
                "detection rule exceeds condition limit".into(),
            ));
        }
        if rule.conditions.to_string().contains("'; DROP") {
            self.violation("detection_rule", "dangerous pattern", &rule.name);
            return Err(XdrError::Security(
                "dangerous detection rule pattern".into(),
            ));
        }
        Ok(())
    }

    pub fn validate_playbook(
        &self,
        policy: &XdrSecurityPolicy,
        playbook: &Playbook,
    ) -> XdrResult<()> {
        if !policy
            .allowed_playbook_kinds
            .contains(&playbook.playbook_kind)
        {
            self.violation("playbook", "playbook kind not allowed", &playbook.name);
            return Err(XdrError::Security("playbook kind not permitted".into()));
        }
        Ok(())
    }

    pub fn validate_response(
        &self,
        policy: &XdrSecurityPolicy,
        request: &ResponseActionRequest,
    ) -> XdrResult<()> {
        if !policy
            .allowed_response_actions
            .contains(&request.action_kind)
        {
            self.violation("response", "action not allowed", &request.target);
            return Err(XdrError::Security("response action not permitted".into()));
        }
        Ok(())
    }

    pub fn validate_incident_transition(
        &self,
        from: IncidentStatus,
        to: IncidentStatus,
    ) -> XdrResult<()> {
        let valid = matches!(
            (from, to),
            (IncidentStatus::Open, IncidentStatus::Investigating)
                | (IncidentStatus::Investigating, IncidentStatus::Contained)
                | (IncidentStatus::Contained, IncidentStatus::Resolved)
                | (IncidentStatus::Resolved, IncidentStatus::Closed)
                | (IncidentStatus::Open, IncidentStatus::Closed)
        );
        if !valid {
            return Err(XdrError::Security(format!(
                "invalid incident transition {:?} -> {:?}",
                from, to
            )));
        }
        Ok(())
    }

    pub fn validate_hunt_query(&self, policy: &XdrSecurityPolicy, hunt: &Hunt) -> XdrResult<()> {
        let dangerous = ["';", "--", "DROP TABLE", "DELETE FROM"];
        if dangerous
            .iter()
            .any(|p| hunt.query.to_uppercase().contains(&p.to_uppercase()))
        {
            if !policy.allow_dangerous_hunt_queries {
                self.violation("hunt", "dangerous query pattern", &hunt.name);
                return Err(XdrError::Security("dangerous hunt query".into()));
            }
        }
        Ok(())
    }

    pub fn validate_case_transition(
        &self,
        from: CaseWorkflowState,
        to: CaseWorkflowState,
    ) -> XdrResult<()> {
        let valid = matches!(
            (from, to),
            (CaseWorkflowState::New, CaseWorkflowState::Assigned)
                | (CaseWorkflowState::Assigned, CaseWorkflowState::InReview)
                | (CaseWorkflowState::InReview, CaseWorkflowState::Closed)
                | (CaseWorkflowState::New, CaseWorkflowState::Closed)
        );
        if !valid {
            return Err(XdrError::Security(format!(
                "invalid case transition {:?} -> {:?}",
                from, to
            )));
        }
        Ok(())
    }

    fn violation(&self, violation_type: &str, detail: &str, resource: &str) {
        let _detail = XdrSecurityViolationDetail {
            violation_type: violation_type.to_string(),
            detail: detail.to_string(),
            resource: resource.to_string(),
        };
        self.emitter
            .emit(ServiceEvent::now(ServiceEventInner::XdrSecurityViolation {
                violation_type: violation_type.to_string(),
                detail: format!("{}: {}", detail, resource),
            }));
    }
}
