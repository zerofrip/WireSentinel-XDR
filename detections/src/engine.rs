use chrono::Utc;
use parking_lot::RwLock;
use shared_types::{
    DetectionMatch, DetectionRule, DetectionRuleKind, DetectionTrigger, ServiceEventInner,
};
use uuid::Uuid;
use xdr_core::{XdrEventEmitter, XdrResult};

struct DetectionState {
    rules: Vec<DetectionRule>,
    matches: Vec<DetectionMatch>,
    triggers: Vec<DetectionTrigger>,
    event_buffer: Vec<serde_json::Value>,
}

impl Default for DetectionState {
    fn default() -> Self {
        Self {
            rules: Vec::new(),
            matches: Vec::new(),
            triggers: Vec::new(),
            event_buffer: Vec::new(),
        }
    }
}

/// Sigma-inspired detection engine with behavioral, correlation, and scheduled rules.
pub struct DetectionEngine<E: XdrEventEmitter> {
    emitter: E,
    state: RwLock<DetectionState>,
}

impl<E: XdrEventEmitter> DetectionEngine<E> {
    pub fn new(emitter: E) -> Self {
        Self {
            emitter,
            state: RwLock::new(DetectionState::default()),
        }
    }

    pub fn add_rule(&self, rule: DetectionRule) -> XdrResult<()> {
        self.state.write().rules.push(rule);
        Ok(())
    }

    pub fn ingest_event(&self, event: serde_json::Value) -> XdrResult<Vec<DetectionTrigger>> {
        self.state.write().event_buffer.push(event.clone());
        let rules = self.state.read().rules.clone();
        let mut triggers = Vec::new();

        for rule in rules.into_iter().filter(|r| r.enabled) {
            if let Some(trigger) = self.evaluate_rule(&rule, &event)? {
                triggers.push(trigger);
            }
        }

        if !triggers.is_empty() {
            let mut state = self.state.write();
            for trigger in &triggers {
                state.triggers.push(trigger.clone());
                self.emitter.emit(shared_types::ServiceEvent::now(
                    ServiceEventInner::DetectionTriggered {
                        trigger: trigger.clone(),
                    },
                ));
            }
        }

        Ok(triggers)
    }

    pub fn run_scheduled_rules(&self) -> XdrResult<Vec<DetectionTrigger>> {
        let rules = self
            .state
            .read()
            .rules
            .iter()
            .filter(|r| r.enabled && r.rule_kind == DetectionRuleKind::Scheduled)
            .cloned()
            .collect::<Vec<_>>();

        let events = self.state.read().event_buffer.clone();
        let mut triggers = Vec::new();

        for rule in rules {
            for event in &events {
                if let Some(trigger) = self.evaluate_rule(&rule, event)? {
                    triggers.push(trigger);
                }
            }
        }

        Ok(triggers)
    }

    pub fn rule_count(&self) -> usize {
        self.state.read().rules.len()
    }

    pub fn trigger_count(&self) -> usize {
        self.state.read().triggers.len()
    }

    fn evaluate_rule(
        &self,
        rule: &DetectionRule,
        event: &serde_json::Value,
    ) -> XdrResult<Option<DetectionTrigger>> {
        let matched = match rule.rule_kind {
            DetectionRuleKind::SigmaInspired => self.eval_sigma(&rule.conditions, event),
            DetectionRuleKind::Behavioral => self.eval_behavioral(&rule.conditions, event),
            DetectionRuleKind::Correlation => self.eval_correlation(&rule.conditions, event),
            DetectionRuleKind::Scheduled => self.eval_sigma(&rule.conditions, event),
        };

        if !matched {
            return Ok(None);
        }

        let match_record = DetectionMatch {
            id: Uuid::new_v4(),
            rule_id: rule.id,
            device_id: event.get("device_id").and_then(|v| v.as_str()).and_then(|s| Uuid::parse_str(s).ok()),
            user_id: event.get("user_id").and_then(|v| v.as_str()).map(str::to_string),
            summary: format!("Rule '{}' matched", rule.name),
            matched_at: Utc::now(),
        };

        self.state.write().matches.push(match_record.clone());

        Ok(Some(DetectionTrigger {
            id: Uuid::new_v4(),
            rule_id: rule.id,
            match_id: match_record.id,
            severity: rule.severity,
            title: rule.name.clone(),
            triggered_at: Utc::now(),
        }))
    }

    fn eval_sigma(&self, conditions: &serde_json::Value, event: &serde_json::Value) -> bool {
        let Some(selection) = conditions.get("selection") else {
            return false;
        };

        if let Some(obj) = selection.as_object() {
            return obj.iter().all(|(key, expected)| {
                event
                    .get(key)
                    .is_some_and(|actual| values_match(expected, actual))
            });
        }

        false
    }

    fn eval_behavioral(&self, conditions: &serde_json::Value, event: &serde_json::Value) -> bool {
        let threshold = conditions
            .get("count_threshold")
            .and_then(|v| v.as_u64())
            .unwrap_or(3) as usize;
        let field = conditions
            .get("field")
            .and_then(|v| v.as_str())
            .unwrap_or("event_kind");
        let value = event.get(field).and_then(|v| v.as_str()).unwrap_or("");

        let count = self
            .state
            .read()
            .event_buffer
            .iter()
            .filter(|e| e.get(field).and_then(|v| v.as_str()) == Some(value))
            .count();

        count >= threshold
    }

    fn eval_correlation(&self, conditions: &serde_json::Value, event: &serde_json::Value) -> bool {
        let kinds = conditions
            .get("event_kinds")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();

        if kinds.is_empty() {
            return false;
        }

        let current = event.get("event_kind").and_then(|v| v.as_str()).unwrap_or("");
        if !kinds.iter().any(|k| k.as_str() == Some(current)) {
            return false;
        }

        let buffer = self.state.read().event_buffer.clone();
        kinds.iter().all(|kind| {
            buffer
                .iter()
                .any(|e| e.get("event_kind").and_then(|v| v.as_str()) == kind.as_str())
        })
    }
}

fn values_match(expected: &serde_json::Value, actual: &serde_json::Value) -> bool {
    match expected {
        serde_json::Value::String(s) => actual.as_str() == Some(s.as_str()),
        serde_json::Value::Number(n) => actual.as_number() == Some(n),
        serde_json::Value::Bool(b) => actual.as_bool() == Some(*b),
        serde_json::Value::Array(arr) => arr.iter().any(|v| values_match(v, actual)),
        _ => expected == actual,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use shared_types::{DetectionRuleKind, XdrSeverity};
    use xdr_core::CollectingEmitter;

    fn sample_rule() -> DetectionRule {
        DetectionRule {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            name: "Suspicious PowerShell".into(),
            rule_kind: DetectionRuleKind::SigmaInspired,
            enabled: true,
            conditions: serde_json::json!({
                "selection": {
                    "event_kind": "process",
                    "process_name": "powershell.exe"
                }
            }),
            severity: XdrSeverity::High,
            mitre_technique_ids: vec!["T1059.001".into()],
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    #[test]
    fn sigma_rule_triggers_detection() {
        let emitter = CollectingEmitter::new();
        let engine = DetectionEngine::new(&emitter);
        engine.add_rule(sample_rule()).unwrap();
        let triggers = engine
            .ingest_event(serde_json::json!({
                "event_kind": "process",
                "process_name": "powershell.exe"
            }))
            .unwrap();
        assert_eq!(triggers.len(), 1);
        assert_eq!(emitter.drain().len(), 1);
    }

    #[test]
    fn behavioral_rule_counts_events() {
        let emitter = CollectingEmitter::new();
        let engine = DetectionEngine::new(&emitter);
        engine
            .add_rule(DetectionRule {
                rule_kind: DetectionRuleKind::Behavioral,
                conditions: serde_json::json!({
                    "field": "user_id",
                    "count_threshold": 3
                }),
                ..sample_rule()
            })
            .unwrap();

        for _ in 0..3 {
            engine
                .ingest_event(serde_json::json!({"user_id": "bob", "event_kind": "login"}))
                .unwrap();
        }
        assert!(engine.trigger_count() >= 1);
    }
}
