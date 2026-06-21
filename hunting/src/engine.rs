use chrono::Utc;
use datalake::{SecurityDataLake, SecurityQueryEngine};
use parking_lot::RwLock;
use shared_types::{
    Hunt, HuntQueryKind, HuntResult, HuntStatus, HuntTimeline, HuntTimelineEntry,
};
use uuid::Uuid;
use xdr_core::{XdrError, XdrResult};

struct HuntingState {
    hunts: Vec<Hunt>,
    results: Vec<HuntResult>,
}

impl Default for HuntingState {
    fn default() -> Self {
        Self {
            hunts: Vec::new(),
            results: Vec::new(),
        }
    }
}

/// Threat hunting engine backed by the security data lake.
pub struct ThreatHuntingEngine {
    lake: SecurityDataLake,
    state: RwLock<HuntingState>,
}

impl ThreatHuntingEngine {
    pub fn new(lake: SecurityDataLake) -> Self {
        Self {
            lake,
            state: RwLock::new(HuntingState::default()),
        }
    }

    pub fn lake(&self) -> &SecurityDataLake {
        &self.lake
    }

    pub fn create_hunt(
        &self,
        tenant_id: Uuid,
        name: impl Into<String>,
        query_kind: HuntQueryKind,
        query: impl Into<String>,
    ) -> Hunt {
        let hunt = Hunt {
            id: Uuid::new_v4(),
            tenant_id,
            name: name.into(),
            query_kind,
            query: query.into(),
            status: HuntStatus::Draft,
            created_at: Utc::now(),
            completed_at: None,
        };
        self.state.write().hunts.push(hunt.clone());
        hunt
    }

    pub fn run_hunt(&self, hunt_id: Uuid) -> XdrResult<Vec<HuntResult>> {
        let hunt = self
            .find_hunt(hunt_id)?
            .ok_or_else(|| XdrError::Hunting(format!("hunt {hunt_id} not found")))?;

        self.set_hunt_status(hunt_id, HuntStatus::Running);

        let query_engine = SecurityQueryEngine::new(&self.lake);
        let matches = match hunt.query_kind {
            HuntQueryKind::Historical => self.search_historical(&query_engine, &hunt),
            HuntQueryKind::Ioc => self.search_ioc(&query_engine, &hunt),
            HuntQueryKind::Behavioral => self.search_behavioral(&query_engine, &hunt),
            HuntQueryKind::Correlation => self.search_correlation(&query_engine, &hunt),
        };

        let mut state = self.state.write();
        state.results.extend(matches.iter().cloned());
        if let Some(h) = state.hunts.iter_mut().find(|h| h.id == hunt_id) {
            h.status = HuntStatus::Completed;
            h.completed_at = Some(Utc::now());
        }
        Ok(matches)
    }

    pub fn generate_timeline(&self, hunt_id: Uuid) -> XdrResult<HuntTimeline> {
        let results = self
            .state
            .read()
            .results
            .iter()
            .filter(|r| r.hunt_id == hunt_id)
            .cloned()
            .collect::<Vec<_>>();

        let entries = results
            .into_iter()
            .map(|r| HuntTimelineEntry {
                timestamp: r.matched_at,
                event_kind: r.event_kind,
                summary: r.summary,
                device_id: None,
            })
            .collect();

        Ok(HuntTimeline {
            hunt_id,
            entries,
            generated_at: Utc::now(),
        })
    }

    pub fn hunt_count(&self) -> usize {
        self.state.read().hunts.len()
    }

    fn find_hunt(&self, hunt_id: Uuid) -> XdrResult<Option<Hunt>> {
        Ok(self
            .state
            .read()
            .hunts
            .iter()
            .find(|h| h.id == hunt_id)
            .cloned())
    }

    fn set_hunt_status(&self, hunt_id: Uuid, status: HuntStatus) {
        if let Some(h) = self
            .state
            .write()
            .hunts
            .iter_mut()
            .find(|h| h.id == hunt_id)
        {
            h.status = status;
        }
    }

    fn search_historical(
        &self,
        query: &SecurityQueryEngine,
        hunt: &Hunt,
    ) -> Vec<HuntResult> {
        query
            .by_tenant(hunt.tenant_id)
            .into_iter()
            .filter(|e| e.event_kind.contains(&hunt.query))
            .map(|e| HuntResult {
                id: Uuid::new_v4(),
                hunt_id: hunt.id,
                event_kind: e.event_kind,
                summary: e.payload.to_string(),
                matched_at: e.ingested_at,
            })
            .collect()
    }

    fn search_ioc(&self, query: &SecurityQueryEngine, hunt: &Hunt) -> Vec<HuntResult> {
        query
            .by_tenant(hunt.tenant_id)
            .into_iter()
            .filter(|e| e.payload.to_string().contains(&hunt.query))
            .map(|e| HuntResult {
                id: Uuid::new_v4(),
                hunt_id: hunt.id,
                event_kind: e.event_kind,
                summary: format!("IOC match: {}", hunt.query),
                matched_at: e.ingested_at,
            })
            .collect()
    }

    fn search_behavioral(
        &self,
        query: &SecurityQueryEngine,
        hunt: &Hunt,
    ) -> Vec<HuntResult> {
        let needle = hunt.query.to_lowercase();
        query
            .by_kind("behavior")
            .into_iter()
            .filter(|e| e.tenant_id == hunt.tenant_id)
            .filter(|e| e.payload.to_string().to_lowercase().contains(&needle))
            .map(|e| HuntResult {
                id: Uuid::new_v4(),
                hunt_id: hunt.id,
                event_kind: e.event_kind,
                summary: "Behavioral pattern matched".into(),
                matched_at: e.ingested_at,
            })
            .collect()
    }

    fn search_correlation(
        &self,
        query: &SecurityQueryEngine,
        hunt: &Hunt,
    ) -> Vec<HuntResult> {
        let kinds: Vec<&str> = hunt.query.split('+').map(str::trim).collect();
        if kinds.len() < 2 {
            return Vec::new();
        }

        let first = query.by_kind(kinds[0]);
        let second = query.by_kind(kinds[1]);
        if first.is_empty() || second.is_empty() {
            return Vec::new();
        }

        vec![HuntResult {
            id: Uuid::new_v4(),
            hunt_id: hunt.id,
            event_kind: "correlation".into(),
            summary: format!("Correlated {} with {}", kinds[0], kinds[1]),
            matched_at: Utc::now(),
        }]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use shared_types::RetentionPolicy;

    #[test]
    fn runs_ioc_hunt() {
        let lake = SecurityDataLake::new(RetentionPolicy::Days30);
        let tenant = Uuid::new_v4();
        lake.ingest(
            tenant,
            "process",
            serde_json::json!({"hash": "evil"}),
        );
        let engine = ThreatHuntingEngine::new(lake);
        let hunt = engine.create_hunt(tenant, "ioc-hunt", HuntQueryKind::Ioc, "evil");
        let results = engine.run_hunt(hunt.id).unwrap();
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn generates_timeline() {
        let engine = ThreatHuntingEngine::new(SecurityDataLake::default());
        let tenant = Uuid::new_v4();
        let hunt = engine.create_hunt(tenant, "timeline", HuntQueryKind::Historical, "login");
        engine.run_hunt(hunt.id).unwrap();
        let timeline = engine.generate_timeline(hunt.id).unwrap();
        assert_eq!(timeline.hunt_id, hunt.id);
    }
}
