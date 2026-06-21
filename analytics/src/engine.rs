use chrono::Utc;
use parking_lot::RwLock;
use shared_types::{
    DetectionTrigger, Incident, IncidentStatus, TechniqueDetection, XdrAnalyticsSummary,
    XdrSeverity,
};
use uuid::Uuid;

struct AnalyticsState {
    incidents: Vec<Incident>,
    detections: Vec<DetectionTrigger>,
    techniques: Vec<TechniqueDetection>,
}

impl Default for AnalyticsState {
    fn default() -> Self {
        Self {
            incidents: Vec::new(),
            detections: Vec::new(),
            techniques: Vec::new(),
        }
    }
}

/// Aggregates incidents, detections, and MITRE coverage into fleet analytics.
pub struct XdrAnalyticsService {
    state: RwLock<AnalyticsState>,
}

impl XdrAnalyticsService {
    pub fn new() -> Self {
        Self {
            state: RwLock::new(AnalyticsState::default()),
        }
    }

    pub fn record_incident(&self, incident: Incident) {
        self.state.write().incidents.push(incident);
    }

    pub fn record_detection(&self, trigger: DetectionTrigger) {
        self.state.write().detections.push(trigger);
    }

    pub fn record_technique(&self, detection: TechniqueDetection) {
        self.state.write().techniques.push(detection);
    }

    pub fn summarize(&self, tenant_id: Uuid, mitre_coverage_pct: f64) -> XdrAnalyticsSummary {
        let state = self.state.read();
        let tenant_incidents: Vec<_> = state
            .incidents
            .iter()
            .filter(|i| i.tenant_id == tenant_id)
            .collect();

        let open = tenant_incidents
            .iter()
            .filter(|i| {
                matches!(
                    i.status,
                    IncidentStatus::Open | IncidentStatus::Investigating
                )
            })
            .count() as u64;

        let critical = tenant_incidents
            .iter()
            .filter(|i| i.severity == XdrSeverity::Critical)
            .count() as u64;

        let total_detections = state
            .detections
            .iter()
            .filter(|d| {
                tenant_incidents
                    .iter()
                    .any(|i| i.detection_id == Some(d.id))
            })
            .count() as u64;

        let techniques_detected = state.techniques.len() as u32;

        let mttr_hours = compute_mttr(&tenant_incidents);

        let fleet_threat_score =
            compute_threat_score(open, critical, total_detections, techniques_detected);

        XdrAnalyticsSummary {
            tenant_id,
            total_incidents: tenant_incidents.len() as u64,
            open_incidents: open,
            critical_incidents: critical,
            total_detections,
            mitre_techniques_detected: techniques_detected,
            mitre_coverage_pct,
            avg_incident_mttr_hours: mttr_hours,
            fleet_threat_score,
            computed_at: Utc::now(),
        }
    }
}

impl Default for XdrAnalyticsService {
    fn default() -> Self {
        Self::new()
    }
}

fn compute_mttr(incidents: &[&Incident]) -> f64 {
    let resolved: Vec<_> = incidents
        .iter()
        .filter_map(|i| {
            i.resolved_at
                .map(|r| (r - i.created_at).num_minutes() as f64 / 60.0)
        })
        .collect();
    if resolved.is_empty() {
        return 0.0;
    }
    resolved.iter().sum::<f64>() / resolved.len() as f64
}

fn compute_threat_score(open: u64, critical: u64, detections: u64, techniques: u32) -> f64 {
    (open as f64 * 2.0 + critical as f64 * 5.0 + detections as f64 + techniques as f64 * 3.0)
        .min(100.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn summarizes_tenant_metrics() {
        let svc = XdrAnalyticsService::new();
        let tenant = Uuid::new_v4();
        let now = Utc::now();
        svc.record_incident(Incident {
            id: Uuid::new_v4(),
            tenant_id: tenant,
            title: "Critical breach".into(),
            description: None,
            severity: XdrSeverity::Critical,
            status: IncidentStatus::Open,
            detection_id: None,
            assigned_to: None,
            created_at: now,
            updated_at: now,
            resolved_at: None,
        });
        let summary = svc.summarize(tenant, 50.0);
        assert_eq!(summary.total_incidents, 1);
        assert_eq!(summary.critical_incidents, 1);
    }

    #[test]
    fn computes_threat_score() {
        let score = compute_threat_score(2, 1, 5, 2);
        assert!(score > 0.0);
        assert!(score <= 100.0);
    }
}
