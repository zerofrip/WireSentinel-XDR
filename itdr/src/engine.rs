use std::collections::HashMap;

use chrono::{DateTime, Utc};
use parking_lot::RwLock;
use shared_types::{
    IdentityRiskRecord, IdentityThreat, IdentityThreatKind, ServiceEventInner, XdrSeverity,
};
use uuid::Uuid;
use xdr_core::{XdrEventEmitter, XdrResult};

const IMPOSSIBLE_TRAVEL_KMH: f64 = 900.0;
const AUTH_FAILURE_THRESHOLD: u32 = 5;
const COMPROMISE_RISK_THRESHOLD: u8 = 80;

#[derive(Debug, Clone)]
pub struct AuthEvent {
    pub tenant_id: Uuid,
    pub user_id: String,
    pub success: bool,
    pub mfa_used: bool,
    pub source_ip: String,
    pub geo_location: Option<String>,
    pub observed_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
struct GeoLocation {
    latitude: f64,
    longitude: f64,
    label: String,
}

struct UserState {
    last_auth: Option<AuthEvent>,
    last_geo: Option<GeoLocation>,
    auth_failures: u32,
    risk_score: u8,
}

struct ItdrState {
    users: HashMap<String, UserState>,
    auth_events: Vec<AuthEvent>,
    threats: Vec<IdentityThreat>,
}

impl Default for ItdrState {
    fn default() -> Self {
        Self {
            users: HashMap::new(),
            auth_events: Vec::new(),
            threats: Vec::new(),
        }
    }
}

/// Identity threat detection engine.
pub struct IdentityThreatEngine<E: XdrEventEmitter> {
    emitter: E,
    state: RwLock<ItdrState>,
}

impl<E: XdrEventEmitter> IdentityThreatEngine<E> {
    pub fn new(emitter: E) -> Self {
        Self {
            emitter,
            state: RwLock::new(ItdrState::default()),
        }
    }

    pub fn ingest_auth(&self, event: AuthEvent) -> XdrResult<IdentityRiskRecord> {
        let (risk, pending) = self.analyze_auth(&event);
        for threat in pending {
            self.emitter.emit(shared_types::ServiceEvent::now(
                ServiceEventInner::IdentityThreatDetected {
                    threat: threat.clone(),
                },
            ));
            if threat.severity == XdrSeverity::Critical
                && threat.threat_kind == IdentityThreatKind::TokenTheft
            {
                self.emitter.emit(shared_types::ServiceEvent::now(
                    ServiceEventInner::IdentityCompromiseSuspected { threat },
                ));
            }
        }
        self.state.write().auth_events.push(event);
        Ok(risk)
    }

    pub fn threat_count(&self) -> usize {
        self.state.read().threats.len()
    }

    fn analyze_auth(&self, event: &AuthEvent) -> (IdentityRiskRecord, Vec<IdentityThreat>) {
        let mut state = self.state.write();
        let user = state
            .users
            .entry(event.user_id.clone())
            .or_insert_with(|| UserState {
                last_auth: None,
                last_geo: None,
                auth_failures: 0,
                risk_score: 0,
            });

        let mut factors = Vec::new();
        let mut pending = Vec::new();

        if !event.success {
            user.auth_failures += 1;
            if user.auth_failures >= AUTH_FAILURE_THRESHOLD {
                factors.push("excessive_auth_failures".into());
                pending.push(build_threat(
                    event,
                    IdentityThreatKind::ExcessiveAuthFailures,
                    XdrSeverity::Medium,
                    "Repeated authentication failures",
                ));
            }
        } else {
            user.auth_failures = 0;
        }

        if event.success && !event.mfa_used {
            factors.push("mfa_bypass".into());
            pending.push(build_threat(
                event,
                IdentityThreatKind::MfaBypass,
                XdrSeverity::High,
                "Authentication succeeded without MFA",
            ));
        }

        if let Some(geo) = parse_geo(event.geo_location.as_deref()) {
            if let (Some(prev), Some(prev_auth)) = (&user.last_geo, &user.last_auth) {
                let hours =
                    (event.observed_at - prev_auth.observed_at).num_seconds() as f64 / 3600.0;
                if hours > 0.0 {
                    let speed = haversine_km(prev, &geo) / hours;
                    if speed > IMPOSSIBLE_TRAVEL_KMH {
                        factors.push("impossible_travel".into());
                        pending.push(build_threat(
                            event,
                            IdentityThreatKind::ImpossibleTravel,
                            XdrSeverity::Critical,
                            &format!(
                                "Impossible travel from {} to {} ({speed:.0} km/h)",
                                prev.label, geo.label
                            ),
                        ));
                    }
                }
            }
            user.last_geo = Some(geo);
        }

        if !event.success && event.source_ip.starts_with("203.0.113.") {
            factors.push("credential_abuse".into());
            pending.push(build_threat(
                event,
                IdentityThreatKind::CredentialAbuse,
                XdrSeverity::High,
                "Credential abuse from known threat range",
            ));
        }

        user.risk_score = (user.risk_score + factors.len() as u8 * 15).min(100);
        user.last_auth = Some(event.clone());

        if user.risk_score >= COMPROMISE_RISK_THRESHOLD {
            pending.push(build_threat(
                event,
                IdentityThreatKind::TokenTheft,
                XdrSeverity::Critical,
                "Identity compromise suspected due to accumulated risk",
            ));
        }

        let risk_score = user.risk_score;
        for threat in &pending {
            state.threats.push(threat.clone());
        }

        (
            IdentityRiskRecord {
                id: Uuid::new_v4(),
                tenant_id: event.tenant_id,
                user_id: event.user_id.clone(),
                risk_score,
                factors,
                evaluated_at: Utc::now(),
            },
            pending,
        )
    }
}

fn build_threat(
    event: &AuthEvent,
    kind: IdentityThreatKind,
    severity: XdrSeverity,
    description: &str,
) -> IdentityThreat {
    IdentityThreat {
        id: Uuid::new_v4(),
        tenant_id: event.tenant_id,
        user_id: event.user_id.clone(),
        threat_kind: kind,
        severity,
        description: description.to_string(),
        source_ip: Some(event.source_ip.clone()),
        geo_location: event.geo_location.clone(),
        detected_at: Utc::now(),
    }
}

fn parse_geo(raw: Option<&str>) -> Option<GeoLocation> {
    let raw = raw?;
    let mut parts = raw.split(',');
    let lat: f64 = parts.next()?.parse().ok()?;
    let lon: f64 = parts.next()?.parse().ok()?;
    let label = parts.next().unwrap_or("unknown").to_string();
    Some(GeoLocation {
        latitude: lat,
        longitude: lon,
        label,
    })
}

fn haversine_km(a: &GeoLocation, b: &GeoLocation) -> f64 {
    let r = 6371.0_f64;
    let d_lat = (b.latitude - a.latitude).to_radians();
    let d_lon = (b.longitude - a.longitude).to_radians();
    let lat1 = a.latitude.to_radians();
    let lat2 = b.latitude.to_radians();
    let h = (d_lat / 2.0).sin().powi(2) + lat1.cos() * lat2.cos() * (d_lon / 2.0).sin().powi(2);
    2.0 * r * h.sqrt().asin()
}

#[cfg(test)]
mod tests {
    use super::*;
    use xdr_core::CollectingEmitter;

    fn auth(success: bool, mfa: bool, geo: &str) -> AuthEvent {
        AuthEvent {
            tenant_id: Uuid::new_v4(),
            user_id: "alice".into(),
            success,
            mfa_used: mfa,
            source_ip: "10.0.0.1".into(),
            geo_location: Some(geo.into()),
            observed_at: Utc::now(),
        }
    }

    #[test]
    fn detects_mfa_bypass() {
        let emitter = CollectingEmitter::new();
        let engine = IdentityThreatEngine::new(&emitter);
        engine
            .ingest_auth(auth(true, false, "40.0,-74.0,NYC"))
            .unwrap();
        assert_eq!(emitter.drain().len(), 1);
    }

    #[test]
    fn detects_auth_failures() {
        let emitter = CollectingEmitter::new();
        let engine = IdentityThreatEngine::new(&emitter);
        for _ in 0..5 {
            engine
                .ingest_auth(AuthEvent {
                    success: false,
                    mfa_used: false,
                    source_ip: "203.0.113.1".into(),
                    ..auth(false, false, "0,0,test")
                })
                .unwrap();
        }
        assert!(engine.threat_count() >= 2);
    }
}
