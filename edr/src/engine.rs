use chrono::Utc;
use parking_lot::RwLock;
use shared_types::{
    DriverEvent, EdrServiceEvent, FileEvent, MaliciousExecution, PersistenceFinding,
    ProcessAnomaly, ProcessEvent, RegistryEvent, ServiceEventInner, XdrSeverity,
};
use uuid::Uuid;
use xdr_core::{XdrEventEmitter, XdrResult};

const PERSISTENCE_REGISTRY_PREFIXES: &[&str] = &[
    "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
    "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
    "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
];

const MALICIOUS_HASHES: &[&str] = &[
    "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
    "badc0ffeebadc0ffeebadc0ffeebadc0ffeebadc0ffeebadc0ffeebadc0ffee",
];

const SUSPICIOUS_CMDLINE: &[&str] = &["-enc ", "powershell -e", "cmd /c certutil", "mimikatz"];

struct EdrState {
    processes: Vec<ProcessEvent>,
    files: Vec<FileEvent>,
    registry: Vec<RegistryEvent>,
    services: Vec<EdrServiceEvent>,
    drivers: Vec<DriverEvent>,
}

impl Default for EdrState {
    fn default() -> Self {
        Self {
            processes: Vec::new(),
            files: Vec::new(),
            registry: Vec::new(),
            services: Vec::new(),
            drivers: Vec::new(),
        }
    }
}

/// Endpoint detection engine for process, file, registry, service, and driver telemetry.
pub struct EdrEngine<E: XdrEventEmitter> {
    emitter: E,
    state: RwLock<EdrState>,
}

impl<E: XdrEventEmitter> EdrEngine<E> {
    pub fn new(emitter: E) -> Self {
        Self {
            emitter,
            state: RwLock::new(EdrState::default()),
        }
    }

    pub fn ingest_process(&self, event: ProcessEvent) -> XdrResult<()> {
        self.analyze_process(&event);
        self.state.write().processes.push(event);
        Ok(())
    }

    pub fn ingest_file(&self, event: FileEvent) -> XdrResult<()> {
        self.analyze_file(&event);
        self.state.write().files.push(event);
        Ok(())
    }

    pub fn ingest_registry(&self, event: RegistryEvent) -> XdrResult<()> {
        self.analyze_registry(&event);
        self.state.write().registry.push(event);
        Ok(())
    }

    pub fn ingest_service(&self, event: EdrServiceEvent) -> XdrResult<()> {
        self.analyze_service(&event);
        self.state.write().services.push(event);
        Ok(())
    }

    pub fn ingest_driver(&self, event: DriverEvent) -> XdrResult<()> {
        self.analyze_driver(&event);
        self.state.write().drivers.push(event);
        Ok(())
    }

    pub fn process_count(&self) -> usize {
        self.state.read().processes.len()
    }

    pub fn file_count(&self) -> usize {
        self.state.read().files.len()
    }

    fn analyze_process(&self, event: &ProcessEvent) {
        let cmd = event.command_line.as_deref().unwrap_or("");
        let parent_missing = event.parent_pid.is_none() && event.process_name != "System";
        let suspicious_cmd = SUSPICIOUS_CMDLINE
            .iter()
            .any(|p| cmd.to_lowercase().contains(&p.to_lowercase()));

        if parent_missing || suspicious_cmd {
            let anomaly = ProcessAnomaly {
                id: Uuid::new_v4(),
                device_id: event.device_id,
                process_event_id: event.id,
                anomaly_kind: if suspicious_cmd {
                    "suspicious_command_line".into()
                } else {
                    "orphan_process".into()
                },
                severity: if suspicious_cmd {
                    XdrSeverity::High
                } else {
                    XdrSeverity::Medium
                },
                description: format!("Suspicious process: {}", event.process_name),
                detected_at: Utc::now(),
            };
            self.emitter.emit(shared_types::ServiceEvent::now(
                ServiceEventInner::ProcessAnomalyDetected { anomaly },
            ));
        }
    }

    fn analyze_file(&self, event: &FileEvent) {
        if let Some(hash) = &event.hash_sha256 {
            if MALICIOUS_HASHES.contains(&hash.as_str()) {
                let execution = MaliciousExecution {
                    id: Uuid::new_v4(),
                    device_id: event.device_id,
                    process_event_id: None,
                    file_event_id: Some(event.id),
                    indicator: hash.clone(),
                    severity: XdrSeverity::Critical,
                    detected_at: Utc::now(),
                };
                self.emitter.emit(shared_types::ServiceEvent::now(
                    ServiceEventInner::MaliciousExecutionDetected { execution },
                ));
            }
        }
    }

    fn analyze_registry(&self, event: &RegistryEvent) {
        if event.operation.eq_ignore_ascii_case("set")
            && PERSISTENCE_REGISTRY_PREFIXES
                .iter()
                .any(|p| event.key_path.starts_with(p))
        {
            let finding = PersistenceFinding {
                id: Uuid::new_v4(),
                device_id: event.device_id,
                persistence_kind: "registry_run_key".into(),
                target: event.key_path.clone(),
                severity: XdrSeverity::High,
                detected_at: Utc::now(),
            };
            self.emitter.emit(shared_types::ServiceEvent::now(
                ServiceEventInner::PersistenceDetected { finding },
            ));
        }
    }

    fn analyze_service(&self, event: &EdrServiceEvent) {
        if event.operation.eq_ignore_ascii_case("create")
            || event.operation.eq_ignore_ascii_case("start")
        {
            let finding = PersistenceFinding {
                id: Uuid::new_v4(),
                device_id: event.device_id,
                persistence_kind: "service".into(),
                target: event.service_name.clone(),
                severity: XdrSeverity::Medium,
                detected_at: Utc::now(),
            };
            self.emitter.emit(shared_types::ServiceEvent::now(
                ServiceEventInner::PersistenceDetected { finding },
            ));
        }
    }

    fn analyze_driver(&self, event: &DriverEvent) {
        if event.operation.eq_ignore_ascii_case("load") {
            let finding = PersistenceFinding {
                id: Uuid::new_v4(),
                device_id: event.device_id,
                persistence_kind: "driver".into(),
                target: event.driver_name.clone(),
                severity: XdrSeverity::High,
                detected_at: Utc::now(),
            };
            self.emitter.emit(shared_types::ServiceEvent::now(
                ServiceEventInner::PersistenceDetected { finding },
            ));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use xdr_core::CollectingEmitter;

    fn sample_process(cmd: Option<&str>) -> ProcessEvent {
        ProcessEvent {
            id: Uuid::new_v4(),
            device_id: Uuid::new_v4(),
            pid: 1234,
            parent_pid: None,
            process_name: "powershell.exe".into(),
            command_line: cmd.map(str::to_string),
            user: Some("SYSTEM".into()),
            observed_at: Utc::now(),
        }
    }

    #[test]
    fn detects_suspicious_process() {
        let emitter = CollectingEmitter::new();
        let engine = EdrEngine::new(&emitter);
        engine
            .ingest_process(sample_process(Some("powershell -enc ABC")))
            .unwrap();
        assert_eq!(engine.process_count(), 1);
        assert_eq!(emitter.drain().len(), 1);
    }

    #[test]
    fn detects_registry_persistence() {
        let emitter = CollectingEmitter::new();
        let engine = EdrEngine::new(&emitter);
        engine
            .ingest_registry(RegistryEvent {
                id: Uuid::new_v4(),
                device_id: Uuid::new_v4(),
                key_path: "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\evil".into(),
                value_name: Some("payload".into()),
                operation: "set".into(),
                observed_at: Utc::now(),
            })
            .unwrap();
        assert_eq!(emitter.drain().len(), 1);
    }
}
