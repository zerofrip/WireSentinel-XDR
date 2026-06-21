# WireSentinel-XDR Architecture

```
Cloud → Controller → XDR Platform → SSE → ZTNA → Core → Guardian
```

## Data Flow

1. Telemetry ingested from Guardian, WFP/NDIS, SSE, ZTNA identity providers
2. EDR/NDR/ITDR engines analyze and emit detection events
3. DetectionEngine evaluates rules and triggers incidents
4. SOAR playbooks execute response actions via ResponseEngine
5. MITRE mapping correlates detections to ATT&CK techniques
6. Threat hunting queries Security Data Lake for historical analysis
