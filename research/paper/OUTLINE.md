## QASecClaw paper outline (draft)

### Abstract

### 1. Introduction
- Motivation: cross-layer QA + security + logs
- Contributions: multi-agent pipeline + correlation

### 2. System Overview
- Architecture: orchestrator + seven agents
- Evidence model and immutable audit trail

### 3. Datasets
- OWASP Benchmark, DVWA, WebGoat
- Defects4J, Bugs.jar, CodeXGLUE
- LogHub (HDFS/BGL/Thunderbird)
- WebArena

### 4. Experimental Setup
- 5% sampling policy (reproducible seeds)
- Baselines: Semgrep, ZAP, Snyk (+ standard test suites where applicable)

### 5. Metrics
- Precision/recall/FPR for vuln detection
- Bug detection rate and localization accuracy
- Anomaly detection and root cause accuracy for logs

### 6. Results
- Tables/plots (generated under `research/figures/`)

### 7. Discussion & Threats to Validity

### 8. Conclusion

