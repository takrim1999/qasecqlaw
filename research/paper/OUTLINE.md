## QASecClaw paper outline (draft)

### Abstract
Multi-agent QA + Security + Log Intelligence framework evaluated against
the OWASP Benchmark with research-standard metrics.

### 1. Introduction
- Motivation: cross-layer QA + security + logs
- Contributions: multi-agent pipeline + correlation + rigorous benchmark evaluation

### 2. System Overview
- Architecture: orchestrator + seven agents
- Evidence model and immutable audit trail

### 3. Research Questions
- **RQ1**: How does QASecClaw compare to standalone SAST tools (Semgrep) on
  standardized vulnerability benchmarks (Precision, Recall, F1)?
- **RQ2**: Does QASecClaw's multi-agent correlation reduce false positives
  compared to individual security scanners?
- **RQ3**: How does detection performance vary across CWE categories
  (Command Injection, SQL Injection, XSS, Path Traversal, etc.)?

### 4. Datasets
- **OWASP Benchmark v1.2** — 2,740 Java test cases across 11 CWE categories
  with ground-truth labels (real vulnerability vs. false positive)
  - Source: `expectedresults-1.2.csv`
  - Test code: `src/main/java/org/owasp/benchmark/testcode/`

### 5. Experimental Setup
- **QASecClaw**: Full multi-agent pipeline (Test Planning → Security Validation → 
  Evidence Correlation → Report)
- **Baselines**: Semgrep CE (standalone SAST) with `auto` ruleset
- **Evaluation**: Cross-reference tool findings against OWASP ground truth
  at the test-case level (BenchmarkTestNNNNN)
- **CWE focus (initial)**: CWE-78 (Command Injection), then expand to all categories

### 6. Metrics
- **Precision** = TP / (TP + FP)
- **Recall (TPR)** = TP / (TP + FN)
- **F1-Score** = 2 × P × R / (P + R)
- **False Positive Rate (FPR)** = FP / (FP + TN)
- **Youden's J** = TPR − FPR (OWASP Benchmark's primary ranking metric)

### 7. Results
- **Table 1**: Overall comparison (QASecClaw vs. Semgrep)
- **Table 2**: Per-CWE breakdown
- **Figure 1**: Bar chart — Precision/Recall/F1 comparison
- **Figure 2**: Radar chart — Per-CWE F1 scores
- **Figure 3**: Confusion matrices

### 8. Discussion & Threats to Validity
- Ground truth accuracy (OWASP Benchmark is synthetic but standardized)
- LLM variation across runs
- Matching granularity (file-level vs. line-level)

### 9. Conclusion
