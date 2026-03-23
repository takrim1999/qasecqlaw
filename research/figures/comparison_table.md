# OWASP Benchmark — Tool Comparison

## Overall Metrics

| Tool | TP | FP | TN | FN | Precision | Recall | F1 | FPR | Youden's J |
|------|----|----|----|----|-----------|--------|----|-----|------------|
| **QASecClaw** | 106 | 23 | 102 | 20 | 0.8217 | 0.8413 | 0.8314 | 0.1840 | 0.6573 |
| **Semgrep** | 117 | 109 | 16 | 9 | 0.5177 | 0.9286 | 0.6648 | 0.8720 | 0.0566 |

## Per-CWE F1 Score Comparison

| CWE | Category | QASecClaw F1 | Semgrep F1 |
|-----|----------|-------- | --------|
| CWE-78 | Command Injection | 0.8314 | 0.6648 |
