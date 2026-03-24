# OWASP Benchmark — Tool Comparison

## Overall Metrics

| Tool | TP | FP | TN | FN | Precision | Recall | F1 | FPR | Youden's J |
|------|----|----|----|----|-----------|--------|----|-----|------------|
| **QASecClaw** | 1233 | 64 | 1261 | 182 | 0.9507 | 0.8714 | 0.9093 | 0.0483 | 0.8231 |
| **Semgrep** | 1273 | 560 | 765 | 142 | 0.6945 | 0.8996 | 0.7839 | 0.4226 | 0.4770 |

## Per-CWE F1 Score Comparison

| CWE | Category | QASecClaw F1 | Semgrep F1 |
|-----|----------|-------- | --------|
| CWE-22 | Path Traversal | 0.8947 | 0.6685 |
| CWE-327 | Weak Crypto | 0.9961 | 1.0000 |
| CWE-328 | Weak Hashing | 0.8000 | 0.8165 |
| CWE-330 | Weak Random | 1.0000 | 1.0000 |
| CWE-501 | Trust Boundary | 0.5932 | 0.7684 |
| CWE-614 | Insecure Cookie | 1.0000 | 1.0000 |
| CWE-643 | XPath Injection | 0.9333 | 0.6667 |
| CWE-78 | Command Injection | 0.8647 | 0.6648 |
| CWE-79 | XSS | 0.8958 | 0.7266 |
| CWE-89 | SQL Injection | 0.9405 | 0.7281 |
| CWE-90 | LDAP Injection | 0.8525 | 0.6420 |
