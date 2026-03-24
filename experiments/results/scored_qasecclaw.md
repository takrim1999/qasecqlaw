# Benchmark Results — QASecClaw

## Overall Metrics

| Metric | Value |
|--------|-------|
| TP | 1233 |
| FP | 64 |
| TN | 1261 |
| FN | 182 |
| Precision | 0.9507 |
| Recall | 0.8714 |
| F1 | 0.9093 |
| FPR | 0.0483 |
| Youdens_J | 0.8231 |
| Total_Cases | 2740 |

## Per-CWE Breakdown

| CWE | Category | TP | FP | TN | FN | Precision | Recall | F1 | FPR | Youden's J |
|-----|----------|----|----|----|----|-----------|--------|----|-----|------------|
| CWE-22 | Path Traversal | 119 | 14 | 121 | 14 | 0.8947 | 0.8947 | 0.8947 | 0.1037 | 0.7910 |
| CWE-78 | Command Injection | 115 | 25 | 100 | 11 | 0.8214 | 0.9127 | 0.8647 | 0.2000 | 0.7127 |
| CWE-79 | Cross-Site Scripting (XSS) | 202 | 3 | 206 | 44 | 0.9854 | 0.8211 | 0.8958 | 0.0144 | 0.8068 |
| CWE-89 | SQL Injection | 253 | 13 | 219 | 19 | 0.9511 | 0.9301 | 0.9405 | 0.0560 | 0.8741 |
| CWE-90 | LDAP Injection | 26 | 8 | 24 | 1 | 0.7647 | 0.9630 | 0.8525 | 0.2500 | 0.7130 |
| CWE-327 | Weak Cryptography | 129 | 0 | 116 | 1 | 1.0000 | 0.9923 | 0.9961 | 0.0000 | 0.9923 |
| CWE-328 | Weak Hashing | 86 | 0 | 107 | 43 | 1.0000 | 0.6667 | 0.8000 | 0.0000 | 0.6667 |
| CWE-330 | Weak Randomness | 218 | 0 | 275 | 0 | 1.0000 | 1.0000 | 1.0000 | 0.0000 | 1.0000 |
| CWE-501 | Trust Boundary Violation | 35 | 0 | 43 | 48 | 1.0000 | 0.4217 | 0.5932 | 0.0000 | 0.4217 |
| CWE-614 | Insecure Cookie | 36 | 0 | 31 | 0 | 1.0000 | 1.0000 | 1.0000 | 0.0000 | 1.0000 |
| CWE-643 | XPath Injection | 14 | 1 | 19 | 1 | 0.9333 | 0.9333 | 0.9333 | 0.0500 | 0.8833 |
