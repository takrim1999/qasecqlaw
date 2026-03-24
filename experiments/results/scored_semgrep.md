# Benchmark Results — Semgrep

## Overall Metrics

| Metric | Value |
|--------|-------|
| TP | 1273 |
| FP | 560 |
| TN | 765 |
| FN | 142 |
| Precision | 0.6945 |
| Recall | 0.8996 |
| F1 | 0.7839 |
| FPR | 0.4226 |
| Youdens_J | 0.477 |
| Total_Cases | 2740 |

## Per-CWE Breakdown

| CWE | Category | TP | FP | TN | FN | Precision | Recall | F1 | FPR | Youden's J |
|-----|----------|----|----|----|----|-----------|--------|----|-----|------------|
| CWE-22 | Path Traversal | 120 | 106 | 29 | 13 | 0.5310 | 0.9023 | 0.6685 | 0.7852 | 0.1171 |
| CWE-78 | Command Injection | 117 | 109 | 16 | 9 | 0.5177 | 0.9286 | 0.6648 | 0.8720 | 0.0566 |
| CWE-79 | Cross-Site Scripting (XSS) | 202 | 108 | 101 | 44 | 0.6516 | 0.8211 | 0.7266 | 0.5167 | 0.3044 |
| CWE-89 | SQL Injection | 253 | 170 | 62 | 19 | 0.5981 | 0.9301 | 0.7281 | 0.7328 | 0.1974 |
| CWE-90 | LDAP Injection | 26 | 28 | 4 | 1 | 0.4815 | 0.9630 | 0.6420 | 0.8750 | 0.0880 |
| CWE-327 | Weak Cryptography | 130 | 0 | 116 | 0 | 1.0000 | 1.0000 | 1.0000 | 0.0000 | 1.0000 |
| CWE-328 | Weak Hashing | 89 | 0 | 107 | 40 | 1.0000 | 0.6899 | 0.8165 | 0.0000 | 0.6899 |
| CWE-330 | Weak Randomness | 218 | 0 | 275 | 0 | 1.0000 | 1.0000 | 1.0000 | 0.0000 | 1.0000 |
| CWE-501 | Trust Boundary Violation | 68 | 26 | 17 | 15 | 0.7234 | 0.8193 | 0.7684 | 0.6047 | 0.2146 |
| CWE-614 | Insecure Cookie | 36 | 0 | 31 | 0 | 1.0000 | 1.0000 | 1.0000 | 0.0000 | 1.0000 |
| CWE-643 | XPath Injection | 14 | 13 | 7 | 1 | 0.5185 | 0.9333 | 0.6667 | 0.6500 | 0.2833 |
