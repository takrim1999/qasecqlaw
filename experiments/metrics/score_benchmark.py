#!/usr/bin/env python3
"""
QASecClaw Benchmark Scoring Engine
===================================
Cross-references QASecClaw (or any tool) findings against the OWASP Benchmark
ground truth (expectedresults-X.X.csv) to compute research-standard metrics:

  TP / FP / TN / FN → Precision, Recall, F1, FPR, Youden's J

Usage:
    python score_benchmark.py \
        --ground-truth /path/to/expectedresults-1.2.csv \
        --findings     /path/to/tool_findings.csv \
        [--cwe 78] \
        [--tool qasecclaw]
"""

from __future__ import annotations

import argparse
import csv
import json
import logging
import sys
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Final

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger(__name__)

# ── OWASP Benchmark category → CWE mapping ──────────────────────────
CATEGORY_TO_CWE: Final[dict[str, int]] = {
    "cmdi": 78,
    "sqli": 89,
    "xss": 79,
    "pathtraver": 22,
    "crypto": 327,
    "hash": 328,
    "weakrand": 330,
    "securecookie": 614,
    "trustbound": 501,
    "ldapi": 90,
    "xpathi": 643,
    "headerinjection": 113,
}

CWE_TO_CATEGORY: Final[dict[int, str]] = {v: k for k, v in CATEGORY_TO_CWE.items()}

CWE_NAMES: Final[dict[int, str]] = {
    78: "Command Injection",
    89: "SQL Injection",
    79: "Cross-Site Scripting (XSS)",
    22: "Path Traversal",
    327: "Weak Cryptography",
    328: "Weak Hashing",
    330: "Weak Randomness",
    614: "Insecure Cookie",
    501: "Trust Boundary Violation",
    90: "LDAP Injection",
    643: "XPath Injection",
    113: "HTTP Header Injection",
}


# ── Data classes ─────────────────────────────────────────────────────

@dataclass(frozen=True)
class GroundTruthEntry:
    """One row from OWASP Benchmark's expectedresults CSV."""
    test_name: str
    category: str
    is_vulnerable: bool
    cwe: int


@dataclass(frozen=True)
class ToolFinding:
    """A single finding reported by a tool, normalized to test-case level."""
    test_name: str
    tool: str
    cwe: int | None = None
    severity: str | None = None
    raw_id: str | None = None


@dataclass
class ConfusionMatrix:
    """Confusion matrix + derived metrics for one evaluation slice."""
    tp: int = 0
    fp: int = 0
    tn: int = 0
    fn: int = 0

    @property
    def precision(self) -> float:
        denom = self.tp + self.fp
        return self.tp / denom if denom > 0 else 0.0

    @property
    def recall(self) -> float:
        """Also known as True Positive Rate (TPR) / Sensitivity."""
        denom = self.tp + self.fn
        return self.tp / denom if denom > 0 else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        denom = p + r
        return 2 * p * r / denom if denom > 0 else 0.0

    @property
    def fpr(self) -> float:
        """False Positive Rate."""
        denom = self.fp + self.tn
        return self.fp / denom if denom > 0 else 0.0

    @property
    def youdens_j(self) -> float:
        """Youden's J statistic = TPR - FPR. OWASP Benchmark's primary metric."""
        return self.recall - self.fpr

    @property
    def total(self) -> int:
        return self.tp + self.fp + self.tn + self.fn

    def summary_dict(self) -> dict:
        return {
            "TP": self.tp,
            "FP": self.fp,
            "TN": self.tn,
            "FN": self.fn,
            "Precision": round(self.precision, 4),
            "Recall": round(self.recall, 4),
            "F1": round(self.f1, 4),
            "FPR": round(self.fpr, 4),
            "Youdens_J": round(self.youdens_j, 4),
            "Total_Cases": self.total,
        }


@dataclass
class BenchmarkResult:
    """Full evaluation result for one tool."""
    tool: str
    overall: ConfusionMatrix = field(default_factory=ConfusionMatrix)
    per_cwe: dict[int, ConfusionMatrix] = field(default_factory=dict)


# ── Parsing ──────────────────────────────────────────────────────────

def load_ground_truth(path: Path, cwe_filter: int | None = None) -> dict[str, GroundTruthEntry]:
    """
    Parse OWASP Benchmark expectedresults CSV.

    Format:
        # test name,category,real vulnerability,CWE
        BenchmarkTest00001,pathtraver,true,22
    """
    entries: dict[str, GroundTruthEntry] = {}
    with open(path, newline="", encoding="utf-8") as f:
        reader = csv.reader(f)
        for row in reader:
            if not row or row[0].startswith("#") or row[0].lower().startswith("benchmark version"):
                continue
            # Some CSVs have leading/trailing whitespace
            test_name = row[0].strip()
            category = row[1].strip().lower()
            is_vuln = row[2].strip().lower() == "true"
            cwe = int(row[3].strip())

            if cwe_filter is not None and cwe != cwe_filter:
                continue

            entries[test_name] = GroundTruthEntry(
                test_name=test_name,
                category=category,
                is_vulnerable=is_vuln,
                cwe=cwe,
            )
    log.info("Loaded %d ground truth entries from %s%s",
             len(entries), path,
             f" (filtered to CWE-{cwe_filter})" if cwe_filter else "")
    return entries


def load_findings_csv(path: Path, tool: str = "qasecclaw") -> dict[str, ToolFinding]:
    """
    Load tool findings from a normalized CSV.

    Expected columns: test_name, tool, [cwe], [severity], [raw_id]
    Only needs `test_name` at minimum — presence implies the tool flagged it.
    """
    findings: dict[str, ToolFinding] = {}
    with open(path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            test_name = row.get("test_name", "").strip()
            if not test_name:
                continue
            findings[test_name] = ToolFinding(
                test_name=test_name,
                tool=row.get("tool", tool).strip(),
                cwe=int(row["cwe"]) if row.get("cwe") else None,
                severity=row.get("severity"),
                raw_id=row.get("raw_id"),
            )
    log.info("Loaded %d findings from %s (tool=%s)", len(findings), path, tool)
    return findings


def parse_qasecclaw_report(report_path: Path) -> dict[str, ToolFinding]:
    """
    Parse a QASecClaw markdown report and extract which BenchmarkTestNNNNN
    files are flagged as vulnerable.

    Looks for `BenchmarkTestNNNNN` mentions in vulnerability tables
    (lines starting with `| ` and containing a test name).
    """
    import re
    findings: dict[str, ToolFinding] = {}
    test_pattern = re.compile(r"BenchmarkTest\d{5}")

    with open(report_path, encoding="utf-8") as f:
        for line in f:
            matches = test_pattern.findall(line)
            for test_name in matches:
                if test_name not in findings:
                    findings[test_name] = ToolFinding(
                        test_name=test_name,
                        tool="qasecclaw",
                    )
    log.info("Parsed %d findings from QASecClaw report %s", len(findings), report_path)
    return findings


# ── Scoring ──────────────────────────────────────────────────────────

def compute_metrics(
    ground_truth: dict[str, GroundTruthEntry],
    findings: dict[str, ToolFinding],
    tool: str = "qasecclaw",
) -> BenchmarkResult:
    """
    Cross-reference findings against ground truth and compute confusion matrix.

    For each test case in ground truth:
      - If ground_truth says vulnerable AND tool flagged it → TP
      - If ground_truth says safe AND tool flagged it → FP
      - If ground_truth says safe AND tool did NOT flag it → TN
      - If ground_truth says vulnerable AND tool did NOT flag it → FN
    """
    result = BenchmarkResult(tool=tool)

    for test_name, gt in ground_truth.items():
        flagged = test_name in findings

        # Ensure per-CWE matrix exists
        if gt.cwe not in result.per_cwe:
            result.per_cwe[gt.cwe] = ConfusionMatrix()

        cwe_cm = result.per_cwe[gt.cwe]

        if gt.is_vulnerable and flagged:
            result.overall.tp += 1
            cwe_cm.tp += 1
        elif not gt.is_vulnerable and flagged:
            result.overall.fp += 1
            cwe_cm.fp += 1
        elif not gt.is_vulnerable and not flagged:
            result.overall.tn += 1
            cwe_cm.tn += 1
        elif gt.is_vulnerable and not flagged:
            result.overall.fn += 1
            cwe_cm.fn += 1

    return result


# ── Output formatting ───────────────────────────────────────────────

def format_results_table(result: BenchmarkResult) -> str:
    """Generate a markdown comparison table from results."""
    lines = []
    lines.append(f"# Benchmark Results — {result.tool}")
    lines.append("")

    # Overall
    lines.append("## Overall Metrics")
    lines.append("")
    s = result.overall.summary_dict()
    lines.append("| Metric | Value |")
    lines.append("|--------|-------|")
    for k, v in s.items():
        lines.append(f"| {k} | {v} |")
    lines.append("")

    # Per-CWE breakdown
    if result.per_cwe:
        lines.append("## Per-CWE Breakdown")
        lines.append("")
        lines.append("| CWE | Category | TP | FP | TN | FN | Precision | Recall | F1 | FPR | Youden's J |")
        lines.append("|-----|----------|----|----|----|----|-----------|--------|----|-----|------------|")
        for cwe in sorted(result.per_cwe.keys()):
            cm = result.per_cwe[cwe]
            cat_name = CWE_NAMES.get(cwe, f"CWE-{cwe}")
            lines.append(
                f"| CWE-{cwe} | {cat_name} "
                f"| {cm.tp} | {cm.fp} | {cm.tn} | {cm.fn} "
                f"| {cm.precision:.4f} | {cm.recall:.4f} | {cm.f1:.4f} "
                f"| {cm.fpr:.4f} | {cm.youdens_j:.4f} |"
            )
        lines.append("")

    return "\n".join(lines)


def format_comparison_table(results: list[BenchmarkResult]) -> str:
    """Generate a side-by-side comparison table for multiple tools."""
    lines = []
    lines.append("# Tool Comparison — OWASP Benchmark")
    lines.append("")
    lines.append("| Tool | TP | FP | TN | FN | Precision | Recall | F1 | FPR | Youden's J |")
    lines.append("|------|----|----|----|----|-----------|--------|----|-----|------------|")
    for r in results:
        cm = r.overall
        lines.append(
            f"| **{r.tool}** "
            f"| {cm.tp} | {cm.fp} | {cm.tn} | {cm.fn} "
            f"| {cm.precision:.4f} | {cm.recall:.4f} | {cm.f1:.4f} "
            f"| {cm.fpr:.4f} | {cm.youdens_j:.4f} |"
        )
    lines.append("")

    # Per-CWE comparison table
    all_cwes = sorted(set().union(*(r.per_cwe.keys() for r in results)))
    if all_cwes:
        lines.append("## Per-CWE F1 Comparison")
        lines.append("")
        header = "| CWE | Category | " + " | ".join(f"{r.tool} F1" for r in results) + " |"
        sep = "|-----|----------|" + "|".join("--------" for _ in results) + "|"
        lines.append(header)
        lines.append(sep)
        for cwe in all_cwes:
            cat_name = CWE_NAMES.get(cwe, f"CWE-{cwe}")
            cells = []
            for r in results:
                cm = r.per_cwe.get(cwe)
                cells.append(f"{cm.f1:.4f}" if cm else "N/A")
            lines.append(f"| CWE-{cwe} | {cat_name} | " + " | ".join(cells) + " |")
        lines.append("")

    return "\n".join(lines)


def save_results_json(result: BenchmarkResult, output_path: Path) -> None:
    """Save results as structured JSON for downstream processing."""
    data = {
        "tool": result.tool,
        "overall": result.overall.summary_dict(),
        "per_cwe": {
            str(cwe): cm.summary_dict()
            for cwe, cm in sorted(result.per_cwe.items())
        },
    }
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    log.info("Saved JSON results to %s", output_path)


# ── CLI ──────────────────────────────────────────────────────────────

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Score tool findings against OWASP Benchmark ground truth."
    )
    parser.add_argument(
        "--ground-truth", type=Path, required=False, default=None,
        help="Path to OWASP expectedresults-X.X.csv",
    )
    parser.add_argument(
        "--findings", type=Path, default=None,
        help="Path to normalized findings CSV (columns: test_name, tool, [cwe], [severity])",
    )
    parser.add_argument(
        "--report", type=Path, default=None,
        help="Path to QASecClaw markdown report (alternative to --findings)",
    )
    parser.add_argument(
        "--cwe", type=int, default=None,
        help="Filter to a specific CWE number (e.g., 78 for Command Injection)",
    )
    parser.add_argument(
        "--tool", type=str, default="qasecclaw",
        help="Tool name label (default: qasecclaw)",
    )
    parser.add_argument(
        "--output-json", type=Path, default=None,
        help="Save results as JSON to this path",
    )
    parser.add_argument(
        "--output-md", type=Path, default=None,
        help="Save results as markdown to this path",
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Run with synthetic data to verify pipeline",
    )

    args = parser.parse_args(argv)

    if args.dry_run:
        return _dry_run()

    # Load ground truth
    if args.ground_truth is None:
        log.error("--ground-truth is required (unless using --dry-run).")
        return 1
    ground_truth = load_ground_truth(args.ground_truth, cwe_filter=args.cwe)
    if not ground_truth:
        log.error("No ground truth entries loaded. Check --ground-truth path and --cwe filter.")
        return 1

    # Load findings
    if args.report:
        findings = parse_qasecclaw_report(args.report)
    elif args.findings:
        findings = load_findings_csv(args.findings, tool=args.tool)
    else:
        log.error("Provide either --findings (CSV) or --report (QASecClaw markdown).")
        return 1

    # Score
    result = compute_metrics(ground_truth, findings, tool=args.tool)

    # Output
    table = format_results_table(result)
    print(table)

    if args.output_json:
        save_results_json(result, args.output_json)

    if args.output_md:
        args.output_md.parent.mkdir(parents=True, exist_ok=True)
        with open(args.output_md, "w", encoding="utf-8") as f:
            f.write(table)
        log.info("Saved markdown results to %s", args.output_md)

    return 0


def _dry_run() -> int:
    """Validate the scoring pipeline with synthetic data."""
    log.info("=== DRY RUN: validating scoring pipeline with synthetic data ===")

    # Synthetic ground truth: 10 test cases, 5 vulnerable + 5 safe
    gt = {}
    for i in range(1, 11):
        name = f"BenchmarkTest{i:05d}"
        gt[name] = GroundTruthEntry(
            test_name=name,
            category="cmdi",
            is_vulnerable=(i <= 5),  # 1-5 are vulnerable
            cwe=78,
        )

    # Synthetic tool findings: detects 1-4 (misses 5), false-alerts 6
    findings = {}
    for i in [1, 2, 3, 4, 6]:
        name = f"BenchmarkTest{i:05d}"
        findings[name] = ToolFinding(test_name=name, tool="dry-run-tool")

    result = compute_metrics(gt, findings, tool="dry-run-tool")

    # Expected: TP=4, FP=1, TN=4, FN=1
    assert result.overall.tp == 4, f"Expected TP=4, got {result.overall.tp}"
    assert result.overall.fp == 1, f"Expected FP=1, got {result.overall.fp}"
    assert result.overall.tn == 4, f"Expected TN=4, got {result.overall.tn}"
    assert result.overall.fn == 1, f"Expected FN=1, got {result.overall.fn}"

    expected_precision = 4 / 5   # 0.8
    expected_recall = 4 / 5      # 0.8
    expected_f1 = 2 * 0.8 * 0.8 / (0.8 + 0.8)  # 0.8

    assert abs(result.overall.precision - expected_precision) < 1e-6
    assert abs(result.overall.recall - expected_recall) < 1e-6
    assert abs(result.overall.f1 - expected_f1) < 1e-6

    print(format_results_table(result))
    log.info("=== DRY RUN PASSED: all assertions OK ===")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
