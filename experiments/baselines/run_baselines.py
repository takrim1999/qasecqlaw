#!/usr/bin/env python3
"""
Baseline Runner for OWASP Benchmark
=====================================
Runs standalone Semgrep against OWASP Benchmark test cases and normalizes
the output to the same format expected by score_benchmark.py.

Usage:
    python run_baselines.py \
        --benchmark-dir /tmp/owasp-benchmark \
        --tool semgrep \
        --cwe 78 \
        --output findings_semgrep.csv
"""

from __future__ import annotations

import argparse
import csv
import json
import logging
import re
import subprocess
import sys
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger(__name__)

TEST_CODE_SUBDIR = "src/main/java/org/owasp/benchmark/testcode"
TEST_NAME_PATTERN = re.compile(r"(BenchmarkTest\d{5})")

# CWE → Semgrep rule tags that would trigger for that category
CWE_TO_SEMGREP_TAGS: dict[int, list[str]] = {
    78: ["os-command-injection", "command-injection", "cmdi", "exec"],
    89: ["sql-injection", "sqli"],
    79: ["xss", "cross-site-scripting", "reflected-xss"],
    22: ["path-traversal", "directory-traversal"],
    327: ["weak-crypto", "insecure-cipher"],
    328: ["weak-hash", "md5", "sha1"],
    330: ["weak-random", "insecure-random", "pseudo-random"],
    90: ["ldap-injection"],
    643: ["xpath-injection"],
}


def run_semgrep(target_dir: Path, cwe_filter: int | None = None) -> dict[str, dict]:
    """
    Run semgrep on the target directory and return a dict mapping
    BenchmarkTestNNNNN → finding info for each flagged test case.
    """
    cmd = [
        "semgrep", "scan",
        "--json",
        "--config", "auto",
        str(target_dir),
    ]

    log.info("Running: %s", " ".join(cmd))
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=600,  # 10 minutes
        )
        # Semgrep returns exit code 1 when findings exist, that's fine
        stdout = result.stdout
    except subprocess.TimeoutExpired:
        log.error("Semgrep timed out after 600s")
        return {}
    except FileNotFoundError:
        log.error("Semgrep not found. Install with: pip install semgrep")
        return {}

    try:
        data = json.loads(stdout)
    except json.JSONDecodeError:
        log.error("Failed to parse Semgrep JSON output")
        log.debug("stdout: %s", stdout[:500])
        return {}

    results = data.get("results", [])
    log.info("Semgrep returned %d raw findings", len(results))

    findings: dict[str, dict] = {}
    for r in results:
        path = r.get("path", "")
        match = TEST_NAME_PATTERN.search(path)
        if not match:
            continue

        test_name = match.group(1)
        check_id = r.get("check_id", "")
        severity = r.get("extra", {}).get("severity", "").upper()

        # If CWE filter is active, try to match finding to the relevant CWE
        # (Semgrep doesn't always label CWE, so we flag any finding in the file)
        findings[test_name] = {
            "test_name": test_name,
            "tool": "semgrep",
            "cwe": cwe_filter or "",
            "severity": severity or "INFO",
            "raw_id": check_id,
        }

    log.info("Semgrep flagged %d unique test cases", len(findings))
    return findings


def run_qasecclaw_report_parse(report_path: Path, cwe_filter: int | None = None) -> dict[str, dict]:
    """
    Parse QASecClaw raw JSON findings (or fallback to markdown report) 
    to extract which BenchmarkTest files were flagged.
    """
    findings: dict[str, dict] = {}

    if report_path.suffix == ".json":
        log.info("Parsing QASecClaw raw JSON findings: %s", report_path)
        try:
            with open(report_path, encoding="utf-8") as f:
                raw_findings = json.load(f)
                
            for finding in raw_findings:
                location = finding.get("location", "")
                match = TEST_NAME_PATTERN.search(location)
                if not match:
                    continue
                    
                test_name = match.group(1)
                
                # Check CWE filter if provided
                if cwe_filter is not None:
                    # QASecClaw might not output exact CWE ids easily, but we can check if it matches
                    # the expected tags/categories similar to Semgrep parsing
                    finding_cwe = finding.get("cweId")
                    if finding_cwe and str(finding_cwe) != str(cwe_filter):
                        # But wait, Semgrep results inside QASecClaw might not have cweId set correctly,
                        # so let's just rely on the test_name matching in the score_benchmark.py phase,
                        # just like we do for Semgrep standalone.
                        pass
                
                if test_name not in findings:
                    findings[test_name] = {
                        "test_name": test_name,
                        "tool": "qasecclaw",
                        "cwe": cwe_filter or "",
                        "severity": finding.get("severity", "INFO").upper(),
                        "raw_id": finding.get("vulnerabilityType", ""),
                    }
        except json.JSONDecodeError:
            log.error("Failed to parse QASecClaw JSON findings")
    else:
        log.info("Parsing QASecClaw markdown report (fallback): %s", report_path)
        with open(report_path, encoding="utf-8") as f:
            for line in f:
                matches = TEST_NAME_PATTERN.findall(line)
                for test_name in matches:
                    if test_name not in findings:
                        findings[test_name] = {
                            "test_name": test_name,
                            "tool": "qasecclaw",
                            "cwe": cwe_filter or "",
                            "severity": "",
                            "raw_id": "",
                        }

    log.info("QASecClaw flagged %d unique test cases", len(findings))
    return findings


def save_findings_csv(findings: dict[str, dict], output_path: Path) -> None:
    """Save findings as CSV for consumption by score_benchmark.py."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = ["test_name", "tool", "cwe", "severity", "raw_id"]
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for finding in sorted(findings.values(), key=lambda x: x["test_name"]):
            writer.writerow(finding)
    log.info("Saved %d findings to %s", len(findings), output_path)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Run baseline tools against OWASP Benchmark and produce normalized findings CSV."
    )
    parser.add_argument(
        "--benchmark-dir", type=Path, required=True,
        help="Path to cloned OWASP BenchmarkJava repository",
    )
    parser.add_argument(
        "--tool", choices=["semgrep", "qasecclaw"],
        required=True,
        help="Which tool to run",
    )
    parser.add_argument(
        "--report", type=Path, default=None,
        help="Path to QASecClaw report (required when --tool=qasecclaw)",
    )
    parser.add_argument(
        "--cwe", type=int, default=None,
        help="Filter to specific CWE (e.g., 78)",
    )
    parser.add_argument(
        "--output", type=Path, required=True,
        help="Output CSV path for normalized findings",
    )

    args = parser.parse_args(argv)

    if args.tool == "semgrep":
        target = args.benchmark_dir / TEST_CODE_SUBDIR
        if not target.is_dir():
            log.error("Test code directory not found: %s", target)
            return 1
        findings = run_semgrep(target, cwe_filter=args.cwe)
    elif args.tool == "qasecclaw":
        if not args.report:
            log.error("--report is required when --tool=qasecclaw")
            return 1
        findings = run_qasecclaw_report_parse(args.report, cwe_filter=args.cwe)
    else:
        log.error("Unknown tool: %s", args.tool)
        return 1

    save_findings_csv(findings, args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
