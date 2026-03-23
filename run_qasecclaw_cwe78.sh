#!/usr/bin/env bash
# ============================================================================
# run_qasecclaw_cwe78.sh — Run QASecClaw on OWASP Benchmark CWE-78 subset
# ============================================================================
#
# Runs QASecClaw (full multi-agent pipeline) against the OWASP Benchmark
# testcode directory, then scores the results against ground truth for
# CWE-78 (Command Injection) and compares with the Semgrep baseline.
#
# Prerequisites:
#   - OWASP Benchmark cloned at /tmp/owasp-benchmark (run ./run_mini_benchmark.sh first)
#   - Semgrep baseline already scored at experiments/results/scored_semgrep_cwe78.json
#
# ============================================================================
set -euo pipefail

BENCHMARK_DIR="/tmp/owasp-benchmark"
TESTCODE_DIR="${BENCHMARK_DIR}/src/main/java/org/owasp/benchmark/testcode"
RESULTS_DIR="./experiments/results"
FIGURES_DIR="./research/figures"
CWE=78

bold=$'\033[1m'
red=$'\033[31m'
green=$'\033[32m'
yellow=$'\033[33m'
blue=$'\033[34m'
cyan=$'\033[36m'
reset=$'\033[0m'

echo ""
echo "${bold}${cyan}╔═══════════════════════════════════════════════════════════╗${reset}"
echo "${bold}${cyan}║  QASecClaw vs Semgrep — CWE-78 Command Injection         ║${reset}"
echo "${bold}${cyan}╚═══════════════════════════════════════════════════════════╝${reset}"
echo ""

mkdir -p "$RESULTS_DIR"
mkdir -p "$FIGURES_DIR"

# ── Verify prerequisites ────────────────────────────────────────────
if [[ ! -d "$BENCHMARK_DIR" ]]; then
  echo "${red}ERROR: OWASP Benchmark not found at ${BENCHMARK_DIR}${reset}"
  echo "Run ./run_mini_benchmark.sh first to clone it."
  exit 1
fi

EXPECTED_RESULTS=$(find "$BENCHMARK_DIR" -maxdepth 1 -name "expectedresults-*.csv" | sort -V | tail -1)
TOTAL=$(grep ",${CWE}$" "$EXPECTED_RESULTS" | wc -l)
VULNS=$(grep ",true,${CWE}$" "$EXPECTED_RESULTS" | wc -l)
SAFE=$(grep ",false,${CWE}$" "$EXPECTED_RESULTS" | wc -l)

echo "${blue}Ground truth:${reset} ${TOTAL} CWE-${CWE} cases (${VULNS} vulnerable, ${SAFE} safe)"
echo ""

# ── Step 1: Run QASecClaw ────────────────────────────────────────────
QASECCLAW_REPORT="${RESULTS_DIR}/qasecclaw_owasp_cwe78_report.md"

echo "${bold}${blue}[1/4] Running QASecClaw multi-agent pipeline...${reset}"
echo "${yellow}  Target: ${TESTCODE_DIR}${reset}"
echo ""

if pnpm -C framework start -- \
    --name "OWASP-Benchmark-CWE78" \
    --source "${TESTCODE_DIR}"; then
  echo ""
  echo "${green}  QASecClaw run completed.${reset}"
else
  echo ""
  echo "${yellow}  QASecClaw run had issues (continuing with available output).${reset}"
fi

# Move the report and raw findings
if [[ -f "framework/qasecclaw-report.md" ]]; then
  cp -f "framework/qasecclaw-report.md" "$QASECCLAW_REPORT"
  echo "${green}  Report saved: ${QASECCLAW_REPORT}${reset}"
else
  echo "${red}  No report found at framework/qasecclaw-report.md${reset}"
  exit 1
fi

QASECCLAW_RAW_JSON="${RESULTS_DIR}/qasecclaw_raw_findings_cwe78.json"
if [[ -f "framework/qasecclaw-raw-findings.json" ]]; then
  cp -f "framework/qasecclaw-raw-findings.json" "$QASECCLAW_RAW_JSON"
  echo "${green}  Raw findings saved: ${QASECCLAW_RAW_JSON}${reset}"
else
  echo "${yellow}  No raw JSON findings found at framework/qasecclaw-raw-findings.json${reset}"
  # Fallback
  QASECCLAW_RAW_JSON="$QASECCLAW_REPORT"
fi
echo ""

# ── Step 2: Extract QASecClaw findings ───────────────────────────────
QASECCLAW_FINDINGS="${RESULTS_DIR}/findings_qasecclaw_cwe78.csv"

echo "${bold}${blue}[2/4] Extracting QASecClaw findings...${reset}"

python3 experiments/baselines/run_baselines.py \
  --benchmark-dir "$BENCHMARK_DIR" \
  --tool qasecclaw \
  --report "$QASECCLAW_RAW_JSON" \
  --cwe "$CWE" \
  --output "$QASECCLAW_FINDINGS"

FOUND=$(tail -n +2 "$QASECCLAW_FINDINGS" | wc -l)
echo "${green}  QASecClaw flagged: ${FOUND} test cases${reset}"
echo ""

# ── Step 3: Score QASecClaw ──────────────────────────────────────────
echo "${bold}${blue}[3/4] Scoring QASecClaw against ground truth...${reset}"
echo ""

python3 experiments/metrics/score_benchmark.py \
  --ground-truth "$EXPECTED_RESULTS" \
  --findings "$QASECCLAW_FINDINGS" \
  --tool "QASecClaw" \
  --cwe "$CWE" \
  --output-json "${RESULTS_DIR}/scored_qasecclaw_cwe78.json" \
  --output-md "${RESULTS_DIR}/scored_qasecclaw_cwe78.md"

echo ""

# ── Step 4: Side-by-side comparison ──────────────────────────────────
echo "${bold}${blue}[4/4] Generating side-by-side comparison...${reset}"

# Check if Semgrep baseline exists
SEMGREP_JSON="${RESULTS_DIR}/scored_semgrep_cwe78.json"
if [[ -f "$SEMGREP_JSON" ]]; then
  python3 experiments/pipelines/generate_results.py \
    --results "${RESULTS_DIR}/scored_qasecclaw_cwe78.json" "$SEMGREP_JSON" \
    --output-dir "$FIGURES_DIR"

  echo ""
  echo "${bold}${green}╔═══════════════════════════════════════════════════════════╗${reset}"
  echo "${bold}${green}║  Experiment complete! QASecClaw vs Semgrep on CWE-78      ║${reset}"
  echo "${bold}${green}╚═══════════════════════════════════════════════════════════╝${reset}"
  echo ""
  echo "${blue}Comparison table:${reset}"
  echo ""
  cat "${FIGURES_DIR}/comparison_table.md"
  echo ""
  echo "${blue}Files:${reset}"
  echo "  ${RESULTS_DIR}/scored_qasecclaw_cwe78.json"
  echo "  ${FIGURES_DIR}/comparison_table.md"
  echo "  ${FIGURES_DIR}/comparison_table.tex"
  echo "  ${FIGURES_DIR}/benchmark_comparison_bar.png"
  echo "  ${FIGURES_DIR}/confusion_matrix_QASecClaw.png"
else
  echo "${yellow}  Semgrep baseline not found. Showing QASecClaw results only.${reset}"
  echo ""
  cat "${RESULTS_DIR}/scored_qasecclaw_cwe78.md"
fi
echo ""
