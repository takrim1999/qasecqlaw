#!/usr/bin/env bash
# ============================================================================
# run_owasp_benchmark.sh — OWASP Benchmark Evaluation Pipeline for QASecClaw
# ============================================================================
#
# This script:
#   1. Clones the official OWASP BenchmarkJava repo (if not cached)
#   2. Runs QASecClaw against the benchmark test code
#   3. Runs standalone Semgrep as a baseline comparison
#   4. Scores both against the OWASP ground truth (expectedresults CSV)
#   5. Generates comparison tables and visualizations
#
# Usage:
#   ./run_owasp_benchmark.sh [--cwe 78] [--skip-clone] [--semgrep-only]
#
# ============================================================================
set -euo pipefail

# ── Configuration ────────────────────────────────────────────────────
BENCHMARK_REPO="https://github.com/OWASP-Benchmark/BenchmarkJava.git"
BENCHMARK_DIR="/tmp/owasp-benchmark"
RESULTS_DIR="./experiments/results"
FIGURES_DIR="./research/figures"
TESTCODE_SUBDIR="src/main/java/org/owasp/benchmark/testcode"
EXPECTED_RESULTS_CSV=""  # auto-detected below

# Python files
SCORE_SCRIPT="./experiments/metrics/score_benchmark.py"
BASELINE_SCRIPT="./experiments/baselines/run_baselines.py"
RESULTS_SCRIPT="./experiments/pipelines/generate_results.py"

# Defaults
CWE_FILTER=""
SKIP_CLONE=false
SEMGREP_ONLY=false

# ── Colors ───────────────────────────────────────────────────────────
bold=$'\033[1m'
red=$'\033[31m'
green=$'\033[32m'
yellow=$'\033[33m'
blue=$'\033[34m'
cyan=$'\033[36m'
reset=$'\033[0m'

# ── Parse arguments ──────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
  case "$1" in
    --cwe)
      CWE_FILTER="$2"
      shift 2
      ;;
    --skip-clone)
      SKIP_CLONE=true
      shift
      ;;
    --semgrep-only)
      SEMGREP_ONLY=true
      shift
      ;;
    -h|--help)
      echo "Usage: $0 [--cwe <CWE_NUMBER>] [--skip-clone] [--semgrep-only]"
      echo ""
      echo "Options:"
      echo "  --cwe <N>       Filter to specific CWE (e.g., 78 for Command Injection)"
      echo "  --skip-clone    Skip cloning if OWASP Benchmark already exists"
      echo "  --semgrep-only  Only run Semgrep baseline (skip QASecClaw)"
      exit 0
      ;;
    *)
      echo "${red}Unknown argument: $1${reset}"
      exit 1
      ;;
  esac
done

# ── Banner ───────────────────────────────────────────────────────────
echo ""
echo "${bold}${cyan}╔══════════════════════════════════════════════════════════╗${reset}"
echo "${bold}${cyan}║  QASecClaw — OWASP Benchmark Evaluation Pipeline        ║${reset}"
echo "${bold}${cyan}╚══════════════════════════════════════════════════════════╝${reset}"
echo ""
if [[ -n "$CWE_FILTER" ]]; then
  echo "${blue}CWE Filter:${reset} CWE-${CWE_FILTER}"
fi
echo "${blue}Benchmark:${reset}  ${BENCHMARK_DIR}"
echo "${blue}Results:${reset}    ${RESULTS_DIR}"
echo ""

mkdir -p "$RESULTS_DIR"
mkdir -p "$FIGURES_DIR"

# ── Step 1: Clone OWASP Benchmark ───────────────────────────────────
echo "${bold}${blue}[Step 1/5] Fetching OWASP Benchmark...${reset}"

if [[ -d "$BENCHMARK_DIR" && "$SKIP_CLONE" == true ]]; then
  echo "${green}  Using cached benchmark at ${BENCHMARK_DIR}${reset}"
elif [[ -d "$BENCHMARK_DIR" ]]; then
  echo "${yellow}  Benchmark directory exists. Pulling latest...${reset}"
  git -C "$BENCHMARK_DIR" pull --ff-only 2>/dev/null || true
else
  echo "${yellow}  Cloning OWASP BenchmarkJava (depth=1)...${reset}"
  git clone --depth 1 "$BENCHMARK_REPO" "$BENCHMARK_DIR"
fi

# Auto-detect expectedresults CSV
EXPECTED_RESULTS_CSV=$(find "$BENCHMARK_DIR" -maxdepth 1 -name "expectedresults-*.csv" | sort -V | tail -1)
if [[ -z "$EXPECTED_RESULTS_CSV" ]]; then
  echo "${red}ERROR: Could not find expectedresults CSV in ${BENCHMARK_DIR}${reset}"
  exit 1
fi
echo "${green}  Ground truth: ${EXPECTED_RESULTS_CSV}${reset}"
echo "${green}  Test code:    ${BENCHMARK_DIR}/${TESTCODE_SUBDIR}/${reset}"

# Count test cases
if [[ -n "$CWE_FILTER" ]]; then
  TOTAL_CASES=$(grep -c ",${CWE_FILTER}$" "$EXPECTED_RESULTS_CSV" 2>/dev/null || echo "0")
  TRUE_VULNS=$(grep ",true,${CWE_FILTER}$" "$EXPECTED_RESULTS_CSV" | wc -l || echo "0")
  FALSE_POS=$(grep ",false,${CWE_FILTER}$" "$EXPECTED_RESULTS_CSV" | wc -l || echo "0")
else
  TOTAL_CASES=$(grep -c "^BenchmarkTest" "$EXPECTED_RESULTS_CSV" 2>/dev/null || echo "0")
  TRUE_VULNS=$(grep ",true," "$EXPECTED_RESULTS_CSV" | wc -l || echo "0")
  FALSE_POS=$(grep ",false," "$EXPECTED_RESULTS_CSV" | wc -l || echo "0")
fi
echo "${blue}  Total test cases: ${TOTAL_CASES} (${TRUE_VULNS} vulnerable, ${FALSE_POS} safe)${reset}"
echo ""

# ── Step 2: Run QASecClaw ────────────────────────────────────────────
QASECCLAW_FINDINGS="${RESULTS_DIR}/findings_qasecclaw.csv"
QASECCLAW_REPORT="${RESULTS_DIR}/qasecclaw_owasp_report.md"

if [[ "$SEMGREP_ONLY" == false ]]; then
  echo "${bold}${blue}[Step 2/5] Running QASecClaw against OWASP Benchmark...${reset}"
  
  if pnpm -C framework start -- \
      --name "OWASP-Benchmark" \
      --source "${BENCHMARK_DIR}/${TESTCODE_SUBDIR}" \
      --api "${BENCHMARK_DIR}/openapi.json" 2>&1; then
    
    # Move report if produced
    if [[ -f "framework/qasecclaw-report.md" ]]; then
      mv -f "framework/qasecclaw-report.md" "$QASECCLAW_REPORT"
      echo "${green}  QASecClaw report saved: ${QASECCLAW_REPORT}${reset}"
    fi
  else
    echo "${yellow}  QASecClaw run had issues (continuing with available data).${reset}"
  fi

  # Parse QASecClaw report into normalized findings CSV
  if [[ -f "$QASECCLAW_REPORT" ]]; then
    echo "${yellow}  Extracting findings from QASecClaw report...${reset}"
    CWE_ARG=""
    [[ -n "$CWE_FILTER" ]] && CWE_ARG="--cwe ${CWE_FILTER}"
    python3 "$BASELINE_SCRIPT" \
      --benchmark-dir "$BENCHMARK_DIR" \
      --tool qasecclaw \
      --report "$QASECCLAW_REPORT" \
      --output "$QASECCLAW_FINDINGS" \
      $CWE_ARG
  else
    echo "${yellow}  No QASecClaw report found. Creating empty findings.${reset}"
    echo "test_name,tool,cwe,severity,raw_id" > "$QASECCLAW_FINDINGS"
  fi
else
  echo "${yellow}[Step 2/5] Skipping QASecClaw (--semgrep-only mode)${reset}"
  echo "test_name,tool,cwe,severity,raw_id" > "$QASECCLAW_FINDINGS"
fi
echo ""

# ── Step 3: Run Semgrep Baseline ─────────────────────────────────────
SEMGREP_FINDINGS="${RESULTS_DIR}/findings_semgrep.csv"

echo "${bold}${blue}[Step 3/5] Running Semgrep baseline on OWASP Benchmark...${reset}"

CWE_ARG=""
[[ -n "$CWE_FILTER" ]] && CWE_ARG="--cwe ${CWE_FILTER}"

python3 "$BASELINE_SCRIPT" \
  --benchmark-dir "$BENCHMARK_DIR" \
  --tool semgrep \
  --output "$SEMGREP_FINDINGS" \
  $CWE_ARG

echo ""

# ── Step 4: Score both tools ─────────────────────────────────────────
echo "${bold}${blue}[Step 4/5] Scoring against OWASP ground truth...${reset}"

CWE_ARG=""
[[ -n "$CWE_FILTER" ]] && CWE_ARG="--cwe ${CWE_FILTER}"

# Score QASecClaw
echo "${cyan}  Scoring QASecClaw...${reset}"
python3 "$SCORE_SCRIPT" \
  --ground-truth "$EXPECTED_RESULTS_CSV" \
  --findings "$QASECCLAW_FINDINGS" \
  --tool "QASecClaw" \
  --output-json "${RESULTS_DIR}/scored_qasecclaw.json" \
  --output-md "${RESULTS_DIR}/scored_qasecclaw.md" \
  $CWE_ARG

echo ""

# Score Semgrep
echo "${cyan}  Scoring Semgrep...${reset}"
python3 "$SCORE_SCRIPT" \
  --ground-truth "$EXPECTED_RESULTS_CSV" \
  --findings "$SEMGREP_FINDINGS" \
  --tool "Semgrep" \
  --output-json "${RESULTS_DIR}/scored_semgrep.json" \
  --output-md "${RESULTS_DIR}/scored_semgrep.md" \
  $CWE_ARG

echo ""

# ── Step 5: Generate comparison tables and plots ─────────────────────
echo "${bold}${blue}[Step 5/5] Generating comparison tables and visualizations...${reset}"

python3 "$RESULTS_SCRIPT" \
  --results "${RESULTS_DIR}/scored_qasecclaw.json" "${RESULTS_DIR}/scored_semgrep.json" \
  --output-dir "$FIGURES_DIR"

echo ""

# ── Summary ──────────────────────────────────────────────────────────
echo "${bold}${green}╔══════════════════════════════════════════════════════════╗${reset}"
echo "${bold}${green}║  Benchmark evaluation complete!                         ║${reset}"
echo "${bold}${green}╚══════════════════════════════════════════════════════════╝${reset}"
echo ""
echo "${blue}Results:${reset}"
echo "  ${RESULTS_DIR}/scored_qasecclaw.json"
echo "  ${RESULTS_DIR}/scored_semgrep.json"
echo ""
echo "${blue}Tables:${reset}"
echo "  ${FIGURES_DIR}/comparison_table.md"
echo "  ${FIGURES_DIR}/comparison_table.tex"
echo ""
echo "${blue}Plots:${reset}"
echo "  ${FIGURES_DIR}/benchmark_comparison_bar.png"
echo "  ${FIGURES_DIR}/benchmark_cwe_radar.png"
echo ""
echo "${cyan}Quick view:${reset} cat ${FIGURES_DIR}/comparison_table.md"
echo ""
