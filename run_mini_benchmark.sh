#!/usr/bin/env bash
# ============================================================================
# run_mini_benchmark.sh — Quick pipeline test with CWE-78 (Command Injection)
# ============================================================================
#
# A lightweight version of run_owasp_benchmark.sh that:
#   1. Clones OWASP Benchmark (if not cached)
#   2. Runs ONLY Semgrep on CWE-78 test files (~126 files)
#   3. Scores against ground truth
#   4. Prints results immediately
#
# This skips the QASecClaw framework run — it validates the scoring pipeline
# end-to-end so you can confirm everything works before the full run.
#
# Usage:
#   ./run_mini_benchmark.sh
#
# ============================================================================
set -euo pipefail

BENCHMARK_REPO="https://github.com/OWASP-Benchmark/BenchmarkJava.git"
BENCHMARK_DIR="/tmp/owasp-benchmark"
RESULTS_DIR="./experiments/results"
TESTCODE_SUBDIR="src/main/java/org/owasp/benchmark/testcode"

CWE=78  # Command Injection — small subset

bold=$'\033[1m'
red=$'\033[31m'
green=$'\033[32m'
yellow=$'\033[33m'
blue=$'\033[34m'
cyan=$'\033[36m'
reset=$'\033[0m'

echo ""
echo "${bold}${cyan}╔════════════════════════════════════════════════════╗${reset}"
echo "${bold}${cyan}║  Mini Benchmark — CWE-${CWE} Command Injection      ║${reset}"
echo "${bold}${cyan}╚════════════════════════════════════════════════════╝${reset}"
echo ""

mkdir -p "$RESULTS_DIR"

# ── Step 1: Clone OWASP Benchmark ───────────────────────────────────
echo "${bold}${blue}[1/3] Fetching OWASP Benchmark...${reset}"

if [[ -d "$BENCHMARK_DIR" ]]; then
  echo "${green}  Cached at ${BENCHMARK_DIR}${reset}"
else
  echo "${yellow}  Cloning (depth=1)...${reset}"
  git clone --depth 1 "$BENCHMARK_REPO" "$BENCHMARK_DIR"
fi

# Find the expected results CSV
EXPECTED_RESULTS=$(find "$BENCHMARK_DIR" -maxdepth 1 -name "expectedresults-*.csv" | sort -V | tail -1)
if [[ -z "$EXPECTED_RESULTS" ]]; then
  echo "${red}ERROR: No expectedresults CSV found!${reset}"
  exit 1
fi

# Stats for CWE-78
TOTAL=$(grep ",${CWE}$" "$EXPECTED_RESULTS" | wc -l)
VULNS=$(grep ",true,${CWE}$" "$EXPECTED_RESULTS" | wc -l)
SAFE=$(grep ",false,${CWE}$" "$EXPECTED_RESULTS" | wc -l)
echo "${green}  Ground truth: ${TOTAL} CWE-${CWE} cases (${VULNS} vulnerable, ${SAFE} safe)${reset}"
echo ""

# ── Step 2: Run Semgrep on CWE-78 files ─────────────────────────────
echo "${bold}${blue}[2/3] Running Semgrep on CWE-${CWE} test files...${reset}"

SEMGREP_OUT="${RESULTS_DIR}/findings_semgrep_cwe${CWE}.csv"

python3 experiments/baselines/run_baselines.py \
  --benchmark-dir "$BENCHMARK_DIR" \
  --tool semgrep \
  --cwe "$CWE" \
  --output "$SEMGREP_OUT"

FOUND=$(tail -n +2 "$SEMGREP_OUT" | wc -l)
echo "${green}  Semgrep flagged: ${FOUND} test cases${reset}"
echo ""

# ── Step 3: Score ────────────────────────────────────────────────────
echo "${bold}${blue}[3/3] Scoring against ground truth...${reset}"
echo ""

python3 experiments/metrics/score_benchmark.py \
  --ground-truth "$EXPECTED_RESULTS" \
  --findings "$SEMGREP_OUT" \
  --tool "Semgrep" \
  --cwe "$CWE" \
  --output-json "${RESULTS_DIR}/scored_semgrep_cwe${CWE}.json" \
  --output-md "${RESULTS_DIR}/scored_semgrep_cwe${CWE}.md"

echo ""
echo "${bold}${green}╔════════════════════════════════════════════════════╗${reset}"
echo "${bold}${green}║  Mini benchmark complete!                          ║${reset}"
echo "${bold}${green}╚════════════════════════════════════════════════════╝${reset}"
echo ""
echo "${blue}Results:${reset}  ${RESULTS_DIR}/scored_semgrep_cwe${CWE}.json"
echo "${blue}Table:${reset}    ${RESULTS_DIR}/scored_semgrep_cwe${CWE}.md"
echo ""
echo "${cyan}If this looks good, run the full benchmark:${reset}"
echo "  ./run_owasp_benchmark.sh"
echo ""
