#!/usr/bin/env bash
set -euo pipefail

MAX_REPOS=100
RESULTS_DIR="./research_reports"
DATASET_CSV="./vulnerability_dataset.csv"
TMP_DIR="/tmp/qasecclaw-batch"
SEED_DIR="/tmp/dataset_repos"

mkdir -p "$RESULTS_DIR"
mkdir -p "$TMP_DIR"

echo "repository,risk_posture,total,critical,high,medium,low" > "$DATASET_CSV"
repo_count=0

# ── Collect repositories ─────────────────────────────────────────────
# 1. If seed_dataset.sh has already cloned repos into SEED_DIR, use those.
# 2. Otherwise fall back to this hardcoded list (cloned on the fly).
FALLBACK_REPOS=(
  "https://github.com/OWASP/NodeGoat.git"
  "https://github.com/juice-shop/juice-shop.git"
  "https://github.com/OWASP/crAPI.git"
  "https://github.com/erev0s/VAmPI.git"
  "https://github.com/appsecco/dvna.git"
  "https://github.com/snoopysecurity/dvws-node.git"
  "https://github.com/WebGoat/WebGoat.git"
  "https://github.com/OWASP/railsgoat.git"
  "https://github.com/we45/Vulnerable-Flask-App.git"
  "https://github.com/anxolerd/dvpwa.git"
  "https://github.com/digininja/DVWA.git"
)

# Detect pre-seeded repos
SEEDED_REPOS=()
if [[ -d "$SEED_DIR" ]]; then
  for d in "$SEED_DIR"/*/; do
    [[ -d "$d" ]] && SEEDED_REPOS+=("$d")
  done
fi

use_seeded=false
if [[ "${#SEEDED_REPOS[@]}" -gt 0 ]]; then
  use_seeded=true
  echo "[SYSTEM] Found ${#SEEDED_REPOS[@]} pre-seeded repos in $SEED_DIR"
else
  echo "[SYSTEM] No seeded repos found. Using ${#FALLBACK_REPOS[@]} fallback URLs."
fi

bold=$'\033[1m'
red=$'\033[31m'
green=$'\033[32m'
yellow=$'\033[33m'
blue=$'\033[34m'
reset=$'\033[0m'

echo "${bold}${blue}QASecClaw batch extract${reset}"
echo "${blue}Results:${reset} ${RESULTS_DIR}"
echo "${blue}Temp:${reset}    ${TMP_DIR}"
echo "${blue}CSV:${reset}     ${DATASET_CSV}"
echo "${blue}Max repos:${reset} ${MAX_REPOS}"
echo

# ── Extract metrics from a report ────────────────────────────────────
extract_metrics() {
  local report_file="$1"
  awk '
    BEGIN { c=0; h=0; m=0; l=0; posture="UNKNOWN" }

    # Match "**Risk Posture: HIGH**" (single bold block)
    /\*\*Risk Posture:[[:space:]]+[A-Z]+\*\*/ {
        posture = $0
        sub(/.*\*\*Risk Posture:[[:space:]]+/, "", posture)
        sub(/\*\*.*/, "", posture)
    }

    # Match "risk posture is assessed as **HIGH**" (inline prose)
    # Use match() to avoid greedy sub() eating past the word
    posture == "UNKNOWN" && /[Rr]isk [Pp]osture/ && /\*\*[A-Z]+\*\*/ {
        if (match($0, /\*\*[A-Z]+\*\*/)) {
            posture = substr($0, RSTART+2, RLENGTH-4)
        }
    }

    # Match "**Risk Posture:** **HIGH**" (two bold blocks)
    /\*\*Risk Posture:\*\*[[:space:]]+\*\*[A-Z]+\*\*/ {
        posture = $0
        sub(/.*\*\*Risk Posture:\*\*[[:space:]]+\*\*/, "", posture)
        sub(/\*\*.*/, "", posture)
    }

    # Track which severity section we are in
    /^### Critical Severity/ { flag="critical" }
    /^### High Severity/     { flag="high" }
    /^### Medium Severity/   { flag="medium" }
    /^### Low Severity/      { flag="low" }
    /^## /                   { flag="" }

    # Count actual data rows: lines starting with "| " followed by an
    # alphanumeric ID (not the header separator "|---|" or header row "| ID")
    /^\| [a-z]/ {
        if(flag=="critical") c++
        if(flag=="high") h++
        if(flag=="medium") m++
        if(flag=="low") l++
    }

    END {
        tot = c+h+m+l
        print posture "," tot "," c "," h "," m "," l
    }
  ' "$report_file"
}


# ── Process a single repository ──────────────────────────────────────
process_repo() {
  local project_name="$1"
  local repo_dir="$2"

  echo "${bold}${blue}==> Target:${reset} ${bold}${project_name}${reset}"

  api_path="${repo_dir}/openapi.json"
  if [[ ! -f "$api_path" ]]; then
    api_path="/tmp/qasecclaw-test/openapi.json"
    echo "${yellow}No openapi.json found; using fallback API spec:${reset} ${api_path}"
  else
    echo "${green}Found API spec:${reset} ${api_path}"
  fi

  echo "${yellow}Running framework...${reset}"
  if pnpm -C framework start -- --name "$project_name" --source "$repo_dir" --api "$api_path"; then
    echo "${green}Framework run completed.${reset}"
  else
    echo "${red}Framework run failed (continuing).${reset}"
  fi

  report_src="framework/qasecclaw-report.md"
  report_dst="${RESULTS_DIR}/${project_name}_report.md"
  if [[ -f "$report_src" ]]; then
    mv -f "$report_src" "$report_dst"
    echo "${green}Report saved:${reset} ${report_dst}"

    metrics=$(extract_metrics "$report_dst")
    echo "$project_name,$metrics" >> "$DATASET_CSV"
    echo "[+] Data extracted and appended to $DATASET_CSV"
  else
    echo "${yellow}No report produced at ${report_src}.${reset}"
  fi
}

# ── Main loop ─────────────────────────────────────────────────────────

# Increase Git HTTP buffer for large repositories
git config --global http.postBuffer 524288000

if [[ "$use_seeded" == true ]]; then
  # ── Path A: process pre-seeded repos ──
  for repo_dir in "${SEEDED_REPOS[@]}"; do
    repo_count=$((repo_count + 1))
    if [ "$repo_count" -gt "$MAX_REPOS" ]; then
      echo "[SYSTEM] Max repository limit ($MAX_REPOS) reached. Stopping."
      break
    fi

    # Strip trailing slash and extract basename
    repo_dir="${repo_dir%/}"
    project_name="$(basename "$repo_dir")"

    process_repo "$project_name" "$repo_dir"
    echo "${green}Done:${reset} ${project_name}"
    echo
  done
else
  # ── Path B: clone from fallback URL list ──
  for url in "${FALLBACK_REPOS[@]}"; do
    repo_count=$((repo_count + 1))
    if [ "$repo_count" -gt "$MAX_REPOS" ]; then
      echo "[SYSTEM] Max repository limit ($MAX_REPOS) reached. Stopping."
      break
    fi

    repo_name="$(basename "$url")"
    repo_name="${repo_name%.git}"
    project_name="$repo_name"
    repo_dir="${TMP_DIR}/${repo_name}"

    echo "${blue}URL:${reset} ${url}"

    # Ensure a clean directory per run.
    rm -rf "$repo_dir"

    echo "${yellow}Cloning...${reset}"

    MAX_RETRIES=3
    RETRY_COUNT=0
    CLONE_SUCCESS=false

    while [ "$RETRY_COUNT" -lt "$MAX_RETRIES" ]; do
      if git clone --depth 1 "$url" "$repo_dir"; then
        CLONE_SUCCESS=true
        break
      else
        echo "[-] Clone failed (network/RPC error). Retrying in 5 seconds... ($((RETRY_COUNT+1))/$MAX_RETRIES)"
        RETRY_COUNT=$((RETRY_COUNT + 1))
        sleep 5
        rm -rf "$repo_dir" # Clean up partial clones before retrying
      fi
    done

    if [ "$CLONE_SUCCESS" = false ]; then
      echo "[-] Failed to clone $project_name after $MAX_RETRIES attempts. Skipping."
      echo
      continue
    fi

    process_repo "$project_name" "$repo_dir"

    echo "${yellow}Cleaning up...${reset}"
    rm -rf "$repo_dir"
    echo "${green}Done:${reset} ${project_name}"
    echo
  done
fi

# ── Also extract metrics from any existing reports not yet in CSV ─────
echo "${blue}Scanning for existing reports not yet in CSV...${reset}"
for report_file in "$RESULTS_DIR"/*_report.md; do
  [[ -f "$report_file" ]] || continue
  fname="$(basename "$report_file")"
  project_name="${fname%_report.md}"

  # Skip if already in the CSV
  if grep -q "^${project_name}," "$DATASET_CSV" 2>/dev/null; then
    continue
  fi

  echo "${yellow}Extracting metrics from existing report:${reset} ${fname}"
  metrics=$(extract_metrics "$report_file")
  echo "$project_name,$metrics" >> "$DATASET_CSV"
  echo "[+] $project_name appended to $DATASET_CSV"
done

echo "${bold}${green}Batch complete.${reset}"
echo "${blue}Dataset:${reset} $(wc -l < "$DATASET_CSV") rows (including header) in $DATASET_CSV"
