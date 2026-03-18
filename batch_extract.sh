#!/usr/bin/env bash
set -euo pipefail

MAX_REPOS=5
RESULTS_DIR="./research_reports"
DATASET_CSV="./vulnerability_dataset.csv"
TMP_DIR="/tmp/qasecclaw-batch"

mkdir -p "$RESULTS_DIR"
mkdir -p "$TMP_DIR"

echo "repository,risk_posture,total,critical,high,medium,low" > "$DATASET_CSV"
repo_count=0

REPOS=(
  "https://github.com/OWASP/NodeGoat.git"
  "https://github.com/juice-shop/juice-shop.git"
)

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

for url in "${REPOS[@]}"; do
  repo_count=$((repo_count + 1))
  if [ "$repo_count" -gt "$MAX_REPOS" ]; then
    echo "[SYSTEM] Max repository limit ($MAX_REPOS) reached. Stopping."
    break
  fi

  repo_name="$(basename "$url")"
  repo_name="${repo_name%.git}"
  project_name="$repo_name"
  repo_dir="${TMP_DIR}/${repo_name}"

  echo "${bold}${blue}==> Target:${reset} ${bold}${project_name}${reset}"
  echo "${blue}URL:${reset} ${url}"

  # Ensure a clean directory per run.
  rm -rf "$repo_dir"

  echo "${yellow}Cloning...${reset}"

  # Increase Git HTTP buffer to handle large repositories
  git config --global http.postBuffer 524288000

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

    metrics=$(awk '
      BEGIN { c=0; h=0; m=0; l=0; posture="UNKNOWN" }
      /\*\*Risk Posture:\*\*/ {
          posture = $0
          sub(/.*\*\*Risk Posture:\*\* \*\*/, "", posture)
          sub(/\*\*.*/, "", posture)
      }
      /^### Critical Severity/ {flag="critical"}
      /^### High Severity/ {flag="high"}
      /^### Medium Severity/ {flag="medium"}
      /^### Low Severity/ {flag="low"}
      /^## / {flag=""}
      /^\| \*\*/ {
          if(flag=="critical") c++
          if(flag=="high") h++
          if(flag=="medium") m++
          if(flag=="low") l++
      }
      END {
          tot = c+h+m+l
          print posture "," tot "," c "," h "," m "," l
      }
    ' "$RESULTS_DIR/${project_name}_report.md")
    
    echo "$project_name,$metrics" >> "$DATASET_CSV"
    echo "[+] Data extracted and appended to $DATASET_CSV"
  else
    echo "${yellow}No report produced at ${report_src}.${reset}"
  fi

  echo "${yellow}Cleaning up...${reset}"
  rm -rf "$repo_dir"
  echo "${green}Done:${reset} ${project_name}"
  echo
done

echo "${bold}${green}Batch complete.${reset}"
