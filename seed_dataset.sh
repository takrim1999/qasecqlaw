#!/usr/bin/env bash
set -euo pipefail

DATASET_DIR="/tmp/dataset_repos"
MAX_REPOS=100

# Network resilience: survive transient WiFi/RPC/curl failures overnight.
MAX_CLONE_RETRIES=60
SLEEP_BETWEEN_RETRIES_SECONDS=10

mkdir -p "$DATASET_DIR"

echo "[SYSTEM] Seeding vulnerable benchmark repositories into $DATASET_DIR..."

# Improve Git reliability for large repos.
git config --global http.postBuffer 524288000
export GIT_TERMINAL_PROMPT=0

declare -A seen
ALL_REPOS=()

add_repo() {
  local url="$1"
  if [[ -z "$url" ]]; then
    return 0
  fi
  if [[ -z "${seen[$url]+x}" ]]; then
    seen["$url"]=1
    ALL_REPOS+=("$url")
  fi
}

REPOS_INITIAL=(
  "https://github.com/OWASP/crAPI.git"
  "https://github.com/erev0s/VAmPI.git"
  "https://github.com/appsecco/dvna.git"
  "https://github.com/snoopysecurity/dvws-node.git"
  "https://github.com/WebGoat/WebGoat.git"
  "https://github.com/OWASP/railsgoat.git"
  "https://github.com/we45/Vulnerable-Flask-App.git"
  "https://github.com/anxolerd/dvpwa.git"
  "https://github.com/digininja/DVWA.git"
  "https://github.com/juice-shop/juice-shop.git"
)

for url in "${REPOS_INITIAL[@]}"; do
  add_repo "$url"
done

retry_capture() {
  # Usage: retry_capture <max_attempts> <sleep_seconds> -- <command...>
  local max_attempts="$1"
  local sleep_seconds="$2"
  shift 2
  if [[ "${1:-}" == "--" ]]; then
    shift 1
  fi

  local attempt=1
  while [ "$attempt" -le "$max_attempts" ]; do
    # Capture stdout only; send failure logs to stderr to keep stdout clean.
    local out
    if out="$("$@" 2>/dev/null)"; then
      printf '%s' "$out"
      return 0
    fi
    echo "[-] Network command failed. Attempt ${attempt}/${max_attempts}. Retrying in ${sleep_seconds}s..." >&2
    attempt=$((attempt + 1))
    sleep "$sleep_seconds"
  done
  return 1
}

fetch_clone_urls_page() {
  # GitHub search without auth; may rate-limit. We retry heavily and page until we collect MAX_REPOS.
  local page="$1"
  local query='(owasp OR "juice-shop" OR webgoat OR railsgoat OR dvwa OR "damn vulnerable") (vulnerable OR exploit OR demo OR pentest)'

  local encoded
  encoded="$(python3 - <<PY
import urllib.parse
print(urllib.parse.quote(${query@Q}))
PY
)"

  local api_url="https://api.github.com/search/repositories?q=${encoded}&per_page=100&page=${page}&sort=stars&order=desc"
  local resp

  resp="$(retry_capture 10 10 -- curl -fsSL "$api_url")" || return 1

  python3 - <<'PY'
import json,sys
data=json.loads(sys.stdin.read())
for item in data.get("items", []):
    cu=item.get("clone_url")
    if cu:
        print(cu)
PY
  <<<"$resp"
}

page=1
while [ "${#ALL_REPOS[@]}" -lt "$MAX_REPOS" ]; do
  echo "[SYSTEM] Expanding repo list via GitHub search (page=${page})..."

  new_urls="$(fetch_clone_urls_page "$page" 2>/dev/null || true)"
  if [[ -z "${new_urls:-}" ]]; then
    echo "[SYSTEM] No URLs returned for page=${page}. Stopping expansion."
    break
  fi

  while IFS= read -r u; do
    add_repo "$u"
    if [ "${#ALL_REPOS[@]}" -ge "$MAX_REPOS" ]; then
      break
    fi
  done <<<"$new_urls"

  page=$((page + 1))
  if [ "$page" -gt 10 ]; then
    echo "[SYSTEM] Reached max search pages (10). Using repos collected so far: ${#ALL_REPOS[@]}."
    break
  fi
done

echo "[SYSTEM] Total repos queued for seeding: ${#ALL_REPOS[@]}"

cloned=0
failed=0

for url in "${ALL_REPOS[@]}"; do
  [ "$cloned" -ge "$MAX_REPOS" ] && break

  repo_name="$(basename "$url")"
  repo_name="${repo_name%.git}"
  dest="$DATASET_DIR/$repo_name"

  if [ -d "$dest" ]; then
    echo "[*] $repo_name already exists. Skipping."
    continue
  fi

  echo "[SYSTEM] ==> Seeding: $repo_name"
  echo "URL: $url"

  attempt=1
  clone_success=false
  while [ "$attempt" -le "$MAX_CLONE_RETRIES" ]; do
    rm -rf "$dest"

    if git clone --depth 1 "$url" "$dest"; then
      clone_success=true
      break
    fi

    echo "[-] Clone failed for $repo_name. Attempt ${attempt}/${MAX_CLONE_RETRIES}. Retrying in ${SLEEP_BETWEEN_RETRIES_SECONDS}s..."
    attempt=$((attempt + 1))
    sleep "$SLEEP_BETWEEN_RETRIES_SECONDS"
  done

  if [ "$clone_success" = true ] && [ -d "$dest" ]; then
    cloned=$((cloned + 1))
    echo "[+] Seeded: $repo_name (${cloned}/${MAX_REPOS})"
  else
    failed=$((failed + 1))
    echo "[-] Giving up seeding $repo_name after $MAX_CLONE_RETRIES attempts. Continuing. (failed=${failed})"
  fi
done

echo "====================================================="
echo "[SYSTEM] Seeding complete. Cloned: ${cloned}. Failed: ${failed}."
echo "You can now run: ./batch_extract.sh"

