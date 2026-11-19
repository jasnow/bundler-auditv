#!/usr/bin/env bash
#
# Fetches the OSV records affecting the given gem versions from the OSV API
# into spec/fixtures/osv/ (needs curl and jq).
#
# Usage:
#   spec/fixtures/fetch_osv_fixtures.sh activerecord 3.2.10 activesupport 3.2.10 \
#                                       activemodel 3.2.10 actionpack 3.1.9
#
set -euo pipefail

out="$(cd "$(dirname "$0")" && pwd)/osv"
mkdir -p "$out"

while [ $# -ge 2 ]; do
  gem_name="$1"
  version="$2"
  shift 2
  token=""

  while :; do
    body=$(jq -n --arg n "$gem_name" --arg v "$version" --arg t "$token" \
      '{package: {name: $n, ecosystem: "RubyGems"}, version: $v}
       + (if $t == "" then {} else {page_token: $t} end)')

    response=$(curl -fsS -X POST -d "$body" https://api.osv.dev/v1/query)

    echo "$response" | jq -c '.vulns[]?' | while IFS= read -r vuln; do
      id=$(echo "$vuln" | jq -r '.id')
      echo "$vuln" | jq '.' > "$out/$id.json"
      echo "wrote $out/$id.json ($gem_name $version)"
    done

    token=$(echo "$response" | jq -r '.next_page_token // ""')
    [ -z "$token" ] && break
  done
done
