#!/usr/bin/env bash
# Usage: check-pkce-events.sh [events.json]
# Reads NDJSON events and asserts: happy result=pass, no-session result=pass, state is pass or skip.
set -e
FILE="${1:-}"
if [ -z "$FILE" ] || [ ! -f "$FILE" ]; then
  echo "Usage: $0 events.json" >&2
  exit 1
fi
if ! command -v jq >/dev/null 2>&1; then
  echo "jq required for check-pkce-events.sh" >&2
  exit 1
fi
JSON_LINES=$(grep '^{' "$FILE" || true)
if [ -z "$JSON_LINES" ]; then
  echo "check-pkce-events: no JSON lines in $FILE" >&2
  exit 1
fi
happy_pass=$(echo "$JSON_LINES" | jq -s 'map(select(.event=="happy" and .result=="pass")) | length')
no_session_pass=$(echo "$JSON_LINES" | jq -s 'map(select(.event=="security" and .test=="no-session" and .result=="pass")) | length')
state_pass=$(echo "$JSON_LINES" | jq -s 'map(select(.event=="security" and .test=="state" and .result=="pass")) | length')
state_skip=$(echo "$JSON_LINES" | jq -s 'map(select(.event=="security" and .test=="state" and .result=="skip")) | length')
open_redirect_pass=$(echo "$JSON_LINES" | jq -s 'map(select(.event=="security" and .test=="open-redirect" and .result=="pass")) | length')
logout_get_pass=$(echo "$JSON_LINES" | jq -s 'map(select(.event=="security" and .test=="logout-get" and .result=="pass")) | length')
security_headers_pass=$(echo "$JSON_LINES" | jq -s 'map(select(.event=="security" and .test=="security-headers" and .result=="pass")) | length')

fail=0
if [ "${happy_pass:-0}" -lt 1 ]; then
  echo "check-pkce-events: no happy result=pass" >&2
  fail=1
fi
if [ "${no_session_pass:-0}" -lt 1 ]; then
  echo "check-pkce-events: no no-session result=pass" >&2
  fail=1
fi
if [ "${state_pass:-0}" -lt 1 ] && [ "${state_skip:-0}" -lt 1 ]; then
  echo "check-pkce-events: state test neither pass nor skip (pass=$state_pass skip=$state_skip)" >&2
  fail=1
fi
if [ "${open_redirect_pass:-0}" -lt 1 ]; then
  echo "check-pkce-events: open-redirect result=pass missing" >&2
  fail=1
fi
if [ "${logout_get_pass:-0}" -lt 1 ]; then
  echo "check-pkce-events: logout-get result=pass missing" >&2
  fail=1
fi
if [ "${security_headers_pass:-0}" -lt 1 ]; then
  echo "check-pkce-events: security-headers result=pass missing" >&2
  fail=1
fi
if [ "$fail" -eq 1 ]; then
  echo "Events sample:" >&2
  echo "$JSON_LINES" | jq -c 'select(.result != null or .event != null)' 2>/dev/null | head -20 >&2
  exit 1
fi
echo "check-pkce-events: happy=pass no-session=pass state=pass_or_skip open-redirect=pass logout-get=pass security-headers=pass"
