#!/usr/bin/env bash
set -e
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
EVENTS_JSON="${EVENTS_JSON:-$ROOT/events.json}"
APP_PORT="${APP_PORT:-8080}"
OAUTH_PORT="${OAUTH_PORT:-9998}"
APP_BASE="http://localhost:$APP_PORT"

cleanup() {
  if [ -n "$OAUTH_PID" ]; then kill "$OAUTH_PID" 2>/dev/null || true; fi
  if [ -n "$APP_PID" ]; then kill "$APP_PID" 2>/dev/null || true; fi
}
trap cleanup EXIT

mkdir -p "$ROOT/bin"
echo "Building PKCE simulation binaries to bin/..."
go build -o "$ROOT/bin/oauth-server" ./cmd/oauth-server/
go build -o "$ROOT/bin/app" ./cmd/app/
(cd "$ROOT/simulate" && go build -o "$ROOT/bin/simulate" .)

echo "Starting mock OIDC server on :$OAUTH_PORT..."
"$ROOT/bin/oauth-server" -port="$OAUTH_PORT" & OAUTH_PID=$!
sleep 2
for i in 1 2 3 4 5; do
  if curl -s -o /dev/null "http://localhost:$OAUTH_PORT/.well-known/openid-configuration"; then break; fi
  if [ "$i" -eq 5 ]; then echo "oauth-server did not become ready"; exit 1; fi
  sleep 1
done

echo "Starting app on :$APP_PORT..."
"$ROOT/bin/app" -port="$APP_PORT" -issuer="http://localhost:$OAUTH_PORT" & APP_PID=$!
sleep 2
for i in 1 2 3 4 5; do
  if curl -s -o /dev/null "http://localhost:$APP_PORT/login"; then break; fi
  if [ "$i" -eq 5 ]; then echo "app did not become ready"; exit 1; fi
  sleep 1
done

echo "Running PKCE simulation (happy + security)..."
: > "$EVENTS_JSON"
"$ROOT/bin/simulate" -app="$APP_BASE" -run=happy,security -headless=true -json 2>"$EVENTS_JSON" || { echo "simulate failed"; exit 1; }

if [ -f "$ROOT/scripts/check-pkce-events.sh" ]; then
  "$ROOT/scripts/check-pkce-events.sh" "$EVENTS_JSON"
fi
echo "PKCE simulation passed."
