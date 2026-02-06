#!/usr/bin/env bash
set -e
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

APP_PORT="${APP_PORT:-8080}"
APP_BASE="http://localhost:$APP_PORT"
EXAMPLES_DIR="$ROOT/docs/error-examples"

OAUTH_PORT="${OAUTH_PORT:-9998}"
cleanup() {
	if [ -n "$APP_PID" ]; then kill "$APP_PID" 2>/dev/null || true; fi
	if [ -n "$OAUTH_PID" ]; then kill "$OAUTH_PID" 2>/dev/null || true; fi
}
trap cleanup EXIT

if [ ! -f "$ROOT/bin/app" ] || [ ! -f "$ROOT/bin/oauth-server" ]; then
	make build
fi

mkdir -p "$EXAMPLES_DIR"

"$ROOT/bin/oauth-server" -port="$OAUTH_PORT" & OAUTH_PID=$!
for i in 1 2 3 4 5; do
	if curl -s -o /dev/null "http://localhost:$OAUTH_PORT/.well-known/openid-configuration"; then break; fi
	if [ "$i" -eq 5 ]; then echo "oauth-server did not become ready"; exit 1; fi
	sleep 1
done

GEN_ERROR_EXAMPLES=1 "$ROOT/bin/app" -port="$APP_PORT" -issuer="http://localhost:$OAUTH_PORT" & APP_PID=$!
for i in 1 2 3 4 5; do
	if curl -s -o /dev/null "$APP_BASE/login"; then break; fi
	if [ "$i" -eq 5 ]; then echo "app did not become ready"; exit 1; fi
	sleep 1
done

for slug in config auth challenge session invalid_state invalid_request about_blank; do
	curl -s -o "$EXAMPLES_DIR/$slug.json" "$APP_BASE/__error_examples__/$slug"
done

cleanup
trap - EXIT

for f in "$EXAMPLES_DIR"/*.json; do
	[ -f "$f" ] || continue
	jq . "$f" > "$f.tmp" && mv "$f.tmp" "$f"
done

SLUGS="config auth challenge session invalid_state invalid_request about_blank"
DOC="$ROOT/docs/errors.md"
TMP="$DOC.tmp"

awk -v examples_dir="$EXAMPLES_DIR" -v slugs="$SLUGS" '
BEGIN {
  n = split(slugs, s)
  replacing = 0
}
/<!-- BEGIN GENERATED EXAMPLES -->/ {
  replacing = 1
  print
  for (i = 1; i <= n; i++) {
    slug = s[i]
    f = examples_dir "/" slug ".json"
    print ""
    print "### " slug
    print ""
    print "```json"
    while ((getline line < f) > 0) print line
    close(f)
    print "```"
  }
  next
}
replacing {
  if (/<!-- END GENERATED EXAMPLES -->/) {
    print
    replacing = 0
  }
  next
}
{ print }
' "$DOC" > "$TMP"
mv "$TMP" "$DOC"
