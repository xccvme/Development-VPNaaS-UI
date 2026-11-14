#!/bin/sh
set -eu
umask 077
: "${SESSION_KEY_FILE:=/var/lib/vpnaas-ui/session.key}"
: "${API_KEY_FILE:=/run/secrets/backend-api.key}"
export SESSION_KEY_FILE API_KEY_FILE
[ -s "$API_KEY_FILE" ] || { printf '%s\n' 'Backend API key file missing or empty.' >&2; exit 1; }
mkdir -p "$(dirname "$SESSION_KEY_FILE")"
if [ ! -e "$SESSION_KEY_FILE" ]; then
  # noclobber protects existing state; never print signing material.
  (set -C; openssl rand -hex 48 > "$SESSION_KEY_FILE")
fi
chmod 0600 "$SESSION_KEY_FILE"
exec /usr/local/bin/vpnaas-ui
