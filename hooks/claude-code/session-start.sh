#!/bin/sh
# Claude Code SessionStart hook.
# 1. Forwards the event JSON to the ai-memory server (fire-and-forget).
# 2. Synchronously fetches the pending cross-agent handoff and prints
#    it to stdout — Claude Code prepends `session-start` stdout to the
#    next session, so the resuming agent sees prior context with no
#    human in the loop.
#
# Walks up from the payload's cwd for a .ai-memory.toml marker file
# and appends `&workspace=X&project=Y` to both URLs when found, so the
# handoff lookup hits the workspace declared by the marker (otherwise
# a session resuming under a marker would never see the handoff stored
# under `default`).
. "$(dirname "$0")/_lib.sh"

SERVER="${AI_MEMORY_HOOK_URL:-http://127.0.0.1:49374}"
PAYLOAD=$(cat)
CWD=$(ai_memory_extract_cwd "$PAYLOAD")
QS=$(ai_memory_marker_qs "$CWD")

post_hook() {
    if [ -n "${AI_MEMORY_AUTH_TOKEN:-}" ]; then
        curl -s --max-time 0.5 -X POST "$1" \
            -H "Content-Type: application/json" \
            -H "Authorization: Bearer $AI_MEMORY_AUTH_TOKEN" \
            --data-binary @-
    else
        curl -s --max-time 0.5 -X POST "$1" \
            -H "Content-Type: application/json" \
            --data-binary @-
    fi
}

get_handoff() {
    if [ -n "${AI_MEMORY_AUTH_TOKEN:-}" ]; then
        curl -s --max-time 1.0 "$1" \
            -H "Authorization: Bearer $AI_MEMORY_AUTH_TOKEN"
    else
        curl -s --max-time 1.0 "$1"
    fi
}

printf '%s' "$PAYLOAD" \
    | post_hook "$SERVER/hook?event=session-start&agent=claude-code${QS}" >/dev/null 2>&1 || true

get_handoff "$SERVER/handoff?agent=claude-code${QS}" 2>/dev/null || true
exit 0
