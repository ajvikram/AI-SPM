#!/bin/bash
# ─────────────────────────────────────────────────────────
# AI-SPM Shell Guard Wrapper
# ─────────────────────────────────────────────────────────
# Wraps any command through the AI-SPM Shell Guardrail.
#
# Usage:
#   ./guard.sh <command>
#   ./guard.sh rm -rf /tmp/foo
#   ./guard.sh npm install untrusted-pkg
#
# Configuration:
#   AI_SPM_URL   - AI-SPM server URL (default: http://127.0.0.1:8080)
#   AI_SPM_AGENT - Agent ID (default: shell-guard-wrapper)
#
# Integration with AI agents:
#   Configure your agent to use this as its shell executor.
#   For Cursor: settings.json → "terminal.integrated.shell.osx": "/path/to/guard.sh"
#   For Cline:  set shell command prefix in extension settings.
# ─────────────────────────────────────────────────────────

set -euo pipefail

AI_SPM_URL="${AI_SPM_URL:-http://127.0.0.1:8080}"
AI_SPM_AGENT="${AI_SPM_AGENT:-shell-guard-wrapper}"
COMMAND="$*"

if [ -z "$COMMAND" ]; then
    echo "Usage: guard.sh <command>"
    exit 1
fi

# Call the Shell Guard API
RESULT=$(curl -s --max-time 3 -X POST "${AI_SPM_URL}/api/shell/evaluate" \
    -H "Content-Type: application/json" \
    -d "{\"command\":\"${COMMAND//\"/\\\"}\", \"agent_id\":\"${AI_SPM_AGENT}\"}" 2>/dev/null)

# If server is unreachable, warn but allow (fail-open)
if [ -z "$RESULT" ]; then
    echo "⚠️  AI-SPM server unreachable, executing without guardrail"
    eval "$COMMAND"
    exit $?
fi

VERDICT=$(echo "$RESULT" | python3 -c "import sys,json; print(json.load(sys.stdin)['data']['verdict']['verdict'])" 2>/dev/null || echo "error")
REASON=$(echo "$RESULT" | python3 -c "import sys,json; v=json.load(sys.stdin)['data']['verdict']; print(v.get('reason',''))" 2>/dev/null || echo "")

case "$VERDICT" in
    allow)
        eval "$COMMAND"
        ;;
    deny)
        echo ""
        echo "🚫 ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo "🚫  BLOCKED by AI-SPM Shell Guard"
        echo "🚫  Command: $COMMAND"
        echo "🚫  Reason:  $REASON"
        echo "🚫 ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo ""
        exit 1
        ;;
    requires_approval)
        echo ""
        echo "⚠️  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo "⚠️   APPROVAL REQUIRED by AI-SPM Shell Guard"
        echo "⚠️   Command: $COMMAND"
        echo "⚠️   Reason:  $REASON"
        echo "⚠️  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo ""
        read -p "Allow this command? [y/N] " confirm
        if [ "$confirm" = "y" ] || [ "$confirm" = "Y" ]; then
            eval "$COMMAND"
        else
            echo "Command cancelled."
            exit 1
        fi
        ;;
    *)
        echo "⚠️  AI-SPM returned unexpected verdict: $VERDICT"
        echo "    Executing command anyway..."
        eval "$COMMAND"
        ;;
esac
