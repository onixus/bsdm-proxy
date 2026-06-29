#!/usr/bin/env bash
# Close a single architecture blocker issue B1–B25 (GitHub #32–#56).
# Requires: gh auth with issues write scope
#
# Usage:
#   ./scripts/close-blocker-issue.sh 6              # close B6 → #37
#   ./scripts/close-blocker-issue.sh 6 65           # with PR reference
#   ./scripts/close-blocker-issue.sh --dry-run 6
set -euo pipefail

REPO="${GITHUB_REPO:-onixus/bsdm-proxy}"
DRY_RUN=false
PR_NUM=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run) DRY_RUN=true; shift ;;
    -*) echo "Unknown option: $1" >&2; exit 1 ;;
    *)
      if [[ -z "${BLOCKER_ID:-}" ]]; then
        BLOCKER_ID="$1"
      elif [[ -z "$PR_NUM" ]]; then
        PR_NUM="$1"
      fi
      shift
      ;;
  esac
done

if [[ -z "${BLOCKER_ID:-}" ]]; then
  echo "Usage: $0 [--dry-run] <blocker_id 1-25> [pr_number]" >&2
  exit 1
fi

if ! [[ "$BLOCKER_ID" =~ ^[0-9]+$ ]] || (( BLOCKER_ID < 1 || BLOCKER_ID > 25 )); then
  echo "blocker_id must be 1–25 (got: $BLOCKER_ID)" >&2
  exit 1
fi

ISSUE_NUM=$((31 + BLOCKER_ID))
PR_REF=""
if [[ -n "$PR_NUM" ]]; then
  PR_REF="Implemented in PR #${PR_NUM} (merged)."
fi

COMMENT="$(cat <<EOF
${PR_REF}
Blocker **B${BLOCKER_ID}** marked completed.

Closed via \`scripts/close-blocker-issue.sh\`.
See [docs/BLOCKERS.md](docs/BLOCKERS.md).
EOF
)"

if $DRY_RUN; then
  echo "[dry-run] Would close #${ISSUE_NUM} (B${BLOCKER_ID})"
  echo "$COMMENT"
  exit 0
fi

STATE=$(gh issue view "$ISSUE_NUM" --repo "$REPO" --json state --jq .state 2>/dev/null || echo "UNKNOWN")
if [[ "$STATE" == "CLOSED" ]]; then
  echo "Issue #${ISSUE_NUM} (B${BLOCKER_ID}) already closed"
  exit 0
fi

gh issue close "$ISSUE_NUM" --repo "$REPO" --comment "$COMMENT"
echo "Closed #${ISSUE_NUM} (B${BLOCKER_ID})"
