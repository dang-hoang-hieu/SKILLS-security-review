#!/bin/bash
# Wrapper script to run security review and save output

set -e

PHASE="${1:-mvp}"
TARGET="${2:-codebase}"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
REPORT_FILE=".claude/skills/security-review/reports/security-review-${PHASE}-${TIMESTAMP}.md"

echo "🔍 Running security review: $PHASE $TARGET"
echo "📝 Report will be saved to: $REPORT_FILE"
echo ""

# Create reports directory if needed
mkdir -p .claude/skills/security-review/reports

# Run analyzer to get changes
if [[ $TARGET == commit:* ]] || [[ $TARGET == pr:* ]] || [[ $TARGET == range:* ]]; then
    echo "📊 Analyzing git changes..."
    python3 .claude/skills/security-review/scripts/analyze_changes.py "$TARGET" . --phase="$PHASE" > /tmp/security-analysis-$$.json 2>&1

    echo ""
    echo "✅ Analysis complete. Changes extracted."
    echo ""
    echo "⚠️  NOTE: You (Claude) should now analyze the changes and create a security report."
    echo "📄 Analysis data available at: /tmp/security-analysis-$$.json"
    echo ""
    echo "To view formatted diff:"
    python3 -c "import json; data=json.load(open('/tmp/security-analysis-$$.json')); print(data.get('formatted_diff', '')[:5000])"
    echo "...[truncated]"
else
    echo "ℹ️  Codebase review mode"
fi

echo ""
echo "💾 When you create the security report, save it to: $REPORT_FILE"
