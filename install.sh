#!/bin/bash
# Deploy Claude Code skills and CLAUDE.md
# Usage:
#   ./install.sh        Install to this repo's .claude/
#   ./install.sh -g     Install globally to ~/.claude/
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

if [ "$1" = "-g" ]; then
    TARGET="$HOME/.claude"
    echo "Installing globally to $TARGET/"
else
    TARGET="$SCRIPT_DIR/.claude"
    echo "Installing locally to $TARGET/"
fi

mkdir -p "$TARGET/skills"
cp -r "$SCRIPT_DIR/claude/skills/"* "$TARGET/skills/"
cp "$SCRIPT_DIR/CLAUDE.md" "$TARGET/CLAUDE.md"

echo "Done."
