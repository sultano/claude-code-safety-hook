#!/bin/bash
# Installation script for Claude Code Prompt Me Less

set -e

HOOKS_DIR="$HOME/.claude/hooks"
SETTINGS_FILE="$HOME/.claude/settings.json"

echo "Installing Claude Code Prompt Me Less..."

# Create hooks directory
mkdir -p "$HOOKS_DIR"

# Copy the hook script
HOOK_DEST="$HOOKS_DIR/validate_tool_safety.py"
if [ -f "$HOOK_DEST" ] && cmp -s validate_tool_safety.py "$HOOK_DEST"; then
    echo "Hook script already up to date"
elif [ -f "$HOOK_DEST" ]; then
    cp validate_tool_safety.py "$HOOK_DEST"
    chmod +x "$HOOK_DEST"
    echo "Hook script updated: $HOOK_DEST"
else
    cp validate_tool_safety.py "$HOOK_DEST"
    chmod +x "$HOOK_DEST"
    echo "Hook script installed: $HOOK_DEST"
fi

# Check if settings.json exists and merge, or create new
if [ -f "$SETTINGS_FILE" ]; then
    # Merge using Python (handles backup only if changes needed)
    python3 - "$SETTINGS_FILE" "settings.json" <<'MERGE_SCRIPT'
import json
import sys
import shutil
from datetime import datetime

existing_path = sys.argv[1]
new_hooks_path = sys.argv[2]

with open(existing_path, 'r') as f:
    existing = json.load(f)

with open(new_hooks_path, 'r') as f:
    new_hooks = json.load(f)

# Ensure hooks structure exists
if 'hooks' not in existing:
    existing['hooks'] = {}

if 'PreToolUse' not in existing['hooks']:
    existing['hooks']['PreToolUse'] = []

# Check if our hook is already installed (by script filename, not exact command)
already_installed = any(
    'validate_tool_safety.py' in hook.get('command', '')
    for hook_group in existing['hooks']['PreToolUse']
    for hook in hook_group.get('hooks', [])
)

if already_installed:
    print(f"Hook already configured in {existing_path} (skipped)")
else:
    # Backup before making changes (with timestamp)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_path = existing_path.replace('.json', f'.backup.{timestamp}.json')
    shutil.copy2(existing_path, backup_path)

    # Add our hook configuration
    existing['hooks']['PreToolUse'].extend(new_hooks['hooks']['PreToolUse'])

    with open(existing_path, 'w') as f:
        json.dump(existing, f, indent=2)

    print(f"Hook added to {existing_path} (backup: {backup_path})")
MERGE_SCRIPT

else
    mkdir -p "$(dirname "$SETTINGS_FILE")"
    cp settings.json "$SETTINGS_FILE"
    echo "Settings installed to: $SETTINGS_FILE"
fi

# Warn if Claude CLI is not available
if ! command -v claude &> /dev/null; then
    echo ""
    echo "Warning: Claude CLI not found. Install it with:"
    echo "  npm install -g @anthropic-ai/claude-code"
fi

echo ""
echo "Installation complete!"
