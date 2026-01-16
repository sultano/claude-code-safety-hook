#!/bin/bash
# Installation script for Claude Code Safety Hook

set -e

HOOKS_DIR="$HOME/.claude/hooks"
SETTINGS_FILE="$HOME/.claude/settings.json"

echo "Installing Claude Code Safety Hook..."

# Create hooks directory
mkdir -p "$HOOKS_DIR"

# Copy the hook script
cp validate_tool_safety.py "$HOOKS_DIR/"
chmod +x "$HOOKS_DIR/validate_tool_safety.py"

echo "Hook script installed to: $HOOKS_DIR/validate_tool_safety.py"

# Check if settings.json exists and merge, or create new
if [ -f "$SETTINGS_FILE" ]; then
    echo ""
    echo "Existing settings.json found at $SETTINGS_FILE"
    echo "Please manually add the following to your hooks configuration:"
    echo ""
    cat settings.json
    echo ""
    echo "Or backup your existing settings and replace:"
    echo "  cp $SETTINGS_FILE ${SETTINGS_FILE}.backup"
    echo "  # Then merge the hook configuration"
else
    cp settings.json "$SETTINGS_FILE"
    echo "Settings installed to: $SETTINGS_FILE"
fi

# Check if Ollama is running
echo ""
echo "Checking Ollama..."
if curl -s http://localhost:11434/api/tags > /dev/null 2>&1; then
    echo "Ollama is running."

    # Check if the model is available
    if ollama list 2>/dev/null | grep -q "qwen2.5-coder:7b"; then
        echo "Model qwen2.5-coder:7b is available."
    else
        echo "Model not found. Installing qwen2.5-coder:7b..."
        echo "Run: ollama pull qwen2.5-coder:7b"
    fi
else
    echo "Ollama is not running. Please start Ollama first:"
    echo "  ollama serve"
    echo ""
    echo "Then pull the model:"
    echo "  ollama pull qwen2.5-coder:7b"
fi

echo ""
echo "Installation complete!"
