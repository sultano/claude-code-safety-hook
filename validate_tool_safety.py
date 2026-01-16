#!/usr/bin/env python3
"""
Claude Code Hook: LLM-based Tool Safety Validator

Uses Ollama to assess whether a tool call is safe (read-only) or requires
user confirmation (write/destructive operations).

BEHAVIOR: This hook intercepts tool calls and uses an LLM to classify them
as safe (auto-approve) or potentially dangerous (ask user). The LLM assessment
provides context-aware safety decisions beyond simple pattern matching.
"""

import json
import os
import sys
import urllib.request
import urllib.error
from pathlib import Path
from typing import Any

# Configuration
OLLAMA_URL = "http://localhost:11434/api/generate"
OLLAMA_MODEL = "qwen2.5-coder:7b"  # Good balance of capability and size
TIMEOUT_SECONDS = 30  # Higher timeout for initial model load

# Tools that are always safe (read-only by design)
ALWAYS_SAFE_TOOLS = {"Read", "Glob", "Grep", "WebSearch", "WebFetch"}

# Tools that always need user confirmation
ALWAYS_ASK_TOOLS = {"Task", "Skill"}

# Settings file paths
GLOBAL_SETTINGS = Path.home() / ".claude" / "settings.local.json"
PROJECT_SETTINGS_NAME = ".claude/settings.local.json"

# Multi-word command tools (use subcommand as base)
MULTI_WORD_TOOLS = {"go", "npm", "yarn", "cargo", "make", "git", "docker", "kubectl", "python", "pip", "bun"}

# BEHAVIOR: Code-based safety net - catches dangerous patterns before LLM
# These are checked with simple string matching for 100% reliability

# Commands that are NEVER safe to run (always ask user)
UNSAFE_COMMANDS = {
    # Destructive
    "rm ", "rm\t", "rmdir", "unlink",
    "git clean", "git reset --hard", "git reset --mixed",
    # Force flags
    "--force", " -f ", " -rf", "-rf ",
    # Secrets in file paths
    ".env", ".ssh", ".aws", ".gnupg", "credentials", "secrets",
    "/etc/passwd", "/etc/shadow",
    # Inline secrets (API keys, tokens) - should never be whitelisted
    "sk-", "api_key=", "apikey=", "API_KEY=",
    "token=", "TOKEN=", "secret=", "SECRET=",
    "password=", "PASSWORD=", "passwd=",
    "Bearer ", "Basic ",
    # System modification
    "sudo ", "sudo\t", "doas ",
    "chmod ", "chown ", "chgrp ",
    "systemctl", "service ",
    # Process killing
    "pkill ", "kill ", "killall ",
    # Arbitrary execution
    "eval ", "exec ",
    "docker run", "docker exec",
    "kubectl run", "kubectl exec",
    # Network (data exfiltration risk)
    "curl ", "wget ", "nc ", "netcat",
    # Package managers (run arbitrary install scripts)
    "brew install", "brew upgrade",
    "pip install", "npm install", "yarn add", "pnpm install", "bun install",
}

# Commands safe to run but NEVER auto-whitelist (pattern could be abused)
NEVER_WHITELIST_COMMANDS = {
    # Git push - could add --force later
    "git push",
    # Docker/k8s - arbitrary execution
    "docker run", "docker exec",
    "kubectl exec", "kubectl run", "kubectl delete", "kubectl apply",
}

# Base commands that are always safe to run AND whitelist
SAFE_COMMAND_BASES = {
    # Version checks
    "--version", "-v", "-V", "version",
    # Read-only git
    "git status", "git log", "git diff", "git branch", "git show", "git remote",
    # Build/test (local operations)
    "go build", "go test", "go run", "go mod", "go version",
    "cargo build", "cargo test", "cargo run", "cargo check",
    "npm test", "npm run", "npm start",
    "make", "cmake",
    "pytest", "python -m pytest",
    # Read-only file operations
    "ls", "cat ", "head ", "tail ", "less ", "more ",
    "find ", "grep ", "wc ", "du ", "df ",
}

WHITELIST_PATTERN_PROMPT = """Given a bash command, suggest the SAFEST permission pattern to whitelist it.

Valid pattern syntax:
- "Bash(go build:*)" - prefix match, allows "go build", "go build ./...", "go build -v"
- "Bash(npm *)" - wildcard, allows "npm install", "npm test", "npm run dev"
- "Bash(git * main)" - allows "git checkout main", "git merge main"
- "Bash(exact cmd)" - exact match only

Return a pattern ONLY if ALL possible matching commands are safe:
- Could adding ANY flags make it dangerous? If yes → "none"
- Could changing arguments cause harm? If yes → "none"
- Does it only read/display/build/test? If yes → safe pattern

Return "none" if:
- Different arguments could be destructive (git push → git push --force)
- It deletes data, makes network requests, runs arbitrary code, or changes system state

Think: "If I whitelist this pattern, what's the WORST command that would match?"

Respond with ONLY: {"pattern": "Bash(...)"} or {"pattern": "none"}
"""

SYSTEM_PROMPT = """Evaluate if this command is safe to run without user confirmation.

SAFE if the command:
- Only reads, displays, or queries information
- Builds, compiles, or tests code (local operations)
- Installs dependencies from standard registries
- Checks versions or system info

UNSAFE if the command:
- Deletes or modifies files (rm, mv to overwrite, truncate)
- Uses --force or -f flags (destructive override)
- Accesses secrets (.env, .ssh, .aws, credentials, keys, tokens, passwd)
- Makes network requests that could send data (curl, wget)
- Runs arbitrary/untrusted code (docker run, eval, exec)
- Changes permissions or ownership (chmod, chown, sudo)
- Has irreversible effects (git reset --hard, git clean, drop)

Think: "Could this command leak secrets, destroy data, or cause harm?"

Respond with ONLY: {"safe": true, "reason": "..."} or {"safe": false, "reason": "..."}
"""


def check_unsafe_command(command: str) -> bool:
    """Code-based check: Is this command unsafe to run? (100% reliable)"""
    cmd_lower = command.lower()
    return any(pattern in cmd_lower for pattern in UNSAFE_COMMANDS)


def check_never_whitelist(command: str) -> bool:
    """Code-based check: Should this command never be whitelisted? (100% reliable)"""
    cmd_lower = command.lower()
    return any(pattern in cmd_lower for pattern in NEVER_WHITELIST_COMMANDS)


def check_safe_command(command: str) -> bool:
    """Code-based check: Is this command known-safe to run AND whitelist?"""
    cmd_lower = command.lower()
    return any(pattern in cmd_lower for pattern in SAFE_COMMAND_BASES)


def get_settings_path() -> Path:
    """Get the closest settings file (project-level if exists, else global)."""
    project_settings = Path.cwd() / PROJECT_SETTINGS_NAME
    if project_settings.exists():
        return project_settings
    return GLOBAL_SETTINGS


def extract_permission_pattern(command: str) -> str:
    """Extract base command for whitelist pattern at subcommand level."""
    parts = command.strip().split()
    if not parts:
        return f"Bash({command}:*)"

    # For multi-word tools, use first two words (e.g., "go test" -> "Bash(go test:*)")
    if len(parts) >= 2 and parts[0] in MULTI_WORD_TOOLS:
        base = f"{parts[0]} {parts[1]}"
    else:
        base = parts[0]

    return f"Bash({base}:*)"


def get_whitelist_pattern(command: str) -> str | None:
    """Ask LLM to suggest the safest whitelist pattern for a command."""
    payload = {
        "model": OLLAMA_MODEL,
        "prompt": f"Command: {command}",
        "system": WHITELIST_PATTERN_PROMPT,
        "stream": False,
        "options": {
            "temperature": 0.1,
            "num_predict": 100,
        },
    }

    try:
        req = urllib.request.Request(
            OLLAMA_URL,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=TIMEOUT_SECONDS) as response:
            result = json.loads(response.read().decode("utf-8"))
            response_text = result.get("response", "")

            start = response_text.find("{")
            end = response_text.rfind("}") + 1
            if start != -1 and end > start:
                llm_result = json.loads(response_text[start:end])
                pattern = llm_result.get("pattern", "none")
                if pattern and pattern != "none":
                    return pattern
    except (urllib.error.URLError, json.JSONDecodeError, TimeoutError):
        pass

    return None


def add_to_whitelist(command: str) -> None:
    """Add permission pattern to the closest settings.local.json if safe."""
    # BEHAVIOR: Code-based safety net first (100% reliable)
    if check_never_whitelist(command):
        return
    if check_unsafe_command(command):
        return

    # BEHAVIOR: Ask LLM for the safest pattern to whitelist this command
    pattern = get_whitelist_pattern(command)
    if not pattern:
        return

    settings_path = get_settings_path()

    try:
        if settings_path.exists():
            settings = json.loads(settings_path.read_text())
        else:
            settings = {}
    except json.JSONDecodeError:
        settings = {}

    # Ensure structure exists
    permissions = settings.setdefault("permissions", {})
    allow_list = permissions.setdefault("allow", [])

    # Add pattern if not already present
    if pattern not in allow_list:
        allow_list.append(pattern)
        settings_path.parent.mkdir(parents=True, exist_ok=True)
        settings_path.write_text(json.dumps(settings, indent=2) + "\n")


def query_ollama(prompt: str) -> dict[str, Any] | None:
    """Query Ollama for safety assessment."""
    payload = {
        "model": OLLAMA_MODEL,
        "prompt": prompt,
        "system": SYSTEM_PROMPT,
        "stream": False,
        "options": {
            "temperature": 0.1,  # Low temperature for consistent classification
            "num_predict": 100,  # Short response expected
        },
    }

    try:
        req = urllib.request.Request(
            OLLAMA_URL,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=TIMEOUT_SECONDS) as response:
            result = json.loads(response.read().decode("utf-8"))
            response_text = result.get("response", "")

            # Extract JSON from response
            start = response_text.find("{")
            end = response_text.rfind("}") + 1
            if start != -1 and end > start:
                return json.loads(response_text[start:end])
    except (urllib.error.URLError, json.JSONDecodeError, TimeoutError) as e:
        print(f"Ollama query failed: {e}", file=sys.stderr)
    return None


def format_tool_for_analysis(tool_name: str, tool_input: dict[str, Any]) -> str:
    """Format tool call for LLM analysis."""
    if tool_name == "Bash":
        command = tool_input.get("command", "")
        description = tool_input.get("description", "")
        return f"Tool: Bash\nCommand: {command}\nDescription: {description}"

    if tool_name in ("Write", "Edit"):
        file_path = tool_input.get("file_path", "")
        if tool_name == "Write":
            content_preview = tool_input.get("content", "")[:200]
            return f"Tool: Write\nFile: {file_path}\nContent preview: {content_preview}..."
        old_string = tool_input.get("old_string", "")[:100]
        new_string = tool_input.get("new_string", "")[:100]
        return f"Tool: Edit\nFile: {file_path}\nReplacing: {old_string}\nWith: {new_string}"

    if tool_name == "NotebookEdit":
        notebook_path = tool_input.get("notebook_path", "")
        edit_mode = tool_input.get("edit_mode", "replace")
        return f"Tool: NotebookEdit\nNotebook: {notebook_path}\nMode: {edit_mode}"

    # Generic format for other tools
    return f"Tool: {tool_name}\nInput: {json.dumps(tool_input, indent=2)[:500]}"


def make_decision(safe: bool, reason: str) -> dict[str, Any] | None:
    """Create the hook response. Returns None for unsafe operations to let Claude Code decide."""
    if safe:
        # BEHAVIOR: Auto-approve safe commands without prompting
        return {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "allow",
                "permissionDecisionReason": reason,
            }
        }
    # BEHAVIOR: Return nothing for unsafe operations - lets Claude Code's
    # built-in permission system handle it (respects existing whitelist)
    return None


def main() -> None:
    try:
        input_data = json.load(sys.stdin)
    except json.JSONDecodeError:
        sys.exit(0)  # Let it pass if we can't parse input

    tool_name = input_data.get("tool_name", "")
    tool_input = input_data.get("tool_input", {})

    # BEHAVIOR: Always-safe tools bypass LLM check - let Claude Code decide
    if tool_name in ALWAYS_SAFE_TOOLS:
        sys.exit(0)

    # BEHAVIOR: Always-ask tools - let Claude Code decide (respects whitelist)
    if tool_name in ALWAYS_ASK_TOOLS:
        sys.exit(0)

    # For Bash commands, use code-based safety net first
    if tool_name == "Bash":
        command = tool_input.get("command", "")

        # BEHAVIOR: Code-based unsafe check (100% reliable, no LLM needed)
        if check_unsafe_command(command):
            # Return nothing - let Claude Code ask user
            sys.exit(0)

        # BEHAVIOR: Code-based safe check (100% reliable, no LLM needed)
        if check_safe_command(command):
            add_to_whitelist(command)
            decision = make_decision(True, "Code safety check: known safe command")
            if decision:
                print(json.dumps(decision))
            sys.exit(0)

    # For commands not caught by code checks, use LLM
    analysis_prompt = format_tool_for_analysis(tool_name, tool_input)
    llm_result = query_ollama(analysis_prompt)

    if llm_result is None:
        # BEHAVIOR: If LLM unavailable, let Claude Code decide (respects whitelist)
        sys.exit(0)

    safe = llm_result.get("safe", False)
    reason = llm_result.get("reason", "LLM assessment")

    # BEHAVIOR: Auto-whitelist safe Bash commands for future runs
    if safe and tool_name == "Bash":
        command = tool_input.get("command", "")
        if command:
            add_to_whitelist(command)

    decision = make_decision(safe, f"LLM assessment: {reason}")
    if decision:
        print(json.dumps(decision))
    sys.exit(0)


if __name__ == "__main__":
    main()
