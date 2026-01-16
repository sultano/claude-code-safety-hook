# Claude Code Safety Hook

An LLM-powered safety validator for Claude Code that auto-approves safe commands and auto-whitelists them for future use.

## What It Does

This hook intercepts Bash commands before execution and:

1. **Auto-approves** safe commands (build, test, read-only operations)
2. **Auto-whitelists** safe command patterns so future runs skip the check
3. **Blocks** dangerous commands (secrets access, destructive operations)
4. **Defers** to Claude Code's permission system for everything else

## Architecture

```
Command → Code Safety Net → LLM Check → Claude Code Permission System
              (100%)         (nuanced)        (user's whitelist)
```

### Defense-in-Depth

The hook uses a layered approach because small LLMs (7B parameters) struggle with principle-based security reasoning:

| Layer | Purpose | Reliability |
|-------|---------|-------------|
| Code safety net | Catch known dangerous patterns | 100% |
| Code never-whitelist | Prevent risky patterns from being saved | 100% |
| Code safe commands | Auto-approve known safe patterns | 100% |
| LLM | Handle nuanced/novel cases | Best effort |

### Hook Output Behavior

| Output | Effect |
|--------|--------|
| `{"permissionDecision": "allow"}` | Auto-approve, no prompt |
| Nothing (empty) | Let Claude Code decide (respects user's existing whitelist) |

This means the hook **respects Claude Code's permission system** - if a user has already whitelisted a command, returning nothing lets it through.

## Installation

```bash
# Copy hook to Claude Code hooks directory
cp validate_tool_safety.py ~/.claude/hooks/

# Add to ~/.claude/settings.json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": "python3 ~/.claude/hooks/validate_tool_safety.py"
          }
        ]
      }
    ]
  }
}
```

Requires [Ollama](https://ollama.ai) running locally with `qwen2.5-coder:7b` model:
```bash
ollama pull qwen2.5-coder:7b
ollama serve
```

## Permission Pattern Syntax

Claude Code supports these whitelist patterns in `settings.local.json`:

```
Bash(go build:*)     # Prefix match - "go build", "go build ./...", "go build -v"
Bash(npm *)          # Wildcard - "npm install", "npm test", "npm run dev"
Bash(git * main)     # Middle wildcard - "git checkout main", "git merge main"
Bash(exact command)  # Exact match only
```

The hook generates patterns at the **subcommand level** (e.g., `go build:*` not `go:*`) for appropriate granularity.

## Safety Rules

### Never Safe to Run (always ask user)

Commands containing:
- **Destructive**: `rm`, `rmdir`, `git clean`, `git reset --hard`
- **Force flags**: `--force`, `-f`, `-rf`
- **Secrets access**: `.env`, `.ssh`, `.aws`, `/etc/passwd`
- **Inline secrets**: `sk-`, `API_KEY=`, `Bearer `, `token=`
- **System modification**: `sudo`, `chmod`, `chown`, `systemctl`
- **Process killing**: `pkill`, `kill`, `killall`
- **Arbitrary execution**: `docker run`, `kubectl exec`, `eval`
- **Network**: `curl`, `wget`, `nc`

### Never Auto-Whitelist (safe to run once, but pattern is risky)

- `git push` - user could add `--force` later
- `npm install`, `pip install`, `yarn add` - runs arbitrary package scripts
- `docker run`, `kubectl exec` - arbitrary execution

### Always Safe (auto-approve and whitelist)

- **Version checks**: `--version`, `go version`, `node --version`
- **Read-only git**: `git status`, `git log`, `git diff`, `git branch`
- **Build/test**: `go build`, `go test`, `cargo build`, `npm test`
- **File reading**: `ls`, `cat`, `head`, `tail`, `find`, `grep`

## Auto-Whitelist Behavior

When a command is approved, the hook:

1. Asks the LLM for the **safest pattern** to whitelist
2. Writes to the **closest** `settings.local.json`:
   - Project-level: `.claude/settings.local.json` (if exists)
   - Global: `~/.claude/settings.local.json` (fallback)

The LLM decides pattern granularity:
- `go build ./...` → `Bash(go build:*)` (any go build is safe)
- `git push origin main` → `none` (broader pattern allows --force)

## Testing

```bash
cd /path/to/claude-safety-hook
python3 test_validate_tool_safety.py
```

Tests distinguish between:
- **Critical failures**: Security issues (test fails, exit code 1)
- **Warnings**: LLM pattern quality issues (logged but test passes)

## Learnings & Design Decisions

### Why Code + LLM?

Initially tried pure LLM with principle-based prompts ("decide if safe based on these principles"). Small LLMs (7B) failed on critical cases:
- `cat .env` → LLM said "safe" (wrong!)
- `git push` → LLM whitelisted with `git * main` pattern (dangerous!)

The code safety net catches these with 100% reliability. LLM handles novel cases the code doesn't cover.

### Why Not Just Block Everything?

The goal is **convenience with safety**:
- Running `go test` 50 times shouldn't require 50 approvals
- But `rm -rf` should always ask

The hook auto-approves the boring stuff so you can focus on reviewing the dangerous stuff.

### Why Subcommand-Level Patterns?

`Bash(go:*)` is too broad (matches `go run malicious.go`).
`Bash(go build ./...)` is too narrow (doesn't match `go build -v`).
`Bash(go build:*)` is the sweet spot.

### Why Never Whitelist `npm install`?

It's safe to **run** `npm install lodash`, but whitelisting `Bash(npm install:*)` means:
- `npm install malicious-package` auto-approves
- Package install scripts run arbitrary code

Same reasoning for `pip install`, `yarn add`, etc.

## Configuration

Edit constants in `validate_tool_safety.py`:

```python
OLLAMA_MODEL = "qwen2.5-coder:7b"  # Change model
TIMEOUT_SECONDS = 30               # LLM timeout

UNSAFE_COMMANDS = {...}            # Never safe to run
NEVER_WHITELIST_COMMANDS = {...}   # Safe to run, never whitelist
SAFE_COMMAND_BASES = {...}         # Always safe
```

## Files

```
claude-safety-hook/
├── validate_tool_safety.py   # The hook
├── test_validate_tool_safety.py  # Test suite
├── install.sh                # Installation script
├── settings.json             # Example settings
└── README.md                 # This file
```
