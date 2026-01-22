# Commands

## sai

Live monitoring - streams events to stdout.

```bash
sai [flags]
```

| Flag | Description |
|------|-------------|
| `-a` | All domain events, not just known AI |
| `-j` | JSON lines output |
| `-i <iface>` | Network interface (default: en0) |
| `--enable-pid0` | Include PID 0 / system processes |

Output format:
```
<process>:<pid> <binary_path> <domain> <source> <confidence> [<agent>]
```

Confidence levels: `none`, `low`, `medium`, `high`

## sai start

Start the daemon in the background.

```bash
sai start [flags]
```

| Flag | Description |
|------|-------------|
| `-a` | All domain events, not just known AI |
| `-j` | JSON lines output |
| `-i <iface>` | Network interface (default: en0) |
| `--enable-pid0` | Include PID 0 / system processes |

## sai stop

Stop the background daemon.

```bash
sai stop
```

## sai status

Check if the daemon is running.

```bash
sai status
```

## sai events

Query stored events from SQLite.

```bash
sai events [flags]
```

| Flag | Description |
|------|-------------|
| `--since <dur>` | Events in last duration (e.g., 1h, 30m) |
| `--process <name>` | Filter by process name |
| `--domain <name>` | Filter by domain |
| `-n <num>` | Limit results (default: 50) |
| `-j` | JSON output |

## sai agents

Manage AI agent definitions.

```bash
sai agents                              # list all agents
sai agents add <name> <process>         # create agent with process pattern
sai agents add-domain <name> <domain>   # add domain pattern to agent
sai agents rm <name>                    # remove agent
```

Patterns support:
- `*` - match all
- `*.domain.com` - match subdomains
- `prefix*` - match prefix

## sai ignore

Ignore domains (if it's not an LLM, it's not an agent).

```bash
sai ignore              # list ignore rules
sai ignore <url>        # add ignore rule (wildcards supported: *.example.com)
sai ignore rm <url>     # remove ignore rule
```

## sai triage

Interactive triage of unclassified events.

```bash
sai triage
```

Shows each unique process:domain pair with computed confidence level.

Actions:
- `a` - add as agent (uses process name, `*.basedomain`)
- `A` - add as agent with prompts to edit name
- `i` - ignore domain (`basedomain`)
- `I` - ignore with prompt to edit URL (defaults to `*.basedomain`)
- `s` - skip
- `q` - quit

## sai sig

Signature management - export/import agent definitions.

```bash
sai sig export              # export agents and ignores as JSON
sai sig import < file.json  # import from JSON
```

JSON format:
```json
{
  "version": "2026-01-22",
  "agents": [{"name": "Cursor", "process": "cursor", "domains": ["*.anthropic.com"]}],
  "ignore": [{"url": "*.cloudflare.com"}]
}
```

## sai doctor

Check system health and configuration.

```bash
sai doctor
```

Checks:
- BPF access permissions
- Database accessibility
- Available network interfaces
- Configured agents and ignore rules
- Stored event count

## sai setup

Display BPF setup instructions for macOS.

```bash
sai setup
```

## sai nuke (dev only)

Clear the database. Only available in dev builds (`make dev`).

```bash
sai nuke
```
