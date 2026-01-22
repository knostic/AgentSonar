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
sai agents                                      # list all agents
sai agents add <name> <process> <domain>        # create agent
sai agents add-domain <name> <domain>           # add domain to existing agent
sai agents rm <name>                            # remove agent
```

Patterns support:
- `*` - match all
- `*.domain.com` - match subdomains
- `prefix*` - match prefix

Agents are stored in `~/.config/sai/filters.bin` alongside the non-AI bloom filter.

## sai ignore

Add domain to non-AI bloom filter.

```bash
sai ignore <domain>     # add domain to non-AI filter
```

Ignored domains are filtered from output (unless `-a` flag is used).

## sai triage

Interactive triage of unclassified events.

```bash
sai triage
```

Shows each unique process:domain pair with computed confidence level.

Actions:
- `a` - add as agent (uses process name)
- `A` - add as agent with prompts to edit name/domain
- `n` - mark as noise (adds to non-AI bloom filter)
- `s` - skip
- `q` - quit and save filters

## sai sig

Signature management - export/import signatures file.

```bash
sai sig export <file>   # export signatures to file
sai sig import <file>   # import signatures from file
```

Signatures file (`~/.config/sai/filters.bin`) contains:
- Named AI agents (process + domain patterns)
- Non-AI bloom filter (ignored domains)

## sai classifier

Manage external classifiers for scoring unknown traffic.

```bash
sai classifier list             # list loaded classifiers
sai classifier load <config>    # load external classifier
sai classifier unload <name>    # unload classifier
```

External classifiers are long-running processes that receive JSON on stdin and return confidence scores on stdout.

Config format:
```json
{
  "name": "ml-model",
  "command": "/path/to/classifier",
  "args": ["--model", "default"],
  "timeout_ms": 5000
}
```

Protocol:
```
stdin:  {"domain":"api.example.com","process":"app","source":"tls","stats":{...}}
stdout: {"confidence":0.85}
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
