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

Output format (tab-separated):
```
15:04:05	claude	claude-code	1234	api.anthropic.com	tls	0.85
```

Columns: timestamp, agent, process, pid, domain, source, confidence

Known agents are highlighted in yellow when output is a TTY. Pipe-friendly (colors disabled when not a TTY).

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

Logs: `~/.config/sai/sai.log`, PID: `~/.config/sai/sai.pid`

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

Agents are stored in `~/.config/sai/overrides.bin`.

## sai ignore

Manage noise domains (known non-AI).

```bash
sai ignore                  # list noise domains
sai ignore add <domain>     # add domain to noise list
sai ignore rm <domain>      # remove domain from noise list
```

Noise domains and their subdomains are filtered from output (unless `-a` flag is used).

## sai triage

Interactive triage of unclassified events.

```bash
sai triage
```

Shows each unique process:domain pair with computed confidence level.

Actions:
- `a` - add as agent (uses process name)
- `A` - add as agent with prompts to edit name/domain
- `n` - mark as noise (adds domain to noise list)
- `s` - skip
- `q` - quit and save

## sai sig

Overrides management - export/import overrides file.

```bash
sai sig export <file>   # export overrides to file
sai sig import <file>   # import overrides from file
```

Overrides file (`~/.config/sai/overrides.bin`) contains:
- Named AI agents (process + domain patterns)
- Noise domains list

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
- Overrides file
- Available network interfaces
- Configured agents and noise domains
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

## Environment

`SAI_CONFIG_DIR`, `SAI_OVERRIDES_PATH`, `SAI_DB_PATH` override default paths.
