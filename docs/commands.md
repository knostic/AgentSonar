# Commands

## agentsonar

Live monitoring - streams events to stdout.

```bash
agentsonar [flags]
```

| Flag | Description |
|------|-------------|
| `-a` | All domain events, not just known AI |
| `-j` | JSON lines output |
| `-i <iface>` | Network interface (default: en0) |
| `--enable-pid0` | Include traffic without local process association (containers, mirrored traffic, proxy monitoring) |

Output format (tab-separated):
```
15:04:05	claude	claude-code	1234	api.anthropic.com	tls	0.85
```

Columns: timestamp, agent, process, pid, domain, source, ai_score

Known agents are highlighted in yellow when output is a TTY. Pipe-friendly (colors disabled when not a TTY).

## agentsonar start

Start the daemon in the background.

```bash
agentsonar start [flags]
```

| Flag | Description |
|------|-------------|
| `-a` | All domain events, not just known AI |
| `-j` | JSON lines output |
| `-i <iface>` | Network interface (default: en0) |
| `--enable-pid0` | Include traffic without local process association (containers, mirrored traffic, proxy monitoring) |

Logs: `~/.config/agentsonar/agentsonar.log`, PID: `~/.config/agentsonar/agentsonar.pid`

## agentsonar stop

Stop the background daemon.

```bash
agentsonar stop
```

## agentsonar status

Check if the daemon is running.

```bash
agentsonar status
```

## agentsonar events

Query stored events from SQLite.

```bash
agentsonar events [flags]
```

| Flag | Description |
|------|-------------|
| `--since <dur>` | Events in last duration (e.g., 1h, 30m) |
| `--process <name>` | Filter by process name |
| `--domain <name>` | Filter by domain |
| `-n <num>` | Limit results (default: 50) |
| `-j` | JSON output |

## agentsonar agents

Manage AI agent definitions.

```bash
agentsonar agents                                      # list all agents
agentsonar agents add <name> <process> <domain>        # create agent
agentsonar agents add-domain <name> <domain>           # add domain to existing agent
agentsonar agents rm <name>                            # remove agent
```

Patterns support:
- `*` - match all
- `*.domain.com` - match subdomains
- `prefix*` - match prefix

Agents are stored in `~/.config/agentsonar/overrides.bin`.

## agentsonar ignore

Manage noise domains (known non-AI).

```bash
agentsonar ignore                  # list noise domains
agentsonar ignore add <domain>     # add domain to noise list
agentsonar ignore rm <domain>      # remove domain from noise list
```

Noise domains and their subdomains are filtered from output (unless `-a` flag is used).

## agentsonar triage

Interactive triage of unclassified events.

```bash
agentsonar triage
```

Shows each unique process:domain pair with computed confidence level.

Actions:
- `a` - add as agent (uses process name)
- `A` - add as agent with prompts to edit name/domain
- `n` - mark as noise (adds domain to noise list)
- `s` - skip
- `q` - quit and save

## agentsonar export / agentsonar import

Export/import overrides file.

```bash
agentsonar export [--format binary|sigma] <file>
agentsonar import [--format binary|sigma] <file>
```

| Flag | Description |
|------|-------------|
| `-f, --format` | Format: `binary` (default) or `sigma` |

Formats:
- `binary`: gob-encoded binary (default, for machine use)
- `sigma`: Sigma YAML rules (human-readable, for SIEM integration)

Sigma format exports agents as detection rules and noise domains as filter rules, compatible with [sigconverter.io](https://sigconverter.io) and sigma-cli.

Overrides file (`~/.config/agentsonar/overrides.bin`) contains:
- Named AI agents (process + domain patterns)
- Noise domains list

## agentsonar classifier

Manage external classifiers for scoring unknown traffic.

```bash
agentsonar classifier list             # list loaded classifiers
agentsonar classifier load <config>    # load external classifier
agentsonar classifier unload <name>    # unload classifier
```

External classifiers are long-running processes that receive JSON on stdin and return AI scores on stdout.

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
stdout: {"ai_score":0.85}
```

## agentsonar doctor

Check system health and configuration.

```bash
agentsonar doctor
```

Checks:
- BPF access permissions
- Database accessibility
- Overrides file
- Available network interfaces
- Configured agents and noise domains
- Stored event count

## agentsonar install

Setup BPF permissions for packet capture. Exits non-zero if not configured.

```bash
agentsonar install
```

On macOS:
1. Creates `access_bpf` group (if needed)
2. Adds current user to the group
3. Sets `/dev/bpf*` device permissions
4. Optionally installs LaunchDaemon to persist permissions across reboots (only offered for fresh installs)

Log out and back in for group membership to take effect.

## agentsonar uninstall

Remove BPF permissions.

```bash
agentsonar uninstall
```

- Removes LaunchDaemon if installed
- Removes current user from the `access_bpf` group

Log out and back in for changes to take effect.

## agentsonar setup

Display BPF setup instructions for macOS.

```bash
agentsonar setup
```

## agentsonar nuke (dev only)

Clear the database. Only available in dev builds (`make dev`).

```bash
agentsonar nuke
```

## Environment

`AGENTSONAR_CONFIG_DIR`, `AGENTSONAR_OVERRIDES_PATH`, `AGENTSONAR_DB_PATH` override default paths.
