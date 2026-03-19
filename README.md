```
██╗  ██╗███╗   ██╗ ██████╗ ███████╗████████╗██╗ ██████╗
██║ ██╔╝████╗  ██║██╔═══██╗██╔════╝╚══██╔══╝██║██╔════╝
█████╔╝ ██╔██╗ ██║██║   ██║███████╗   ██║   ██║██║     
██╔═██╗ ██║╚██╗██║██║   ██║╚════██║   ██║   ██║██║     
██║  ██╗██║ ╚████║╚██████╔╝███████║   ██║   ██║╚██████╗
╚═╝  ╚═╝╚═╝  ╚═══╝ ╚═════╝ ╚══════╝   ╚═╝   ╚═╝ ╚═════╝
```

# AgentSonar
Detect shadow AI agents by monitoring network traffic for patterns that resemble LLM communication, and by classifying process-to-domain pairs for future detection. Contribute to the community by submitting your agent classifications.

**By [Knostic](https://knostic.ai/)**

Also check out:
- **OpenAnt:** https://github.com/knostic/OpenAnt/. [OpenAnt](https://knostic.ai/openant) is an open source LLM-based vulnerability discovery product that helps defenders proactively find verified security flaws while minimizing both false positives and false negatives. Stage 1 detects. Stage 2 attacks. What survives is real.
- **Like what we do?** Knostic helps you with visibility and control of your agents, coding assistants, and MCP/extensions/skills, from Cursor and Claude Code, to Copilot and Cowork.

## What AgentSonar does and how it works

AgentSonar watches outbound traffic on your machine and answers: **which process is talking to which domain, and is that likely an AI tool?** It associates each connection with a process (via socket ownership), records which domain was contacted (TLS SNI or DNS), and assigns an **AI score** (0–1) to each process–domain pair based on traffic analysis.

- **Known agents** — You define agents (e.g. “Claude” = process `claude*` → `*.anthropic.com`). Matches get score 1.0 and can be filtered or labeled in the UI.
- **Unknown traffic** — Everything else is scored by a built-in **heuristic classifier**: it uses traffic shape (byte/packet asymmetry, small packets, long-lived or streaming connections, programmatic TLS) to guess “looks like an LLM API.” No hardcoded list of AI domains; high score means likely shadow AI.
- **Noise** — Domains you mark as noise (e.g. `google.com`) are ignored and get score 0.

**How to operate it:** Run `agentsonar` (or `agentsonar start`) to monitor live. Events are written to the terminal and stored in a local DB. Use `agentsonar agents` and `agentsonar ignore` to maintain known AI agents and noise. Use `agentsonar triage` to review unknown, high-scoring pairs and mark them as agent or noise. You can also pipe pre-made events into `agentsonar classify` without running capture.

## Install

Download the binary for your platform from [Releases](https://github.com/knostic/agentsonar/releases).

To build from source, see [docs/development.md](docs/development.md).

### Runtime Dependencies

**macOS:** None.

**Debian/Ubuntu:**
```bash
apt-get install libpcap0.8 libcap2-bin
```

**Fedora/RHEL:**
```bash
dnf install libpcap libcap
```

### Permissions

```bash
agentsonar install
```

This sets up packet capture permissions:
- **macOS:** Creates `access_bpf` group, sets BPF device permissions
- **Linux:** Sets `cap_net_raw,cap_net_admin` capabilities on the binary

## Usage

### Monitoring

```bash
agentsonar                     # monitor AI domain events (foreground)
agentsonar start               # start daemon (background)
agentsonar stop                # stop daemon
agentsonar status              # check if daemon is running
```

| Flag | Description |
|------|-------------|
| `-a` | All domains, not just AI |
| `-j` | JSON output |
| `-i <iface>` | Network interface (default: en0) |
| `--enable-pid0` | Include traffic without process association |

### Subcommands

```bash
agentsonar events --since 1h   # query stored events
agentsonar classify            # classify events from stdin (JSON lines)
agentsonar agents              # list/add/remove known agents
agentsonar ignore              # list/add/remove noise domains
agentsonar triage              # interactive classification of unknown events
agentsonar export / agentsonar import # import/export overrides
agentsonar classifier          # manage external classifiers
agentsonar doctor              # check system health
agentsonar install / uninstall # setup/remove BPF permissions
```

See [docs/commands.md](docs/commands.md) for full reference.

### Classify-only Mode

Classify events from external sources without live network monitoring:

```bash
echo '{"proc":"myagent","domain":"ai.example.com","source":"tls","extras":{"bytes_in":"50000","bytes_out":"1000","packets_in":"300","packets_out":"10","duration_ms":"10000","programmatic":"true"}}' | agentsonar classify
# {"proc":"myagent","domain":"ai.example.com","scores":{"default":0.8},"agent":"","is_noise":false}

# Use specific classifiers
agentsonar classify -c default -c my-model < events.jsonl
```

### Monitoring Without Process Association

AgentSonar associates network traffic with local processes by looking up socket ownership. In some scenarios, this lookup fails:

- **Containers:** Namespace isolation prevents PID resolution
- **Proxy/gateway servers:** Traffic passing through has no local process
- **TAP/span ports:** Mirrored traffic from other hosts

Use `--enable-pid0` to capture all traffic regardless of process association:

```bash
agentsonar -i bond0 --enable-pid0    # monitor mirrored traffic
agentsonar -i eth0 --enable-pid0     # proxy server seeing client traffic
```

For offline analysis, capture traffic externally and pipe to the classifier:

```bash
# Extract SNI from pcap, format as JSON, classify
tshark -r capture.pcap -Y 'tls.handshake.extensions_server_name' \
  -T fields -e tls.handshake.extensions_server_name | \
  jq -Rc '{domain: ., source: "tls"}' | agentsonar classify
```

## Go API

Library API available for embedding. See [docs/api.md](docs/api.md) and [examples/](examples/).
