# sai

Detect shadow AI on your machine by tracking which processes call AI-related domains.

## Install

Download the binary for your platform from [Releases](https://github.com/knostic/shadow_ai/releases).

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
sai install
```

This sets up packet capture permissions:
- **macOS:** Creates `access_bpf` group, sets BPF device permissions
- **Linux:** Sets `cap_net_raw,cap_net_admin` capabilities on the binary

### Containers

When running in Docker/Kubernetes, PID lookup may fail due to namespace isolation (e.g., `curl` requests won't appear). Use `--enable-pid0` to capture all traffic regardless of PID resolution.

## Usage

```bash
sai                     # monitor AI domain events (foreground)
sai start               # start daemon (background)
sai stop                # stop daemon
sai status              # check if daemon is running
sai -a                  # all domains, not just AI
sai -j                  # JSON output
sai --enable-pid0       # include events where PID lookup fails
sai events --since 1h   # query stored events
sai classify            # classify events from stdin (JSON lines)
sai agents              # list known agents
sai ignore              # list/add/remove noise domains
sai triage              # classify unknown events
sai sig                 # import/export overrides
sai classifier          # manage external classifiers
sai doctor              # check system health
sai setup               # setup BPF permissions
```

## Go API

Library API available for embedding. See [docs/api.md](docs/api.md) and [examples/](examples/).

```go
mon := sai.NewMonitor(sai.Config{Interface: "en0"})
mon.Start()
for event := range mon.Events() {
    fmt.Printf("%s -> %s\n", event.Process, event.Domain)
}

// Overrides and classifiers work cross-platform
overrides := sai.NewOverrides()
overrides.AddAgent("claude", "claude*", []string{"*.anthropic.com"})
overrides.AddNoise("google.com")
acc := sai.NewAccumulatorWithOverrides(overrides, sai.NewClassifierRegistry())
```

### Examples

```bash
go run ./examples/custom_signals   # custom Signals implementation
go run ./examples/export_import    # Overrides serialization
go run ./examples/basic_monitor    # simple monitoring (darwin)
go run ./examples/full_monitor     # full monitoring with accumulator (darwin)
```

### Classify-only Mode

Classify events from external sources without live network monitoring:

```bash
echo '{"proc":"myagent","domain":"ai.example.com","source":"tls","extras":{"bytes_in":"50000","bytes_out":"1000","packets_in":"300","packets_out":"10","duration_ms":"10000","programmatic":"true"}}' | sai classify
# {"proc":"myagent","domain":"ai.example.com","scores":{"default":0.8},"agent":"","is_noise":false}

# Use specific classifiers
sai classify -c default -c my-model < events.jsonl
```

## Commands

See [docs/commands.md](docs/commands.md) for full reference.
