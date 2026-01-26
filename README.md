# sai

Detect shadow AI on your machine by tracking which processes call AI-related domains.

## Install

```bash
make build
sudo make install
```

BPF permissions (macOS):
```bash
sudo chgrp admin /dev/bpf* && sudo chmod g+rw /dev/bpf*
```

## Usage

```bash
sai                     # monitor AI domain events (foreground)
sai start               # start daemon (background)
sai stop                # stop daemon
sai status              # check if daemon is running
sai -a                  # all domains, not just AI
sai -j                  # JSON output
sai events --since 1h   # query stored events
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
// Monitor network traffic (darwin only)
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

## Commands

See [docs/commands.md](docs/commands.md) for full reference.
