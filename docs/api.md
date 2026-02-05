# Go API

Library for embedding agentsonar's network monitoring into your own tools.

## Install

```bash
go get github.com/knostic/agentsonar
```

## Platform Support

| Component | darwin | linux |
|-----------|--------|-------|
| Monitor | Yes | Yes |
| Signals/Overrides | Yes | Yes |
| Accumulator | Yes | Yes |
| Classifiers | Yes | Yes |
| DB | Yes | Yes |

## Monitor

Network monitoring requires darwin (macOS) or linux.

```go
import "github.com/knostic/agentsonar"

mon := sai.NewMonitor(sai.Config{
    Interface:  "en0",      // network interface (en0 on macOS, eth0 on Linux)
    EnablePID0: false,      // include kernel/system processes
})

if err := mon.Start(); err != nil {
    log.Fatal(err)
}
defer mon.Stop()

for event := range mon.Events() {
    fmt.Printf("%s (%d) -> %s [%s]\n",
        event.Process, event.PID, event.Domain, event.Source)
}
```

## Event

```go
type Event struct {
    Timestamp  time.Time
    PID        int
    Process    string            // process name
    BinaryPath string            // full path to binary
    Domain     string            // destination domain
    Source     string            // tls, dns, streaming
    JA4        string            // TLS fingerprint
    Agent      string            // matched agent name (if any)
    AIScore    AIScore           // computed AI score
    Extras     map[string]string
}
```

## Accumulator

Tracks events over time and computes AI scores for process:domain pairs.

```go
// Interface - implement your own for custom persistence
type Accumulator interface {
    Record(event Event)
    AIScore(process, domain string) AIScore
    Count(process, domain string) int
    Stats(process, domain string) *PairStats
}
```

### In-memory (default)

```go
acc := sai.NewAccumulator()

for event := range mon.Events() {
    acc.Record(event)
    score := acc.AIScore(event.Process, event.Domain)
    fmt.Printf("%s -> %s [%s]\n", event.Process, event.Domain, score)
}
```

### With custom Signals

```go
signals := &MySignals{db: myDB}  // your Signals implementation
registry := sai.NewClassifierRegistry()
registry.Add(sai.NewDefaultClassifier())

acc := sai.NewAccumulatorWithSignals(signals, registry)
```

### With Overrides

```go
overrides := sai.NewOverrides()
overrides.Import(loadFromStorage())

registry := sai.NewClassifierRegistry()
registry.Add(sai.NewDefaultClassifier())

acc := sai.NewAccumulatorWithOverrides(overrides, registry)
```

### Custom Accumulator implementation

Implement the `Accumulator` interface to use your own persistence (Redis, Postgres, etc.):

```go
type MyAccumulator struct {
    db *sql.DB
}

func (a *MyAccumulator) Record(event sai.Event) {
    // store in your database
}

func (a *MyAccumulator) AIScore(process, domain string) sai.AIScore {
    // compute from your stored data
}

// ... implement Count and Stats
```

### AI Score

AIScore is a float64 from 0.0 to 1.0:

- `1.0` - known AI agent (in overrides)
- `0.0` - known noise (in overrides)
- `0.0-0.99` - computed by classifiers for unknown traffic

See [classifiers.md](classifiers.md) for scoring signals and infrastructure penalties.

## Signals

Interface for known classifications. Implement this for custom storage backends.

```go
type Signals interface {
    MatchAgent(process, domain string) string  // agent name or ""
    IsNonAIDomain(domain string) bool
}
```

### Custom implementation

```go
type MySignals struct {
    db *sql.DB
}

func (s *MySignals) MatchAgent(process, domain string) string {
    // query your database for known agents
}

func (s *MySignals) IsNonAIDomain(domain string) bool {
    // query your database
}

// Use it
signals := &MySignals{db: myDB}
acc := sai.NewAccumulatorWithSignals(signals, sai.NewClassifierRegistry())
```

## Overrides

Reference implementation of `Signals`. Contains known agents and noise domains.

```go
overrides := sai.NewOverrides()

// Load from file
if sai.OverridesFileExists() {
    overrides.Load(sai.DefaultOverridesPath())
}

// Check if traffic matches a known agent
agentName := overrides.MatchAgent(process, domain)
if agentName != "" {
    // Known AI agent, confidence = 1.0
}

// Check if traffic is known noise
if overrides.IsNoise(domain) {
    // Known noise, confidence = 0.0
}

// Add agent
overrides.AddAgent("cursor", "cursor", []string{"*.anthropic.com"})
overrides.AddAgentDomain("cursor", "*.openai.com")

// Add noise domain
overrides.AddNoise("example.com")

// Save to file
overrides.Save(sai.DefaultOverridesPath())
```

### Export/Import

For custom storage backends, use `Export()` and `Import()` instead of file-based persistence:

```go
// Export to your storage
data := overrides.Export()
saveToRedis(data)  // or database, S3, etc.

// Import from your storage
loaded := sai.NewOverrides()
loaded.Import(loadFromRedis())
```

`OverridesData` contains:
- `Agents` - list of `Agent{Name, Process, Domains}`
- `Noise` - list of noise domain strings

## ClassifierRegistry

Registry for external classifiers that score unknown traffic.

```go
registry := sai.NewClassifierRegistry()
registry.Add(sai.NewDefaultClassifier()) // traffic heuristics

// Add external classifier
cfg := sai.ProcessClassifierConfig{
    Name:    "ml-model",
    Command: "/path/to/classifier",
}
external, _ := sai.NewProcessClassifier(cfg)
registry.Add(external)

// Classify unknown traffic
input := sai.ClassifierInput{
    Domain:  "api.example.com",
    Process: "app",
    Stats:   pairStats,
}
confidence := registry.Classify(input)
```

## Database

Optional SQLite storage (CLI uses this):

```go
db, _ := sai.OpenDB(sai.DefaultDBPath())
defer db.Close()

db.InsertEvent(event)
events, _ := db.QueryEvents(time.Hour, "", "", 100)
```
