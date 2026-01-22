# Go API

Library for embedding sai's network monitoring into your own tools.

## Install

```bash
go get github.com/knostic/sai
```

## Monitor

```go
import "github.com/knostic/sai"

mon := sai.NewMonitor(sai.Config{
    Interface:  "en0",      // network interface
    EnablePID0: false,      // include kernel/system processes
    AllDomains: false,      // monitor all domains, not just AI
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
    Confidence Confidence        // computed confidence level
    Extras     map[string]string
}
```

## Accumulator

Tracks events over time and computes confidence levels for process:domain pairs.

```go
// Interface - implement your own for custom persistence
type Accumulator interface {
    Record(event Event)
    Confidence(process, domain string) Confidence
    Count(process, domain string) int
    Stats(process, domain string) *PairStats
}
```

### In-memory (default)

```go
acc := sai.NewAccumulator()

for event := range mon.Events() {
    acc.Record(event)
    conf := acc.Confidence(event.Process, event.Domain)
    fmt.Printf("%s -> %s [%s]\n", event.Process, event.Domain, conf)
}
```

### Custom implementation

Implement the `Accumulator` interface to use your own persistence (Redis, Postgres, etc.):

```go
type MyAccumulator struct {
    db *sql.DB
}

func (a *MyAccumulator) Record(event sai.Event) {
    // store in your database
}

func (a *MyAccumulator) Confidence(process, domain string) sai.Confidence {
    // compute from your stored data
}

// ... implement Count and Stats
```

### Confidence levels

```go
type Confidence int

const (
    ConfidenceNone   // unknown
    ConfidenceLow    // streaming behavior only
    ConfidenceMedium // parent domain match
    ConfidenceHigh   // direct bloom filter hit
)
```

Confidence increases with:
- Direct domain match in AI bloom filter → high
- Parent domain match (api.openai.com → openai.com) → medium
- Streaming behavior detected → low (bumps up with repetition)
- Multiple observations → increases confidence over time

### Infrastructure penalties

Certain subdomains indicate non-LLM infrastructure and reduce confidence:

| Penalty | Subdomains |
|---------|------------|
| 0.5 | `logs`, `log`, `logging`, `telemetry`, `ocsp`, `ocsp2`, `crl` |
| 0.4 | `metrics`, `intake`, `analytics`, `tracking`, `tracker`, `statsig`, `cloudkit`, `apple-cloudkit`, `cloudfront`, `cloudflare`, `akamai`, `fastly`, `icloud` |
| 0.3 | `events`, `cdn`, `static`, `assets`, `media`, `gateway`, `stats`, `status`, `health` |
| 0.2 | `auth`, `oauth`, `oauth2`, `login`, `sso` |

Penalties stack when multiple infrastructure subdomains are present.

## Classifier

Check if a domain is a known AI provider:

```go
c := sai.NewClassifier()
if c.IsAI("api.openai.com") {
    // known AI domain
}
```

## Database

Optional SQLite storage (CLI uses this, library users can ignore):

```go
db, _ := sai.OpenDB(sai.DefaultDBPath())
defer db.Close()

db.InsertEvent(event)
events, _ := db.QueryEvents(time.Hour, "", "", 100)
```
