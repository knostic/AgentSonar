# Classifiers

## Default Classifier

The built-in classifier scores traffic based on patterns typical of LLM API calls.

**Signals** (each adds to score):

| Signal | Threshold | Score |
|--------|-----------|-------|
| Byte asymmetry (in/out) | >5x | +0.10 |
| Byte asymmetry (in/out) | >20x | +0.05 |
| Packet asymmetry (in/out) | >5x | +0.10 |
| Packet asymmetry (in/out) | >20x | +0.05 |
| Small packets (token streaming) | <500 bytes avg | +0.10 |
| Small packets (token streaming) | <200 bytes avg | +0.05 |
| Sustained packet rate | >2/sec | +0.10 |
| Long-lived connection | >5s | +0.10 |
| TLS + streaming combined | | +0.15 |
| TLS only | | +0.05 |
| Streaming only | | +0.05 |
| Concurrent connections | >1 | +0.05 |
| Programmatic TLS client | | +0.10 |
| Repeated observations | ≥3 | +0.05 |
| Repeated observations | ≥10 | +0.05 |

**Infrastructure penalties** (subtracted from score):

Subdomains indicating non-LLM traffic reduce the score:

- `-0.5`: `logs`, `log`, `logging`, `telemetry`, `ocsp`, `ocsp2`, `crl`
- `-0.4`: `metrics`, `intake`, `analytics`, `tracking`, `statsig`, `cloudkit`, `cloudfront`, `cloudflare`, `akamai`, `fastly`, `icloud`
- `-0.3`: `events`, `cdn`, `static`, `assets`, `media`, `gateway`, `stats`, `status`, `health`
- `-0.2`: `auth`, `oauth`, `oauth2`, `login`, `sso`

Penalties stack (e.g., `logs.metrics.example.com` gets -0.9).

## External Classifiers

External classifiers are long-running processes that score unknown traffic. They receive JSON on stdin and return AI scores on stdout.

## Protocol

### Input

One JSON object per line:

```json
{
  "domain": "api.example.com",
  "process": "myapp",
  "source": "tls",
  "ja4": "t13d1516h2_8daaf6152771_b0da82dd1658",
  "stats": {
    "count": 5,
    "bytes_in": 56789,
    "bytes_out": 1234,
    "packets_in": 100,
    "packets_out": 10,
    "duration_ms": 5000,
    "max_concurrent": 2,
    "is_programmatic": true,
    "sources": {"tls": 3, "streaming": 2}
  }
}
```

| Field | Type | Description |
|-------|------|-------------|
| `domain` | string | Destination domain |
| `process` | string | Process name |
| `source` | string | Detection source: `tls`, `dns`, `streaming` |
| `ja4` | string | TLS fingerprint (optional) |
| `stats` | object | Traffic statistics (optional, may be null) |

### Stats object

| Field | Type | Description |
|-------|------|-------------|
| `count` | int | Number of observations |
| `bytes_in` | int64 | Total bytes received |
| `bytes_out` | int64 | Total bytes sent |
| `packets_in` | int | Total packets received |
| `packets_out` | int | Total packets sent |
| `duration_ms` | int64 | Total connection duration |
| `max_concurrent` | int | Max concurrent connections observed |
| `is_programmatic` | bool | TLS client appears programmatic |
| `sources` | map | Count by detection source |

### Output

One JSON object per line:

```json
{"ai_score": 0.85}
```

| Field | Type | Description |
|-------|------|-------------|
| `ai_score` | float64 | Score from 0.0 (not AI) to 1.0 (definitely AI) |

## Example: Python classifier

```python
#!/usr/bin/env python3
import json
import sys

# Known AI domains (simple lookup)
AI_DOMAINS = {"openai.com", "anthropic.com", "cohere.ai"}

def classify(data):
    domain = data.get("domain", "")

    # Check domain suffix
    for ai in AI_DOMAINS:
        if domain.endswith(ai):
            return 0.9

    # Check traffic patterns
    stats = data.get("stats")
    if not stats:
        return 0.0

    score = 0.0

    # High byte ratio (large response vs small request)
    if stats["bytes_out"] > 0:
        ratio = stats["bytes_in"] / stats["bytes_out"]
        if ratio > 10:
            score += 0.3

    # Streaming detection
    if stats["sources"].get("streaming", 0) > 0:
        score += 0.2

    # Long-lived connection
    if stats["duration_ms"] > 5000:
        score += 0.1

    return min(score, 0.99)

if __name__ == "__main__":
    for line in sys.stdin:
        try:
            data = json.loads(line)
            score = classify(data)
            print(json.dumps({"ai_score": score}), flush=True)
        except:
            print(json.dumps({"ai_score": 0.0}), flush=True)
```

## Example: Shell classifier

```bash
#!/bin/bash
# Simple domain-based classifier

while IFS= read -r line; do
    domain=$(echo "$line" | jq -r '.domain')

    case "$domain" in
        *openai.com|*anthropic.com|*cohere.ai)
            echo '{"ai_score": 0.9}'
            ;;
        *)
            echo '{"ai_score": 0.0}'
            ;;
    esac
done
```

## Config file

Save as `~/.config/sai/classifiers/my-classifier.json`:

```json
{
  "name": "my-classifier",
  "command": "/path/to/classifier.py",
  "args": [],
  "timeout_ms": 5000
}
```

Load with:

```bash
sai classifier load ~/.config/sai/classifiers/my-classifier.json
```

## Tips

- Flush stdout after each response
- Handle malformed input gracefully (return 0.0)
- Keep latency low (default timeout is 5 seconds)
- Return 0.0 for unknown, not negative values
- Scores are capped at 0.99 for unknown traffic (1.0 is reserved for bloom filter matches)
