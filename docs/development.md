# Development

## Requirements

- Go 1.21+
- macOS or Linux

### Build Dependencies

**Debian/Ubuntu:**
```bash
apt-get install libpcap-dev
```

**Fedora/RHEL:**
```bash
dnf install libpcap-devel
```

**macOS:** No additional packages required.

## Setup

```bash
git clone https://github.com/knostic/agentsonar
cd agentsonar
go mod download
```

Build the binary, then set up packet capture (see below). To do both in one step:

```bash
make setup-bpf    # builds and runs agentsonar install
```

### Packet Capture Permissions

**Automated setup** (after building):

```bash
make setup-bpf    # build + run agentsonar install
# or, if already built:
./bin/agentsonar install
```

#### macOS

Creates `access_bpf` group and sets `/dev/bpf*` permissions.

**Manual setup:**
```bash
sudo dseditgroup -o create access_bpf
sudo dseditgroup -o edit -a $USER -t user access_bpf
sudo chgrp access_bpf /dev/bpf*
sudo chmod g+rw /dev/bpf*
```

BPF device permissions reset on reboot. See `scripts/` for a LaunchDaemon that restores them automatically.

#### Linux

Sets capabilities on the binary. Requires `libcap2-bin` (Debian/Ubuntu) or `libcap` (Fedora/RHEL) for `setcap`.

**Manual setup:**
```bash
sudo setcap cap_net_raw,cap_net_admin=eip /path/to/agentsonar
```

Log out and back in for group membership to take effect.

Run `agentsonar doctor` to verify permissions.

## Build

```bash
make build        # production binary → bin/agentsonar
make dev          # dev build (-tags dev, e.g. extra logging / nuke) → bin/agentsonar
make install      # build and copy to /usr/local/bin
make clean        # remove bin/
make tidy         # go mod tidy
```

Typical workflow: use `make dev` while developing, run `make test` to verify, then `make build` for a release binary.

## Test

```bash
make test         # go test -v ./...
```

## Project Structure

```
cmd/agentsonar/          # CLI entrypoint
internal/         # internal packages
docs/             # documentation
```

## Dev vs Production

Dev builds (`make dev`) include:
- `agentsonar nuke` - clear database
