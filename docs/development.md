# Development

## Requirements

- Go 1.21+
- macOS (network monitoring uses BPF)

## Setup

```bash
git clone https://github.com/knostic/sai
cd sai
go mod download
```

### BPF Permissions

Packet capture requires access to `/dev/bpf*` devices. On macOS, this is controlled via group membership.

**Automated setup:**
```bash
sai install
```

The command will:
1. Create the `access_bpf` group (if needed)
2. Add your user to the group
3. Set `/dev/bpf*` permissions

**Manual setup:**
```bash
# Create access_bpf group
sudo dseditgroup -o create access_bpf

# Add yourself to the group
sudo dseditgroup -o edit -a $USER -t user access_bpf

# Set device permissions
sudo chgrp access_bpf /dev/bpf*
sudo chmod g+rw /dev/bpf*
```

Log out and back in for group membership to take effect.

**Persistence across reboots:**

BPF device permissions reset on reboot. See `scripts/` for a LaunchDaemon that restores them automatically.

Run `sai doctor` to verify permissions.

## Build

```bash
make build        # production binary -> bin/sai
make dev          # dev build (includes sai nuke)
make install      # copy to /usr/local/bin
```

## Test

```bash
make test
```

## Project Structure

```
cmd/sai/          # CLI entrypoint
internal/         # internal packages
docs/             # documentation
```

## Dev vs Production

Dev builds (`make dev`) include:
- `sai nuke` - clear database
