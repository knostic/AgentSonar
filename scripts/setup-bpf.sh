#!/bin/bash
# Setup BPF permissions for macOS
# Run with: sudo ./setup-bpf.sh

set -e

if [[ "$OSTYPE" != "darwin"* ]]; then
    echo "This script is for macOS only"
    exit 1
fi

echo "Setting up BPF permissions..."
chgrp admin /dev/bpf*
chmod g+rw /dev/bpf*

echo "Done. You may need to restart your terminal."
echo "Test with: sai"
