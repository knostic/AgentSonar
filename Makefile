.PHONY: build dev clean install test tidy

BINARY=sai
BUILD_DIR=bin

build:
	@mkdir -p $(BUILD_DIR)
	go build -ldflags="-s -w" -o $(BUILD_DIR)/$(BINARY) ./cmd/sai

dev:
	@mkdir -p $(BUILD_DIR)
	go build -tags dev -o $(BUILD_DIR)/$(BINARY) ./cmd/sai

install: build
	cp $(BUILD_DIR)/$(BINARY) /usr/local/bin/

clean:
	rm -rf $(BUILD_DIR)

test:
	go test -v ./...

tidy:
	go mod tidy

setup-bpf:
	@echo "Setting up BPF permissions for macOS..."
	sudo chgrp admin /dev/bpf*
	sudo chmod g+rw /dev/bpf*
	@echo "Done. You may need to restart your terminal."
