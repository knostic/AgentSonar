.PHONY: build dev clean install test tidy

BINARY=agentsonar
BUILD_DIR=bin

build:
	@mkdir -p $(BUILD_DIR)
	go build -ldflags="-s -w" -o $(BUILD_DIR)/$(BINARY) ./cmd/agentsonar

dev:
	@mkdir -p $(BUILD_DIR)
	go build -tags dev -o $(BUILD_DIR)/$(BINARY) ./cmd/agentsonar

install: build
	cp $(BUILD_DIR)/$(BINARY) /usr/local/bin/

clean:
	rm -rf $(BUILD_DIR)

test:
	go test -v ./...

tidy:
	go mod tidy

setup-bpf: build
	@./bin/agentsonar install
