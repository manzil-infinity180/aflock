.PHONY: build test test-hooks clean docker-build docker-up docker-down docker-test

# Build variables
BINARY_NAME=aflock
BUILD_DIR=bin
VERSION?=0.1.0

# Go variables
GOCMD=go
GOBUILD=$(GOCMD) build
GOTEST=$(GOCMD) test
GOMOD=$(GOCMD) mod
LDFLAGS=-ldflags "-s -w -X main.version=$(VERSION)"

# Build the binary
build:
	@mkdir -p $(BUILD_DIR)
	$(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME) ./cmd/aflock

# Build for multiple platforms
build-all:
	@mkdir -p $(BUILD_DIR)
	GOOS=darwin GOARCH=arm64 $(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-arm64 ./cmd/aflock
	GOOS=darwin GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-amd64 ./cmd/aflock
	GOOS=linux GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64 ./cmd/aflock
	GOOS=linux GOARCH=arm64 $(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-linux-arm64 ./cmd/aflock

# Run tests
test:
	$(GOTEST) -v ./...

# Test hooks locally
test-hooks: build
	@echo "Testing SessionStart hook..."
	@echo '{"session_id":"test1","hook_event_name":"SessionStart","cwd":"$(PWD)/test-project","source":"startup"}' | $(BUILD_DIR)/$(BINARY_NAME) --hook SessionStart | jq .
	@echo ""
	@echo "Testing PreToolUse (allowed)..."
	@echo '{"session_id":"test1","hook_event_name":"PreToolUse","cwd":"$(PWD)/test-project","tool_name":"Read","tool_input":{"file_path":"src/main.go"}}' | $(BUILD_DIR)/$(BINARY_NAME) --hook PreToolUse | jq .
	@echo ""
	@echo "Testing PreToolUse (denied - Task tool)..."
	@echo '{"session_id":"test1","hook_event_name":"PreToolUse","cwd":"$(PWD)/test-project","tool_name":"Task","tool_input":{"prompt":"test"}}' | $(BUILD_DIR)/$(BINARY_NAME) --hook PreToolUse 2>&1 || true
	@echo ""
	@echo "Testing PreToolUse (requires approval)..."
	@echo '{"session_id":"test1","hook_event_name":"PreToolUse","cwd":"$(PWD)/test-project","tool_name":"Bash","tool_input":{"command":"rm -rf /tmp/test"}}' | $(BUILD_DIR)/$(BINARY_NAME) --hook PreToolUse | jq .

# Clean build artifacts
clean:
	rm -rf $(BUILD_DIR)
	rm -rf plugin/bin

# Tidy dependencies
tidy:
	$(GOMOD) tidy

# Build docker image
docker-build:
	docker build -t aflock:latest -f docker/Dockerfile .

# Start docker compose
docker-up:
	docker-compose up -d

# Stop docker compose
docker-down:
	docker-compose down -v

# Run tests in docker
docker-test: docker-build docker-up
	@echo "Waiting for SPIRE to be ready..."
	@sleep 5
	@echo "Running aflock in container..."
	docker-compose exec -T aflock-test aflock --help
	docker-compose exec -T aflock-test /bin/sh -c 'echo "{\"session_id\":\"docker-test\",\"hook_event_name\":\"SessionStart\",\"cwd\":\"/workspace\",\"source\":\"startup\"}" | aflock --hook SessionStart'

# Package plugin
plugin: build-all
	@mkdir -p plugin/bin
	cp $(BUILD_DIR)/$(BINARY_NAME)-darwin-arm64 plugin/bin/
	cp $(BUILD_DIR)/$(BINARY_NAME)-darwin-amd64 plugin/bin/
	cp $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64 plugin/bin/

# Install locally (for development)
install: build
	@mkdir -p ~/.claude-plugins/aflock
	cp -r plugin/* ~/.claude-plugins/aflock/
	cp $(BUILD_DIR)/$(BINARY_NAME) ~/.claude-plugins/aflock/bin/aflock-$$(uname -s | tr '[:upper:]' '[:lower:]')-$$(uname -m | sed 's/x86_64/amd64/' | sed 's/aarch64/arm64/')
	@echo "Installed aflock plugin to ~/.claude-plugins/aflock"

# Help
help:
	@echo "aflock - Cryptographically signed policy enforcement for AI agents"
	@echo ""
	@echo "Targets:"
	@echo "  build        Build the aflock binary"
	@echo "  build-all    Build for all platforms"
	@echo "  test         Run unit tests"
	@echo "  test-hooks   Test hooks locally"
	@echo "  clean        Clean build artifacts"
	@echo "  tidy         Tidy go modules"
	@echo "  docker-build Build docker image"
	@echo "  docker-up    Start docker compose"
	@echo "  docker-down  Stop docker compose"
	@echo "  docker-test  Run tests in docker"
	@echo "  plugin       Package plugin binaries"
	@echo "  install      Install plugin locally"
