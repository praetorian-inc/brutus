# Makefile for Brutus
# Modern credential brute-forcing library in pure Go

.PHONY: all build build-packed build-wasm clean test test-integration lint install help \
	services-up services-down

# Build configuration
BINARY_NAME := brutus
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
BUILD_TIME := $(shell date -u '+%Y-%m-%dT%H:%M:%SZ')
COMMIT_SHA := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")

# Go build flags
LDFLAGS := -s -w \
	-X main.Version=$(VERSION) \
	-X main.BuildTime=$(BUILD_TIME) \
	-X main.CommitSHA=$(COMMIT_SHA)

# Directories
BUILD_DIR := dist

# Default target
all: build

# Build single static binary (no CGO)
build:
	@echo "Building $(BINARY_NAME) $(VERSION)..."
	GOWORK=off CGO_ENABLED=0 go build -trimpath -ldflags="$(LDFLAGS)" -o $(BINARY_NAME) ./cmd/brutus
	@echo "Built: $(BINARY_NAME)"

# Build UPX-compressed binary (requires: upx)
build-packed: build
	@command -v upx >/dev/null 2>&1 || { echo "ERROR: upx not found. Install with: brew install upx"; exit 1; }
	@echo "Compressing $(BINARY_NAME) with UPX..."
	cp $(BINARY_NAME) $(BINARY_NAME)-upx
	upx --best --lzma $(BINARY_NAME)-upx
	@echo "Packed: $(BINARY_NAME)-upx"

# Build IronRDP WASM module (requires Rust toolchain with wasm32-wasip1 target)
build-wasm:
	@echo "Building IronRDP WASM module..."
	@cd internal/plugins/rdp/rust && bash build.sh

# Build for all platforms
build-all: $(BUILD_DIR)
	@echo "Building for all platforms..."
	GOWORK=off GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags="$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64 ./cmd/brutus
	GOWORK=off GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -trimpath -ldflags="$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY_NAME)-linux-arm64 ./cmd/brutus
	GOWORK=off GOOS=darwin GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags="$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-amd64 ./cmd/brutus
	GOWORK=off GOOS=darwin GOARCH=arm64 CGO_ENABLED=0 go build -trimpath -ldflags="$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-arm64 ./cmd/brutus
	GOWORK=off GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags="$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY_NAME)-windows-amd64.exe ./cmd/brutus
	@echo "Built binaries in $(BUILD_DIR)/"

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

# Run tests (unit tests only, no services required)
test:
	GOWORK=off CGO_ENABLED=0 go test -short -coverprofile=coverage.out ./...

# Integration test environment
INTEGRATION_COMPOSE := testdata/docker-compose.yml

# Start integration test services
services-up:
	@echo "Starting integration test services..."
	docker compose -f $(INTEGRATION_COMPOSE) up -d
	@echo "Waiting for services to be ready..."
	@for i in $$(seq 1 30); do \
		nc -z localhost 3306 2>/dev/null && break || sleep 2; \
	done
	@sleep 5
	@echo "Services ready."

# Stop integration test services
services-down:
	@echo "Stopping integration test services..."
	docker compose -f $(INTEGRATION_COMPOSE) down -v

# Run all tests including integration tests (requires: make services-up)
test-integration:
	GOWORK=off CGO_ENABLED=0 \
	SSH_TEST_HOST=localhost:2222 SSH_TEST_USER=testuser SSH_TEST_PASS=testpass \
	FTP_TEST_HOST=localhost:21 FTP_TEST_USER=ftpuser FTP_TEST_PASS=ftppass \
	TELNET_TEST_HOST=localhost:23 TELNET_TEST_USER=user TELNET_TEST_PASS=password \
	VNC_TEST_HOST=localhost:5901 VNC_TEST_PASS=vncpass \
	SMB_TEST_HOST=localhost:445 SMB_TEST_USER=smbuser SMB_TEST_PASS=smbpass \
	LDAP_TEST_HOST=localhost:389 LDAP_TEST_USER="cn=admin,dc=test,dc=local" LDAP_TEST_PASS=adminpass \
	RDP_TEST_HOST=localhost:3389 RDP_TEST_USER=guest RDP_TEST_PASS=rdppass \
	MYSQL_TEST_HOST=localhost:3306 MYSQL_TEST_USER=root MYSQL_TEST_PASS=rootpass \
	POSTGRES_TEST_HOST=localhost:5432 POSTGRES_TEST_USER=postgres POSTGRES_TEST_PASS=postgrespass \
	MSSQL_TEST_HOST=localhost:1433 MSSQL_TEST_USER=sa MSSQL_TEST_PASS='MssqlPass123!' \
	MONGODB_TEST_HOST=localhost:27017 MONGODB_TEST_USER=mongouser MONGODB_TEST_PASS=mongopass \
	REDIS_TEST_HOST=localhost:6379 REDIS_TEST_PASS=redispass \
	NEO4J_TEST_HOST=localhost:7687 NEO4J_TEST_USER=neo4j NEO4J_TEST_PASS=neo4jpass \
	CASSANDRA_TEST_HOST=localhost:9042 CASSANDRA_TEST_USER=cassandra CASSANDRA_TEST_PASS=cassandra \
	COUCHDB_TEST_HOST=localhost:5984 COUCHDB_TEST_USER=couchuser COUCHDB_TEST_PASS=couchpass \
	ELASTICSEARCH_TEST_HOST=localhost:9200 ELASTICSEARCH_TEST_USER=elastic ELASTICSEARCH_TEST_PASS=elasticpass \
	INFLUXDB_TEST_HOST=localhost:8086 INFLUXDB_TEST_USER=influxuser INFLUXDB_TEST_PASS=influxpass \
	SMTP_TEST_HOST=localhost:3025 SMTP_TEST_USER=testuser SMTP_TEST_PASS=testpass \
	IMAP_TEST_HOST=localhost:3143 IMAP_TEST_USER=testuser IMAP_TEST_PASS=testpass \
	POP3_TEST_HOST=localhost:3110 POP3_TEST_USER=testuser POP3_TEST_PASS=testpass \
	SNMP_TEST_HOST=localhost:161 SNMP_TEST_COMMUNITY=public \
	go test -tags=integration -coverprofile=coverage.out ./...

# Run linter
lint:
	@if command -v golangci-lint >/dev/null 2>&1; then \
		GOWORK=off golangci-lint run ./...; \
	else \
		echo "golangci-lint not installed, running go vet..."; \
		GOWORK=off go vet ./...; \
	fi

# Install to GOPATH/bin
install:
	GOWORK=off CGO_ENABLED=0 go install -trimpath -ldflags="$(LDFLAGS)" ./cmd/brutus

# Clean build artifacts
clean:
	rm -f $(BINARY_NAME) $(BINARY_NAME)-upx
	rm -rf $(BUILD_DIR)
	rm -f coverage.out

# Show version info
version:
	@echo "Version:    $(VERSION)"
	@echo "Build Time: $(BUILD_TIME)"
	@echo "Commit:     $(COMMIT_SHA)"

# Check dependencies
deps:
	@echo "Checking Go..."
	@go version
	@echo ""
	@echo "Checking golangci-lint (optional)..."
	@golangci-lint --version 2>/dev/null || echo "golangci-lint not installed"

# Demo environment
DEMO_DIR := testdata/demo
DEMO_COMPOSE := $(DEMO_DIR)/docker-compose.yml

.PHONY: demo-up demo-down demo demo-ssh-key demo-wait demo-deps demo-simple

# Install demo dependencies (naabu + nerva)
demo-deps:
	@echo "Installing demo dependencies..."
	@echo "Installing naabu (port scanner)..."
	go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
	@echo "Installing nerva (service fingerprinter)..."
	go install github.com/praetorian-inc/nerva/cmd/nerva@latest
	@echo ""
	@echo "Done! Make sure $(shell go env GOPATH)/bin is in your PATH."

# Start demo environment
demo-up:
	@echo "Starting Brutus demo environment..."
	docker compose -f $(DEMO_COMPOSE) up -d --build
	@echo "Waiting for services to be healthy..."
	@$(MAKE) demo-wait
	@echo ""
	@echo "Demo environment ready!"
	@echo "  SSH:      localhost:2222 (vagrant/vagrant or Vagrant insecure key via badkeys)"
	@echo "  MySQL:    localhost:3306 (root/root)"
	@echo "  Redis:    localhost:6379 (password: redis)"
	@echo "  FTP:      localhost:21   (ftpuser/ftpuser)"
	@echo "  iDRAC:    localhost:8080 (root/calvin) - HTTP Basic Auth, --experimental-ai"
	@echo "  Xerox:    localhost:8081 (admin/1111) - Form login, --experimental-ai --browser"

# Wait for services to be healthy
demo-wait:
	@echo "Waiting for SSH..."
	@for i in 1 2 3 4 5 6 7 8 9 10; do \
		nc -z localhost 2222 2>/dev/null && break || sleep 1; \
	done
	@echo "Waiting for MySQL..."
	@for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do \
		nc -z localhost 3306 2>/dev/null && break || sleep 1; \
	done
	@echo "Waiting for Redis..."
	@for i in 1 2 3 4 5; do \
		nc -z localhost 6379 2>/dev/null && break || sleep 1; \
	done
	@echo "Waiting for iDRAC..."
	@for i in 1 2 3 4 5 6 7 8 9 10; do \
		nc -z localhost 8080 2>/dev/null && break || sleep 1; \
	done
	@echo "Waiting for Xerox..."
	@for i in 1 2 3 4 5 6 7 8 9 10; do \
		nc -z localhost 8081 2>/dev/null && break || sleep 1; \
	done

# Stop demo environment
demo-down:
	@echo "Stopping Brutus demo environment..."
	docker compose -f $(DEMO_COMPOSE) down -v
	@echo "Demo environment stopped."

# Run full pipeline demo: naabu -> nerva -> brutus
demo: build demo-up
	@echo ""
	@echo "═══════════════════════════════════════════════════════════════════"
	@echo "  Brutus Demo: naabu -> nerva -> brutus pipeline"
	@echo "═══════════════════════════════════════════════════════════════════"
	@echo ""
	@command -v naabu >/dev/null 2>&1 || { echo "ERROR: naabu not found. Run: make demo-deps"; exit 1; }
	@command -v nerva >/dev/null 2>&1 || { echo "ERROR: nerva not found. Run: make demo-deps"; exit 1; }
	@echo "Running: naabu | nerva --json | brutus creds (uses built-in default credentials)"
	@echo ""
	naabu -host 127.0.0.1 -p 21,2222,3306,6379 -silent | \
		nerva --json | \
		./brutus creds
	@echo ""
	@echo "═══════════════════════════════════════════════════════════════════"
	@echo "  Demo complete! Run 'make demo-down' to stop the environment."
	@echo "═══════════════════════════════════════════════════════════════════"

# Simple demo without naabu/nerva (direct brutus testing)
demo-simple: build demo-up
	@echo ""
	@echo "═══════════════════════════════════════════════════════════════════"
	@echo "  Brutus Demo: Direct credential testing"
	@echo "═══════════════════════════════════════════════════════════════════"
	@echo ""
	@echo "[1/6] Testing SSH with password..."
	./brutus creds --target 127.0.0.1:2222 -u vagrant -p "wrong,vagrant" || true
	@echo ""
	@echo "[2/6] Testing SSH with badkeys (auto-detects Vagrant insecure key)..."
	./brutus badkeys --target 127.0.0.1:2222 || true
	@echo ""
	@echo "[3/6] Testing MySQL..."
	./brutus creds --target 127.0.0.1:3306 -u root -p "wrong,root" || true
	@echo ""
	@echo "[4/6] Testing Redis..."
	./brutus creds --target 127.0.0.1:6379 -p "wrong,redis" || true
	@echo ""
	@echo "[5/6] Testing FTP..."
	./brutus creds --target 127.0.0.1:21 -u ftpuser -p "wrong,ftpuser" || true
	@echo ""
	@echo "[6/6] Testing Dell iDRAC (HTTP Basic Auth)..."
	./brutus web --target 127.0.0.1:8080 --protocol http -u root -p "wrong,calvin" || true
	@echo ""
	@echo "═══════════════════════════════════════════════════════════════════"
	@echo "  Demo complete! Run 'make demo-down' to stop the environment."
	@echo "═══════════════════════════════════════════════════════════════════"

# Quick SSH badkeys demo (auto-detects Vagrant insecure key)
demo-ssh-key: build demo-up
	@echo ""
	@echo "Testing SSH with badkeys (auto-detects Vagrant insecure key)..."
	./brutus badkeys --target 127.0.0.1:2222

# Help
help:
	@echo "Brutus - Modern credential brute-forcing library in pure Go"
	@echo ""
	@echo "Usage: make [target]"
	@echo ""
	@echo "Build targets:"
	@echo "  build        Build single static binary (default)"
	@echo "  build-packed Build UPX-compressed binary (requires upx)"
	@echo "  build-wasm   Build IronRDP WASM module (requires Rust)"
	@echo "  build-all    Build for all platforms"
	@echo "  install      Install to GOPATH/bin"
	@echo ""
	@echo "Development targets:"
	@echo "  test             Run unit tests (no services required)"
	@echo "  test-integration Run all tests including integration (requires: make services-up)"
	@echo "  services-up      Start integration test services (Docker)"
	@echo "  services-down    Stop integration test services"
	@echo "  lint             Run linter"
	@echo "  deps             Check build dependencies"
	@echo "  version          Show version info"
	@echo ""
	@echo "Demo targets:"
	@echo "  demo-deps    Install naabu + nerva (required for full demo)"
	@echo "  demo-up      Start demo environment (vulnerable containers)"
	@echo "  demo-down    Stop demo environment"
	@echo "  demo         Run full pipeline: naabu -> nerva -> brutus"
	@echo "  demo-simple  Run demo without naabu/nerva (direct testing)"
	@echo "  demo-ssh-key Quick SSH private key demo only"
	@echo ""
	@echo "Cleanup targets:"
	@echo "  clean        Remove all build artifacts"
