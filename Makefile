.PHONY: all build clean test install lint help deps example-tailor example-evaluate example-analyze example-serve docker-build docker-run docker-push release-build

# Version information
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
GIT_COMMIT ?= $(shell git rev-parse HEAD 2>/dev/null || echo "unknown")
BUILD_DATE ?= $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")

# Build configuration
BINARY_NAME = resumatter
BUILD_DIR = ./build
DOCKER_IMAGE = resumatter
DOCKER_REGISTRY = ghcr.io
DOCKER_REPO = $(DOCKER_REGISTRY)/$(shell echo $(GITHUB_REPOSITORY) | tr '[:upper:]' '[:lower:]' 2>/dev/null || echo "ajiwo/resumatter")

# Build flags
LDFLAGS = -s -w \
          -X resumatter/internal/cli.Version=$(VERSION) \
          -X resumatter/internal/cli.GitCommit=$(GIT_COMMIT) \
          -X resumatter/internal/cli.BuildDate=$(BUILD_DATE)

# Go build flags
GOFLAGS = -trimpath
CGO_ENABLED = 0

# Create build directory
build-dir:
	mkdir -p $(BUILD_DIR)

# Build the application
build: build-dir vet
	CGO_ENABLED=$(CGO_ENABLED) go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY_NAME) ./cmd/resumatter

# Build for multiple architectures
release-build: build-dir
	@echo "Building for multiple architectures..."
	@for os in linux darwin windows; do \
		for arch in amd64 arm64; do \
			echo "Building $$os/$$arch..."; \
			if [ "$$os" = "windows" ]; then \
				GOOS=$$os GOARCH=$$arch CGO_ENABLED=0 go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY_NAME)-$$os-$$arch.exe ./cmd/resumatter; \
			else \
				GOOS=$$os GOARCH=$$arch CGO_ENABLED=0 go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY_NAME)-$$os-$$arch ./cmd/resumatter; \
			fi; \
		done; \
	done

# Clean build artifacts
clean:
	rm -rf $(BUILD_DIR)
	docker rmi $(DOCKER_IMAGE) 2>/dev/null || true

# Run tests with coverage
test:
	go test -race -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html

# Run tests verbosely
test-verbose:
	go test -v -race -coverprofile=coverage.out ./...

# Install dependencies
deps:
	go mod tidy
	go mod download
	go mod verify

# Install the binary to GOPATH/bin
install: build
	@echo "Installing resumatter to GOPATH/bin..."
	go install -ldflags "$(LDFLAGS)" ./cmd/resumatter

# Docker targets
docker-build:
	@echo "Building Docker image..."
	docker build \
		--build-arg VERSION=$(VERSION) \
		--build-arg GIT_COMMIT=$(GIT_COMMIT) \
		--build-arg BUILD_DATE=$(BUILD_DATE) \
		-t $(DOCKER_IMAGE):$(VERSION) \
		-t $(DOCKER_IMAGE):latest \
		.

docker-run: docker-build
	@echo "Running Docker container..."
	docker run --rm -p 8080:8080 $(DOCKER_IMAGE):latest

docker-push: docker-build
	@echo "Pushing Docker image to registry..."
	docker tag $(DOCKER_IMAGE):$(VERSION) $(DOCKER_REPO):$(VERSION)
	docker tag $(DOCKER_IMAGE):latest $(DOCKER_REPO):latest
	docker push $(DOCKER_REPO):$(VERSION)
	docker push $(DOCKER_REPO):latest

# Development targets
dev-setup:
	@echo "Setting up development environment..."
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	go install golang.org/x/tools/cmd/goimports@latest
	go install golang.org/x/tools/gopls/internal/analysis/modernize/cmd/modernize@latest

format:
	@echo "Formatting code..."
	go fmt ./...
	goimports -w .

# Security scanning
security:
	@echo "Running security scan..."
	gosec -tests -exclude G304 ./...

# Modernization check (optional)
modernize:
	@echo "Checking for modernization opportunities..."
	modernize -test ./...

# Run the application with example files
example-tailor: build
	@echo "Tailoring resume for job description..."
	$(BUILD_DIR)/$(BINARY_NAME) tailor examples/resume.txt examples/job.txt --format text

# Run evaluation example (requires tailored resume)
example-evaluate: build
	@echo "First, create a tailored resume:"
	$(BUILD_DIR)/$(BINARY_NAME) tailor examples/resume.txt examples/job.txt --output examples/tailored.txt --format text
	@echo "Now evaluating the tailored resume:"
	$(BUILD_DIR)/$(BINARY_NAME) evaluate examples/resume.txt examples/tailored.txt --format text

# Run job analysis example
example-analyze: build
	@echo "Analyzing job description for quality and effectiveness:"
	$(BUILD_DIR)/$(BINARY_NAME) analyze examples/job.txt --format text

# Start the HTTP server
example-serve: build
	@echo "Starting HTTP server on http://localhost:8080"
	@echo "Available endpoints:"
	@echo "  GET  /health    - Health check"
	@echo "  POST /tailor    - Tailor resume"
	@echo "  POST /evaluate  - Evaluate resume"
	@echo "  POST /analyze   - Analyze job description"
	$(BUILD_DIR)/$(BINARY_NAME) serve

# API testing
test-api: build
	@echo "Testing API endpoints (requires server to be running)..."
	@echo "Starting server in background..."
	$(BUILD_DIR)/$(BINARY_NAME) serve &
	@sleep 2
	@echo "Testing health endpoint..."
	curl -s http://localhost:8080/health | jq .
	@echo "Stopping server..."
	@pkill -f "$(BINARY_NAME) serve" || true

# Lint the code
lint:
	@echo "Running linter..."
	golangci-lint run --timeout=5m

# Vet the code
vet:
	@echo "Running go vet..."
	go vet ./...

# Show help
help:
	@echo "Available targets:"
	@echo ""
	@echo "Build targets:"
	@echo "  build           - Build the resumatter binary"
	@echo "  release-build   - Build for multiple architectures"
	@echo "  clean           - Remove build artifacts"
	@echo "  install         - Install binary to GOPATH/bin"
	@echo ""
	@echo "Development targets:"
	@echo "  test            - Run tests with coverage"
	@echo "  test-verbose    - Run tests verbosely"
	@echo "  deps            - Install/update dependencies"
	@echo "  dev-setup       - Setup development tools (includes modernize)"
	@echo "  format          - Format code"
	@echo "  lint            - Run linter"
	@echo "  vet             - Run go vet"
	@echo "  security        - Run security scan (excludes G304 file inclusion warnings)"
	@echo "  modernize       - Check for Go modernization opportunities (optional)"
	@echo ""
	@echo "Docker targets:"
	@echo "  docker-build    - Build Docker image"
	@echo "  docker-run      - Run Docker container"
	@echo "  docker-push     - Push Docker image to registry"
	@echo ""
	@echo "Example targets:"
	@echo "  example-tailor  - Run tailor command with example files"
	@echo "  example-evaluate- Run evaluate command with example files"
	@echo "  example-analyze - Run analyze command with example job description"
	@echo "  example-serve   - Start HTTP server with API endpoints"
	@echo "  test-api        - Test API endpoints"
	@echo ""
	@echo "  help            - Show this help message"

# Default target
all: deps build
