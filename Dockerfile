# Build stage
FROM golang:1.24-alpine AS builder

# Install git and ca-certificates (needed for go mod download)
RUN apk add --no-cache git ca-certificates tzdata

# Create appuser for security
RUN adduser -D -g '' appuser

# Set working directory
WORKDIR /build

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download
RUN go mod verify

# Copy source code
COPY . .

# Build arguments for version info
ARG VERSION=dev
ARG GIT_COMMIT=unknown
ARG BUILD_DATE=unknown

# Build the binary
RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags="-w -s -X resumatter/internal/cli.Version=${VERSION} -X resumatter/internal/cli.GitCommit=${GIT_COMMIT} -X resumatter/internal/cli.BuildDate=${BUILD_DATE}" \
    -a -installsuffix cgo \
    -o resumatter \
    ./cmd/resumatter

# Final stage
FROM alpine:latest

# Install curl for health checks and ca-certificates for HTTPS
RUN apk --no-cache add curl ca-certificates tzdata

# Import user from builder
COPY --from=builder /etc/passwd /etc/passwd

# Copy the binary
COPY --from=builder /build/resumatter /resumatter

# Use an unprivileged user
USER appuser

# Expose port (configurable via environment)
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -f -s http://localhost:8080/health > /dev/null || exit 1

# Default command
ENTRYPOINT ["/resumatter"]
CMD ["serve"]