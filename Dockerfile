# Build stage
FROM golang:1.27-alpine AS builder

WORKDIR /app

# Install build dependencies
RUN apk add --no-cache git ca-certificates

# Copy go mod files first for caching
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build arguments for version info
ARG VERSION=dev
ARG BUILD_TIME
ARG COMMIT_SHA

# Build the binary
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath \
    -ldflags="-s -w \
    -X main.Version=${VERSION} \
    -X main.BuildTime=${BUILD_TIME} \
    -X main.CommitSHA=${COMMIT_SHA}" \
    -o brutus ./cmd/brutus

# Final stage
FROM alpine:3.21

# Install runtime dependencies
RUN apk add --no-cache ca-certificates tzdata

# Create non-root user
RUN adduser -D -g '' brutus
USER brutus

WORKDIR /home/brutus

# Copy binary from builder
COPY --from=builder /app/brutus /usr/local/bin/brutus

# Copy wordlists (optional - embedded in binary, but useful for customization)
COPY --from=builder /app/pkg/brutus/wordlists /home/brutus/wordlists

ENTRYPOINT ["brutus"]
CMD ["--help"]
