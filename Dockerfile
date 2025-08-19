# File: Dockerfile

# Modern multi-stage Dockerfile with security hardening
FROM alpine:3.19 as builder

# Install build dependencies
RUN apk add --no-cache \
    build-base \
    musl-dev \
    linux-headers

# Create non-root user for building
RUN adduser -D -s /bin/sh builder

# Copy source files
COPY --chown=builder:builder sshoney.c Makefile /build/
WORKDIR /build

# Switch to non-root user for build
USER builder

# Build with additional security flags
RUN make CFLAGS="-std=c99 -Wall -Wextra -Wno-missing-field-initializers -O2 -fstack-protector-strong -D_FORTIFY_SOURCE=2" \
    LDFLAGS="-Wl,-z,relro,-z,now"

# Runtime stage
FROM alpine:3.19

# Install runtime dependencies
RUN apk add --no-cache \
    ca-certificates \
    tzdata

# Create dedicated user for sshoney
RUN addgroup -g 1000 sshoney && \
    adduser -D -u 1000 -G sshoney -s /bin/sh sshoney

# Copy binary from builder stage
COPY --from=builder --chown=root:root /build/sshoney /usr/local/bin/sshoney
RUN chmod 755 /usr/local/bin/sshoney

# Create config directory
RUN mkdir -p /etc/sshoney && \
    chown sshoney:sshoney /etc/sshoney

# Default config file
COPY --chown=sshoney:sshoney docker-config.conf /etc/sshoney/config

# Switch to non-root user
USER sshoney

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD nc -z localhost 2222 || exit 1

# Expose port
EXPOSE 2222/tcp

# Set entrypoint
ENTRYPOINT ["/usr/local/bin/sshoney"]
CMD ["-f", "/etc/sshoney/config", "-v"]