# Build stage
FROM rust:slim AS builder

WORKDIR /usr/src/baton-cloud-router
COPY . .

RUN apt-get update && apt-get install -y pkg-config libssl-dev
RUN cargo build --release

# Production stage
FROM debian:bookworm-slim

WORKDIR /app
COPY --from=builder /usr/src/baton-cloud-router/target/release/baton-Cloud-Router /app/cloud-router

EXPOSE 8082
EXPOSE 3478/udp

RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*
RUN groupadd -r appuser && useradd -r -g appuser appuser && chown -R appuser:appuser /app
USER appuser

CMD ["./cloud-router"]
