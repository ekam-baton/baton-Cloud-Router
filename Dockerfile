# Build stage
FROM rust:slim AS builder

WORKDIR /usr/src/baton-cloud-router
COPY . .

RUN cargo build --release

# Production stage
FROM debian:bookworm-slim

WORKDIR /app
COPY --from=builder /usr/src/baton-cloud-router/target/release/baton-Cloud-Router /app/cloud-router

EXPOSE 8082

CMD ["./cloud-router"]
