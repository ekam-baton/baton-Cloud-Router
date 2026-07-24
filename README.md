# Baton Cloud Router

The Baton Cloud Router is a highly concurrent Signaling Server designed to route End-to-End Encrypted (E2EE) payloads between the Baton Mobile App and the Baton Desktop Hub. 

This repository contains the cloud infrastructure codebase, separate from the client applications, to support massive horizontal scaling.

## Architecture: "The Dumb Pipe"

To support 1,000,000+ users efficiently and securely:
- **No Payload Decryption:** The Router routes JSON envelopes based on the `destination_id`. It never decrypts the actual AI payload. All context, file data, and prompts remain End-to-End Encrypted between the mobile app and the desktop app.
- **WebSocket Driven:** Uses Axum and Tokio to maintain persistent WebSocket connections with minimal overhead.
- **Cluster Ready:** (WIP) Redis Pub/Sub integration allows you to deploy multiple Router nodes behind a load balancer.

## Running Locally

To run the Cloud Router on your local machine for testing:

```bash
cargo run --release
```

The router will start listening on `ws://0.0.0.0:3000/relay/:client_id`.

## Deployment to the Cloud (Scaling to 1M Users)

1. **Load Balancer:** Deploy an AWS Network Load Balancer (NLB) or Cloudflare proxy to handle incoming WebSocket connections and distribute them.
2. **Server Fleet:** Deploy this Rust binary to a fleet of Linux servers (e.g., AWS ECS, Kubernetes, or bare metal). 
3. **Redis Cluster:** Deploy an AWS ElastiCache Redis cluster. Configure the Rust nodes to publish and subscribe to Redis so that a message received on Node A can be instantly forwarded to a client connected to Node B.
4. **Ulimit:** Ensure your Linux servers have their file descriptor limits (`ulimit -n`) raised to at least 1,048,576 to allow for massive concurrency.
