# SecureComm (WIP)

SecureComm is a privacy-first communication platform combining end-to-end encrypted messaging, peer-to-peer payments, and integrated VPN. This repository contains the initial MVP focused on **secure, end-to-end encrypted text messaging**.

## Quick status
- MVP: Encrypted messaging (server + web client) — **IN PROGRESS**
- Payments: planned
- VPN: planned

## Goals
- Strong, memory-safe cryptography (Rust)
- High-performance networking (C++ for data plane when needed)
- Reliable services and buy-in to CI/CD
- Privacy-first defaults (no plaintext on servers, forward secrecy)

## Getting started (local dev)
Prerequisites:
- Rust (stable)
- Go (1.21+)
- Node.js (18+)
- Docker & docker-compose

### 1) Start services (local)
```bash
# build rust crypto lib (used by ts-sdk/tests)
cd libs/rust-crypto
cargo build

# start relay server (go)
cd services/relay-go
go run ./cmd/relay

# start web client
cd clients/web
npm install
npm run dev
