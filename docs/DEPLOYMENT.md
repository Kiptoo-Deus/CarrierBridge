# CarrierBridge — Deployment Guide

This guide covers development, staging, and production deployment recommendations for CarrierBridge components (client SDK, relay servers, payment gateway, and optional VPN). It provides example commands and best practices.

> Assumptions: you have a Linux/macOS build host with `cmake`, `make`, and `libsodium` installed. For production, Docker and Kubernetes are recommended.

## Build (Local development)

```bash
# macOS
brew install cmake libsodium

# Linux (Ubuntu/Debian)
sudo apt update
sudo apt install build-essential cmake libsodium-dev git

# Build repository
git clone https://github.com/Kiptoo-Deus/SecureComm-WIP.git
cd CarrierBridge
mkdir -p build && cd build
cmake ..
make -j$(nproc)

# Run desktop demo
./desktop_demo
```

## Docker (Recommended for server components)

Create a `Dockerfile` for the relay/gateway service (example):

```Dockerfile
FROM debian:stable-slim
RUN apt-get update && apt-get install -y ca-certificates libsodium23
COPY relay_server /usr/local/bin/relay_server
EXPOSE 443
USER 1000
ENTRYPOINT ["/usr/local/bin/relay_server"]
```

Build & run:
```bash
docker build -t carrierbridge/relay:latest .
docker run -d --restart=always -p 443:443 --name carrierbridge-relay carrierbridge/relay:latest
```

## Kubernetes (Production)
- Use a Deployment with at least 3 replicas behind a LoadBalancer
- Use `Readiness`/`Liveness` probes to detect failure
- Store TLS certs in `kubernetes.io/tls` Secrets and mount into pods
- Use NetworkPolicies to restrict ingress to trusted sources

Example `deployment.yaml` (skeleton):
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: carrierbridge-relay
spec:
  replicas: 3
  selector:
    matchLabels:
      app: carrierbridge-relay
  template:
    metadata:
      labels:
        app: carrierbridge-relay
    spec:
      containers:
      - name: relay
        image: carrierbridge/relay:latest
        ports:
        - containerPort: 443
        livenessProbe:
          httpGet:
            path: /v1/health
            port: 443
          initialDelaySeconds: 10
          periodSeconds: 30
```

## TLS & Certificates
- Use TLS 1.3 for all relay and gateway endpoints
- Recommend issuing short-lived certs (e.g., 90 days) and automating renewal via ACME (Cert-Manager in k8s)
- Pin root certificates in mobile clients for high security scenarios (TOFU or pre-provisioned).

## Secrets & Key Storage
- Server keys: store in Vault or Cloud KMS (AWS KMS, GCP KMS)
- Client secrets: use platform keystore or secure enclave
- Do not commit any private keys or credentials to source control

## Monitoring & Logging
- Centralized logging (ELK / Loki) with redaction rules to avoid secrets in logs
- Metrics: Prometheus metrics for message rate, decrypt failures, ratchet events
- Alerts: PagerDuty/Slack integration for high failure rates or degraded health

## Backups & Recovery
- Backup any persistent payment ledger or audit logs daily
- Encrypt backups at rest and test restores regularly

## Scaling Recommendations
- Relay servers: scale horizontally behind a load balancer
- Payment gateway: separate service for payment processing with rate limiting
- Use caching for frequent session lookups but enforce cache invalidation on key change

## High-Availability & Disaster Recovery
- Deploy multi-region clusters for relay and gateway services
- Maintain hot standby for payment gateway with replication
- Use geo-proxied DNS (e.g., Cloudflare) with health checks

## CI/CD
- Build artifacts in CI (GitHub Actions / GitLab CI)
- Run unit tests and static analysis on each PR
- Merge to `main` triggers build of Docker images and deployment to staging
- Manual approval before production promotion

## Hardening Checklist (Pre-Production)
- [ ] Disable debug logging
- [ ] Enable server-side rate limiting
- [ ] Use WAF for public endpoints
- [ ] Enforce TLS 1.3 and strong ciphers only
- [ ] Run periodic dependency scans (OSS vulnerability scanners)

## Example: Quick Local Server Run (development)
```bash
# Build server binary (assumes server code is in server/)
cd CarrierBridge/server
GOOS=linux GOARCH=amd64 go build -o relay_server main.go

# Run locally (dev certs)
./relay_server --tls-cert ../infra/pki/certs/server.crt --tls-key ../infra/pki/certs/server.key --port 8443
```

## VPN & Mesh (Operational Notes)
- VPN: run dedicated WireGuard/IKEv2 gateway instances; keep them minimal and monitored
- Mesh: enable discovery services with careful rate limiting to avoid DoS




