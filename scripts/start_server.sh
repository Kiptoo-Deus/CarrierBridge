#!/bin/bash

# Simple server startup script
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
SERVER_DIR="${REPO_ROOT}/server"

echo "[INFO] Starting CarrierBridge server..."
echo "[INFO] Server will listen on localhost:8080"
echo "[INFO] SQLite database: ./carrier.db"
echo ""
echo "To connect from Android app, use: ws://<YOUR_MACHINE_IP>:8080/ws"
echo "Find your IP with: ifconfig | grep 'inet '"
echo ""

cd "${SERVER_DIR}"

# Build if binary doesn't exist
if [ ! -f "server_binary" ]; then
    echo "[INFO] Building server..."
    go build -o server_binary main.go
fi

# Run server
./server_binary
