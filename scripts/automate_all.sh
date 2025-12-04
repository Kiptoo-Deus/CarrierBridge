#!/bin/bash

# Master automation script - run once to prepare everything for device testing

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

log_info "CarrierBridge MVP - Complete Automation"
log_info "========================================"
log_info ""

# Step 1: Download libsodium
log_info "Step 1/4: Downloading libsodium for Android..."
if [ -f "${SCRIPT_DIR}/download_libsodium.sh" ]; then
    chmod +x "${SCRIPT_DIR}/download_libsodium.sh"
    "${SCRIPT_DIR}/download_libsodium.sh" || log_warn "libsodium download had issues (may be OK if manual placement)"
else
    log_warn "download_libsodium.sh not found, skipping"
fi

log_info ""
log_info "Step 2/4: Building Android APK..."
if [ -f "${SCRIPT_DIR}/build.sh" ]; then
    chmod +x "${SCRIPT_DIR}/build.sh"
    "${SCRIPT_DIR}/build.sh" || {
        log_error "APK build failed"
        exit 1
    }
else
    log_error "build.sh not found"
    exit 1
fi

log_info ""
log_info "Step 3/4: Building Go server binary..."
cd "${REPO_ROOT}/server"
go mod tidy
go build -o server_binary main.go || {
    log_error "Server build failed"
    exit 1
}
log_info "Server binary ready: server/server_binary"

log_info ""
log_info "Step 4/4: Configuration summary"
log_info "========================================"

APK_PATH="${REPO_ROOT}/android/app/build/outputs/apk/debug/app-debug.apk"
if [ -f "${APK_PATH}" ]; then
    log_info "✓ APK ready: ${APK_PATH}"
else
    log_warn "APK not found at expected location"
fi

JNILIBS="${REPO_ROOT}/android/app/src/main/jniLibs"
if [ -d "${JNILIBS}" ]; then
    log_info "✓ jniLibs directory exists"
    find "${JNILIBS}" -name "*.so" -type f | while read -r so_file; do
        log_info "  - $(basename $(dirname "$so_file"))/$(basename "$so_file")"
    done
else
    log_warn "⚠ jniLibs not found - you may need to place libsodium.so manually"
fi

log_info ""
log_info "========================================"
log_info "NEXT: Run the server and install APK"
log_info "========================================"
log_info ""
log_info "1. Start the server in a new terminal:"
log_info "   ./scripts/start_server.sh"
log_info ""
log_info "2. Find your machine IP:"
log_info "   ifconfig | grep 'inet '"
log_info ""
log_info "3. Install APK on Android devices:"
log_info "   adb install ${APK_PATH}"
log_info ""
log_info "4. In the app, tap Register, then Connect"
log_info "   Enter: ws://<YOUR_IP>:8080/ws"
log_info ""
log_info "For details, see: DEVICE_DEPLOYMENT.md"
log_info ""
