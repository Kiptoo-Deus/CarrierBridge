#!/bin/bash

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
ANDROID_DIR="${REPO_ROOT}/android"
APP_DIR="${ANDROID_DIR}/app"
JNILIBS_DIR="${APP_DIR}/src/main/jniLibs"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Step 1: Download prebuilt libsodium
download_libsodium() {
    log_info "Downloading prebuilt libsodium for Android..."

    mkdir -p "${JNILIBS_DIR}"

    # ABIs and filenames
    ABIS=("arm64-v8a" "armeabi-v7a" "x86" "x86_64")
    ABI_FILES=("libsodium-1.0.18-android-armv8.tar.gz" \
               "libsodium-1.0.18-android-armv7.tar.gz" \
               "libsodium-1.0.18-android-x86.tar.gz" \
               "libsodium-1.0.18-android-x86_64.tar.gz")
    
    for i in "${!ABIS[@]}"; do
        abi="${ABIS[$i]}"
        filename="${ABI_FILES[$i]}"
        
        log_info "Processing ABI: $abi"
        abi_dir="${JNILIBS_DIR}/${abi}"
        mkdir -p "${abi_dir}"

        # Placeholder - actual download commented out
        # url="https://github.com/jedisct1/libsodium/releases/download/1.0.18-RELEASE/${filename}"
        # curl -fSL "${url}" -o "/tmp/${filename}" && tar xzf "/tmp/${filename}" -C "${abi_dir}"
        
        log_warn "Placeholder for libsodium ${abi}. In production, place libsodium.so here:"
        log_warn "  ${abi_dir}/libsodium.so"
    done

    log_info "libsodium directories prepared at ${JNILIBS_DIR}"
}

# Step 2: Build libsecurecomm for Android (stubbed for now)
build_libsecurecomm() {
    log_info "Building/preparing libsecurecomm for Android..."

    # Placeholder: cross-compile libsecurecomm or fetch prebuilt
    # For MVP, we assume libsecurecomm is already available as a prebuilt .so
    log_warn "Placeholder for libsecurecomm build. Expected location:"
    log_warn "  ${JNILIBS_DIR}/<abi>/libsecurecomm.so"
    
    # If you have a CMake build for Android, add it here
    # Example: cd ${REPO_ROOT} && cmake -DCMAKE_TOOLCHAIN_FILE=... -DCMAKE_BUILD_TYPE=Release
}

# Step 3: Build Android APK
build_apk() {
    log_info "Building Android APK..."
    cd "${ANDROID_DIR}"
    
    if [ ! -f "gradlew" ]; then
        log_error "gradlew not found in ${ANDROID_DIR}"
        return 1
    fi

    chmod +x gradlew
    ./gradlew clean assembleDebug || {
        log_error "Gradle build failed"
        return 1
    }

    APK_PATH="${APP_DIR}/build/outputs/apk/debug/app-debug.apk"
    if [ -f "${APK_PATH}" ]; then
        log_info "APK built successfully: ${APK_PATH}"
    else
        log_error "APK not found after build"
        return 1
    fi
}

# Step 4: Build and start server
setup_server() {
    log_info "Building Go server..."
    cd "${REPO_ROOT}/server"
    
    go mod tidy || {
        log_error "go mod tidy failed"
        return 1
    }

    go build -o server_binary main.go || {
        log_error "Server build failed"
        return 1
    }

    log_info "Server built successfully"
}

# Main execution
main() {
    log_info "Starting CarrierBridge build automation..."
    
    # Step 1: Prepare native libs
    download_libsodium
    build_libsecurecomm

    # Step 2: Build Android APK
    if ! build_apk; then
        log_error "Failed to build APK"
        exit 1
    fi

    # Step 3: Setup server
    if ! setup_server; then
        log_error "Failed to setup server"
        exit 1
    fi

    log_info "========================================"
    log_info "Build complete!"
    log_info "========================================"
    log_info ""
    log_info "Next steps:"
    log_info "1. Place libsodium.so in ${JNILIBS_DIR}/<abi>/"
    log_info "2. Place libsecurecomm.so in ${JNILIBS_DIR}/<abi>/"
    log_info "3. Install APK on device:"
    log_info "   adb install ${APP_DIR}/build/outputs/apk/debug/app-debug.apk"
    log_info "4. Start server (run 'scripts/start_server.sh')"
    log_info "5. Open app on two devices and connect to server IP:8080"
    log_info ""
}

main "$@"
