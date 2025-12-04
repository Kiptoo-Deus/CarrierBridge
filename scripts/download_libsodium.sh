#!/bin/bash

# Script to download and prepare prebuilt libsodium for Android

set -e

ANDROID_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/android"
JNILIBS_DIR="${ANDROID_DIR}/app/src/main/jniLibs"

echo "[INFO] Downloading libsodium for Android..."

# Create directories
mkdir -p "${JNILIBS_DIR}"

# libsodium 1.0.18 prebuilt binaries from GitHub releases
LIBSODIUM_VERSION="1.0.18"
RELEASES_URL="https://github.com/jedisct1/libsodium/releases/download/${LIBSODIUM_VERSION}-RELEASE"

# ABIs and their corresponding filenames
ABIS=("arm64-v8a" "armeabi-v7a" "x86" "x86_64")
ABI_FILES=("libsodium-${LIBSODIUM_VERSION}-android-armv8.tar.gz" \
           "libsodium-${LIBSODIUM_VERSION}-android-armv7.tar.gz" \
           "libsodium-${LIBSODIUM_VERSION}-android-x86.tar.gz" \
           "libsodium-${LIBSODIUM_VERSION}-android-x86_64.tar.gz")

for i in "${!ABIS[@]}"; do
    abi="${ABIS[$i]}"
    filename="${ABI_FILES[$i]}"
    
    abi_dir="${JNILIBS_DIR}/${abi}"
    mkdir -p "${abi_dir}"

    url="${RELEASES_URL}/${filename}"
    
    echo "[INFO] Downloading libsodium for ${abi}"
    
    # Download to temp location
    temp_file="/tmp/${filename}"
    if curl -fSL "${url}" -o "${temp_file}"; then
        # Extract
        if tar xzf "${temp_file}" -C "${abi_dir}"; then
            echo "[OK] libsodium.so ready for ${abi}"
        else
            echo "[WARN] Failed to extract ${filename}"
        fi
        rm -f "${temp_file}"
    else
        echo "[WARN] Failed to download ${filename}"
    fi
done

echo "[INFO] libsodium preparation complete"
echo "[WARN] Ensure libsecurecomm.so is also placed in ${JNILIBS_DIR}/<abi>/"
