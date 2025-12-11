#!/usr/bin/env bash
set -euo pipefail

# Configurable variables
TFHE_VERSION="${TFHE_VERSION:-v1.0.0}"
OS="$(uname -s | tr '[:upper:]' '[:lower:]')"   # darwin / linux
ARCH="$(uname -m)"                              # arm64 / x86_64
ARTIFACT_BASE="${ARTIFACT_BASE:-https://github.com/your-org/your-public-binaries/releases/download}"

ZIP_NAME="tfhe-release-${OS}-${ARCH}.zip"
URL="${ARTIFACT_BASE}/${TFHE_VERSION}/${ZIP_NAME}"

DEST_DIR="tfhe-c/release"
TMP_ZIP="$(mktemp -t tfhe-XXXXXX.zip)"

echo ">> Downloading ${URL}"
curl -fL "${URL}" -o "${TMP_ZIP}"

echo ">> Preparing ${DEST_DIR}"
mkdir -p "${DEST_DIR}"

echo ">> Unpacking to ${DEST_DIR}"
unzip -o "${TMP_ZIP}" -d "${DEST_DIR}"

echo ">> Done. Files in ${DEST_DIR}:"
ls -l "${DEST_DIR}"

rm -f "${TMP_ZIP}"

