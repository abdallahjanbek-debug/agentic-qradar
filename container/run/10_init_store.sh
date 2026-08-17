#!/bin/bash
# Runs on every app start. Must be idempotent — /opt/app-root/store persists
# across stop/start and upgrade, so this may run against an existing store.
set -e

STORE_DB_DIR="/opt/app-root/store/db"
STORE_LOG_DIR="/opt/app-root/store/log"

mkdir -p "${STORE_DB_DIR}"
mkdir -p "${STORE_LOG_DIR}"

echo "socai: store directories ready"
