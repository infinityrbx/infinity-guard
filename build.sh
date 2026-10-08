#!/usr/bin/env bash
# Reproducible build of the agent jar (Java 8 bytecode, fixed timestamps/order).
# Requires JDK 17+ (for `jar --date`). Same source -> same SHA-256.
set -euo pipefail
cd "$(dirname "$0")"

EPOCH="2020-01-01T00:00:00Z"

rm -rf classes && mkdir -p classes
javac --release 8 -d classes src/infinity/GuardAgent.java

rm -f infinity-guard-1.2.2.jar
# Explicit, sorted entry list -> deterministic order regardless of FS listing.
jar --create \
    --file infinity-guard-1.2.2.jar \
    --manifest src/META-INF/MANIFEST.MF \
    --date "$EPOCH" \
    -C classes 'infinity/GuardAgent$HttpResult.class' \
    -C classes 'infinity/GuardAgent.class'

echo "Built infinity-guard-1.2.2.jar"
sha256sum infinity-guard-1.2.2.jar 2>/dev/null || shasum -a 256 infinity-guard-1.2.2.jar
