#!/usr/bin/env bash
# Reproducible build of the agent jar (Java 8 bytecode, fixed timestamps/order).
# Requires JDK 17+ (for `jar --date`). Same source -> same SHA-1.
set -euo pipefail
cd "$(dirname "$0")"

EPOCH="2020-01-01T00:00:00Z"

rm -rf classes && mkdir -p classes
javac --release 8 -d classes src/infinity/GuardAgent.java

rm -f infinity-guard-1.1.0.jar
# Explicit, sorted entry list -> deterministic order regardless of FS listing.
jar --create \
    --file infinity-guard-1.1.0.jar \
    --manifest src/META-INF/MANIFEST.MF \
    --date "$EPOCH" \
    -C classes 'infinity/GuardAgent$HttpResult.class' \
    -C classes 'infinity/GuardAgent.class'

echo "Built infinity-guard-1.1.0.jar"
sha1sum infinity-guard-1.1.0.jar 2>/dev/null || shasum -a 1 infinity-guard-1.1.0.jar
