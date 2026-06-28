#!/usr/bin/env bash
# Build the agent jar (Java 8 bytecode for broad JVM compatibility).
set -euo pipefail
rm -rf classes && mkdir -p classes
javac --release 8 -d classes src/infinity/GuardAgent.java
rm -f infinity-guard-1.0.0.jar
jar cfm infinity-guard-1.0.0.jar src/META-INF/MANIFEST.MF -C classes .
echo "Built infinity-guard-1.0.0.jar"
