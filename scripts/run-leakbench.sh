#!/bin/bash
# Run the LeakBench evaluation: deterministic Layer 1+2 detection metrics over
# the committed corpus. Reproduces the numbers reported in the README.
#
# Usage: ./scripts/run-leakbench.sh [corpus.jsonl]

set -euo pipefail

cd "$(dirname "$0")/../provn-cli"

echo "Building provn (release)..."
cargo build --release --quiet

if [ "$#" -gt 0 ]; then
    # Explicit corpus path → run just that one.
    echo ""
    echo "Running LeakBench (Layer 1+2, offline): $1"
    ./target/release/provn bench "$1"
else
    for corpus in tests/corpus/realistic.jsonl tests/corpus/leakbench.jsonl; do
        echo ""
        echo "Running LeakBench (Layer 1+2, offline): $corpus"
        ./target/release/provn bench "$corpus"
    done
fi

echo ""
echo "Regression gate:"
cargo test --release --test leakbench --quiet
