#! /bin/bash

params_dir="./params"
output_dir="./output"

if [ ! -d "$params_dir" ]; then
    # If it doesn't exist, create it
    mkdir -p "$params_dir"
else
    echo "./params exists"
fi

if [ ! -d "$output_dir" ]; then
    # If it doesn't exist, create it
    mkdir -p "$output_dir"
else
    echo "./output exists"
fi

cargo build

RUST_BACKTRACE=1 ./target/release/circuit-batcher \
    --params ./params \
    --output ./output \
    batch \
    --challenge sha \
    --openschema shplonk \
    --accumulator use-hash \
    -k 21 \
    --info output/test_circuit.loadinfo.json \
    --name singlebatch \
    --commits sample/batchinfo_empty.json

echo ""
echo "batch test END."
