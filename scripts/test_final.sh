#! /bin/bash

params_dir="./test_params"
output_dir="./test_output"

if [ ! -d "$params_dir" ]; then
    # If it doesn't exist, create it
    mkdir -p "$params_dir"
else
    echo "params exists"
fi

if [ ! -d "$output_dir" ]; then
    # If it doesn't exist, create it
    mkdir -p "$output_dir"
else
    echo "output exists"
fi

cargo run --features perf --release -- \
    --params $params_dir \
    --output $output_dir \
    batch \
    --challenge poseidon \
    --openschema shplonk \
    --accumulator use-hash \
    -k 23 \
    --info custom.loadinfo.json \
    --name autobatch \
    --commits sample/batchinfo_empty.json

echo ""
echo "batch test END."
