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

./target/debug/circuit-batcher \
    --param ./params \
    --output ./output \
    batch \
    --challenge sha \
    -k 21 \
    --info output/test1.loadinfo.json \
    --name singlebatch \
    --commits sample/batchinfo1.json

echo ""
echo "batch test END."