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

# Get the resource ready for tests
cargo test --release --features cuda

# verify generated proof for test circuits
cargo run --release --features cuda -- --params ./params --output ./output verify --challenge poseidon --info output/test_circuit.loadinfo.json

# batch test proofs
cargo run --release --features cuda -- --params ./params --output ./output batch -k 22 --openschema shplonk --challenge keccak --info output/test_circuit.loadinfo.json --name batchsample --commits sample/batchinfo_empty.json


# verify generated proof for test circuits
cargo run --release --features cuda -- --params ./params --output ./output verify --challenge keccak --info output/batchsample.loadinfo.json

# generate solidity
cargo run --release -- --params ./params --output ./output solidity -k 22 --challenge keccak --info output/batchsample.loadinfo.json
