## Summary
This branch is using to reproduce the playground cont manual proof task scenario. Which is K23, --challenge keccak,  --accumulator use-hash, and select_chip is false

## Steps
1. use zkwasm repo (git = "https://github.com/DelphinusLab/zkWasm.git", features = ["continuation"], branch = "explorer-integration-2.0") to build fibonacci single proof. Can use the test_cli.sh in zkwasm repo's 
```
test_continuation_cli() {
    cargo build --release --features continuation $CUDA
    rm -rf params/*.data params/*.config output
    $CLI --params ./params fibonacci setup
    $CLI --params ./params fibonacci dry-run --wasm crates/zkwasm/wasm/fibonacci.wasm --public 25:i64 --output ./output
    $CLI --params ./params fibonacci prove --wasm crates/zkwasm/wasm/fibonacci.wasm --public 25:i64 --output ./output
    $CLI --params ./params fibonacci verify --output ./output
}
```

2. Update script test_cont.sh to point WKDIR to the folder of zkwasm
3. Run `bash scripts/test_cont.sh`