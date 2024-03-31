TARGET="/home/xgao/continuation/zkWasm"
PROOFINFO="output/r3.loadinfo.json"

# generate solidity
cargo run --release --features perf -- --param $TARGET/params --output $TARGET/output solidity -k 23 --challenge keccak --info $TARGET/$PROOFINFO
