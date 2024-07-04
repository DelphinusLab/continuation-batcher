CONFIGDIR="."
## circuit batcher
# BATCHER_DIR=$WKDIR/continuation-batcher
# BATCHER=$BATCHER_DIR/target/release/circuit-batcher

BATCH_INFO_INIT=$CONFIGDIR/sample/cont-init.json
BATCH_INFO_RECT=$CONFIGDIR/sample/cont-rec.json
BATCH_INFO_FINAL=$CONFIGDIR/sample/cont-final.json

WKDIR="/home/xgao/zkWasm"

# Make sure the name field in fibonacci.loadinfo.json is changed to single to fit the above batch configure

# gen solidity failed, but proof generation succeeds
# k must be 23, otherwise it'll throws not enough rows at the last final round (if you are not care about the final round to be is_final, set k = 22)
RUST_BACKTRACE=1 cargo run --features perf --release -- --params $WKDIR/params --output $WKDIR/output batch -k 22  -s shplonk --challenge sha --info $WKDIR/output/fibonacci.loadinfo.json --name fib_agg --commits $BATCH_INFO_INIT $BATCH_INFO_RECT $BATCH_INFO_FINAL --cont

cargo run --release --features cuda -- --params $WKDIR/params --output $WKDIR/output verify --challenge sha --info output/fib_agg.loadinfo.json
