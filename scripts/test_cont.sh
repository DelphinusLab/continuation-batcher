CONFIGDIR="."
WKDIR="/home/richard/git/zkWasm"

BATCH_INFO_INIT=$CONFIGDIR/sample/cont-init.json
BATCH_INFO_RECT=$CONFIGDIR/sample/cont-rec.json
BATCH_INFO_FINAL=$CONFIGDIR/sample/cont-final.json

# Make sure the name field in fibonacci.loadinfo.json is changed to single to fit the above batch configure
CUDA_VISIBLE_DEVICES=1 RUST_BACKTRACE=1 cargo run --features perf --release -- --params $WKDIR/params --output $WKDIR/output batch -k 22  -s shplonk --challenge keccak --info $WKDIR/output/context.loadinfo.json --name ctx_agg --commits $BATCH_INFO_INIT $BATCH_INFO_RECT $BATCH_INFO_FINAL --cont 4

cargo run --release --features cuda -- --params $WKDIR/params --output $WKDIR/output verify --challenge keccak --info $WKDIR/output/ctx_agg.final.loadinfo.json
