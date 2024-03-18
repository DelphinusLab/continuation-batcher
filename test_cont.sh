
cargo run --release --features cuda -- --param ./params --output ./output batch -k 22 --challenge sha --info output/wasm_output.loadinfo.json --name wasm_output_agg --commits sample/batchinfo_cont.json --cont
cargo run --release --features cuda -- --param ./params --output ./output verify --challenge sha --info output/wasm_output_agg.loadinfo.json