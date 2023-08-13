# Get the resource ready for tests
cargo test --release

# verify generated proof for test circuits
cargo run --release -- --output ./output verify -k 8 --info output/test.loadinfo.json

# batch test proofs
cargo run --release -- --output ./output batch --challenge poseidon -k 21 --info output/test.loadinfo.json --name batchsample


# verify generated proof for test circuits
cargo run --release -- --output ./output verify -k 21 --info output/batchsample.loadinfo.json
