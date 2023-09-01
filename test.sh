rm -rf output
rm -rf params

mkdir output
mkdir params
# Get the resource ready for tests
cargo test --release

# verify generated proof for test circuits
cargo run --release --features cuda -- --param ./params --output ./output verify --info output/test1.loadinfo.json

# batch test proofs
cargo run --release --features cuda -- --param ./params --output ./output batch --challenge sha -k 21 --info output/test2.loadinfo.json output/test1.loadinfo.json --name batchsample --commits sample/batchinfo1.json


# verify generated proof for test circuits
cargo run --release --features cuda -- --param ./params --output ./output verify --challenge sha --info output/batchsample.loadinfo.json

# generate solidity
cargo run --release -- --param ./params --output ./output solidity -k 22 --info output/batchsample.loadinfo.json output/test2.loadinfo.json output/test1.loadinfo.json --commits sample/batchinfo1.json
