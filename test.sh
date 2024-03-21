mkdir output
mkdir params

rm -rf output/*.data
rm -rf params/*.data

# Get the resource ready for tests
cargo test --release

# verify generated proof for test circuits
cargo run --release --features cuda -- --param ./params --output ./output verify --challenge poseidon --info output/test_circuit.loadinfo.json

# batch test proofs
#cargo run --release --features cuda -- --param ./params --output ./output batch -k 22 --challenge sha --info output/test_circuit.loadinfo.json --name batchsample --commits sample/batchinfo1.json
cargo run --features cuda -- --param ./params --output ./output batch -k 22 --challenge keccak --info output/test_circuit.loadinfo.json --name batchsample --commits sample/batchinfo1.json


# verify generated proof for test circuits
cargo run --release --features cuda -- --param ./params --output ./output verify --challenge keccak --info output/batchsample.loadinfo.json

# generate solidity
cargo run --release -- --param ./params --output ./output solidity -k 22 --challenge keccak --info output/batchsample.loadinfo.json output/test2.loadinfo.json output/test1.loadinfo.json --commits sample/batchinfo1.json
