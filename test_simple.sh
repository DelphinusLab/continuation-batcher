#rm -rf output
#rm -rf params

#mkdir output
#mkdir params
# Get the resource ready for tests
#cargo test --release

# verify generated proof for test circuits
cargo run --release --features cuda -- --param ./params --output ./output verify --info output/test1.loadinfo.json

# batch test proofs
cargo run --release --features cuda -- --param ./params --output ./output batch --challenge sha -k 21 --info output/test1.loadinfo.json --name singlebatch --commits sample/batchinfo_empty.json


# verify generated proof for test circuits
cargo run --release --features cuda -- --param ./params --output ./output verify --challenge sha --info output/singlebatch.loadinfo.json

# generate solidity
cargo run --release -- --param ./params --output ./output solidity -k 22 --info output/singlebatch.loadinfo.json output/test1.loadinfo.json --commits sample/batchinfo_empty.json
