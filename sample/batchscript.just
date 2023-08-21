batch2: batch1
    cargo run --release --features cuda -- --output ./output batch --challenge poseidon -k 22 --info output/batch1.loadinfo.json output/test2.loadinfo.json --name batch2 --commits sample/batchinfo2.json

batch1:
    cargo run --release --features cuda -- --output ./output batch --challenge poseidon -k 22 --info output/test1.loadinfo.json --name batch1 --commits sample/batchinfo1.json



