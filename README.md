# This is a standalone proof compress & batch tool for zkWASM guest and host circuits.

## Descript proof for a specific target through ProofLoadInfo

```
{
  "vkey": "test.vkeyfull.data",
  "instance_size": [
    1
  ],
  "transcripts": [
    "test.0.transcript.data"
  ],
  "instances": [
    "test.0.instance.data"
  ],
  "hashtype": "Poseidon",
  "param": "K8.params",
  "name": "test"
}

```

## Generate batch proof from ProofLoadInfos

```
cargo run -- --challenge poseidon -k 21 --output ./sample batch --info sample/test.loadinfo.json --name batchsample
```

## Verify batch proof from ProofLoadInfos

```
cargo run -- --challenge poseidon -k 21 --output ./sample verify --info sample/batchsample.loadinfo.json
```
