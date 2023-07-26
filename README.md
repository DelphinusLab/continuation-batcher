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
  "param": "K8.params",
  "name": "test"
}

```

## Generate batch proof from ProofLoadInfos

```
cargo run -- -k 8 --output sample aggregate-prove --batch sample/test.loadinfo.json
```
