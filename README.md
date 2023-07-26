# batcher-stack

## ProofLoadInfo

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

## generate batch proof

```
cargo run -- -k 8 --output sample aggregate-prove --batch sample/test.loadinfo.json
```
