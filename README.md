# This is a standalone proof compress & batch tool for zkWASM guest and host circuits.

## Motivation

Delphinus-zkWASM supports a restricted continuation protocol by providing the context read(write) host APIs so that the execution of a large trace can be splitted into multiple code traces and the following trace can access the previous stack and memory. The whole process works similar to a context store/restore in a standard operation system.

The basic idea is to put context in a specific column so that in the proof the commitment of that column is stored in the proof transcript. When the batcher batchs a continuation flow of proofs, it checks that the input context commitment is equal to the output context commitment of the previous context.

## Description of a withness input
```
{
  "vkey": "xxx.vkeyfull.data",
  "k": 21,
  "instance_size": [
    9
  ],
  "transcripts": [
    "xxx.0.transcript.data"
  ],
  "instances": [
    "xxx.0.instance.data"
  ],
  "witnesses": [
    "xxx.0.witness.data"
  ],
  "param": "K21.params",
  "name": "xxx_name",
  "hashtype": "Poseidon"
}
```


## Description proof for a specific target through ProofLoadInfo

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

## General Command Usage

The general usage is as follows:

```
cargo run --release -- --output [OUTPUT_DIR] [SUBCOMMAND] --[ARGS]
```

where `[SUBCOMMAND]` is the command to execute, and `[ARGS]` are the args specific to that command.

The `--output` arg specifies the directory to write all the output files to and is required for all commands.

## Generate batch proof from ProofLoadInfos

```
cargo run --release -- --output ./sample batch --challenge poseidon -k 21 --info sample/test.loadinfo.json --name batchsample --commits output/commits.json
```

## Verify batch proof from ProofLoadInfos

```
cargo run --release -- --output ./sample verify -k 21 --info sample/batchsample.loadinfo.json
```

## Generate proof from witness
cargo run --release -- --output output prove --info output/aggregator.witnessinfo.json

## integrate with just

1. install just: cargo install just
2. configure your batch in a just script: see sample/batchscript.just
3. just -f sample/batchscript.just
