# This is a standalone proof compress & batch tool for zkWASM guest and host circuits.

## Motivation

Delphinus-zkWASM supports a restricted continuation protocol by providing the context read(write) host APIs so that the execution of a large trace can be splitted into multiple code traces and the following trace can access the previous stack and memory. The whole process works similar to a context store/restore in a standard operation system.

The basic idea is to put context in a specific column so that in the proof the commitment of that column is stored in the proof transcript. When the batcher batchs a continuation flow of proofs, it checks that the input context commitment is equal to the output context commitment of the previous context.


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

## General Command Usage

The general usage is as follows:

```
cargo run -- --output [OUTPUT_DIR] [SUBCOMMAND] --[ARGS]
```

where `[SUBCOMMAND]` is the command to execute, and `[ARGS]` are the args specific to that command.

The `--output` arg specifies the directory to write all the output files to and is required for all commands.

## Generate batch proof from ProofLoadInfos

```
cargo run -- --output ./sample batch --challenge poseidon -k 21 --info sample/test.loadinfo.json --name batchsample
```

## Verify batch proof from ProofLoadInfos

```
cargo run -- --output ./sample verify -k 21 --info sample/batchsample.loadinfo.json
```
