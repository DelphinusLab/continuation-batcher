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

## General Command Usage

The general usage is as follows:

```
cargo run -- --output [OUTPUT_DIR] [SUBCOMMAND] --[ARGS]
```

where `[SUBCOMMAND]` is the command to execute, and `[ARGS]` are the args specific to that command.

The `--output` arg specifies the directory to write all the output files to and is required for all commands.

## Generate batch proof from ProofLoadInfos

```
cargo run -- --challenge poseidon -k 21 --output ./sample batch --info sample/test.loadinfo.json --name batchsample
```

## Verify batch proof from ProofLoadInfos

```
cargo run -- --challenge poseidon -k 21 --output ./sample verify --info sample/batchsample.loadinfo.json
```
