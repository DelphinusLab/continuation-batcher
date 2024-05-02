# This is a standalone proof compress & batch tool for zkWASM guest and host circuits.

## Motivation

Delphinus-zkWASM supports a restricted continuation protocol by providing the context read(write) host APIs so that the execution of a large trace can be splitted into multiple code traces and the following trace can access the previous stack and memory. The whole process works similar to a context store/restore in a standard operation system.

The basic idea is to put context in a specific column so that in the proof the commitment of that column is stored in the proof transcript. When the batcher batchs a continuation flow of proofs, it checks that the input context commitment is equal to the output context commitment of the previous context.

# Simple Example

## Generate batch proof from ProofLoadInfos
We support two modes of batching proofs. The rollup continuation mode and the flat mode. In both mode we have two options to handle the public instance of the target proofs when batching.
1. The commitment encode: The commitment of the target instance becomes the public instance of the batch proof.
2. The hash encode: The hash of the target instance become the public instance of the batch proof.

Meanwhile, we provide two openschema when batching proofs, the Shplonk and GWC and three different challenge computation methods: sha, keccak and poseidon. (If the batched proofs are suppose to be the target proofs of another round of batching, then the challenge method needs to be poseidon.)

## General Command Usage

The general usage is as follows:

```
cargo run --release -- --params [PARAMS_DIR] --output [OUTPUT_DIR] [SUBCOMMAND] --[ARGS]
```

where `[SUBCOMMAND]` is the command to execute, and `[ARGS]` are the args specific to that command.

The `--output` arg specifies the directory to write all the output files to and is required for all commands.
The `--params` arg specifies the directory to write all the params files to and is required for all commands.

## Batching Sub Command

```
USAGE:
    circuit-batcher batch [OPTIONS] --challenge <CHALLENGE_HASH_TYPE>... --openschema <OPEN_SCHEMA>...

OPTIONS:
    -a, --accumulator [<ACCUMULATOR>...]
            Accumulator of the public instances (default is using commitment) [possible values:
            use-commitment, use-hash]

    -c, --challenge <CHALLENGE_HASH_TYPE>...
            HashType of Challenge [possible values: poseidon, sha, keccak]

        --commits <commits>...
            Path of the batch config files

        --cont [<CONT>...]
            Is continuation's loadinfo.

    -h, --help
            Print help information

        --info <info>...
            Path of the batch config files

    -k [<K>...]
            Circuit Size K

    -n, --name [<PROOF_NAME>...]
            name of this task.

    -s, --openschema <OPEN_SCHEMA>...
            Open Schema [possible values: gwc, shplonk]
```

**Example:**

```
#! /bin/bash

params_dir="./params"
output_dir="./output"

if [ ! -d "$params_dir" ]; then
    # If it doesn't exist, create it
    mkdir -p "$params_dir"
else
    echo "./params exists"
fi

if [ ! -d "$output_dir" ]; then
    # If it doesn't exist, create it
    mkdir -p "$output_dir"
else
    echo "./output exists"
fi

# Get the resource ready for tests
cargo test --release --features cuda

# verify generated proof for test circuits
cargo run --release --features cuda -- --params ./params --output ./output verify --challenge poseidon --info output/test_circuit.loadinfo.json

# batch test proofs
cargo run --features cuda -- --params ./params --output ./output batch -k 22 --openschema shplonk --challenge keccak --info output/test_circuit.loadinfo.json --name batchsample --commits sample/batchinfo_empty.json


# verify generated proof for test circuits
cargo run --release --features cuda -- --params ./params --output ./output verify --challenge keccak --info output/batchsample.loadinfo.json

# generate solidity
cargo run --release -- --params ./params --output ./output solidity -k 22 --challenge keccak --info output/batchsample.loadinfo.json
```


# Tool Details

1. Describe circuits.
2. Generate the proofs of target circuits.
3. Define your batching policy via the batch DSL.
4. Execute the batching DSL and generate the batching circuit.
5. Generate the final solidity for your batching circuit.

## Proof Description
To describe a proof, we need to specify (in file name)
1. The circuit this proof related to.
2. The instance size of the proof.
3. The witness data if the proof have not been generated yet.
4. The proof transcript.

```
type ProofPieceInfo = {
  circuit: filename,
  instance_size: int,
  witness: filename,
  instance: filename,
  transcript: filename
}
```
## Description of a proof batching group
To batch a group of proofs together, the proofs themself needs to be generated use same param k (not necessary same circuit). When describe the group we provide the following fields:

```
type ProofGenerationInfo {
  proofs: Vec<ProofPieceInfo>
  k: int
  param: filename,
  name: string,
  hashtype: Poseidon | Sha256 | Keccak
}
```

This tool requires the target proofs (the proofs we want to batch) are all uses the **Poseidon** as hash functions for challenge generation. If the batch circuit is used to generate intermediate proofs for another batching circuit, then we need to specifiy the batch circuit to use the **Poseidon** hash for challenge generation as well. If the batch circuit is used to generate a final proof for verification on chain, then you should specify the challenge hash to be either Keccak or Poseidon.

## Handling the instances of target proofs
Suppose that we would like to batch our target proofs **T_i**, the batching circuit is **C_b**, the verifier of **C_b** is **V_b** and our batched proof is called proof **B**. If is important to understand the instance structure of **C_b**.

In this tool, we support two accumulator mode to pass the information of the instance of **T_i** to the instance of **C_b**, namely in **HashInstance** mode and **CommitInstance** mode.

![Alt text](./images/prove-agg-instance-mode.png?raw=true "Two modes to carry the instances of target proofs")

## Description the batch schema when connecting proofs
When connecting proofs (mainly plonkish KZG backend), we need to provide two groups of attributes that decides
1. How the proof is batched
2. What are the extra connections between different proofs.

When batch proofs, we are infact writing the verifying function into circuits. Thus we need to specify the compoments of the circuits we used to construct the final verifying circuit. The main conponents of the verifing cicruit contains the challenge circuit (the hash we use to generate the challenge), the ecc circuit (what is used to generate msm and pairing), the proof relation circuit (what is used to describe the relation between proofs, their instances, commitments, etc)

1. The hash circuit has three different type
```
hashtype: Poseidon | Sha256 | Keccak
```

2. The ecc circuit has two options. One is use the ecc circuit with lookup features. This circuit can do ecc operation with minimized rows thus can be used to batch a relatively big amount of target circuits. The other option is to use a concise ecc circuit. This circuit do not use the lookup feature thus generate a lot rows when doing ecc operation. This ecc circuit is usually used at the last around of batch as the solidity for this circuit is much more gas effective.

3. The proof relation circuit can be described in a json with commitment arithments. The commitment arithments has three categories: equivalents, expose and absorb.

```
{
    "equivalents": [
        {
            "source": {"name": "circuit_1", "proof_idx": 0, "column_name": "A"},
            "target": {"name": "circuit_2", "proof_idx": 0, "column_name": "A"}
        }
    ],
    "expose": [
        {"name": "test_circuit", "proof_idx": 0, "column_name": "A"}
    ],
    "absorb": []
}
```
