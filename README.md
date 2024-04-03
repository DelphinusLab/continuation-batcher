# This is a standalone proof compress & batch tool for KZG-based ZK proofs.

## Motivation

Delphinus-zkWASM supports a continuation protocol by providing columns of witnesses that represent the VM state. So that the execution of a large trace can be split into multiple code traces and the following trace can access the previous stack and memory. The whole process works similar to a context store/restore in a standard operation system. The basic idea is to track the commitment of the context column stored in the proof transcript and then provide a configurable circuit component in the proof batcher to reason about different commitments between proofs. In the case of ZKWASM continuation implementation, when the proof-batcher batches a continuation flow of proofs, it checks that the input context commitment is equal to the output context commitment of the previous context.

Although the tool is initially developed for a specific ZKVM (ZKWASM), it can be used to batch all KZG-based proofs and the DSL used to reasoning about the commitments and instances still work. Also, it can be used to support different continuation schemas (eg. flat continuation, rollup continuation) and rollup schemas (eg. layered batching, accululator batching).

At the end, we provide a solidity generation tool for your final round of batching script so that the proof you generated after executing the batching DSL can be verified on the chain and we also provide a demo tracking contract with which you can check whether a single proof has been involved in a large batched proof (inclusive proof of the batched proof).

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
cargo run --release --features cuda -- --param ./params --output ./output verify --challenge poseidon --info output/test_circuit.loadinfo.json

# batch test proofs
cargo run --features cuda -- --param ./params --output ./output batch -k 22 --openschema shplonk --challenge keccak --info output/test_circuit.loadinfo.json --name batchsample --commits sample/batchinfo_empty.json


# verify generated proof for test circuits
cargo run --release --features cuda -- --param ./params --output ./output verify --challenge keccak --info output/batchsample.loadinfo.json

# generate solidity
cargo run --release -- --param ./params --output ./output solidity -k 22 --challenge keccak --info output/batchsample.loadinfo.json
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
## Description of a proof group
To batch a group of proofs together, the proofs themself need to be generated using the same param k (not necessarily the same circuit). When describing the group we provide the following fields:

```
type ProofGenerationInfo {
  proofs: Vec<ProofPieceInfo>
  k: int
  param: filename,
  name: string,
  hashtype: Poseidon | Sha256 | Keccak
}
```

This tool requires the target proofs (the proofs we want to batch) are all uses the **Poseidon** as hash functions for challenge generation. If the batch circuit is used to generate intermediate proofs for another batching circuit, then we need to specify the batch circuit to use the **Poseidon** hash for challenge generation as well. If the batch circuit is used to generate a final proof for verification on chain, then you should specify the challenge hash to be either Keccak or Poseidon.

## Handling the instances of target proofs
Suppose that we would like to batch our target proofs **T_i**, the batching circuit is **C_b**, the verifier of **C_b** is **V_b** and our batched proof is called proof **B**. If is important to understand the instance structure of **C_b**.

In this tool, we support two accumulator modes to pass the information of the instance of **T_i** to the instance of **C_b**, namely in **HashInstance** mode and **CommitInstance** mode.

![Alt text](./images/prove-agg-instance-mode.png?raw=true "Two modes to carry the instances of target proofs")

## Description the batch schema when connecting proofs
When batch proofs, we are in fact writing the verifying function into circuits. Thus we need to specify the components of the circuits we used to construct the final verifying circuit. The main components of the verifing circuit contains the challenge circuit (the hash we use to generate the challenge), the ECC circuit (what is used to generate msm and pairing), the proof relation circuit (what is used to describe the relation between proofs, their instances, commitments, etc)

1. The challenge circuit has three different type
```
hashtype: Poseidon | Sha256 | Keccak
```

2. The ECC circuit has two options. One is to use the ECC circuit with lookup features. This circuit can do ECC operation with minimized rows and thus can be used to batch a relatively big amount of target circuits. The other option is to use a concise ECC circuit. This circuit do not use the lookup feature and thus generates a lot of rows when doing ECC operation. This ECC circuit is usually used at the last round of batch as the solidity for this circuit is much more gas effective.

3. The proof relation circuit is configurable. It can be described in a JSON with commitment arithmetic and the commitment arithmetic has three categories: equivalents, expose and absorb.

**Example: A simple proof relation sheet with commitment arithmetic**
```
{
    "equivalents": [
        {
            "source": {"name": "circuit_1", "proof_idx": 0, "column_name": "A"},
            "target": {"name": "circuit_2", "proof_idx": 0, "column_name": "B"}
        }
    ],
    "expose": [
        {"name": "test_circuit", "proof_idx": 0, "column_name": "A"}
    ],
    "absorb": []
}
```

## Specify the proof relation

There are a few scenarios we need to specify the constraints between commitments of different proofs.

### Equivalents
Suppose that we have two circuits, **circuit_1** and **circuit_2**, they both have instances and witnesses namely **instances_1**, **instances_2**, **witness_1**, **witness_2**. It follows that, after batching the proofs, we lose the information of **witness_1** and **witness_2**. Thus to establish the connection between **witness_1** and **witness_2** we provide a configurable component in the batching circuit that allows user to specify equivalents between columns of **witness_1** and **witness_2**. when we put the following configuration into the proof relation sheet
```
{
    "equivalents": [
        {
            "source": {"name": "circuit_1", "proof_idx": 0, "column_name": "A"},
            "target": {"name": "circuit_2", "proof_idx": 0, "column_name": "B"}
        }
    ],
}
```
the batch will ensure the witness of column **A** of the first proof of **circuit_1** will equal to the witness of column **B** of the first proof of **circuit_2**.
<div><img src="./images/commitment-equivalent.png?" width="60%"/></div>


### Expose
Suppose that we have two groups of proofs that batched into **batch_proof_1** and **batch_proof_2** where **batch_proof_1** contains **proofA** and **batch_proof_2** contains **proofB**. It follows that we can not establish connections between the witness of **proofA** and **proofB** when batching **batch_proof_1** and **batching_proof_2** because **batch_proof_1** lost the track of witness of **proofA** and  **batch_proof_2** lost the track of witness of **proofB**. Thus to solve this problem, we provide the **expose** semantics when batching **batch_proof_1** and **batch_proof_2**. For example, if we want to constraint that witness column **A** of **proofA** is equal to the witness column **B** of **proofB**, we can first expose **A** of **proofA** in the proof relation sheet of **batch_proof_1** as follows
```
{
    "expose": [
        {
            {"name": "circuit_1", "proof_idx": 0, "column_name": "A"},
        }
    ],
}
```
and then expose **B** in the proof relation sheet of **batch_proof_2**. The expose of the witness will append three new instances to the instances of the batched proof which represents the commitment of the witness.
<div><img src="./images/commitment-expose.png?" width="40%"/></div>

### Absorb
Suppose that we have a batched proof **batch_proof_1** which contains **proof_1** and another proof **proof_2**. Then it follows that if we would like to establish a connection between witness **A** of **proof_1** and witness **B** of **proof_2**, we need not only expose **A** in the proof relation sheet of **batch_proof_1** but also provide a semantic for the batcher to ensure that the exposed commitment of **A** is equal to the commitment of **B** in **proof_2**. Since **proof_2** has not been batched yet, neither **equivalents** nor **expose** will work. Thus, we need a new semantic called **absorb** here.
```
    "absorb": [
	    {
		    "instance_idx": {"name": "single", "proof_idx": 1, "group_idx": 2},
		    "target": {"name": "single", "proof_idx": 0, "column_name": "post_img_col"}
	    }
    ]
```
<div><img src="./images/commitment-absorb.png?raw=true" width="70%"/></div>
