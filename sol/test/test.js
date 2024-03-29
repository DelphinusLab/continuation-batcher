const fs = require("fs");
const BN = require("bn.js");

function readBnLe(file) {
  let buffer = fs.readFileSync(file);
  let buffer256 = [];
  for (let i = 0; i < buffer.length / 32; i++) {
    let v = new BN(0);
    let shift = new BN(1);
    for (let j = 0; j < 32; j++) {
      v = v.add(shift.muln(buffer[i * 32 + j]));
      shift = shift.muln(256);
    }
    buffer256.push(v);
  }

  return buffer256;
}

const AggregatorVerifier = artifacts.require("AggregatorVerifier");
const ProofTracker = artifacts.require("ProofTracker");

//contract("AggregatorVerifier", () => {
contract("ProofTracker", () => {
  it("test", async () => {
    const verifier = await AggregatorVerifier.deployed();
    const tracker = await ProofTracker.deployed();

    console.log("set verifier:", verifier.address);
    console.log("tracker address:", tracker.address);

    c = await tracker.set_verifier(verifier.address);
    console.log("set verifier", c);

    const verify_real_instance = readBnLe(
      __dirname + "/../../sample/result/r3.0.instance.data"
    );
    const verify_shadow_instance = readBnLe(
      __dirname + "/../../sample/result/r3.0.shadowinstance.data"
    );
    const proof = readBnLe(
      __dirname + "/../../sample/result/r3.0.transcript.data"
    );
    const aux = readBnLe(
      __dirname + "/../../sample/result/r3.0.aux.data"
    );

    const round2_shadow_instance = readBnLe(
      __dirname + "/../../sample/result/r2.0.shadowinstance.data"
    )

    const round2_instance = readBnLe(
      __dirname + "/../../sample/result/r2.0.instance.data"
    )

    const round1_shadow_instance = readBnLe(
      __dirname + "/../../sample/result/r1.final.0.shadowinstance.data"
    )

    const round1_instance = readBnLe(
      __dirname + "/../../sample/result/r1.final.0.instance.data"
    )


    const single_proof = readBnLe(
      __dirname + "/../../sample/result/r1.final.0.transcript.data"
    );
    const single_proof_instance = readBnLe(
      //__dirname + "/../../sample/result/fibonacci.0.instance.json"
      __dirname + "/../../sample/result/fibonacci.6.instance.json"
    );
    const zkwasm_shadow_instance = readBnLe(
      __dirname + "/../../sample/result/r1.final.0.shadowinstance.data"
    )

    console.log("set round2 shadow instance", c);
    c = await tracker.set_round1_verifier_instances(round2_shadow_instance);

    let gas = await verifier.verify.estimateGas(
      proof,
      verify_shadow_instance,
      aux,
      [round2_instance]
    );

    console.log("gas cost", gas);

    console.log("register proofs of via final proof");

    gas = await tracker.register_proofs.estimateGas(
      proof,
      verify_shadow_instance,
      aux,
      [round2_instance]
    );

    console.log("gas cost", gas);

    const xy = await tracker.register_proofs(
      proof,
      verify_shadow_instance,
      aux,
      [round2_instance]
    );

    console.log(xy);

    console.log("check r2 proof");
    gas = await tracker.check_verified_proof.estimateGas(
      round2_shadow_instance,
      [],
      [round1_instance]
    );

    console.log("gas cost", gas);


    console.log("check single proof");
    gas = await tracker.check_verified_proof.estimateGas(
      zkwasm_shadow_instance,
      [round1_instance],
      [single_proof_instance]
    );

    console.log("gas cost of check verified proof", gas);


  });
});
