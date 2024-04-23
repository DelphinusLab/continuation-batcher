const AggregatorLib = artifacts.require("AggregatorLib");
const AggregatorConfig = artifacts.require("AggregatorConfig");
const AggregatorVerifier = artifacts.require("AggregatorVerifier");
const ProofTracker = artifacts.require("ProofTracker");

module.exports = async function (deployer) {
  await deployer.deploy(AggregatorLib);

  let index = 1;
  let steps = [];

  while (index > 0) {
    let AggregatorVerifierCoreStep;
    try {
      AggregatorVerifierCoreStep = artifacts.require("AggregatorVerifierCoreStep" + index.toString());
    } catch {
      index = 0;
      continue;
    }
    deployer.link(AggregatorLib, AggregatorVerifierCoreStep);
    const step = await deployer.deploy(AggregatorVerifierCoreStep);
    steps.push(step.address);
    console.log("deployed AggregatorVerifierCoreStep", index);
    index += 1;
  }

  deployer.link(AggregatorLib, AggregatorConfig);
  await deployer.deploy(AggregatorConfig);

  deployer.link(AggregatorLib, AggregatorVerifier);
  deployer.link(AggregatorConfig, AggregatorVerifier);
  await deployer.deploy(AggregatorVerifier, steps);
  await deployer.deploy(ProofTracker);
};
