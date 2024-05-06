// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;
import "./AggregatorConfig.sol";

interface SnarkVerifier {
    /**
     * @dev snark verification stub
     */
    function verify (
        uint256[] calldata proof,
        uint256[] calldata verify_instance,
        uint256[] calldata aux,
        uint256[][] calldata target_instance
    ) external view;
}

contract ProofTracker {
    event ProofAck(uint256 hash);
    SnarkVerifier private verifier;

    mapping(uint256 => bool) private _tracked_instances;

    address private _owner;

    constructor(address verifier_address) {
        verifier = SnarkVerifier(verifier_address);
        _owner = msg.sender;
    }

    function set_verifier(address vaddr) public onlyOwner {
        verifier = SnarkVerifier(vaddr);
    }

    /* hash(target_proof instance) ---> first round agg instances */
    function register_proofs(
        uint256[] calldata proof,
        uint256[] calldata verify_instance,
        uint256[] calldata aux,
        uint256[][] calldata instances
    ) public {
        verifier.verify(proof, verify_instance, aux, instances);
        for (uint i = 0; i<instances.length; i++) {
            for (uint j = 0; j<instances[i].length; j++) {
                _tracked_instances[instances[i][j]] = true;
		        emit ProofAck(instances[i][j]);
            }
        }
    }

    /* first round agg instances = hash (target_proof instances + shadow_instances) */
    function check_verified_proof(
        uint256[] calldata membership_proof_index, /* one element index */
        uint256[] calldata verify_instance,
        uint256[][] calldata sibling_instances,
        uint256[][] calldata target_instances
    ) public view {
        uint256[] memory buf = new uint256[](36);
        uint256 len = 0;
        for (uint256 i = 0; i < target_instances.length; i++) {
            for (uint256 j = 0; j < target_instances[i].length; j++) {
                buf[len++] = target_instances[i][j];
            }
        }

        for (uint256 i = 0; i < verify_instance.length; i++) {
                buf[len++] = verify_instance[i];
        }

        uint256 target_instance = AggregatorLib.hash_instances(buf, len);

        for (uint256 i = 0; i < sibling_instances.length; i++) {
            /* check that sibling_instances contains our target instance */
            require(sibling_instances[i][membership_proof_index[i]] == target_instance, "membership proof of sibling instances fail");

            /* calculated the target instance for the next round */
            len = sibling_instances[i].length;
            target_instance = AggregatorLib.hash_instances(sibling_instances[i], len);

	    }

        require(_tracked_instances[target_instance] == true);
    }

    modifier onlyOwner() {
        require(msg.sender == _owner, "Only owner can call this function");
        _;
    }

    function transferOwnership(address newOwner) public onlyOwner {
        require(newOwner != address(0), "Owner cannot be zero address");
        _owner = newOwner;
    }
}
