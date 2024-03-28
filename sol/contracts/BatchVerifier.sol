// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;
import "./Verifier.sol";

contract ProofTracker {
    DelphinusVerifier private verifier;

    mapping(uint256 => bool) private _tracked_instances;

    uint256[] private _round1_verifier_instances;

    address private _owner;

    constructor(uint256[] memory round1_verifier_instances) {
        _round1_verifier_instances = round1_verifier_instances;
        _owner = msg.sender;
    }

    uint256 constant p_mod = 21888242871839275222246405745257275088696311157297823662689037894645226208583;
    uint256 constant q_mod = 21888242871839275222246405745257275088548364400416034343698204186575808495617;

    function hash_instances(uint256[] memory absorbing, uint256 length)
        internal
        pure
        returns (uint256)
    {
        bytes memory tmp = new bytes(32 * length);
        for (uint256 i = 0; i < length; i++) {
            uint256 offset = 32 + (i * 32);
            uint256 data = absorbing[i];
            assembly { mstore(add(tmp, offset), data) }
        }
        return uint256(keccak256(tmp)) % q_mod;
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
            }
        }
    }

    /* first round agg instances = hash (target_proof instances + shadow_instances) */
    function check_verified_proof(
        uint256[] calldata verify_instance,
        uint256[][] calldata target_instances
        uint256[] calldata sibling_instances,
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

        uint256 target_instance = hash_instances(buf, len);

        uint256 contains = 0;

        for (uint256 i = 0; i < sibling_instances.length; i++) {
            if (target_instance == sibling_instances[i]) {
                contains = 1;
            }
        }

        require(contains == 1, "sibling instances does not match");

        len = 0;

        for (uint256 i = 0; i < sibling_instances.length; i++) {
            buf[len++] = sibling_instances[i];
        }

        for (uint256 i = 0; i < _round1_verifier_instances.length; i++) {
            buf[len++] = _round1_verifier_instances[i];
        }

        uint256 round1_instance = hash_instances(buf, len);

        require(_tracked_instances[round1_instance] == true);
    }
}
