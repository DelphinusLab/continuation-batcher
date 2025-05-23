// SPDX-License-Identifier: MIT
// Tells the Solidity compiler to compile only from v0.8.13 to v0.9.0
pragma solidity ^0.8.13;

import "./AggregatorLib.sol";
import "./AggregatorConfig.sol";

interface AggregatorVerifierCoreStep {
    function verify_proof(
        uint256[] calldata transcript,
        uint256[] calldata aux,
        uint256[] memory buf
    ) external view returns (uint256[] memory);
}

contract AggregatorVerifier {
    uint256 constant chunk_bits = 18 * 6;
    uint256 constant chunk_modulus = (1 << chunk_bits) - 1;

    AggregatorVerifierCoreStep[] steps;

    constructor(AggregatorVerifierCoreStep[] memory _steps) {
        steps = _steps;
    }

    function encoding_scalars_to_point(
        uint256 a,
        uint256 b,
        uint256 c
    ) internal pure returns (uint256 x, uint256 y) {
        x = a + ((b & chunk_modulus) << (chunk_bits * 2));
        y = (c << chunk_bits) + (b >> chunk_bits);
    }

    function verify(
        uint256[] calldata proof,
        uint256[] calldata verify_instance,
        uint256[] calldata aux,
        uint256[][] calldata target_instance
    ) public view {
        uint256[] memory buf = new uint256[](52);

        // step 0: calc real verify instance with keccak
        uint256 len = 0;
        for (uint256 i = 0; i < target_instance.length; i++) {
            for (uint256 j = 0; j < target_instance[i].length; j++) {
                buf[len++] = target_instance[i][j];
            }
        }

        for (uint256 i = 0; i < verify_instance.length; i++) {
                buf[len++] = verify_instance[i];
        }

        buf[2] = AggregatorLib.hash_instances(buf, len);

        uint256[] memory verify_circuit_pairing_buf = new uint256[](12);

        {
            // step 1: calculate verify circuit instance commitment
            AggregatorConfig.calc_verify_circuit_lagrange(buf);

            // step 2: calculate challenge
            AggregatorConfig.get_challenges(proof, buf);

            // step 3: calculate verify circuit pair
            for (uint256 i = 0; i < steps.length; i++) {
                buf = steps[i].verify_proof(proof, aux, buf);
            }

            verify_circuit_pairing_buf[0] = buf[0];
            verify_circuit_pairing_buf[1] = buf[1];
            verify_circuit_pairing_buf[6] = buf[2];
            verify_circuit_pairing_buf[7] = buf[3];

            require(
                verify_circuit_pairing_buf[0] != 0 &&
                    verify_circuit_pairing_buf[1] != 0,
                "invalid w point"
            );
            require(
                verify_circuit_pairing_buf[6] != 0 &&
                    verify_circuit_pairing_buf[7] != 0,
                "invalid g point"
            );
        }

        bool checked;

        AggregatorConfig.fill_verify_circuits_g2(verify_circuit_pairing_buf);
        checked = AggregatorLib.pairing(verify_circuit_pairing_buf);
        require(checked, "verify circuit pairing check failed");
    }
}
