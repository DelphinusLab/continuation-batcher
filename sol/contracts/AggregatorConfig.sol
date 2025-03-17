// SPDX-License-Identifier: MIT
// Tells the Solidity compiler to compile only from v0.8.13 to v0.9.0
pragma solidity ^0.8.13;

import "./AggregatorLib.sol";

library AggregatorConfig {
    function fill_verify_circuits_g2(uint256[] memory s) internal pure {
        s[2] = 17131510004222863239408580011965663790707790083758508980521431927481455316244;
        s[3] = 13239981408604951437450014900617239305783482703680168225708776375178235958414;
        s[4] = 16758014440826914722508163669181150884980044788823938544831532724103579389691;
        s[5] = 8824020152601776802611073397094798788346180506242534327221018398726195908688;

        s[8] = 11559732032986387107991004021392285783925812861821192530917403151452391805634;
        s[9] = 10857046999023057135944570762232829481370756359578518086990519993285655852781;
        s[10] = 17805874995975841540914202342111839520379459829704422454583296818431106115052;
        s[11] = 13392588948715843804641432497768002650278120570034223513918757245338268106653;
    }

    function calc_verify_circuit_lagrange(uint256[] memory buf) internal view {
        buf[0] = 4246485553913621569067470645392660895027649716862194263429156289599464730996;
        buf[1] = 15899192751216009222363664025367168439943024377694320324116625506830866071849;
        
        AggregatorLib.msm(buf, 0, 1);
    }

    function hash(uint256[] memory absorbing, uint256 length)
        private
        view
        returns (bytes32[1] memory v)
    {
        
        bytes memory tmp = new bytes(32 * length + 1);
        tmp[length * 32] = 0;
        for (uint256 i = 0; i < length; i++) {
            uint256 offset = 32 + (i * 32);
            uint256 data = absorbing[i];
            assembly { mstore(add(tmp, offset), data) }
        }
        v[0] = keccak256(tmp);
        
    }

    function squeeze_challenge(uint256[] memory absorbing, uint256 length) internal view returns (uint256 v) {
        absorbing[length] = 0;
        bytes32 res = hash(absorbing, length)[0];
        absorbing[0] = uint256(res);
        v = absorbing[0] % AggregatorLib.q_mod;
    }

    function get_challenges(
        uint256[] calldata transcript,
        uint256[] memory buf // buf[0..1] is instance_commitment
    ) internal view {
        return get_challenges_shplonk(transcript, buf);
    }

    function get_challenges_shplonk(
        uint256[] calldata transcript,
        uint256[] memory buf // buf[0..1] is instance_commitment
    ) internal view {
        
        
        uint256[] memory absorbing = new uint256[](152);
        absorbing[0] = 6901874450049050949560638117932163566866099697656126185212198417536751485015;
        absorbing[1] = buf[0];
        absorbing[2] = buf[1];

        uint256 pos = 3;
        uint256 transcript_pos = 0;
        for (uint i = 0; i < 9; i ++) {
            AggregatorLib.check_on_curve(transcript[transcript_pos], transcript[transcript_pos + 1]);
            absorbing[pos++] = transcript[transcript_pos++];
            absorbing[pos++] = transcript[transcript_pos++];
        }
        // theta
        buf[2] = squeeze_challenge(absorbing, pos);
        
        
        pos = 1;
        for (uint i = 0; i < 2; i ++) {
            AggregatorLib.check_on_curve(transcript[transcript_pos], transcript[transcript_pos + 1]);
            absorbing[pos++] = transcript[transcript_pos++];
            absorbing[pos++] = transcript[transcript_pos++];
        }
        // beta
        buf[3] = squeeze_challenge(absorbing, pos);
        
        
        pos = 1;
        // gamma
        buf[4] = squeeze_challenge(absorbing, pos);
        
        
        pos = 1;
        for (uint i = 0; i < 9; i ++) {
            AggregatorLib.check_on_curve(transcript[transcript_pos], transcript[transcript_pos + 1]);
            absorbing[pos++] = transcript[transcript_pos++];
            absorbing[pos++] = transcript[transcript_pos++];
        }
        // y
        buf[5] = squeeze_challenge(absorbing, pos);
        
        
        pos = 1;
        for (uint i = 0; i < 3; i ++) {
            AggregatorLib.check_on_curve(transcript[transcript_pos], transcript[transcript_pos + 1]);
            absorbing[pos++] = transcript[transcript_pos++];
            absorbing[pos++] = transcript[transcript_pos++];
        }
        //x
        buf[6] = squeeze_challenge(absorbing, pos);
        
        
        pos = 1;
        for (uint i = 0; i < 76; i ++) {
            absorbing[pos++] = transcript[transcript_pos++];
        }
        //y
        buf[7] = squeeze_challenge(absorbing, pos);
        
        
        pos = 1;
        //v
        buf[8] = squeeze_challenge(absorbing, pos);
        
        

        AggregatorLib.check_on_curve(transcript[transcript_pos], transcript[transcript_pos + 1]);
        absorbing[pos++] = transcript[transcript_pos++];
        absorbing[pos++] = transcript[transcript_pos++];
        
        //u
        buf[9] = squeeze_challenge(absorbing, pos);
        
        

        AggregatorLib.check_on_curve(transcript[transcript_pos], transcript[transcript_pos + 1]);
    }
}
