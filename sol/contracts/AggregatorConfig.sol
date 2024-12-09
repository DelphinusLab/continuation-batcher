// SPDX-License-Identifier: MIT
// Tells the Solidity compiler to compile only from v0.8.13 to v0.9.0
pragma solidity ^0.8.13;

import "./AggregatorLib.sol";

library AggregatorConfig {
    function fill_verify_circuits_g2(uint256[] memory s) internal pure {
        s[2] = 19421566405792910425150600043884120074272338961363343881376021205116912860799;
        s[3] = 10904134646699597860345541285463430358588842761713475807738276547690324561690;
        s[4] = 3214498706309538880501475110991747346532035521907912766892479865608160258741;
        s[5] = 7958816339349746617965806850396780341948382898964675517411807490154555541565;

        s[8] = 11559732032986387107991004021392285783925812861821192530917403151452391805634;
        s[9] = 10857046999023057135944570762232829481370756359578518086990519993285655852781;
        s[10] = 17805874995975841540914202342111839520379459829704422454583296818431106115052;
        s[11] = 13392588948715843804641432497768002650278120570034223513918757245338268106653;
    }

    function calc_verify_circuit_lagrange(uint256[] memory buf) internal view {
        buf[0] = 9794723626381637444279213838642881279206110983530803961569106349394267934236;
        buf[1] = 2039764858454400466625081930382491043168936920253688760270649773185328950945;
        
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
        
        
        uint256[] memory absorbing = new uint256[](128);
        absorbing[0] = 14446911045823058465336077417170322472585765237392245048501524162423833766996;
        absorbing[1] = buf[0];
        absorbing[2] = buf[1];

        uint256 pos = 3;
        uint256 transcript_pos = 0;
        for (uint i = 0; i < 10; i ++) {
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
        for (uint i = 0; i < 64; i ++) {
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
