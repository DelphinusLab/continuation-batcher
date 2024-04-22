// SPDX-License-Identifier: MIT
// Tells the Solidity compiler to compile only from v0.8.13 to v0.9.0
pragma solidity ^0.8.13;

import "./AggregatorLib.sol";

library AggregatorConfig {
    function fill_verify_circuits_g2(uint256[] memory s) internal pure {
        s[2] = 245594121536359573923098574574226326976999057568186541946386251521899051239;
        s[3] = 11989966233273451827196188952389165206577659839709149893302910060266325627571;
        s[4] = 11910458354706402682903890364451297053898217829624118573734401521924804373440;
        s[5] = 18959020778577892511275037308105300366342066298066792876219332202571921563881;

        s[8] = 11559732032986387107991004021392285783925812861821192530917403151452391805634;
        s[9] = 10857046999023057135944570762232829481370756359578518086990519993285655852781;
        s[10] = 17805874995975841540914202342111839520379459829704422454583296818431106115052;
        s[11] = 13392588948715843804641432497768002650278120570034223513918757245338268106653;
    }

    function calc_verify_circuit_lagrange(uint256[] memory buf) internal view {
        buf[0] = 21212064348612611901561423219879055645551074583119790177064738204301217053650;
        buf[1] = 21132618524209467515678062617824281241872283101978369676623106767352325954433;
        
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
        
        
        uint256[] memory absorbing = new uint256[](140);
        absorbing[0] = 551621251195677807166452993210395209455583904580652063116816829719364515818;
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
        for (uint i = 0; i < 6; i ++) {
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
        for (uint i = 0; i < 70; i ++) {
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
