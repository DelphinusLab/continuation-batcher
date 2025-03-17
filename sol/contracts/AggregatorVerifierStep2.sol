// SPDX-License-Identifier: MIT
// Tells the Solidity compiler to compile only from v0.8.13 to v0.9.0
pragma solidity ^0.8.13;

import "./AggregatorLib.sol";

contract AggregatorVerifierCoreStep2 {
    function verify_proof(
        uint256[] calldata transcript,
        uint256[] calldata aux,
        uint256[] memory buf
    ) public view returns (uint256[] memory)  {
        buf[33] = addmod(mulmod(addmod(buf[33], mulmod(buf[3], transcript[96], AggregatorLib.q_mod), AggregatorLib.q_mod), mulmod(addmod(buf[34], mulmod(buf[3], transcript[95], AggregatorLib.q_mod), AggregatorLib.q_mod), transcript[109], AggregatorLib.q_mod), AggregatorLib.q_mod), AggregatorLib.q_mod - mulmod(addmod(buf[33], mulmod(4131629893567559867359510883348571134090853742863529169391034518566172092834, buf[35], AggregatorLib.q_mod), AggregatorLib.q_mod), mulmod(addmod(buf[34], buf[35], AggregatorLib.q_mod), transcript[108], AggregatorLib.q_mod), AggregatorLib.q_mod), AggregatorLib.q_mod);
buf[21] = mulmod(addmod(mulmod(addmod(buf[21], mulmod(buf[28], buf[29], AggregatorLib.q_mod), AggregatorLib.q_mod), buf[5], AggregatorLib.q_mod), mulmod(buf[33], buf[29], AggregatorLib.q_mod), AggregatorLib.q_mod), buf[5], AggregatorLib.q_mod);
buf[28] = addmod(transcript[56], buf[4], AggregatorLib.q_mod);
buf[33] = addmod(transcript[55], buf[4], AggregatorLib.q_mod);
buf[34] = AggregatorLib.fr_pow(4131629893567559867359510883348571134090853742863529169391034518566172092834, 8);
buf[31] = mulmod(buf[31], buf[34], AggregatorLib.q_mod);
buf[28] = addmod(mulmod(addmod(buf[28], mulmod(buf[3], transcript[98], AggregatorLib.q_mod), AggregatorLib.q_mod), mulmod(addmod(buf[33], mulmod(buf[3], transcript[97], AggregatorLib.q_mod), AggregatorLib.q_mod), transcript[112], AggregatorLib.q_mod), AggregatorLib.q_mod), AggregatorLib.q_mod - mulmod(addmod(buf[28], mulmod(4131629893567559867359510883348571134090853742863529169391034518566172092834, buf[31], AggregatorLib.q_mod), AggregatorLib.q_mod), mulmod(addmod(buf[33], buf[31], AggregatorLib.q_mod), transcript[111], AggregatorLib.q_mod), AggregatorLib.q_mod), AggregatorLib.q_mod);
buf[21] = mulmod(addmod(mulmod(addmod(buf[21], mulmod(buf[28], buf[29], AggregatorLib.q_mod), AggregatorLib.q_mod), buf[5], AggregatorLib.q_mod), mulmod(buf[25], transcript[114], AggregatorLib.q_mod), AggregatorLib.q_mod), buf[5], AggregatorLib.q_mod);
buf[28] = addmod(transcript[81], buf[3], AggregatorLib.q_mod);
buf[28] = addmod(mulmod(addmod(mulmod(buf[28], addmod(transcript[115], AggregatorLib.q_mod - transcript[114], AggregatorLib.q_mod), AggregatorLib.q_mod), transcript[113], AggregatorLib.q_mod), addmod(transcript[54], buf[3], AggregatorLib.q_mod), AggregatorLib.q_mod), AggregatorLib.q_mod - buf[28], AggregatorLib.q_mod);
buf[21] = mulmod(addmod(mulmod(addmod(buf[21], mulmod(buf[27], transcript[117], AggregatorLib.q_mod), AggregatorLib.q_mod), buf[5], AggregatorLib.q_mod), mulmod(buf[28], buf[29], AggregatorLib.q_mod), AggregatorLib.q_mod), buf[5], AggregatorLib.q_mod);
buf[28] = addmod(transcript[55], buf[3], AggregatorLib.q_mod);
buf[31] = addmod(transcript[56], buf[3], AggregatorLib.q_mod);
buf[21] = addmod(mulmod(addmod(buf[21], mulmod(buf[25], addmod(transcript[117], AggregatorLib.q_mod - transcript[116], AggregatorLib.q_mod), AggregatorLib.q_mod), AggregatorLib.q_mod), buf[5], AggregatorLib.q_mod), mulmod(addmod(mulmod(addmod(transcript[118], AggregatorLib.q_mod - transcript[117], AggregatorLib.q_mod), mulmod(buf[28], buf[31], AggregatorLib.q_mod), AggregatorLib.q_mod), AggregatorLib.q_mod - addmod(buf[31], buf[28], AggregatorLib.q_mod), AggregatorLib.q_mod), buf[29], AggregatorLib.q_mod), AggregatorLib.q_mod);
buf[21] = mulmod(addmod(mulmod(addmod(mulmod(buf[21], buf[5], AggregatorLib.q_mod), mulmod(buf[25], transcript[120], AggregatorLib.q_mod), AggregatorLib.q_mod), buf[5], AggregatorLib.q_mod), mulmod(buf[27], transcript[120], AggregatorLib.q_mod), AggregatorLib.q_mod), buf[5], AggregatorLib.q_mod);
buf[25] = mulmod(addmod(mulmod(addmod(mulmod(transcript[86], buf[2], AggregatorLib.q_mod), transcript[47], AggregatorLib.q_mod), buf[2], AggregatorLib.q_mod), transcript[48], AggregatorLib.q_mod), buf[2], AggregatorLib.q_mod);
buf[27] = addmod(addmod(buf[25], transcript[87], AggregatorLib.q_mod), buf[3], AggregatorLib.q_mod);
buf[25] = addmod(mulmod(addmod(mulmod(buf[27], addmod(transcript[121], AggregatorLib.q_mod - transcript[120], AggregatorLib.q_mod), AggregatorLib.q_mod), transcript[119], AggregatorLib.q_mod), addmod(buf[25], buf[3], AggregatorLib.q_mod), AggregatorLib.q_mod), AggregatorLib.q_mod - buf[27], AggregatorLib.q_mod);
buf[20] = addmod(mulmod(buf[7], addmod(mulmod(buf[7], addmod(buf[20], transcript[97], AggregatorLib.q_mod), AggregatorLib.q_mod), transcript[98], AggregatorLib.q_mod), AggregatorLib.q_mod), AggregatorLib.fr_div(addmod(buf[21], mulmod(buf[25], buf[29], AggregatorLib.q_mod), AggregatorLib.q_mod), buf[24], aux[14]), AggregatorLib.q_mod);
buf[17] = addmod(buf[9], AggregatorLib.q_mod - buf[17], AggregatorLib.q_mod);
buf[21] = addmod(buf[9], AggregatorLib.q_mod - buf[19], AggregatorLib.q_mod);
buf[24] = mulmod(1426404432721484388505361748317961535523355871255605456897797744433766488507, buf[6], AggregatorLib.q_mod);
buf[25] = addmod(buf[9], AggregatorLib.q_mod - buf[24], AggregatorLib.q_mod);
buf[27] = mulmod(12619617507853212586156872920672483948819476989779550311307282715684870266992, buf[6], AggregatorLib.q_mod);
buf[28] = addmod(buf[9], AggregatorLib.q_mod - buf[27], AggregatorLib.q_mod);
buf[29] = AggregatorLib.fr_div(1, mulmod(buf[25], buf[28], AggregatorLib.q_mod), aux[15]);
buf[31] = mulmod(mulmod(mulmod(mulmod(buf[17], buf[21], AggregatorLib.q_mod), buf[25], AggregatorLib.q_mod), buf[28], AggregatorLib.q_mod), buf[29], AggregatorLib.q_mod);
buf[18] = mulmod(buf[8], addmod(mulmod(buf[8], buf[18], AggregatorLib.q_mod), mulmod(addmod(mulmod(buf[7], buf[20], AggregatorLib.q_mod), transcript[88], AggregatorLib.q_mod), buf[31], AggregatorLib.q_mod), AggregatorLib.q_mod), AggregatorLib.q_mod);
buf[20] = AggregatorLib.q_mod - buf[30];
buf[30] = AggregatorLib.q_mod - buf[32];
buf[32] = mulmod(buf[7], addmod(mulmod(addmod(mulmod(buf[23], transcript[54], AggregatorLib.q_mod), mulmod(buf[26], transcript[57], AggregatorLib.q_mod), AggregatorLib.q_mod), buf[9], AggregatorLib.q_mod), addmod(mulmod(buf[20], transcript[54], AggregatorLib.q_mod), mulmod(buf[30], transcript[57], AggregatorLib.q_mod), AggregatorLib.q_mod), AggregatorLib.q_mod), AggregatorLib.q_mod);
buf[32] = addmod(buf[32], addmod(mulmod(addmod(mulmod(buf[23], transcript[55], AggregatorLib.q_mod), mulmod(buf[26], transcript[58], AggregatorLib.q_mod), AggregatorLib.q_mod), buf[9], AggregatorLib.q_mod), addmod(mulmod(buf[20], transcript[55], AggregatorLib.q_mod), mulmod(buf[30], transcript[58], AggregatorLib.q_mod), AggregatorLib.q_mod), AggregatorLib.q_mod), AggregatorLib.q_mod);
buf[32] = addmod(mulmod(buf[7], buf[32], AggregatorLib.q_mod), addmod(mulmod(addmod(mulmod(buf[23], transcript[56], AggregatorLib.q_mod), mulmod(buf[26], transcript[59], AggregatorLib.q_mod), AggregatorLib.q_mod), buf[9], AggregatorLib.q_mod), addmod(mulmod(buf[20], transcript[56], AggregatorLib.q_mod), mulmod(buf[30], transcript[59], AggregatorLib.q_mod), AggregatorLib.q_mod), AggregatorLib.q_mod), AggregatorLib.q_mod);
buf[32] = addmod(mulmod(buf[7], buf[32], AggregatorLib.q_mod), addmod(mulmod(addmod(mulmod(buf[23], transcript[111], AggregatorLib.q_mod), mulmod(buf[26], transcript[112], AggregatorLib.q_mod), AggregatorLib.q_mod), buf[9], AggregatorLib.q_mod), addmod(mulmod(buf[20], transcript[111], AggregatorLib.q_mod), mulmod(buf[30], transcript[112], AggregatorLib.q_mod), AggregatorLib.q_mod), AggregatorLib.q_mod), AggregatorLib.q_mod);
buf[32] = addmod(mulmod(buf[7], buf[32], AggregatorLib.q_mod), addmod(mulmod(addmod(mulmod(buf[23], transcript[117], AggregatorLib.q_mod), mulmod(buf[26], transcript[118], AggregatorLib.q_mod), AggregatorLib.q_mod), buf[9], AggregatorLib.q_mod), addmod(mulmod(buf[20], transcript[117], AggregatorLib.q_mod), mulmod(buf[30], transcript[118], AggregatorLib.q_mod), AggregatorLib.q_mod), AggregatorLib.q_mod), AggregatorLib.q_mod);
buf[32] = addmod(mulmod(buf[7], buf[32], AggregatorLib.q_mod), addmod(mulmod(addmod(mulmod(buf[23], transcript[120], AggregatorLib.q_mod), mulmod(buf[26], transcript[121], AggregatorLib.q_mod), AggregatorLib.q_mod), buf[9], AggregatorLib.q_mod), addmod(mulmod(buf[20], transcript[120], AggregatorLib.q_mod), mulmod(buf[30], transcript[121], AggregatorLib.q_mod), AggregatorLib.q_mod), AggregatorLib.q_mod), AggregatorLib.q_mod);
buf[25] = mulmod(mulmod(mulmod(buf[17], buf[25], AggregatorLib.q_mod), buf[28], AggregatorLib.q_mod), buf[29], AggregatorLib.q_mod);
buf[33] = AggregatorLib.fr_div(1, addmod(buf[6], AggregatorLib.q_mod - buf[24], AggregatorLib.q_mod), aux[16]);
buf[34] = mulmod(buf[23], buf[33], AggregatorLib.q_mod);
buf[35] = AggregatorLib.fr_div(1, addmod(buf[19], AggregatorLib.q_mod - buf[24], AggregatorLib.q_mod), aux[17]);
buf[36] = mulmod(buf[26], buf[35], AggregatorLib.q_mod);
buf[37] = AggregatorLib.fr_div(1, addmod(buf[24], AggregatorLib.q_mod - buf[6], AggregatorLib.q_mod), aux[18]);
buf[38] = AggregatorLib.fr_div(1, addmod(buf[24], AggregatorLib.q_mod - buf[19], AggregatorLib.q_mod), aux[19]);
buf[39] = mulmod(buf[37], buf[38], AggregatorLib.q_mod);
buf[40] = mulmod(buf[33], buf[24], AggregatorLib.q_mod);
buf[23] = addmod(mulmod(buf[20], buf[33], AggregatorLib.q_mod), AggregatorLib.q_mod - mulmod(buf[23], buf[40], AggregatorLib.q_mod), AggregatorLib.q_mod);
buf[33] = mulmod(buf[35], buf[24], AggregatorLib.q_mod);
buf[26] = addmod(mulmod(buf[30], buf[35], AggregatorLib.q_mod), AggregatorLib.q_mod - mulmod(buf[26], buf[33], AggregatorLib.q_mod), AggregatorLib.q_mod);
buf[35] = AggregatorLib.q_mod - mulmod(buf[37], buf[6], AggregatorLib.q_mod);
buf[41] = mulmod(buf[38], buf[19], AggregatorLib.q_mod);
buf[37] = addmod(mulmod(buf[35], buf[38], AggregatorLib.q_mod), AggregatorLib.q_mod - mulmod(buf[37], buf[41], AggregatorLib.q_mod), AggregatorLib.q_mod);
buf[38] = addmod(mulmod(addmod(addmod(mulmod(buf[34], transcript[50], AggregatorLib.q_mod), mulmod(buf[36], transcript[63], AggregatorLib.q_mod), AggregatorLib.q_mod), mulmod(buf[39], transcript[65], AggregatorLib.q_mod), AggregatorLib.q_mod), buf[9], AggregatorLib.q_mod), addmod(addmod(mulmod(buf[23], transcript[50], AggregatorLib.q_mod), mulmod(buf[26], transcript[63], AggregatorLib.q_mod), AggregatorLib.q_mod), mulmod(buf[37], transcript[65], AggregatorLib.q_mod), AggregatorLib.q_mod), AggregatorLib.q_mod);
buf[20] = AggregatorLib.q_mod - mulmod(buf[20], buf[40], AggregatorLib.q_mod);
buf[30] = AggregatorLib.q_mod - mulmod(buf[30], buf[33], AggregatorLib.q_mod);
buf[33] = AggregatorLib.q_mod - mulmod(buf[35], buf[41], AggregatorLib.q_mod);
buf[35] = mulmod(buf[7], addmod(mulmod(buf[38], buf[9], AggregatorLib.q_mod), addmod(addmod(mulmod(buf[20], transcript[50], AggregatorLib.q_mod), mulmod(buf[30], transcript[63], AggregatorLib.q_mod), AggregatorLib.q_mod), mulmod(buf[33], transcript[65], AggregatorLib.q_mod), AggregatorLib.q_mod), AggregatorLib.q_mod), AggregatorLib.q_mod);
buf[38] = addmod(mulmod(addmod(addmod(mulmod(buf[34], transcript[51], AggregatorLib.q_mod), mulmod(buf[36], transcript[52], AggregatorLib.q_mod), AggregatorLib.q_mod), mulmod(buf[39], transcript[67], AggregatorLib.q_mod), AggregatorLib.q_mod), buf[9], AggregatorLib.q_mod), addmod(addmod(mulmod(buf[23], transcript[51], AggregatorLib.q_mod), mulmod(buf[26], transcript[52], AggregatorLib.q_mod), AggregatorLib.q_mod), mulmod(buf[37], transcript[67], AggregatorLib.q_mod), AggregatorLib.q_mod), AggregatorLib.q_mod);
buf[35] = addmod(buf[35], addmod(mulmod(buf[38], buf[9], AggregatorLib.q_mod), addmod(addmod(mulmod(buf[20], transcript[51], AggregatorLib.q_mod), mulmod(buf[30], transcript[52], AggregatorLib.q_mod), AggregatorLib.q_mod), mulmod(buf[33], transcript[67], AggregatorLib.q_mod), AggregatorLib.q_mod), AggregatorLib.q_mod), AggregatorLib.q_mod);
buf[28] = mulmod(mulmod(buf[17], buf[28], AggregatorLib.q_mod), buf[29], AggregatorLib.q_mod);
buf[18] = mulmod(buf[8], addmod(mulmod(buf[8], addmod(buf[18], mulmod(buf[32], buf[25], AggregatorLib.q_mod), AggregatorLib.q_mod), AggregatorLib.q_mod), mulmod(buf[35], buf[28], AggregatorLib.q_mod), AggregatorLib.q_mod), AggregatorLib.q_mod);
buf[32] = AggregatorLib.fr_div(1, addmod(buf[6], AggregatorLib.q_mod - buf[27], AggregatorLib.q_mod), aux[20]);
buf[35] = mulmod(buf[34], buf[32], AggregatorLib.q_mod);
buf[38] = AggregatorLib.fr_div(1, addmod(buf[19], AggregatorLib.q_mod - buf[27], AggregatorLib.q_mod), aux[21]);
buf[40] = mulmod(buf[36], buf[38], AggregatorLib.q_mod);
buf[41] = AggregatorLib.fr_div(1, addmod(buf[24], AggregatorLib.q_mod - buf[27], AggregatorLib.q_mod), aux[22]);
buf[42] = mulmod(buf[39], buf[41], AggregatorLib.q_mod);
buf[43] = AggregatorLib.fr_div(1, addmod(buf[27], AggregatorLib.q_mod - buf[6], AggregatorLib.q_mod), aux[23]);
buf[44] = AggregatorLib.fr_div(1, addmod(buf[27], AggregatorLib.q_mod - buf[19], AggregatorLib.q_mod), aux[24]);
buf[45] = mulmod(buf[43], buf[44], AggregatorLib.q_mod);
buf[46] = AggregatorLib.fr_div(1, addmod(buf[27], AggregatorLib.q_mod - buf[24], AggregatorLib.q_mod), aux[25]);
buf[47] = mulmod(buf[45], buf[46], AggregatorLib.q_mod);
buf[48] = mulmod(addmod(addmod(addmod(mulmod(buf[35], transcript[47], AggregatorLib.q_mod), mulmod(buf[40], transcript[62], AggregatorLib.q_mod), AggregatorLib.q_mod), mulmod(buf[42], transcript[66], AggregatorLib.q_mod), AggregatorLib.q_mod), mulmod(buf[47], transcript[68], AggregatorLib.q_mod), AggregatorLib.q_mod), buf[9], AggregatorLib.q_mod);
buf[49] = mulmod(buf[32], buf[27], AggregatorLib.q_mod);
buf[34] = addmod(mulmod(buf[23], buf[32], AggregatorLib.q_mod), AggregatorLib.q_mod - mulmod(buf[34], buf[49], AggregatorLib.q_mod), AggregatorLib.q_mod);
buf[50] = mulmod(buf[38], buf[27], AggregatorLib.q_mod);
buf[36] = addmod(mulmod(buf[26], buf[38], AggregatorLib.q_mod), AggregatorLib.q_mod - mulmod(buf[36], buf[50], AggregatorLib.q_mod), AggregatorLib.q_mod);
buf[27] = mulmod(buf[41], buf[27], AggregatorLib.q_mod);
buf[39] = addmod(mulmod(buf[37], buf[41], AggregatorLib.q_mod), AggregatorLib.q_mod - mulmod(buf[39], buf[27], AggregatorLib.q_mod), AggregatorLib.q_mod);
buf[51] = AggregatorLib.q_mod - mulmod(buf[43], buf[6], AggregatorLib.q_mod);
buf[19] = mulmod(buf[44], buf[19], AggregatorLib.q_mod);
buf[43] = addmod(mulmod(buf[51], buf[44], AggregatorLib.q_mod), AggregatorLib.q_mod - mulmod(buf[43], buf[19], AggregatorLib.q_mod), AggregatorLib.q_mod);
buf[24] = mulmod(buf[46], buf[24], AggregatorLib.q_mod);
buf[44] = addmod(mulmod(buf[43], buf[46], AggregatorLib.q_mod), AggregatorLib.q_mod - mulmod(buf[45], buf[24], AggregatorLib.q_mod), AggregatorLib.q_mod);
buf[45] = addmod(buf[48], addmod(addmod(addmod(mulmod(buf[34], transcript[47], AggregatorLib.q_mod), mulmod(buf[36], transcript[62], AggregatorLib.q_mod), AggregatorLib.q_mod), mulmod(buf[39], transcript[66], AggregatorLib.q_mod), AggregatorLib.q_mod), mulmod(buf[44], transcript[68], AggregatorLib.q_mod), AggregatorLib.q_mod), AggregatorLib.q_mod);
buf[23] = addmod(mulmod(buf[20], buf[32], AggregatorLib.q_mod), AggregatorLib.q_mod - mulmod(buf[23], buf[49], AggregatorLib.q_mod), AggregatorLib.q_mod);
buf[26] = addmod(mulmod(buf[30], buf[38], AggregatorLib.q_mod), AggregatorLib.q_mod - mulmod(buf[26], buf[50], AggregatorLib.q_mod), AggregatorLib.q_mod);
buf[32] = addmod(mulmod(buf[33], buf[41], AggregatorLib.q_mod), AggregatorLib.q_mod - mulmod(buf[37], buf[27], AggregatorLib.q_mod), AggregatorLib.q_mod);
buf[19] = AggregatorLib.q_mod - mulmod(buf[51], buf[19], AggregatorLib.q_mod);
buf[37] = addmod(mulmod(buf[19], buf[46], AggregatorLib.q_mod), AggregatorLib.q_mod - mulmod(buf[43], buf[24], AggregatorLib.q_mod), AggregatorLib.q_mod);
buf[38] = addmod(mulmod(buf[45], buf[9], AggregatorLib.q_mod), addmod(addmod(addmod(mulmod(buf[23], transcript[47], AggregatorLib.q_mod), mulmod(buf[26], transcript[62], AggregatorLib.q_mod), AggregatorLib.q_mod), mulmod(buf[32], transcript[66], AggregatorLib.q_mod), AggregatorLib.q_mod), mulmod(buf[37], transcript[68], AggregatorLib.q_mod), AggregatorLib.q_mod), AggregatorLib.q_mod);
buf[20] = AggregatorLib.q_mod - mulmod(buf[20], buf[49], AggregatorLib.q_mod);
buf[30] = AggregatorLib.q_mod - mulmod(buf[30], buf[50], AggregatorLib.q_mod);
buf[27] = AggregatorLib.q_mod - mulmod(buf[33], buf[27], AggregatorLib.q_mod);
buf[19] = AggregatorLib.q_mod - mulmod(buf[19], buf[24], AggregatorLib.q_mod);
buf[24] = addmod(mulmod(buf[38], buf[9], AggregatorLib.q_mod), addmod(addmod(addmod(mulmod(buf[20], transcript[47], AggregatorLib.q_mod), mulmod(buf[30], transcript[62], AggregatorLib.q_mod), AggregatorLib.q_mod), mulmod(buf[27], transcript[66], AggregatorLib.q_mod), AggregatorLib.q_mod), mulmod(buf[19], transcript[68], AggregatorLib.q_mod), AggregatorLib.q_mod), AggregatorLib.q_mod);
buf[33] = mulmod(addmod(addmod(addmod(mulmod(buf[35], transcript[48], AggregatorLib.q_mod), mulmod(buf[40], transcript[60], AggregatorLib.q_mod), AggregatorLib.q_mod), mulmod(buf[42], transcript[69], AggregatorLib.q_mod), AggregatorLib.q_mod), mulmod(buf[47], transcript[70], AggregatorLib.q_mod), AggregatorLib.q_mod), buf[9], AggregatorLib.q_mod);
buf[33] = addmod(buf[33], addmod(addmod(addmod(mulmod(buf[34], transcript[48], AggregatorLib.q_mod), mulmod(buf[36], transcript[60], AggregatorLib.q_mod), AggregatorLib.q_mod), mulmod(buf[39], transcript[69], AggregatorLib.q_mod), AggregatorLib.q_mod), mulmod(buf[44], transcript[70], AggregatorLib.q_mod), AggregatorLib.q_mod), AggregatorLib.q_mod);
buf[33] = addmod(mulmod(buf[33], buf[9], AggregatorLib.q_mod), addmod(addmod(addmod(mulmod(buf[23], transcript[48], AggregatorLib.q_mod), mulmod(buf[26], transcript[60], AggregatorLib.q_mod), AggregatorLib.q_mod), mulmod(buf[32], transcript[69], AggregatorLib.q_mod), AggregatorLib.q_mod), mulmod(buf[37], transcript[70], AggregatorLib.q_mod), AggregatorLib.q_mod), AggregatorLib.q_mod);
buf[33] = addmod(mulmod(buf[33], buf[9], AggregatorLib.q_mod), addmod(addmod(addmod(mulmod(buf[20], transcript[48], AggregatorLib.q_mod), mulmod(buf[30], transcript[60], AggregatorLib.q_mod), AggregatorLib.q_mod), mulmod(buf[27], transcript[69], AggregatorLib.q_mod), AggregatorLib.q_mod), mulmod(buf[19], transcript[70], AggregatorLib.q_mod), AggregatorLib.q_mod), AggregatorLib.q_mod);
buf[35] = mulmod(addmod(addmod(addmod(mulmod(buf[35], transcript[49], AggregatorLib.q_mod), mulmod(buf[40], transcript[61], AggregatorLib.q_mod), AggregatorLib.q_mod), mulmod(buf[42], transcript[64], AggregatorLib.q_mod), AggregatorLib.q_mod), mulmod(buf[47], transcript[71], AggregatorLib.q_mod), AggregatorLib.q_mod), buf[9], AggregatorLib.q_mod);


        return buf;
    }
}
