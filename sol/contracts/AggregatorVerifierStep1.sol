// SPDX-License-Identifier: MIT
// Tells the Solidity compiler to compile only from v0.8.13 to v0.9.0
pragma solidity ^0.8.13;

import "./AggregatorLib.sol";

contract AggregatorVerifierCoreStep1 {
    function verify_proof(
        uint256[] calldata transcript,
        uint256[] calldata aux,
        uint256[] memory buf
    ) public view returns (uint256[] memory)  {
        (buf[10], buf[11]) = (transcript[114], transcript[115]);
buf[12] = 1;
AggregatorLib.ecc_mul(buf, 10);
buf[17] = mulmod(10939663269433627367777756708678102241564365262857670666700619874077960926249, buf[6], AggregatorLib.q_mod);
buf[18] = AggregatorLib.fr_div(1, addmod(buf[17], AggregatorLib.q_mod - buf[6], AggregatorLib.q_mod), aux[0]);
buf[19] = mulmod(11211301017135681023579411905410872569206244553457844956874280139879520583390, buf[6], AggregatorLib.q_mod);
buf[20] = AggregatorLib.fr_div(1, addmod(buf[17], AggregatorLib.q_mod - buf[19], AggregatorLib.q_mod), aux[1]);
buf[21] = mulmod(buf[18], buf[20], AggregatorLib.q_mod);
buf[22] = AggregatorLib.fr_div(1, addmod(buf[6], AggregatorLib.q_mod - buf[17], AggregatorLib.q_mod), aux[2]);
buf[23] = AggregatorLib.fr_div(1, addmod(buf[6], AggregatorLib.q_mod - buf[19], AggregatorLib.q_mod), aux[3]);
buf[24] = mulmod(buf[22], buf[23], AggregatorLib.q_mod);
buf[25] = AggregatorLib.fr_div(1, addmod(buf[19], AggregatorLib.q_mod - buf[17], AggregatorLib.q_mod), aux[4]);
buf[26] = AggregatorLib.fr_div(1, addmod(buf[19], AggregatorLib.q_mod - buf[6], AggregatorLib.q_mod), aux[5]);
buf[27] = mulmod(buf[25], buf[26], AggregatorLib.q_mod);
buf[28] = AggregatorLib.q_mod - mulmod(buf[18], buf[6], AggregatorLib.q_mod);
buf[29] = mulmod(buf[20], buf[19], AggregatorLib.q_mod);
buf[18] = addmod(mulmod(buf[28], buf[20], AggregatorLib.q_mod), AggregatorLib.q_mod - mulmod(buf[18], buf[29], AggregatorLib.q_mod), AggregatorLib.q_mod);
buf[20] = AggregatorLib.q_mod - mulmod(buf[22], buf[17], AggregatorLib.q_mod);
buf[30] = mulmod(buf[23], buf[19], AggregatorLib.q_mod);
buf[22] = addmod(mulmod(buf[20], buf[23], AggregatorLib.q_mod), AggregatorLib.q_mod - mulmod(buf[22], buf[30], AggregatorLib.q_mod), AggregatorLib.q_mod);
buf[31] = AggregatorLib.q_mod - mulmod(buf[25], buf[17], AggregatorLib.q_mod);
buf[32] = mulmod(buf[26], buf[6], AggregatorLib.q_mod);
buf[25] = addmod(mulmod(buf[31], buf[26], AggregatorLib.q_mod), AggregatorLib.q_mod - mulmod(buf[25], buf[32], AggregatorLib.q_mod), AggregatorLib.q_mod);
buf[33] = addmod(mulmod(addmod(addmod(mulmod(buf[21], transcript[91], AggregatorLib.q_mod), mulmod(buf[24], transcript[89], AggregatorLib.q_mod), AggregatorLib.q_mod), mulmod(buf[27], transcript[90], AggregatorLib.q_mod), AggregatorLib.q_mod), buf[9], AggregatorLib.q_mod), addmod(addmod(mulmod(buf[18], transcript[91], AggregatorLib.q_mod), mulmod(buf[22], transcript[89], AggregatorLib.q_mod), AggregatorLib.q_mod), mulmod(buf[25], transcript[90], AggregatorLib.q_mod), AggregatorLib.q_mod), AggregatorLib.q_mod);
buf[28] = AggregatorLib.q_mod - mulmod(buf[28], buf[29], AggregatorLib.q_mod);
buf[20] = AggregatorLib.q_mod - mulmod(buf[20], buf[30], AggregatorLib.q_mod);
buf[29] = AggregatorLib.q_mod - mulmod(buf[31], buf[32], AggregatorLib.q_mod);
buf[31] = mulmod(buf[7], addmod(mulmod(buf[33], buf[9], AggregatorLib.q_mod), addmod(addmod(mulmod(buf[28], transcript[91], AggregatorLib.q_mod), mulmod(buf[20], transcript[89], AggregatorLib.q_mod), AggregatorLib.q_mod), mulmod(buf[29], transcript[90], AggregatorLib.q_mod), AggregatorLib.q_mod), AggregatorLib.q_mod), AggregatorLib.q_mod);
buf[33] = addmod(mulmod(addmod(addmod(mulmod(buf[21], transcript[94], AggregatorLib.q_mod), mulmod(buf[24], transcript[92], AggregatorLib.q_mod), AggregatorLib.q_mod), mulmod(buf[27], transcript[93], AggregatorLib.q_mod), AggregatorLib.q_mod), buf[9], AggregatorLib.q_mod), addmod(addmod(mulmod(buf[18], transcript[94], AggregatorLib.q_mod), mulmod(buf[22], transcript[92], AggregatorLib.q_mod), AggregatorLib.q_mod), mulmod(buf[25], transcript[93], AggregatorLib.q_mod), AggregatorLib.q_mod), AggregatorLib.q_mod);
buf[31] = addmod(buf[31], addmod(mulmod(buf[33], buf[9], AggregatorLib.q_mod), addmod(addmod(mulmod(buf[28], transcript[94], AggregatorLib.q_mod), mulmod(buf[20], transcript[92], AggregatorLib.q_mod), AggregatorLib.q_mod), mulmod(buf[29], transcript[93], AggregatorLib.q_mod), AggregatorLib.q_mod), AggregatorLib.q_mod), AggregatorLib.q_mod);
buf[33] = addmod(mulmod(addmod(addmod(mulmod(buf[21], transcript[97], AggregatorLib.q_mod), mulmod(buf[24], transcript[95], AggregatorLib.q_mod), AggregatorLib.q_mod), mulmod(buf[27], transcript[96], AggregatorLib.q_mod), AggregatorLib.q_mod), buf[9], AggregatorLib.q_mod), addmod(addmod(mulmod(buf[18], transcript[97], AggregatorLib.q_mod), mulmod(buf[22], transcript[95], AggregatorLib.q_mod), AggregatorLib.q_mod), mulmod(buf[25], transcript[96], AggregatorLib.q_mod), AggregatorLib.q_mod), AggregatorLib.q_mod);
buf[31] = addmod(mulmod(buf[7], buf[31], AggregatorLib.q_mod), addmod(mulmod(buf[33], buf[9], AggregatorLib.q_mod), addmod(addmod(mulmod(buf[28], transcript[97], AggregatorLib.q_mod), mulmod(buf[20], transcript[95], AggregatorLib.q_mod), AggregatorLib.q_mod), mulmod(buf[29], transcript[96], AggregatorLib.q_mod), AggregatorLib.q_mod), AggregatorLib.q_mod), AggregatorLib.q_mod);
buf[33] = addmod(mulmod(addmod(addmod(mulmod(buf[21], transcript[100], AggregatorLib.q_mod), mulmod(buf[24], transcript[98], AggregatorLib.q_mod), AggregatorLib.q_mod), mulmod(buf[27], transcript[99], AggregatorLib.q_mod), AggregatorLib.q_mod), buf[9], AggregatorLib.q_mod), addmod(addmod(mulmod(buf[18], transcript[100], AggregatorLib.q_mod), mulmod(buf[22], transcript[98], AggregatorLib.q_mod), AggregatorLib.q_mod), mulmod(buf[25], transcript[99], AggregatorLib.q_mod), AggregatorLib.q_mod), AggregatorLib.q_mod);
buf[31] = addmod(mulmod(buf[7], buf[31], AggregatorLib.q_mod), addmod(mulmod(buf[33], buf[9], AggregatorLib.q_mod), addmod(addmod(mulmod(buf[28], transcript[100], AggregatorLib.q_mod), mulmod(buf[20], transcript[98], AggregatorLib.q_mod), AggregatorLib.q_mod), mulmod(buf[29], transcript[99], AggregatorLib.q_mod), AggregatorLib.q_mod), AggregatorLib.q_mod), AggregatorLib.q_mod);
buf[18] = addmod(mulmod(addmod(addmod(mulmod(buf[21], transcript[109], AggregatorLib.q_mod), mulmod(buf[24], transcript[107], AggregatorLib.q_mod), AggregatorLib.q_mod), mulmod(buf[27], transcript[108], AggregatorLib.q_mod), AggregatorLib.q_mod), buf[9], AggregatorLib.q_mod), addmod(addmod(mulmod(buf[18], transcript[109], AggregatorLib.q_mod), mulmod(buf[22], transcript[107], AggregatorLib.q_mod), AggregatorLib.q_mod), mulmod(buf[25], transcript[108], AggregatorLib.q_mod), AggregatorLib.q_mod), AggregatorLib.q_mod);
buf[18] = addmod(mulmod(buf[7], buf[31], AggregatorLib.q_mod), addmod(mulmod(buf[18], buf[9], AggregatorLib.q_mod), addmod(addmod(mulmod(buf[28], transcript[109], AggregatorLib.q_mod), mulmod(buf[20], transcript[107], AggregatorLib.q_mod), AggregatorLib.q_mod), mulmod(buf[29], transcript[108], AggregatorLib.q_mod), AggregatorLib.q_mod), AggregatorLib.q_mod), AggregatorLib.q_mod);
buf[20] = mulmod(buf[7], addmod(mulmod(buf[7], addmod(mulmod(buf[7], transcript[48], AggregatorLib.q_mod), transcript[49], AggregatorLib.q_mod), AggregatorLib.q_mod), transcript[50], AggregatorLib.q_mod), AggregatorLib.q_mod);
buf[20] = addmod(mulmod(buf[7], addmod(mulmod(buf[7], addmod(buf[20], transcript[51], AggregatorLib.q_mod), AggregatorLib.q_mod), transcript[52], AggregatorLib.q_mod), AggregatorLib.q_mod), transcript[55], AggregatorLib.q_mod);
buf[20] = mulmod(buf[7], addmod(mulmod(buf[7], addmod(mulmod(buf[7], buf[20], AggregatorLib.q_mod), transcript[62], AggregatorLib.q_mod), AggregatorLib.q_mod), transcript[63], AggregatorLib.q_mod), AggregatorLib.q_mod);
buf[20] = addmod(mulmod(buf[7], addmod(mulmod(buf[7], addmod(buf[20], transcript[103], AggregatorLib.q_mod), AggregatorLib.q_mod), transcript[106], AggregatorLib.q_mod), AggregatorLib.q_mod), transcript[64], AggregatorLib.q_mod);
buf[20] = mulmod(buf[7], addmod(mulmod(buf[7], addmod(mulmod(buf[7], buf[20], AggregatorLib.q_mod), transcript[65], AggregatorLib.q_mod), AggregatorLib.q_mod), transcript[66], AggregatorLib.q_mod), AggregatorLib.q_mod);
buf[20] = addmod(mulmod(buf[7], addmod(mulmod(buf[7], addmod(buf[20], transcript[67], AggregatorLib.q_mod), AggregatorLib.q_mod), transcript[68], AggregatorLib.q_mod), AggregatorLib.q_mod), transcript[69], AggregatorLib.q_mod);
buf[20] = mulmod(buf[7], addmod(mulmod(buf[7], addmod(mulmod(buf[7], buf[20], AggregatorLib.q_mod), transcript[70], AggregatorLib.q_mod), AggregatorLib.q_mod), transcript[71], AggregatorLib.q_mod), AggregatorLib.q_mod);
buf[20] = addmod(mulmod(buf[7], addmod(mulmod(buf[7], addmod(buf[20], transcript[72], AggregatorLib.q_mod), AggregatorLib.q_mod), transcript[73], AggregatorLib.q_mod), AggregatorLib.q_mod), transcript[74], AggregatorLib.q_mod);
buf[20] = mulmod(buf[7], addmod(mulmod(buf[7], addmod(mulmod(buf[7], buf[20], AggregatorLib.q_mod), transcript[75], AggregatorLib.q_mod), AggregatorLib.q_mod), transcript[76], AggregatorLib.q_mod), AggregatorLib.q_mod);
buf[20] = addmod(mulmod(buf[7], addmod(mulmod(buf[7], addmod(buf[20], transcript[77], AggregatorLib.q_mod), AggregatorLib.q_mod), transcript[78], AggregatorLib.q_mod), AggregatorLib.q_mod), transcript[80], AggregatorLib.q_mod);
buf[20] = mulmod(buf[7], addmod(mulmod(buf[7], addmod(mulmod(buf[7], buf[20], AggregatorLib.q_mod), transcript[81], AggregatorLib.q_mod), AggregatorLib.q_mod), transcript[82], AggregatorLib.q_mod), AggregatorLib.q_mod);
buf[20] = addmod(mulmod(buf[7], addmod(mulmod(buf[7], addmod(buf[20], transcript[83], AggregatorLib.q_mod), AggregatorLib.q_mod), transcript[84], AggregatorLib.q_mod), AggregatorLib.q_mod), transcript[85], AggregatorLib.q_mod);
buf[20] = mulmod(buf[7], addmod(mulmod(buf[7], addmod(mulmod(buf[7], buf[20], AggregatorLib.q_mod), transcript[86], AggregatorLib.q_mod), AggregatorLib.q_mod), transcript[87], AggregatorLib.q_mod), AggregatorLib.q_mod);
buf[21] = addmod(addmod(addmod(addmod(transcript[64], mulmod(transcript[54], transcript[65], AggregatorLib.q_mod), AggregatorLib.q_mod), mulmod(transcript[49], transcript[66], AggregatorLib.q_mod), AggregatorLib.q_mod), mulmod(transcript[50], transcript[67], AggregatorLib.q_mod), AggregatorLib.q_mod), mulmod(transcript[51], transcript[68], AggregatorLib.q_mod), AggregatorLib.q_mod);
buf[21] = addmod(addmod(addmod(addmod(buf[21], mulmod(transcript[52], transcript[69], AggregatorLib.q_mod), AggregatorLib.q_mod), mulmod(transcript[53], transcript[70], AggregatorLib.q_mod), AggregatorLib.q_mod), mulmod(mulmod(transcript[49], transcript[50], AggregatorLib.q_mod), transcript[71], AggregatorLib.q_mod), AggregatorLib.q_mod), mulmod(mulmod(transcript[51], transcript[52], AggregatorLib.q_mod), transcript[72], AggregatorLib.q_mod), AggregatorLib.q_mod);
buf[22] = addmod(transcript[76], 21888242871839275222246405745257275088548364400416034343698204186575808495615, AggregatorLib.q_mod);
buf[24] = addmod(transcript[76], 21888242871839275222246405745257275088548364400416034343698204186575808495614, AggregatorLib.q_mod);
buf[25] = mulmod(mulmod(mulmod(addmod(transcript[55], AggregatorLib.q_mod - transcript[56], AggregatorLib.q_mod), transcript[76], AggregatorLib.q_mod), buf[22], AggregatorLib.q_mod), buf[24], AggregatorLib.q_mod);
buf[27] = addmod(addmod(transcript[55], AggregatorLib.q_mod - transcript[57], AggregatorLib.q_mod), AggregatorLib.q_mod - mulmod(transcript[58], 262144, AggregatorLib.q_mod), AggregatorLib.q_mod);
buf[28] = mulmod(addmod(addmod(buf[27], AggregatorLib.q_mod - mulmod(transcript[56], 68719476736, AggregatorLib.q_mod), AggregatorLib.q_mod), AggregatorLib.q_mod - mulmod(transcript[59], 18014398509481984, AggregatorLib.q_mod), AggregatorLib.q_mod), transcript[76], AggregatorLib.q_mod);
buf[29] = addmod(transcript[76], 21888242871839275222246405745257275088548364400416034343698204186575808495616, AggregatorLib.q_mod);
buf[21] = mulmod(addmod(mulmod(addmod(mulmod(buf[21], buf[5], AggregatorLib.q_mod), buf[25], AggregatorLib.q_mod), buf[5], AggregatorLib.q_mod), mulmod(mulmod(buf[28], buf[29], AggregatorLib.q_mod), buf[24], AggregatorLib.q_mod), AggregatorLib.q_mod), buf[5], AggregatorLib.q_mod);
buf[24] = addmod(addmod(addmod(buf[27], AggregatorLib.q_mod - mulmod(transcript[60], 68719476736, AggregatorLib.q_mod), AggregatorLib.q_mod), AggregatorLib.q_mod - mulmod(transcript[56], 18014398509481984, AggregatorLib.q_mod), AggregatorLib.q_mod), AggregatorLib.q_mod - mulmod(transcript[59], 4722366482869645213696, AggregatorLib.q_mod), AggregatorLib.q_mod);
buf[24] = mulmod(mulmod(addmod(buf[24], AggregatorLib.q_mod - mulmod(transcript[61], 1237940039285380274899124224, AggregatorLib.q_mod), AggregatorLib.q_mod), transcript[76], AggregatorLib.q_mod), buf[29], AggregatorLib.q_mod);
buf[25] = AggregatorLib.fr_pow(buf[6], 4194304);
buf[27] = addmod(buf[25], AggregatorLib.q_mod - 1, AggregatorLib.q_mod);
buf[28] = AggregatorLib.fr_div(mulmod(21888237653275510688422624196183639687472264873923820041627027729598873448513, buf[27], AggregatorLib.q_mod), addmod(buf[6], AggregatorLib.q_mod - 1, AggregatorLib.q_mod), aux[6]);
buf[21] = mulmod(addmod(mulmod(addmod(buf[21], mulmod(buf[24], buf[22], AggregatorLib.q_mod), AggregatorLib.q_mod), buf[5], AggregatorLib.q_mod), mulmod(buf[28], addmod(1, AggregatorLib.q_mod - transcript[89], AggregatorLib.q_mod), AggregatorLib.q_mod), AggregatorLib.q_mod), buf[5], AggregatorLib.q_mod);
buf[22] = AggregatorLib.fr_div(mulmod(20023042075029862075635603136649050502962424708267292886390647475108663608857, buf[27], AggregatorLib.q_mod), addmod(buf[6], AggregatorLib.q_mod - 10939663269433627367777756708678102241564365262857670666700619874077960926249, AggregatorLib.q_mod), aux[7]);
buf[21] = mulmod(addmod(buf[21], mulmod(buf[22], addmod(mulmod(transcript[101], transcript[101], AggregatorLib.q_mod), AggregatorLib.q_mod - transcript[101], AggregatorLib.q_mod), AggregatorLib.q_mod), AggregatorLib.q_mod), buf[5], AggregatorLib.q_mod);
buf[21] = addmod(mulmod(addmod(buf[21], mulmod(addmod(transcript[92], AggregatorLib.q_mod - transcript[91], AggregatorLib.q_mod), buf[28], AggregatorLib.q_mod), AggregatorLib.q_mod), buf[5], AggregatorLib.q_mod), mulmod(addmod(transcript[95], AggregatorLib.q_mod - transcript[94], AggregatorLib.q_mod), buf[28], AggregatorLib.q_mod), AggregatorLib.q_mod);
buf[21] = addmod(mulmod(addmod(mulmod(buf[21], buf[5], AggregatorLib.q_mod), mulmod(addmod(transcript[98], AggregatorLib.q_mod - transcript[97], AggregatorLib.q_mod), buf[28], AggregatorLib.q_mod), AggregatorLib.q_mod), buf[5], AggregatorLib.q_mod), mulmod(addmod(transcript[101], AggregatorLib.q_mod - transcript[100], AggregatorLib.q_mod), buf[28], AggregatorLib.q_mod), AggregatorLib.q_mod);
buf[24] = addmod(transcript[50], buf[4], AggregatorLib.q_mod);
buf[29] = addmod(transcript[49], buf[4], AggregatorLib.q_mod);
buf[31] = mulmod(buf[3], buf[6], AggregatorLib.q_mod);
buf[24] = addmod(mulmod(addmod(buf[24], mulmod(buf[3], transcript[81], AggregatorLib.q_mod), AggregatorLib.q_mod), mulmod(addmod(buf[29], mulmod(buf[3], transcript[80], AggregatorLib.q_mod), AggregatorLib.q_mod), transcript[90], AggregatorLib.q_mod), AggregatorLib.q_mod), AggregatorLib.q_mod - mulmod(addmod(buf[24], mulmod(4131629893567559867359510883348571134090853742863529169391034518566172092834, buf[31], AggregatorLib.q_mod), AggregatorLib.q_mod), mulmod(addmod(buf[29], buf[31], AggregatorLib.q_mod), transcript[89], AggregatorLib.q_mod), AggregatorLib.q_mod), AggregatorLib.q_mod);
buf[29] = addmod(addmod(addmod(AggregatorLib.fr_div(mulmod(496209762031177553439375370250532367801224970379575774747024844773905018536, buf[27], AggregatorLib.q_mod), addmod(buf[6], AggregatorLib.q_mod - 11016257578652593686382655500910603527869149377564754001549454008164059876499, AggregatorLib.q_mod), aux[8]), AggregatorLib.fr_div(mulmod(20459617746544248062014976317203465365908990827508925305769002868034509119086, buf[27], AggregatorLib.q_mod), addmod(buf[6], AggregatorLib.q_mod - 15402826414547299628414612080036060696555554914079673875872749760617770134879, AggregatorLib.q_mod), aux[9]), AggregatorLib.q_mod), AggregatorLib.fr_div(mulmod(9952375098572582562392692839581731570430874250722926349774599560449354965478, buf[27], AggregatorLib.q_mod), addmod(buf[6], AggregatorLib.q_mod - 21710372849001950800533397158415938114909991150039389063546734567764856596059, AggregatorLib.q_mod), aux[10]), AggregatorLib.q_mod), AggregatorLib.fr_div(mulmod(2475562068482919789434538161456555368473369493180072113639899532770322825977, buf[27], AggregatorLib.q_mod), addmod(buf[6], AggregatorLib.q_mod - 2785514556381676080176937710880804108647911392478702105860685610379369825016, AggregatorLib.q_mod), aux[11]), AggregatorLib.q_mod);
buf[29] = addmod(1, AggregatorLib.q_mod - addmod(buf[22], addmod(buf[29], AggregatorLib.fr_div(mulmod(12919475148704033459056799975164749366765443418491560826543287262494049147445, buf[27], AggregatorLib.q_mod), addmod(buf[6], AggregatorLib.q_mod - 8734126352828345679573237859165904705806588461301144420590422589042130041188, AggregatorLib.q_mod), aux[12]), AggregatorLib.q_mod), AggregatorLib.q_mod), AggregatorLib.q_mod);
buf[33] = addmod(transcript[52], buf[4], AggregatorLib.q_mod);
buf[34] = addmod(transcript[51], buf[4], AggregatorLib.q_mod);
buf[35] = AggregatorLib.fr_pow(4131629893567559867359510883348571134090853742863529169391034518566172092834, 2);
buf[35] = mulmod(buf[31], buf[35], AggregatorLib.q_mod);
buf[33] = addmod(mulmod(addmod(buf[33], mulmod(buf[3], transcript[83], AggregatorLib.q_mod), AggregatorLib.q_mod), mulmod(addmod(buf[34], mulmod(buf[3], transcript[82], AggregatorLib.q_mod), AggregatorLib.q_mod), transcript[93], AggregatorLib.q_mod), AggregatorLib.q_mod), AggregatorLib.q_mod - mulmod(addmod(buf[33], mulmod(4131629893567559867359510883348571134090853742863529169391034518566172092834, buf[35], AggregatorLib.q_mod), AggregatorLib.q_mod), mulmod(addmod(buf[34], buf[35], AggregatorLib.q_mod), transcript[92], AggregatorLib.q_mod), AggregatorLib.q_mod), AggregatorLib.q_mod);
buf[21] = mulmod(addmod(mulmod(addmod(mulmod(buf[21], buf[5], AggregatorLib.q_mod), mulmod(buf[24], buf[29], AggregatorLib.q_mod), AggregatorLib.q_mod), buf[5], AggregatorLib.q_mod), mulmod(buf[33], buf[29], AggregatorLib.q_mod), AggregatorLib.q_mod), buf[5], AggregatorLib.q_mod);
buf[24] = addmod(transcript[55], buf[4], AggregatorLib.q_mod);
buf[33] = addmod(transcript[53], buf[4], AggregatorLib.q_mod);
buf[34] = AggregatorLib.fr_pow(4131629893567559867359510883348571134090853742863529169391034518566172092834, 4);
buf[34] = mulmod(buf[31], buf[34], AggregatorLib.q_mod);
buf[24] = addmod(mulmod(addmod(buf[24], mulmod(buf[3], transcript[85], AggregatorLib.q_mod), AggregatorLib.q_mod), mulmod(addmod(buf[33], mulmod(buf[3], transcript[84], AggregatorLib.q_mod), AggregatorLib.q_mod), transcript[96], AggregatorLib.q_mod), AggregatorLib.q_mod), AggregatorLib.q_mod - mulmod(addmod(buf[24], mulmod(4131629893567559867359510883348571134090853742863529169391034518566172092834, buf[34], AggregatorLib.q_mod), AggregatorLib.q_mod), mulmod(addmod(buf[33], buf[34], AggregatorLib.q_mod), transcript[95], AggregatorLib.q_mod), AggregatorLib.q_mod), AggregatorLib.q_mod);
buf[33] = addmod(transcript[63], buf[4], AggregatorLib.q_mod);
buf[34] = addmod(transcript[62], buf[4], AggregatorLib.q_mod);
buf[35] = AggregatorLib.fr_pow(4131629893567559867359510883348571134090853742863529169391034518566172092834, 6);
buf[35] = mulmod(buf[31], buf[35], AggregatorLib.q_mod);
buf[33] = addmod(mulmod(addmod(buf[33], mulmod(buf[3], transcript[87], AggregatorLib.q_mod), AggregatorLib.q_mod), mulmod(addmod(buf[34], mulmod(buf[3], transcript[86], AggregatorLib.q_mod), AggregatorLib.q_mod), transcript[99], AggregatorLib.q_mod), AggregatorLib.q_mod), AggregatorLib.q_mod - mulmod(addmod(buf[33], mulmod(4131629893567559867359510883348571134090853742863529169391034518566172092834, buf[35], AggregatorLib.q_mod), AggregatorLib.q_mod), mulmod(addmod(buf[34], buf[35], AggregatorLib.q_mod), transcript[98], AggregatorLib.q_mod), AggregatorLib.q_mod), AggregatorLib.q_mod);
buf[21] = mulmod(addmod(mulmod(addmod(buf[21], mulmod(buf[24], buf[29], AggregatorLib.q_mod), AggregatorLib.q_mod), buf[5], AggregatorLib.q_mod), mulmod(buf[33], buf[29], AggregatorLib.q_mod), AggregatorLib.q_mod), buf[5], AggregatorLib.q_mod);
buf[24] = addmod(transcript[48], buf[4], AggregatorLib.q_mod);
buf[33] = AggregatorLib.fr_pow(4131629893567559867359510883348571134090853742863529169391034518566172092834, 8);
buf[24] = mulmod(addmod(mulmod(addmod(buf[24], mulmod(buf[3], transcript[88], AggregatorLib.q_mod), AggregatorLib.q_mod), transcript[102], AggregatorLib.q_mod), AggregatorLib.q_mod - mulmod(addmod(buf[24], mulmod(buf[31], buf[33], AggregatorLib.q_mod), AggregatorLib.q_mod), transcript[101], AggregatorLib.q_mod), AggregatorLib.q_mod), buf[29], AggregatorLib.q_mod);
buf[21] = addmod(mulmod(addmod(mulmod(addmod(buf[21], buf[24], AggregatorLib.q_mod), buf[5], AggregatorLib.q_mod), mulmod(buf[28], transcript[104], AggregatorLib.q_mod), AggregatorLib.q_mod), buf[5], AggregatorLib.q_mod), mulmod(buf[22], transcript[104], AggregatorLib.q_mod), AggregatorLib.q_mod);
buf[24] = mulmod(transcript[62], buf[2], AggregatorLib.q_mod);
buf[31] = addmod(addmod(mulmod(addmod(buf[24], transcript[77], AggregatorLib.q_mod), buf[2], AggregatorLib.q_mod), transcript[78], AggregatorLib.q_mod), buf[3], AggregatorLib.q_mod);
buf[24] = addmod(mulmod(addmod(buf[24], addmod(mulmod(340282366920938463463374607431768211456, transcript[63], AggregatorLib.q_mod), transcript[77], AggregatorLib.q_mod), AggregatorLib.q_mod), buf[2], AggregatorLib.q_mod), buf[3], AggregatorLib.q_mod);
buf[24] = addmod(mulmod(addmod(mulmod(buf[31], addmod(transcript[105], AggregatorLib.q_mod - transcript[104], AggregatorLib.q_mod), AggregatorLib.q_mod), transcript[103], AggregatorLib.q_mod), buf[24], AggregatorLib.q_mod), AggregatorLib.q_mod - buf[31], AggregatorLib.q_mod);


        return buf;
    }
}
