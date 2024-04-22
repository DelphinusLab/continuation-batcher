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
        (buf[10], buf[11]) = (transcript[128], transcript[129]);
buf[12] = 1;
AggregatorLib.ecc_mul(buf, 10);
buf[17] = mulmod(21710372849001950800533397158415938114909991150039389063546734567764856596059, buf[6], AggregatorLib.q_mod);
buf[18] = AggregatorLib.fr_div(1, addmod(buf[17], AggregatorLib.q_mod - buf[6], AggregatorLib.q_mod), aux[0]);
buf[19] = mulmod(8374374965308410102411073611984011876711565317741801500439755773472076597347, buf[6], AggregatorLib.q_mod);
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
buf[33] = addmod(mulmod(addmod(addmod(mulmod(buf[21], transcript[99], AggregatorLib.q_mod), mulmod(buf[24], transcript[97], AggregatorLib.q_mod), AggregatorLib.q_mod), mulmod(buf[27], transcript[98], AggregatorLib.q_mod), AggregatorLib.q_mod), buf[9], AggregatorLib.q_mod), addmod(addmod(mulmod(buf[18], transcript[99], AggregatorLib.q_mod), mulmod(buf[22], transcript[97], AggregatorLib.q_mod), AggregatorLib.q_mod), mulmod(buf[25], transcript[98], AggregatorLib.q_mod), AggregatorLib.q_mod), AggregatorLib.q_mod);
buf[28] = AggregatorLib.q_mod - mulmod(buf[28], buf[29], AggregatorLib.q_mod);
buf[20] = AggregatorLib.q_mod - mulmod(buf[20], buf[30], AggregatorLib.q_mod);
buf[29] = AggregatorLib.q_mod - mulmod(buf[31], buf[32], AggregatorLib.q_mod);
buf[31] = mulmod(buf[7], addmod(mulmod(buf[33], buf[9], AggregatorLib.q_mod), addmod(addmod(mulmod(buf[28], transcript[99], AggregatorLib.q_mod), mulmod(buf[20], transcript[97], AggregatorLib.q_mod), AggregatorLib.q_mod), mulmod(buf[29], transcript[98], AggregatorLib.q_mod), AggregatorLib.q_mod), AggregatorLib.q_mod), AggregatorLib.q_mod);
buf[33] = addmod(mulmod(addmod(addmod(mulmod(buf[21], transcript[102], AggregatorLib.q_mod), mulmod(buf[24], transcript[100], AggregatorLib.q_mod), AggregatorLib.q_mod), mulmod(buf[27], transcript[101], AggregatorLib.q_mod), AggregatorLib.q_mod), buf[9], AggregatorLib.q_mod), addmod(addmod(mulmod(buf[18], transcript[102], AggregatorLib.q_mod), mulmod(buf[22], transcript[100], AggregatorLib.q_mod), AggregatorLib.q_mod), mulmod(buf[25], transcript[101], AggregatorLib.q_mod), AggregatorLib.q_mod), AggregatorLib.q_mod);
buf[31] = addmod(buf[31], addmod(mulmod(buf[33], buf[9], AggregatorLib.q_mod), addmod(addmod(mulmod(buf[28], transcript[102], AggregatorLib.q_mod), mulmod(buf[20], transcript[100], AggregatorLib.q_mod), AggregatorLib.q_mod), mulmod(buf[29], transcript[101], AggregatorLib.q_mod), AggregatorLib.q_mod), AggregatorLib.q_mod), AggregatorLib.q_mod);
buf[33] = addmod(mulmod(addmod(addmod(mulmod(buf[21], transcript[105], AggregatorLib.q_mod), mulmod(buf[24], transcript[103], AggregatorLib.q_mod), AggregatorLib.q_mod), mulmod(buf[27], transcript[104], AggregatorLib.q_mod), AggregatorLib.q_mod), buf[9], AggregatorLib.q_mod), addmod(addmod(mulmod(buf[18], transcript[105], AggregatorLib.q_mod), mulmod(buf[22], transcript[103], AggregatorLib.q_mod), AggregatorLib.q_mod), mulmod(buf[25], transcript[104], AggregatorLib.q_mod), AggregatorLib.q_mod), AggregatorLib.q_mod);
buf[31] = addmod(mulmod(buf[7], buf[31], AggregatorLib.q_mod), addmod(mulmod(buf[33], buf[9], AggregatorLib.q_mod), addmod(addmod(mulmod(buf[28], transcript[105], AggregatorLib.q_mod), mulmod(buf[20], transcript[103], AggregatorLib.q_mod), AggregatorLib.q_mod), mulmod(buf[29], transcript[104], AggregatorLib.q_mod), AggregatorLib.q_mod), AggregatorLib.q_mod), AggregatorLib.q_mod);
buf[18] = addmod(mulmod(addmod(addmod(mulmod(buf[21], transcript[108], AggregatorLib.q_mod), mulmod(buf[24], transcript[106], AggregatorLib.q_mod), AggregatorLib.q_mod), mulmod(buf[27], transcript[107], AggregatorLib.q_mod), AggregatorLib.q_mod), buf[9], AggregatorLib.q_mod), addmod(addmod(mulmod(buf[18], transcript[108], AggregatorLib.q_mod), mulmod(buf[22], transcript[106], AggregatorLib.q_mod), AggregatorLib.q_mod), mulmod(buf[25], transcript[107], AggregatorLib.q_mod), AggregatorLib.q_mod), AggregatorLib.q_mod);
buf[18] = addmod(mulmod(buf[7], buf[31], AggregatorLib.q_mod), addmod(mulmod(buf[18], buf[9], AggregatorLib.q_mod), addmod(addmod(mulmod(buf[28], transcript[108], AggregatorLib.q_mod), mulmod(buf[20], transcript[106], AggregatorLib.q_mod), AggregatorLib.q_mod), mulmod(buf[29], transcript[107], AggregatorLib.q_mod), AggregatorLib.q_mod), AggregatorLib.q_mod), AggregatorLib.q_mod);
buf[20] = mulmod(9741553891420464328295280489650144566903017206473301385034033384879943874347, buf[6], AggregatorLib.q_mod);
buf[21] = AggregatorLib.fr_div(1, addmod(buf[20], AggregatorLib.q_mod - buf[6], AggregatorLib.q_mod), aux[6]);
buf[22] = AggregatorLib.fr_div(1, addmod(buf[6], AggregatorLib.q_mod - buf[20], AggregatorLib.q_mod), aux[7]);
buf[24] = AggregatorLib.q_mod - mulmod(buf[21], buf[6], AggregatorLib.q_mod);
buf[25] = AggregatorLib.q_mod - mulmod(buf[22], buf[20], AggregatorLib.q_mod);
buf[27] = mulmod(buf[7], addmod(mulmod(addmod(mulmod(buf[21], transcript[114], AggregatorLib.q_mod), mulmod(buf[22], transcript[113], AggregatorLib.q_mod), AggregatorLib.q_mod), buf[9], AggregatorLib.q_mod), addmod(mulmod(buf[24], transcript[114], AggregatorLib.q_mod), mulmod(buf[25], transcript[113], AggregatorLib.q_mod), AggregatorLib.q_mod), AggregatorLib.q_mod), AggregatorLib.q_mod);
buf[27] = addmod(buf[27], addmod(mulmod(addmod(mulmod(buf[21], transcript[119], AggregatorLib.q_mod), mulmod(buf[22], transcript[118], AggregatorLib.q_mod), AggregatorLib.q_mod), buf[9], AggregatorLib.q_mod), addmod(mulmod(buf[24], transcript[119], AggregatorLib.q_mod), mulmod(buf[25], transcript[118], AggregatorLib.q_mod), AggregatorLib.q_mod), AggregatorLib.q_mod), AggregatorLib.q_mod);
buf[21] = addmod(mulmod(buf[7], buf[27], AggregatorLib.q_mod), addmod(mulmod(addmod(mulmod(buf[21], transcript[124], AggregatorLib.q_mod), mulmod(buf[22], transcript[123], AggregatorLib.q_mod), AggregatorLib.q_mod), buf[9], AggregatorLib.q_mod), addmod(mulmod(buf[24], transcript[124], AggregatorLib.q_mod), mulmod(buf[25], transcript[123], AggregatorLib.q_mod), AggregatorLib.q_mod), AggregatorLib.q_mod), AggregatorLib.q_mod);
buf[17] = addmod(buf[9], AggregatorLib.q_mod - buf[17], AggregatorLib.q_mod);
buf[22] = addmod(buf[9], AggregatorLib.q_mod - buf[19], AggregatorLib.q_mod);
buf[24] = mulmod(11211301017135681023579411905410872569206244553457844956874280139879520583390, buf[6], AggregatorLib.q_mod);
buf[25] = addmod(buf[9], AggregatorLib.q_mod - buf[24], AggregatorLib.q_mod);
buf[20] = addmod(buf[9], AggregatorLib.q_mod - buf[20], AggregatorLib.q_mod);
buf[27] = AggregatorLib.fr_div(1, mulmod(buf[20], buf[25], AggregatorLib.q_mod), aux[8]);
buf[28] = mulmod(mulmod(mulmod(buf[17], buf[22], AggregatorLib.q_mod), buf[25], AggregatorLib.q_mod), buf[27], AggregatorLib.q_mod);
buf[29] = mulmod(buf[7], addmod(mulmod(buf[7], addmod(mulmod(buf[7], transcript[56], AggregatorLib.q_mod), transcript[57], AggregatorLib.q_mod), AggregatorLib.q_mod), transcript[58], AggregatorLib.q_mod), AggregatorLib.q_mod);
buf[29] = addmod(mulmod(buf[7], addmod(mulmod(buf[7], addmod(buf[29], transcript[59], AggregatorLib.q_mod), AggregatorLib.q_mod), transcript[60], AggregatorLib.q_mod), AggregatorLib.q_mod), transcript[63], AggregatorLib.q_mod);
buf[29] = mulmod(buf[7], addmod(mulmod(buf[7], addmod(mulmod(buf[7], buf[29], AggregatorLib.q_mod), transcript[70], AggregatorLib.q_mod), AggregatorLib.q_mod), transcript[71], AggregatorLib.q_mod), AggregatorLib.q_mod);
buf[29] = addmod(mulmod(buf[7], addmod(mulmod(buf[7], addmod(buf[29], transcript[115], AggregatorLib.q_mod), AggregatorLib.q_mod), transcript[120], AggregatorLib.q_mod), AggregatorLib.q_mod), transcript[125], AggregatorLib.q_mod);
buf[29] = mulmod(buf[7], addmod(mulmod(buf[7], addmod(mulmod(buf[7], buf[29], AggregatorLib.q_mod), transcript[72], AggregatorLib.q_mod), AggregatorLib.q_mod), transcript[73], AggregatorLib.q_mod), AggregatorLib.q_mod);
buf[29] = addmod(mulmod(buf[7], addmod(mulmod(buf[7], addmod(buf[29], transcript[74], AggregatorLib.q_mod), AggregatorLib.q_mod), transcript[75], AggregatorLib.q_mod), AggregatorLib.q_mod), transcript[76], AggregatorLib.q_mod);
buf[29] = mulmod(buf[7], addmod(mulmod(buf[7], addmod(mulmod(buf[7], buf[29], AggregatorLib.q_mod), transcript[77], AggregatorLib.q_mod), AggregatorLib.q_mod), transcript[78], AggregatorLib.q_mod), AggregatorLib.q_mod);
buf[29] = addmod(mulmod(buf[7], addmod(mulmod(buf[7], addmod(buf[29], transcript[79], AggregatorLib.q_mod), AggregatorLib.q_mod), transcript[80], AggregatorLib.q_mod), AggregatorLib.q_mod), transcript[81], AggregatorLib.q_mod);
buf[29] = mulmod(buf[7], addmod(mulmod(buf[7], addmod(mulmod(buf[7], buf[29], AggregatorLib.q_mod), transcript[82], AggregatorLib.q_mod), AggregatorLib.q_mod), transcript[83], AggregatorLib.q_mod), AggregatorLib.q_mod);
buf[29] = addmod(mulmod(buf[7], addmod(mulmod(buf[7], addmod(buf[29], transcript[84], AggregatorLib.q_mod), AggregatorLib.q_mod), transcript[85], AggregatorLib.q_mod), AggregatorLib.q_mod), transcript[86], AggregatorLib.q_mod);
buf[29] = mulmod(buf[7], addmod(mulmod(buf[7], addmod(mulmod(buf[7], buf[29], AggregatorLib.q_mod), transcript[88], AggregatorLib.q_mod), AggregatorLib.q_mod), transcript[89], AggregatorLib.q_mod), AggregatorLib.q_mod);
buf[29] = addmod(mulmod(buf[7], addmod(mulmod(buf[7], addmod(buf[29], transcript[90], AggregatorLib.q_mod), AggregatorLib.q_mod), transcript[91], AggregatorLib.q_mod), AggregatorLib.q_mod), transcript[92], AggregatorLib.q_mod);
buf[29] = mulmod(buf[7], addmod(mulmod(buf[7], addmod(mulmod(buf[7], buf[29], AggregatorLib.q_mod), transcript[93], AggregatorLib.q_mod), AggregatorLib.q_mod), transcript[94], AggregatorLib.q_mod), AggregatorLib.q_mod);
buf[31] = addmod(addmod(addmod(addmod(transcript[72], mulmod(transcript[62], transcript[73], AggregatorLib.q_mod), AggregatorLib.q_mod), mulmod(transcript[57], transcript[74], AggregatorLib.q_mod), AggregatorLib.q_mod), mulmod(transcript[58], transcript[75], AggregatorLib.q_mod), AggregatorLib.q_mod), mulmod(transcript[59], transcript[76], AggregatorLib.q_mod), AggregatorLib.q_mod);
buf[31] = addmod(addmod(addmod(addmod(buf[31], mulmod(transcript[60], transcript[77], AggregatorLib.q_mod), AggregatorLib.q_mod), mulmod(transcript[61], transcript[78], AggregatorLib.q_mod), AggregatorLib.q_mod), mulmod(mulmod(transcript[57], transcript[58], AggregatorLib.q_mod), transcript[79], AggregatorLib.q_mod), AggregatorLib.q_mod), mulmod(mulmod(transcript[59], transcript[60], AggregatorLib.q_mod), transcript[80], AggregatorLib.q_mod), AggregatorLib.q_mod);
buf[33] = addmod(transcript[84], 21888242871839275222246405745257275088548364400416034343698204186575808495615, AggregatorLib.q_mod);
buf[34] = addmod(transcript[84], 21888242871839275222246405745257275088548364400416034343698204186575808495614, AggregatorLib.q_mod);
buf[35] = mulmod(mulmod(mulmod(addmod(transcript[63], AggregatorLib.q_mod - transcript[64], AggregatorLib.q_mod), transcript[84], AggregatorLib.q_mod), buf[33], AggregatorLib.q_mod), buf[34], AggregatorLib.q_mod);
buf[36] = addmod(addmod(transcript[63], AggregatorLib.q_mod - transcript[65], AggregatorLib.q_mod), AggregatorLib.q_mod - mulmod(transcript[66], 262144, AggregatorLib.q_mod), AggregatorLib.q_mod);
buf[37] = mulmod(addmod(addmod(buf[36], AggregatorLib.q_mod - mulmod(transcript[64], 68719476736, AggregatorLib.q_mod), AggregatorLib.q_mod), AggregatorLib.q_mod - mulmod(transcript[67], 18014398509481984, AggregatorLib.q_mod), AggregatorLib.q_mod), transcript[84], AggregatorLib.q_mod);
buf[38] = addmod(transcript[84], 21888242871839275222246405745257275088548364400416034343698204186575808495616, AggregatorLib.q_mod);
buf[31] = mulmod(addmod(mulmod(addmod(mulmod(buf[31], buf[5], AggregatorLib.q_mod), buf[35], AggregatorLib.q_mod), buf[5], AggregatorLib.q_mod), mulmod(mulmod(buf[37], buf[38], AggregatorLib.q_mod), buf[34], AggregatorLib.q_mod), AggregatorLib.q_mod), buf[5], AggregatorLib.q_mod);
buf[34] = addmod(addmod(addmod(buf[36], AggregatorLib.q_mod - mulmod(transcript[68], 68719476736, AggregatorLib.q_mod), AggregatorLib.q_mod), AggregatorLib.q_mod - mulmod(transcript[64], 18014398509481984, AggregatorLib.q_mod), AggregatorLib.q_mod), AggregatorLib.q_mod - mulmod(transcript[67], 4722366482869645213696, AggregatorLib.q_mod), AggregatorLib.q_mod);
buf[34] = mulmod(mulmod(addmod(buf[34], AggregatorLib.q_mod - mulmod(transcript[69], 1237940039285380274899124224, AggregatorLib.q_mod), AggregatorLib.q_mod), transcript[84], AggregatorLib.q_mod), buf[38], AggregatorLib.q_mod);
buf[35] = AggregatorLib.fr_pow(buf[6], 8388608);
buf[36] = addmod(buf[35], AggregatorLib.q_mod - 1, AggregatorLib.q_mod);
buf[37] = AggregatorLib.fr_div(mulmod(21888240262557392955334514970720457388010314637169927192662615958087340972065, buf[36], AggregatorLib.q_mod), addmod(buf[6], AggregatorLib.q_mod - 1, AggregatorLib.q_mod), aux[9]);
buf[31] = mulmod(addmod(mulmod(addmod(buf[31], mulmod(buf[34], buf[33], AggregatorLib.q_mod), AggregatorLib.q_mod), buf[5], AggregatorLib.q_mod), mulmod(buf[37], addmod(1, AggregatorLib.q_mod - transcript[97], AggregatorLib.q_mod), AggregatorLib.q_mod), AggregatorLib.q_mod), buf[5], AggregatorLib.q_mod);
buf[33] = AggregatorLib.fr_div(mulmod(4976187549286291281196346419790865785215437125361463174887299780224677482739, buf[36], AggregatorLib.q_mod), addmod(buf[6], AggregatorLib.q_mod - 21710372849001950800533397158415938114909991150039389063546734567764856596059, AggregatorLib.q_mod), aux[10]);
buf[31] = mulmod(addmod(buf[31], mulmod(buf[33], addmod(mulmod(transcript[109], transcript[109], AggregatorLib.q_mod), AggregatorLib.q_mod - transcript[109], AggregatorLib.q_mod), AggregatorLib.q_mod), AggregatorLib.q_mod), buf[5], AggregatorLib.q_mod);
buf[31] = addmod(mulmod(addmod(buf[31], mulmod(addmod(transcript[100], AggregatorLib.q_mod - transcript[99], AggregatorLib.q_mod), buf[37], AggregatorLib.q_mod), AggregatorLib.q_mod), buf[5], AggregatorLib.q_mod), mulmod(addmod(transcript[103], AggregatorLib.q_mod - transcript[102], AggregatorLib.q_mod), buf[37], AggregatorLib.q_mod), AggregatorLib.q_mod);
buf[31] = addmod(mulmod(addmod(mulmod(buf[31], buf[5], AggregatorLib.q_mod), mulmod(addmod(transcript[106], AggregatorLib.q_mod - transcript[105], AggregatorLib.q_mod), buf[37], AggregatorLib.q_mod), AggregatorLib.q_mod), buf[5], AggregatorLib.q_mod), mulmod(addmod(transcript[109], AggregatorLib.q_mod - transcript[108], AggregatorLib.q_mod), buf[37], AggregatorLib.q_mod), AggregatorLib.q_mod);
buf[34] = addmod(transcript[58], buf[4], AggregatorLib.q_mod);
buf[38] = addmod(transcript[57], buf[4], AggregatorLib.q_mod);
buf[39] = mulmod(buf[3], buf[6], AggregatorLib.q_mod);
buf[34] = addmod(mulmod(addmod(buf[34], mulmod(buf[3], transcript[89], AggregatorLib.q_mod), AggregatorLib.q_mod), mulmod(addmod(buf[38], mulmod(buf[3], transcript[88], AggregatorLib.q_mod), AggregatorLib.q_mod), transcript[98], AggregatorLib.q_mod), AggregatorLib.q_mod), AggregatorLib.q_mod - mulmod(addmod(buf[34], mulmod(4131629893567559867359510883348571134090853742863529169391034518566172092834, buf[39], AggregatorLib.q_mod), AggregatorLib.q_mod), mulmod(addmod(buf[38], buf[39], AggregatorLib.q_mod), transcript[97], AggregatorLib.q_mod), AggregatorLib.q_mod), AggregatorLib.q_mod);
buf[38] = addmod(addmod(addmod(AggregatorLib.fr_div(mulmod(17545179510056424625657753961500172777187948487824275719647175633757629801999, buf[36], AggregatorLib.q_mod), addmod(buf[6], AggregatorLib.q_mod - 1887003188133998471169152042388914354640772748308168868301418279904560637395, AggregatorLib.q_mod), aux[11]), AggregatorLib.fr_div(mulmod(12181902470161097505840471953356915228510866946798053228669051859673065660797, buf[36], AggregatorLib.q_mod), addmod(buf[6], AggregatorLib.q_mod - 2785514556381676080176937710880804108647911392478702105860685610379369825016, AggregatorLib.q_mod), aux[12]), AggregatorLib.q_mod), AggregatorLib.fr_div(mulmod(3094683119308499972127188652296432785995218440930254516456812473854441617488, buf[36], AggregatorLib.q_mod), addmod(buf[6], AggregatorLib.q_mod - 14655294445420895451632927078981340937842238432098198055057679026789553137428, AggregatorLib.q_mod), aux[13]), AggregatorLib.q_mod), AggregatorLib.fr_div(mulmod(17403859010271654340651602860211012227656903909453797585120745724534928821531, buf[36], AggregatorLib.q_mod), addmod(buf[6], AggregatorLib.q_mod - 8734126352828345679573237859165904705806588461301144420590422589042130041188, AggregatorLib.q_mod), aux[14]), AggregatorLib.q_mod);
buf[38] = addmod(1, AggregatorLib.q_mod - addmod(buf[33], addmod(buf[38], AggregatorLib.fr_div(mulmod(7444483286096152693477325065105185543054922671492455540957072536952082259082, buf[36], AggregatorLib.q_mod), addmod(buf[6], AggregatorLib.q_mod - 9741553891420464328295280489650144566903017206473301385034033384879943874347, AggregatorLib.q_mod), aux[15]), AggregatorLib.q_mod), AggregatorLib.q_mod), AggregatorLib.q_mod);
buf[40] = addmod(transcript[60], buf[4], AggregatorLib.q_mod);
buf[41] = addmod(transcript[59], buf[4], AggregatorLib.q_mod);
buf[42] = AggregatorLib.fr_pow(4131629893567559867359510883348571134090853742863529169391034518566172092834, 2);
buf[42] = mulmod(buf[39], buf[42], AggregatorLib.q_mod);
buf[40] = addmod(mulmod(addmod(buf[40], mulmod(buf[3], transcript[91], AggregatorLib.q_mod), AggregatorLib.q_mod), mulmod(addmod(buf[41], mulmod(buf[3], transcript[90], AggregatorLib.q_mod), AggregatorLib.q_mod), transcript[101], AggregatorLib.q_mod), AggregatorLib.q_mod), AggregatorLib.q_mod - mulmod(addmod(buf[40], mulmod(4131629893567559867359510883348571134090853742863529169391034518566172092834, buf[42], AggregatorLib.q_mod), AggregatorLib.q_mod), mulmod(addmod(buf[41], buf[42], AggregatorLib.q_mod), transcript[100], AggregatorLib.q_mod), AggregatorLib.q_mod), AggregatorLib.q_mod);
buf[31] = mulmod(addmod(mulmod(addmod(mulmod(buf[31], buf[5], AggregatorLib.q_mod), mulmod(buf[34], buf[38], AggregatorLib.q_mod), AggregatorLib.q_mod), buf[5], AggregatorLib.q_mod), mulmod(buf[40], buf[38], AggregatorLib.q_mod), AggregatorLib.q_mod), buf[5], AggregatorLib.q_mod);
buf[34] = addmod(transcript[63], buf[4], AggregatorLib.q_mod);
buf[40] = addmod(transcript[61], buf[4], AggregatorLib.q_mod);
buf[41] = AggregatorLib.fr_pow(4131629893567559867359510883348571134090853742863529169391034518566172092834, 4);
buf[41] = mulmod(buf[39], buf[41], AggregatorLib.q_mod);
buf[34] = addmod(mulmod(addmod(buf[34], mulmod(buf[3], transcript[93], AggregatorLib.q_mod), AggregatorLib.q_mod), mulmod(addmod(buf[40], mulmod(buf[3], transcript[92], AggregatorLib.q_mod), AggregatorLib.q_mod), transcript[104], AggregatorLib.q_mod), AggregatorLib.q_mod), AggregatorLib.q_mod - mulmod(addmod(buf[34], mulmod(4131629893567559867359510883348571134090853742863529169391034518566172092834, buf[41], AggregatorLib.q_mod), AggregatorLib.q_mod), mulmod(addmod(buf[40], buf[41], AggregatorLib.q_mod), transcript[103], AggregatorLib.q_mod), AggregatorLib.q_mod), AggregatorLib.q_mod);
buf[40] = addmod(transcript[71], buf[4], AggregatorLib.q_mod);


        return buf;
    }
}
