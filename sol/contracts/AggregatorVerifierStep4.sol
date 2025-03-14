// SPDX-License-Identifier: MIT
// Tells the Solidity compiler to compile only from v0.8.13 to v0.9.0
pragma solidity ^0.8.13;

import "./AggregatorLib.sol";

contract AggregatorVerifierCoreStep4 {
    function verify_proof(
        uint256[] calldata transcript,
        uint256[] calldata aux,
        uint256[] memory buf
    ) public view returns (uint256[] memory)  {
        (buf[14], buf[15]) = (3485352785218733130382545172103328837021794818319892061587750343874992026690, 7631097809654549230473542512961848881196199304598008750331689483497279251726);
buf[16] = mulmod(buf[27], mulmod(buf[35], buf[7], AggregatorLib.q_mod), AggregatorLib.q_mod);
AggregatorLib.ecc_mul_add(buf, 12);
(buf[14], buf[15]) = (transcript[122], transcript[123]);
buf[16] = AggregatorLib.q_mod - mulmod(mulmod(buf[17], addmod(buf[9], AggregatorLib.q_mod - buf[6], AggregatorLib.q_mod), AggregatorLib.q_mod), buf[21], AggregatorLib.q_mod);
AggregatorLib.ecc_mul_add(buf, 12);
(buf[14], buf[15]) = (transcript[124], transcript[125]);
buf[16] = buf[9];
AggregatorLib.ecc_mul_add(buf, 12);
buf[17] = mulmod(buf[27], buf[7], AggregatorLib.q_mod);
(buf[14], buf[15]) = (transcript[44], transcript[45]);
buf[16] = mulmod(buf[17], mulmod(buf[22], buf[22], AggregatorLib.q_mod), AggregatorLib.q_mod);
AggregatorLib.ecc_mul_add(buf, 12);
(buf[14], buf[15]) = (transcript[42], transcript[43]);
buf[16] = mulmod(buf[17], buf[22], AggregatorLib.q_mod);
AggregatorLib.ecc_mul_add(buf, 12);
(buf[14], buf[15]) = (transcript[40], transcript[41]);
buf[16] = buf[17];
AggregatorLib.ecc_mul_add(buf, 12);
(buf[14], buf[15]) = (buf[0], buf[1]);
buf[16] = mulmod(buf[27], mulmod(buf[32], buf[7], AggregatorLib.q_mod), AggregatorLib.q_mod);
AggregatorLib.ecc_mul_add(buf, 12);
(buf[14], buf[15]) = (transcript[18], transcript[19]);
buf[16] = mulmod(buf[27], mulmod(buf[31], buf[7], AggregatorLib.q_mod), AggregatorLib.q_mod);
AggregatorLib.ecc_mul_add(buf, 12);
buf[17] = mulmod(buf[20], buf[20], AggregatorLib.q_mod);
(buf[14], buf[15]) = (transcript[32], transcript[33]);
buf[16] = buf[17];
AggregatorLib.ecc_mul_add(buf, 12);
(buf[14], buf[15]) = (transcript[34], transcript[35]);
buf[16] = mulmod(buf[23], buf[7], AggregatorLib.q_mod);
AggregatorLib.ecc_mul_add(buf, 12);
(buf[14], buf[15]) = (transcript[20], transcript[21]);
buf[16] = mulmod(buf[27], buf[31], AggregatorLib.q_mod);
AggregatorLib.ecc_mul_add(buf, 12);
(buf[14], buf[15]) = (transcript[36], transcript[37]);
buf[16] = buf[23];
AggregatorLib.ecc_mul_add(buf, 12);
buf[20] = mulmod(buf[28], buf[19], AggregatorLib.q_mod);
(buf[14], buf[15]) = (16013101360777447430391567575998918811509597004290763871753250359697657950684, 18284031839732107412046231472706741488467955619222543589254217767130083585094);
buf[16] = mulmod(buf[27], mulmod(buf[20], buf[7], AggregatorLib.q_mod), AggregatorLib.q_mod);
AggregatorLib.ecc_mul_add(buf, 12);
(buf[14], buf[15]) = (19737112949388897458588954660923088458903640709501932895808401103192630637886, 10675054364325450202178813304652591601320231805686501913156439839611155541187);
buf[16] = mulmod(buf[27], buf[20], AggregatorLib.q_mod);
AggregatorLib.ecc_mul_add(buf, 12);
(buf[14], buf[15]) = (11075133387362804604013739655507111764020652526474683365602194077653197238272, 1318109441292842640674212016592417370670910230830168691558759097428556833331);
buf[16] = mulmod(buf[27], mulmod(buf[28], buf[7], AggregatorLib.q_mod), AggregatorLib.q_mod);
AggregatorLib.ecc_mul_add(buf, 12);
(buf[14], buf[15]) = (6493171341935202456206124325209040072103532752509851882039398057802652209155, 5759392857488024763949679302755042832694498596039414370795425275927948962300);
buf[16] = mulmod(buf[27], buf[28], AggregatorLib.q_mod);
AggregatorLib.ecc_mul_add(buf, 12);
buf[20] = mulmod(buf[24], buf[19], AggregatorLib.q_mod);
(buf[14], buf[15]) = (3434307301702672135490012972724498468724430053586845303435546131578132169565, 9401556957552335892402756214239533149040282436268967679656060418659943805456);
buf[16] = mulmod(buf[27], mulmod(buf[20], buf[7], AggregatorLib.q_mod), AggregatorLib.q_mod);
AggregatorLib.ecc_mul_add(buf, 12);
(buf[14], buf[15]) = (20663073642495903566652507188978303698122574665635693523115271380298096913944, 20626435045404010153820563667748941335090321171987700717901703112061387457625);
buf[16] = mulmod(buf[27], buf[20], AggregatorLib.q_mod);
AggregatorLib.ecc_mul_add(buf, 12);
(buf[14], buf[15]) = (2909633653439036467368225770107015305052480086354402433210031100584322224938, 9113379992454044692611595843225590850770695728397706187195170007447718185937);
buf[16] = mulmod(buf[27], buf[25], AggregatorLib.q_mod);
AggregatorLib.ecc_mul_add(buf, 12);
(buf[14], buf[15]) = (12370723155217111550751604409229284398171581598248158174691848143324925475713, 8485843117039022328500854142848443817737786116149217563496647527406108346263);
buf[16] = mulmod(buf[27], buf[24], AggregatorLib.q_mod);
AggregatorLib.ecc_mul_add(buf, 12);
(buf[14], buf[15]) = (14407351040403581664332334748264473379864203161240022353233241082150176386285, 9844309975623883240590259440306357109543057870677302555594358299006757399285);
buf[16] = mulmod(buf[27], buf[26], AggregatorLib.q_mod);
AggregatorLib.ecc_mul_add(buf, 12);
(buf[14], buf[15]) = (18211387557073157961937239785723760864489490955530153678009805065113423060607, 12247546671223471605851044424338710756724515356960756532877336632123969096339);
buf[16] = mulmod(buf[27], buf[19], AggregatorLib.q_mod);
AggregatorLib.ecc_mul_add(buf, 12);
(buf[14], buf[15]) = (transcript[22], transcript[23]);
buf[16] = mulmod(buf[17], buf[24], AggregatorLib.q_mod);
AggregatorLib.ecc_mul_add(buf, 12);
buf[20] = mulmod(buf[17], buf[19], AggregatorLib.q_mod);
(buf[14], buf[15]) = (transcript[24], transcript[25]);
buf[16] = mulmod(buf[20], buf[7], AggregatorLib.q_mod);
AggregatorLib.ecc_mul_add(buf, 12);
(buf[14], buf[15]) = (transcript[26], transcript[27]);
buf[16] = buf[20];
AggregatorLib.ecc_mul_add(buf, 12);
(buf[14], buf[15]) = (transcript[28], transcript[29]);
buf[16] = mulmod(buf[17], buf[7], AggregatorLib.q_mod);
AggregatorLib.ecc_mul_add(buf, 12);
(buf[14], buf[15]) = (transcript[30], transcript[31]);
buf[16] = mulmod(buf[23], buf[19], AggregatorLib.q_mod);
AggregatorLib.ecc_mul_add(buf, 12);
(buf[14], buf[15]) = (transcript[38], transcript[39]);
buf[16] = buf[27];
AggregatorLib.ecc_mul_add(buf, 12);


        uint256[] memory ret = new uint256[](4);
        ret[0] = buf[10];
        ret[1] = buf[11];
        ret[2] = buf[12];
        ret[3] = buf[13];

        return ret;
    }
}
