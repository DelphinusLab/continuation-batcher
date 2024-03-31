// SPDX-License-Identifier: MIT
// Tells the Solidity compiler to compile only from v0.8.13 to v0.9.0
pragma solidity ^0.8.13;

import "./AggregatorLib.sol";

contract AggregatorVerifierCoreStep3 {
    function verify_proof(
        uint256[] calldata transcript,
        uint256[] calldata aux,
        uint256[] memory buf
    ) public view returns (uint256[] memory)  {
        (buf[14], buf[15]) = (12793304197070861322039157288499237384046564344843827632975863181383635531572, 17571581962002717034265812363741369648688853534557805980083744653945037885577);
buf[16] = mulmod(buf[21], mulmod(buf[20], buf[7], AggregatorLib.q_mod), AggregatorLib.q_mod);
AggregatorLib.ecc_mul_add(buf, 12);
(buf[14], buf[15]) = (20430099892221221788489174454880322911452077551124738711834177490405184066261, 4209737612668921092017398269111494293661793177666451625745910475390664858930);
buf[16] = mulmod(buf[21], buf[20], AggregatorLib.q_mod);
AggregatorLib.ecc_mul_add(buf, 12);
buf[20] = mulmod(buf[27], buf[23], AggregatorLib.q_mod);
(buf[14], buf[15]) = (14238712458989771409578010418116603854100580200684952529603773615205255567430, 1306641168927927773073078898856599071402908037270650984853389030764923858724);
buf[16] = mulmod(buf[21], mulmod(buf[20], buf[7], AggregatorLib.q_mod), AggregatorLib.q_mod);
AggregatorLib.ecc_mul_add(buf, 12);
(buf[14], buf[15]) = (5388356577192600751694710397998770521684413305466003676796426721151588324894, 7643830828982188115150657182645542832785261676734263018085050085190036262072);
buf[16] = mulmod(buf[21], buf[20], AggregatorLib.q_mod);
AggregatorLib.ecc_mul_add(buf, 12);
(buf[14], buf[15]) = (1798961746561967479567644880140724986369805900696929724081637178131982117765, 2618576397476061590762139877122954353752484138743931086624817505233231651716);
buf[16] = mulmod(buf[21], mulmod(buf[27], buf[7], AggregatorLib.q_mod), AggregatorLib.q_mod);
AggregatorLib.ecc_mul_add(buf, 12);
(buf[14], buf[15]) = (1099371261920955167139524208283510236107330129179431156913881909079488667285, 9713368225992310437014942438941637371063471117139600223739723215028298119761);
buf[16] = mulmod(buf[21], buf[30], AggregatorLib.q_mod);
AggregatorLib.ecc_mul_add(buf, 12);
(buf[14], buf[15]) = (16915404722915728087597669518499042167294571296768252770914454265905156845608, 21855912557902073886757593465925993012013279901897969935079125078362497860046);
buf[16] = mulmod(buf[21], mulmod(buf[30], buf[7], AggregatorLib.q_mod), AggregatorLib.q_mod);
AggregatorLib.ecc_mul_add(buf, 12);
(buf[14], buf[15]) = (3623980850458095342089714372106030360960994196811262330980778763245467696874, 614231864457663569049600146392734085164769191835495434090907579949742790833);
buf[16] = mulmod(buf[21], mulmod(buf[32], buf[7], AggregatorLib.q_mod), AggregatorLib.q_mod);
AggregatorLib.ecc_mul_add(buf, 12);
(buf[14], buf[15]) = (transcript[126], transcript[127]);
buf[16] = AggregatorLib.q_mod - mulmod(mulmod(buf[17], addmod(buf[9], AggregatorLib.q_mod - buf[6], AggregatorLib.q_mod), AggregatorLib.q_mod), buf[22], AggregatorLib.q_mod);
AggregatorLib.ecc_mul_add(buf, 12);
(buf[14], buf[15]) = (transcript[128], transcript[129]);
buf[16] = buf[9];
AggregatorLib.ecc_mul_add(buf, 12);
buf[17] = mulmod(buf[21], buf[7], AggregatorLib.q_mod);
(buf[14], buf[15]) = (transcript[54], transcript[55]);
buf[16] = mulmod(buf[17], mulmod(buf[35], buf[35], AggregatorLib.q_mod), AggregatorLib.q_mod);
AggregatorLib.ecc_mul_add(buf, 12);
(buf[14], buf[15]) = (transcript[52], transcript[53]);
buf[16] = mulmod(buf[17], buf[35], AggregatorLib.q_mod);
AggregatorLib.ecc_mul_add(buf, 12);
(buf[14], buf[15]) = (transcript[50], transcript[51]);
buf[16] = buf[17];
AggregatorLib.ecc_mul_add(buf, 12);
(buf[14], buf[15]) = (buf[0], buf[1]);
buf[16] = mulmod(buf[21], mulmod(buf[29], buf[24], AggregatorLib.q_mod), AggregatorLib.q_mod);
AggregatorLib.ecc_mul_add(buf, 12);
buf[17] = mulmod(mulmod(buf[19], buf[8], AggregatorLib.q_mod), buf[28], AggregatorLib.q_mod);
(buf[14], buf[15]) = (transcript[20], transcript[21]);
buf[16] = mulmod(buf[17], buf[23], AggregatorLib.q_mod);
AggregatorLib.ecc_mul_add(buf, 12);
(buf[14], buf[15]) = (transcript[22], transcript[23]);
buf[16] = mulmod(buf[21], buf[31], AggregatorLib.q_mod);
AggregatorLib.ecc_mul_add(buf, 12);
(buf[14], buf[15]) = (transcript[42], transcript[43]);
buf[16] = mulmod(buf[25], buf[23], AggregatorLib.q_mod);
AggregatorLib.ecc_mul_add(buf, 12);
(buf[14], buf[15]) = (transcript[24], transcript[25]);
buf[16] = mulmod(buf[17], buf[7], AggregatorLib.q_mod);
AggregatorLib.ecc_mul_add(buf, 12);
buf[20] = mulmod(buf[30], buf[23], AggregatorLib.q_mod);
(buf[14], buf[15]) = (transcript[26], transcript[27]);
buf[16] = mulmod(buf[21], mulmod(buf[20], buf[7], AggregatorLib.q_mod), AggregatorLib.q_mod);
AggregatorLib.ecc_mul_add(buf, 12);
(buf[14], buf[15]) = (transcript[44], transcript[45]);
buf[16] = mulmod(buf[25], buf[7], AggregatorLib.q_mod);
AggregatorLib.ecc_mul_add(buf, 12);
(buf[14], buf[15]) = (transcript[28], transcript[29]);
buf[16] = buf[17];
AggregatorLib.ecc_mul_add(buf, 12);
(buf[14], buf[15]) = (transcript[30], transcript[31]);
buf[16] = mulmod(buf[21], buf[20], AggregatorLib.q_mod);
AggregatorLib.ecc_mul_add(buf, 12);
(buf[14], buf[15]) = (transcript[46], transcript[47]);
buf[16] = buf[25];
AggregatorLib.ecc_mul_add(buf, 12);
(buf[14], buf[15]) = (8219891373329039313620559132004649204278572593599738452452488319990448482168, 17191082171038123011170867846452699181854051087326502731374243304734055143459);
buf[16] = mulmod(buf[21], buf[33], AggregatorLib.q_mod);
AggregatorLib.ecc_mul_add(buf, 12);
(buf[14], buf[15]) = (9691577873700924310847256392228268072024510474127897562348890244214648687114, 15990940855628906141705545931318183649580524284170685036741911600016454811065);
buf[16] = mulmod(buf[21], mulmod(buf[26], buf[7], AggregatorLib.q_mod), AggregatorLib.q_mod);
AggregatorLib.ecc_mul_add(buf, 12);
(buf[14], buf[15]) = (1117943120685452206041529548548076014855717391006498247726776082332745316324, 6446297355586311521664524783463382504896665023169424234428350123887283779422);
buf[16] = mulmod(buf[21], buf[26], AggregatorLib.q_mod);
AggregatorLib.ecc_mul_add(buf, 12);
buf[17] = mulmod(buf[24], buf[23], AggregatorLib.q_mod);
(buf[14], buf[15]) = (13860034306645247998106447450410781840344143064612552407102965258710143209097, 21362586688876053264639593254469481948654196064965445330465535680514441397469);
buf[16] = mulmod(buf[21], mulmod(buf[17], buf[7], AggregatorLib.q_mod), AggregatorLib.q_mod);
AggregatorLib.ecc_mul_add(buf, 12);
(buf[14], buf[15]) = (15341105670070334552343000349279879422961317781687562225903001585237319952889, 17310808433189222871965653439434961084963562796523444730447726724835566577002);
buf[16] = mulmod(buf[21], buf[17], AggregatorLib.q_mod);
AggregatorLib.ecc_mul_add(buf, 12);
(buf[14], buf[15]) = (20442745111654043254228434662444486889564871869652203548511841340183790023713, 8483199282486650470815487754055351392941325559867585662349857066750613202285);
buf[16] = mulmod(buf[21], mulmod(buf[24], buf[7], AggregatorLib.q_mod), AggregatorLib.q_mod);
AggregatorLib.ecc_mul_add(buf, 12);
(buf[14], buf[15]) = (10802903200164122671756606238878366946066764958726269228146428104706880819196, 14061529637519939674093034748549736352824424337180597543726586783999957477707);
buf[16] = mulmod(buf[21], buf[24], AggregatorLib.q_mod);
AggregatorLib.ecc_mul_add(buf, 12);
buf[17] = mulmod(buf[23], buf[7], AggregatorLib.q_mod);
(buf[14], buf[15]) = (9027853874374995885454351799625600991586249553994299875905943671198429799905, 8896748751053411253095897466619567267041166163407308145675214446150679587124);
buf[16] = mulmod(buf[21], buf[17], AggregatorLib.q_mod);
AggregatorLib.ecc_mul_add(buf, 12);
(buf[14], buf[15]) = (4836571764581335611142393458820780545362308383065865183633539167903876414827, 4971514508941690732892537985722183509937107579278985672256416232177442388664);
buf[16] = mulmod(buf[21], buf[23], AggregatorLib.q_mod);
AggregatorLib.ecc_mul_add(buf, 12);
buf[19] = mulmod(buf[19], buf[19], AggregatorLib.q_mod);
buf[20] = mulmod(buf[19], buf[23], AggregatorLib.q_mod);
(buf[14], buf[15]) = (transcript[32], transcript[33]);
buf[16] = mulmod(buf[20], buf[7], AggregatorLib.q_mod);
AggregatorLib.ecc_mul_add(buf, 12);
(buf[14], buf[15]) = (transcript[34], transcript[35]);
buf[16] = buf[20];
AggregatorLib.ecc_mul_add(buf, 12);
(buf[14], buf[15]) = (transcript[36], transcript[37]);
buf[16] = mulmod(buf[19], buf[7], AggregatorLib.q_mod);
AggregatorLib.ecc_mul_add(buf, 12);
(buf[14], buf[15]) = (transcript[38], transcript[39]);
buf[16] = buf[19];
AggregatorLib.ecc_mul_add(buf, 12);
(buf[14], buf[15]) = (transcript[40], transcript[41]);
buf[16] = mulmod(buf[25], buf[17], AggregatorLib.q_mod);
AggregatorLib.ecc_mul_add(buf, 12);
(buf[14], buf[15]) = (transcript[48], transcript[49]);
buf[16] = buf[21];
AggregatorLib.ecc_mul_add(buf, 12);


        uint256[] memory ret = new uint256[](4);
        ret[0] = buf[10];
        ret[1] = buf[11];
        ret[2] = buf[12];
        ret[3] = buf[13];

        return ret;
    }
}
