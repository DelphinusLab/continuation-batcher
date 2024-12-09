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
        (buf[14], buf[15]) = (8635661353091288437711105003785364416846488507183133401849233923780291676865, 14456646419074606040463808115348409435439576753487925662210158054995141875238);
buf[16] = mulmod(buf[22], mulmod(buf[29], buf[7], AggregatorLib.q_mod), AggregatorLib.q_mod);
AggregatorLib.ecc_mul_add(buf, 12);
(buf[14], buf[15]) = (5650314317337298097307523081991722457993818351750274558428668198041353997288, 3319203533026979141275289940739284988221039920156899156363290464643853735607);
buf[16] = mulmod(buf[22], mulmod(buf[31], buf[7], AggregatorLib.q_mod), AggregatorLib.q_mod);
AggregatorLib.ecc_mul_add(buf, 12);
(buf[14], buf[15]) = (transcript[112], transcript[113]);
buf[16] = AggregatorLib.q_mod - mulmod(mulmod(buf[17], addmod(buf[9], AggregatorLib.q_mod - buf[6], AggregatorLib.q_mod), AggregatorLib.q_mod), buf[21], AggregatorLib.q_mod);
AggregatorLib.ecc_mul_add(buf, 12);
(buf[14], buf[15]) = (transcript[114], transcript[115]);
buf[16] = buf[9];
AggregatorLib.ecc_mul_add(buf, 12);
buf[17] = mulmod(buf[22], buf[7], AggregatorLib.q_mod);
(buf[14], buf[15]) = (transcript[46], transcript[47]);
buf[16] = mulmod(buf[17], mulmod(buf[25], buf[25], AggregatorLib.q_mod), AggregatorLib.q_mod);
AggregatorLib.ecc_mul_add(buf, 12);
(buf[14], buf[15]) = (transcript[44], transcript[45]);
buf[16] = mulmod(buf[17], buf[25], AggregatorLib.q_mod);
AggregatorLib.ecc_mul_add(buf, 12);
(buf[14], buf[15]) = (transcript[42], transcript[43]);
buf[16] = buf[17];
AggregatorLib.ecc_mul_add(buf, 12);
(buf[14], buf[15]) = (buf[0], buf[1]);
buf[16] = mulmod(buf[22], mulmod(buf[30], buf[7], AggregatorLib.q_mod), AggregatorLib.q_mod);
AggregatorLib.ecc_mul_add(buf, 12);
buf[17] = mulmod(buf[29], buf[23], AggregatorLib.q_mod);
(buf[14], buf[15]) = (transcript[20], transcript[21]);
buf[16] = mulmod(buf[22], mulmod(buf[17], buf[7], AggregatorLib.q_mod), AggregatorLib.q_mod);
AggregatorLib.ecc_mul_add(buf, 12);
(buf[14], buf[15]) = (transcript[34], transcript[35]);
buf[16] = mulmod(buf[24], buf[7], AggregatorLib.q_mod);
AggregatorLib.ecc_mul_add(buf, 12);
(buf[14], buf[15]) = (transcript[22], transcript[23]);
buf[16] = mulmod(buf[22], buf[17], AggregatorLib.q_mod);
AggregatorLib.ecc_mul_add(buf, 12);
buf[17] = mulmod(buf[19], buf[8], AggregatorLib.q_mod);
(buf[14], buf[15]) = (transcript[36], transcript[37]);
buf[16] = buf[17];
AggregatorLib.ecc_mul_add(buf, 12);
(buf[14], buf[15]) = (transcript[38], transcript[39]);
buf[16] = buf[24];
AggregatorLib.ecc_mul_add(buf, 12);
(buf[14], buf[15]) = (17618095146359054168474839490989539615817675922105269400962697666628951368836, 6577032313460623248234976089210806159375001392439997515389809644070450227264);
buf[16] = mulmod(buf[22], buf[32], AggregatorLib.q_mod);
AggregatorLib.ecc_mul_add(buf, 12);
(buf[14], buf[15]) = (12748903649485368611103141766760636231453816514176275433512545937994039016997, 5963082584271158291193236472112163454209903687717062039769800665594840086230);
buf[16] = mulmod(buf[22], mulmod(buf[27], buf[7], AggregatorLib.q_mod), AggregatorLib.q_mod);
AggregatorLib.ecc_mul_add(buf, 12);
(buf[14], buf[15]) = (16223879188562592363468051699409013932776887497652182677793826892000238199471, 6566373121248163902739817197074265774428836232485859802529943154511322288812);
buf[16] = mulmod(buf[22], buf[27], AggregatorLib.q_mod);
AggregatorLib.ecc_mul_add(buf, 12);
buf[19] = mulmod(buf[26], buf[23], AggregatorLib.q_mod);
(buf[14], buf[15]) = (10276288269293914594545572409833599116478282075937592729883103535909973888316, 19338927563850659935623013871983881511160235662553240849993267384875965687487);
buf[16] = mulmod(buf[22], mulmod(buf[19], buf[7], AggregatorLib.q_mod), AggregatorLib.q_mod);
AggregatorLib.ecc_mul_add(buf, 12);
(buf[14], buf[15]) = (1275994764662489196331052806164187782230205956126134172912329838801330045213, 15138933200408960159606065990988794448927053418436250365595927111702178144526);
buf[16] = mulmod(buf[22], buf[19], AggregatorLib.q_mod);
AggregatorLib.ecc_mul_add(buf, 12);
(buf[14], buf[15]) = (18167443805851209837116810351415180380688326416341151359114302503308003976702, 15065249205309470849623905815503638574431310848224005388323399834312906585901);
buf[16] = mulmod(buf[22], mulmod(buf[26], buf[7], AggregatorLib.q_mod), AggregatorLib.q_mod);
AggregatorLib.ecc_mul_add(buf, 12);
(buf[14], buf[15]) = (2554960364045854324497988616270782708303456414968057406829605520466391726539, 19886770549350187243934560195039539171800882857575125077472529331824101357789);
buf[16] = mulmod(buf[22], buf[26], AggregatorLib.q_mod);
AggregatorLib.ecc_mul_add(buf, 12);
(buf[14], buf[15]) = (20524129419782898559855440084675287505555635557186949004152097727424645157228, 14729088118892753489716863903147760314850792431342559239238014026693241355860);
buf[16] = mulmod(buf[22], buf[33], AggregatorLib.q_mod);
AggregatorLib.ecc_mul_add(buf, 12);
(buf[14], buf[15]) = (7923181156686521836894630063141690151901446837663655368672520885328588987363, 9653615521698318617880428354923781515348040978252374064817444068494223636007);
buf[16] = mulmod(buf[22], buf[23], AggregatorLib.q_mod);
AggregatorLib.ecc_mul_add(buf, 12);
(buf[14], buf[15]) = (transcript[24], transcript[25]);
buf[16] = mulmod(buf[17], buf[26], AggregatorLib.q_mod);
AggregatorLib.ecc_mul_add(buf, 12);
buf[19] = mulmod(buf[17], buf[23], AggregatorLib.q_mod);
(buf[14], buf[15]) = (transcript[26], transcript[27]);
buf[16] = mulmod(buf[19], buf[7], AggregatorLib.q_mod);
AggregatorLib.ecc_mul_add(buf, 12);
(buf[14], buf[15]) = (transcript[28], transcript[29]);
buf[16] = buf[19];
AggregatorLib.ecc_mul_add(buf, 12);
(buf[14], buf[15]) = (transcript[30], transcript[31]);
buf[16] = mulmod(buf[17], buf[7], AggregatorLib.q_mod);
AggregatorLib.ecc_mul_add(buf, 12);
(buf[14], buf[15]) = (transcript[32], transcript[33]);
buf[16] = mulmod(buf[24], buf[23], AggregatorLib.q_mod);
AggregatorLib.ecc_mul_add(buf, 12);
(buf[14], buf[15]) = (transcript[40], transcript[41]);
buf[16] = buf[22];
AggregatorLib.ecc_mul_add(buf, 12);


        uint256[] memory ret = new uint256[](4);
        ret[0] = buf[10];
        ret[1] = buf[11];
        ret[2] = buf[12];
        ret[3] = buf[13];

        return ret;
    }
}
