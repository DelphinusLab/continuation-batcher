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
        buf[34] = addmod(buf[35], addmod(addmod(addmod(mulmod(buf[34], transcript[49], AggregatorLib.q_mod), mulmod(buf[36], transcript[61], AggregatorLib.q_mod), AggregatorLib.q_mod), mulmod(buf[39], transcript[64], AggregatorLib.q_mod), AggregatorLib.q_mod), mulmod(buf[44], transcript[71], AggregatorLib.q_mod), AggregatorLib.q_mod), AggregatorLib.q_mod);
buf[23] = addmod(mulmod(buf[34], buf[9], AggregatorLib.q_mod), addmod(addmod(addmod(mulmod(buf[23], transcript[49], AggregatorLib.q_mod), mulmod(buf[26], transcript[61], AggregatorLib.q_mod), AggregatorLib.q_mod), mulmod(buf[32], transcript[64], AggregatorLib.q_mod), AggregatorLib.q_mod), mulmod(buf[37], transcript[71], AggregatorLib.q_mod), AggregatorLib.q_mod), AggregatorLib.q_mod);
buf[19] = addmod(mulmod(buf[23], buf[9], AggregatorLib.q_mod), addmod(addmod(addmod(mulmod(buf[20], transcript[49], AggregatorLib.q_mod), mulmod(buf[30], transcript[61], AggregatorLib.q_mod), AggregatorLib.q_mod), mulmod(buf[27], transcript[64], AggregatorLib.q_mod), AggregatorLib.q_mod), mulmod(buf[19], transcript[71], AggregatorLib.q_mod), AggregatorLib.q_mod), AggregatorLib.q_mod);
buf[20] = mulmod(buf[17], buf[29], AggregatorLib.q_mod);
buf[19] = mulmod(addmod(mulmod(buf[7], addmod(mulmod(buf[7], buf[24], AggregatorLib.q_mod), buf[33], AggregatorLib.q_mod), AggregatorLib.q_mod), buf[19], AggregatorLib.q_mod), buf[20], AggregatorLib.q_mod);
buf[18] = addmod(buf[18], buf[19], AggregatorLib.q_mod);
(buf[12], buf[13]) = (1, 21888242871839275222246405745257275088696311157297823662689037894645226208581);
buf[14] = buf[18];
AggregatorLib.ecc_mul(buf, 12);
buf[19] = mulmod(buf[7], buf[7], AggregatorLib.q_mod);
(buf[14], buf[15]) = (transcript[0], transcript[1]);
buf[16] = mulmod(buf[20], buf[19], AggregatorLib.q_mod);
AggregatorLib.ecc_mul_add(buf, 12);
(buf[14], buf[15]) = (transcript[2], transcript[3]);
buf[16] = mulmod(buf[20], buf[7], AggregatorLib.q_mod);
AggregatorLib.ecc_mul_add(buf, 12);
(buf[14], buf[15]) = (transcript[4], transcript[5]);
buf[16] = buf[20];
AggregatorLib.ecc_mul_add(buf, 12);
buf[20] = mulmod(buf[8], buf[28], AggregatorLib.q_mod);
(buf[14], buf[15]) = (transcript[6], transcript[7]);
buf[16] = mulmod(buf[20], buf[7], AggregatorLib.q_mod);
AggregatorLib.ecc_mul_add(buf, 12);
(buf[14], buf[15]) = (transcript[8], transcript[9]);
buf[16] = buf[20];
AggregatorLib.ecc_mul_add(buf, 12);
buf[20] = mulmod(buf[8], buf[8], AggregatorLib.q_mod);
buf[23] = mulmod(buf[20], buf[25], AggregatorLib.q_mod);
buf[24] = mulmod(buf[19], buf[19], AggregatorLib.q_mod);
buf[25] = mulmod(buf[24], buf[7], AggregatorLib.q_mod);
(buf[14], buf[15]) = (transcript[10], transcript[11]);
buf[16] = mulmod(buf[23], buf[25], AggregatorLib.q_mod);
AggregatorLib.ecc_mul_add(buf, 12);
(buf[14], buf[15]) = (transcript[12], transcript[13]);
buf[16] = mulmod(buf[23], buf[24], AggregatorLib.q_mod);
AggregatorLib.ecc_mul_add(buf, 12);
buf[26] = mulmod(buf[19], buf[7], AggregatorLib.q_mod);
(buf[14], buf[15]) = (transcript[14], transcript[15]);
buf[16] = mulmod(buf[23], buf[26], AggregatorLib.q_mod);
AggregatorLib.ecc_mul_add(buf, 12);
buf[27] = mulmod(mulmod(buf[20], buf[8], AggregatorLib.q_mod), buf[31], AggregatorLib.q_mod);
buf[28] = mulmod(buf[24], buf[24], AggregatorLib.q_mod);
buf[29] = mulmod(buf[28], buf[28], AggregatorLib.q_mod);
buf[30] = mulmod(buf[29], buf[28], AggregatorLib.q_mod);
buf[31] = mulmod(buf[30], buf[24], AggregatorLib.q_mod);
buf[32] = mulmod(buf[31], buf[19], AggregatorLib.q_mod);
(buf[14], buf[15]) = (transcript[16], transcript[17]);
buf[16] = mulmod(buf[27], buf[32], AggregatorLib.q_mod);
AggregatorLib.ecc_mul_add(buf, 12);
(buf[14], buf[15]) = (4197764779765500619086905679346349595502678646650401496284249899640081263054, 18735396249204036122862126795171053274142628440718554871209977871188710381062);
buf[16] = mulmod(buf[27], mulmod(buf[30], buf[7], AggregatorLib.q_mod), AggregatorLib.q_mod);
AggregatorLib.ecc_mul_add(buf, 12);
(buf[14], buf[15]) = (20263923995110091594801969246165930232724240793772978764231804343146076859752, 421652627040302342429968092955146532772337732135257753012244505824085349488);
buf[16] = mulmod(buf[27], buf[30], AggregatorLib.q_mod);
AggregatorLib.ecc_mul_add(buf, 12);
(buf[14], buf[15]) = (20316678354551864418735195238200484032571357391673966501704451507022329986473, 12102513160157897850514330171721453385402608165962547679060939399639079969958);
buf[16] = mulmod(buf[27], buf[29], AggregatorLib.q_mod);
AggregatorLib.ecc_mul_add(buf, 12);
(buf[14], buf[15]) = (12131805172690818921224463503619358613621337457707771682409167766796037180283, 13208913633412377005811323489943316350438867644531811596310619546646908788982);
buf[16] = mulmod(buf[27], mulmod(buf[29], buf[7], AggregatorLib.q_mod), AggregatorLib.q_mod);
AggregatorLib.ecc_mul_add(buf, 12);
buf[33] = mulmod(buf[29], buf[19], AggregatorLib.q_mod);
(buf[14], buf[15]) = (16384750106869563780750653698065597928235826011333158029841535278257525622364, 13863360466940931629812474946052676345841354556483994318633110016394763233331);
buf[16] = mulmod(buf[27], buf[33], AggregatorLib.q_mod);
AggregatorLib.ecc_mul_add(buf, 12);
buf[34] = mulmod(buf[28], buf[24], AggregatorLib.q_mod);
buf[35] = mulmod(buf[34], buf[19], AggregatorLib.q_mod);
(buf[14], buf[15]) = (6524097008599549365123830772150400971059064924093724822109556526305030944372, 11975134030697462184533554896933769702953392735855718845296166248150193106755);
buf[16] = mulmod(buf[27], buf[35], AggregatorLib.q_mod);
AggregatorLib.ecc_mul_add(buf, 12);
(buf[14], buf[15]) = (9690307389924373697716902955823195966385072356380965110177571012116884048920, 19618456317950007497155487137872897961718693142124992521591736279635561929953);
buf[16] = mulmod(buf[27], mulmod(buf[34], buf[7], AggregatorLib.q_mod), AggregatorLib.q_mod);
AggregatorLib.ecc_mul_add(buf, 12);
(buf[14], buf[15]) = (13750082717186074527102402301164120215816517966876017904216745309676991818024, 20168282241077459436545457957891042994257112951499120117927799258527671693670);
buf[16] = mulmod(buf[27], buf[34], AggregatorLib.q_mod);
AggregatorLib.ecc_mul_add(buf, 12);
buf[29] = mulmod(buf[29], buf[24], AggregatorLib.q_mod);
buf[34] = mulmod(buf[29], buf[19], AggregatorLib.q_mod);
(buf[14], buf[15]) = (1481491789412622917814053383035511210413784440903980072586462802645485405009, 2190066763502576188001544595293527324760841443296051421799231155294372343162);
buf[16] = mulmod(buf[27], mulmod(buf[34], buf[7], AggregatorLib.q_mod), AggregatorLib.q_mod);
AggregatorLib.ecc_mul_add(buf, 12);
(buf[14], buf[15]) = (1576504727487329391333045229968578967695057954958719721922860567930063861790, 10356720834062446187458923003371025310178336363085896428919562027823018977946);
buf[16] = mulmod(buf[27], buf[34], AggregatorLib.q_mod);
AggregatorLib.ecc_mul_add(buf, 12);
(buf[14], buf[15]) = (8172690645807961515243483619510424773280773072143424731910615647372686727269, 6946490189576295074292967580315696138691199442472005465157927513655793111845);
buf[16] = mulmod(buf[27], mulmod(buf[29], buf[7], AggregatorLib.q_mod), AggregatorLib.q_mod);
AggregatorLib.ecc_mul_add(buf, 12);
(buf[14], buf[15]) = (3313692799062629272001890825506968964421021335301702147428043313291462637368, 3599028245088017049061971064414542879746315866711715822560899522222605065046);
buf[16] = mulmod(buf[27], buf[29], AggregatorLib.q_mod);
AggregatorLib.ecc_mul_add(buf, 12);
(buf[14], buf[15]) = (7182236695780970206389346028844263412451473246832442651054190543660105715259, 12354471184501813978328098045884549982581713624717658557330518233536982619380);
buf[16] = mulmod(buf[27], mulmod(buf[33], buf[7], AggregatorLib.q_mod), AggregatorLib.q_mod);
AggregatorLib.ecc_mul_add(buf, 12);
buf[29] = mulmod(buf[30], buf[19], AggregatorLib.q_mod);
(buf[14], buf[15]) = (0, 0);
buf[16] = mulmod(buf[27], buf[29], AggregatorLib.q_mod);
AggregatorLib.ecc_mul_add(buf, 12);
(buf[14], buf[15]) = (1995050330450656045594488181727773989777810898731449656158144562918905052849, 19548346179324515640145098906356283639256238010242736427346569268582024448891);
buf[16] = mulmod(buf[27], mulmod(buf[29], buf[7], AggregatorLib.q_mod), AggregatorLib.q_mod);
AggregatorLib.ecc_mul_add(buf, 12);


        return buf;
    }
}
