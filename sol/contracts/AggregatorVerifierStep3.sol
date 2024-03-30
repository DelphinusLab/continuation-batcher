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
        (buf[14], buf[15]) = (20766515301240454866169640328788354317427112250835957213602321823506545458180, 16932647451466487417557830046569221525251447239083168056060028354777006530422);
buf[16] = mulmod(buf[21], mulmod(buf[20], buf[7], AggregatorLib.q_mod), AggregatorLib.q_mod);
AggregatorLib.ecc_mul_add(buf, 12);
(buf[14], buf[15]) = (2210452201681531331800272611805625817315743841566518589840852741570599888913, 15121775690611465024981591725540093785250319540532853794129359553490331461173);
buf[16] = mulmod(buf[21], buf[20], AggregatorLib.q_mod);
AggregatorLib.ecc_mul_add(buf, 12);
buf[20] = mulmod(buf[27], buf[23], AggregatorLib.q_mod);
(buf[14], buf[15]) = (20944380943329942167787586217299305285728461842123881699545240448722304876590, 20304610028593568999902002108452016069695738143097301811663494085718593819677);
buf[16] = mulmod(buf[21], mulmod(buf[20], buf[7], AggregatorLib.q_mod), AggregatorLib.q_mod);
AggregatorLib.ecc_mul_add(buf, 12);
(buf[14], buf[15]) = (13596349683840261536145407349339075151295499568324072678504489575454672699017, 13345724809808485342146273118680681939795443087169946520523612907884648823388);
buf[16] = mulmod(buf[21], buf[20], AggregatorLib.q_mod);
AggregatorLib.ecc_mul_add(buf, 12);
(buf[14], buf[15]) = (3474067743500546388978675120447415040988578360711391219924030701537389826190, 19157272985283249396956256471290281319921609139455773114132172060028961126080);
buf[16] = mulmod(buf[21], mulmod(buf[27], buf[7], AggregatorLib.q_mod), AggregatorLib.q_mod);
AggregatorLib.ecc_mul_add(buf, 12);
(buf[14], buf[15]) = (14071002995406699328587641317594261375963575446997232315799142094427876371769, 13949423577289201522291834586905775890419539653199470225834518329298497559155);
buf[16] = mulmod(buf[21], buf[30], AggregatorLib.q_mod);
AggregatorLib.ecc_mul_add(buf, 12);
(buf[14], buf[15]) = (9647964943753966220547903487938699931489113424130390025096103369198343400152, 6849536388949540732391156375057139675504133054897066895676514519256033943113);
buf[16] = mulmod(buf[21], mulmod(buf[30], buf[7], AggregatorLib.q_mod), AggregatorLib.q_mod);
AggregatorLib.ecc_mul_add(buf, 12);
(buf[14], buf[15]) = (5551211862277526771162041827935839146143609909248418495794357278521429908679, 20256101722580200896925678947207415103182393709319662173402390235938816909005);
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
(buf[14], buf[15]) = (1802155750175097994105753340001753051689278785059566754252722804137436767202, 1715632394339196331247906913339582731286518535091054665717038749837361738581);
buf[16] = mulmod(buf[21], buf[33], AggregatorLib.q_mod);
AggregatorLib.ecc_mul_add(buf, 12);
(buf[14], buf[15]) = (16020066612710010236715242393266487546839464615160328518644305572634788848337, 5095065564522862341500220711574011006788372108734867674598092245105040098540);
buf[16] = mulmod(buf[21], mulmod(buf[26], buf[7], AggregatorLib.q_mod), AggregatorLib.q_mod);
AggregatorLib.ecc_mul_add(buf, 12);
(buf[14], buf[15]) = (10941569413771083585315787692796787761426145366406999795501563849998048719045, 20387559496496278631382993468675711993306046317586520324344995160866581374671);
buf[16] = mulmod(buf[21], buf[26], AggregatorLib.q_mod);
AggregatorLib.ecc_mul_add(buf, 12);
buf[17] = mulmod(buf[24], buf[23], AggregatorLib.q_mod);
(buf[14], buf[15]) = (18231755139086712591044496709194507629670434828154960790168230266106014030808, 7394950916712605198130752515026952914770964568809180509633650403787852815165);
buf[16] = mulmod(buf[21], mulmod(buf[17], buf[7], AggregatorLib.q_mod), AggregatorLib.q_mod);
AggregatorLib.ecc_mul_add(buf, 12);
(buf[14], buf[15]) = (202521367442777583062927453676228223703702565605101633430466283064361794230, 12643331623019851225763640654489683465730962816805832938692986374786518998743);
buf[16] = mulmod(buf[21], buf[17], AggregatorLib.q_mod);
AggregatorLib.ecc_mul_add(buf, 12);
(buf[14], buf[15]) = (16901721346656282177723064902897958692433235696725487999004281082548303145586, 7533837930979568376173562305038435619178339862593713178817381276228985028805);
buf[16] = mulmod(buf[21], mulmod(buf[24], buf[7], AggregatorLib.q_mod), AggregatorLib.q_mod);
AggregatorLib.ecc_mul_add(buf, 12);
(buf[14], buf[15]) = (10200728757732635993126219997282130876078357862619182821791726908507776297827, 12171464646647670357699953940528639967533969309584978114937597509196840732272);
buf[16] = mulmod(buf[21], buf[24], AggregatorLib.q_mod);
AggregatorLib.ecc_mul_add(buf, 12);
buf[17] = mulmod(buf[23], buf[7], AggregatorLib.q_mod);
(buf[14], buf[15]) = (7310704426607460364995520901738141534505043311409851042019439506263528831021, 5810053958622626513384160473912702735614839174579326448535580624646923804711);
buf[16] = mulmod(buf[21], buf[17], AggregatorLib.q_mod);
AggregatorLib.ecc_mul_add(buf, 12);
(buf[14], buf[15]) = (21553898477923775802533840917940163885276575473157291817756760924889845988621, 19767441011249861511629637600227716372852671525556418597280411750529184348266);
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
