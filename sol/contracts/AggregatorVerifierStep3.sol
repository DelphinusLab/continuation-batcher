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
        (buf[14], buf[15]) = (20759750461739125992378767610332269963149815513273622864775530410026771269525, 10904937888328550291655302683317062793563163023835893402350487517560378271740);
buf[16] = mulmod(buf[21], mulmod(buf[20], buf[7], AggregatorLib.q_mod), AggregatorLib.q_mod);
AggregatorLib.ecc_mul_add(buf, 12);
(buf[14], buf[15]) = (20535172562163350936385231649483036300506285010829457870326277086727260737108, 3541813171093919660639173436895170349232761818420241457754399128995153953465);
buf[16] = mulmod(buf[21], buf[20], AggregatorLib.q_mod);
AggregatorLib.ecc_mul_add(buf, 12);
buf[20] = mulmod(buf[27], buf[23], AggregatorLib.q_mod);
(buf[14], buf[15]) = (8963798437041490311558810581400049742642391806739178156470649110792803346962, 21733527739878321362130684819544208129949313772900005056011654075687444203428);
buf[16] = mulmod(buf[21], mulmod(buf[20], buf[7], AggregatorLib.q_mod), AggregatorLib.q_mod);
AggregatorLib.ecc_mul_add(buf, 12);
(buf[14], buf[15]) = (13044335068093109184713405311659816839103424242163009066129931502157689763800, 1518725228448113457171224588681451440357186319329077426324365167031915322256);
buf[16] = mulmod(buf[21], buf[20], AggregatorLib.q_mod);
AggregatorLib.ecc_mul_add(buf, 12);
(buf[14], buf[15]) = (10378375775111670462974661170893849818606191580058938457878078998548378133339, 5262430332956946691118296142545888489088654424830069307411528081214450739956);
buf[16] = mulmod(buf[21], mulmod(buf[27], buf[7], AggregatorLib.q_mod), AggregatorLib.q_mod);
AggregatorLib.ecc_mul_add(buf, 12);
(buf[14], buf[15]) = (16119360211658031662124152488786335301718952551975496948933290893122283584002, 17126478774274518541046743009691399967064933997854430031907895572779681858450);
buf[16] = mulmod(buf[21], buf[30], AggregatorLib.q_mod);
AggregatorLib.ecc_mul_add(buf, 12);
(buf[14], buf[15]) = (12033812499184931721582860564707667623821303659769493793187362644519311188990, 18826882166445413285747756770758210903303695148575315117895439394044662368400);
buf[16] = mulmod(buf[21], mulmod(buf[30], buf[7], AggregatorLib.q_mod), AggregatorLib.q_mod);
AggregatorLib.ecc_mul_add(buf, 12);
(buf[14], buf[15]) = (16378743606478335747457944698062120996141682586387099252221092720905405918414, 11103467753241742432413694422925526042089761982492613912800137752450494093528);
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
(buf[14], buf[15]) = (11343734282670825608366768742637083048370202648137513497622290826592242225002, 11782062876775714112753139050553693752089439799769788150379634703515021563754);
buf[16] = mulmod(buf[21], buf[33], AggregatorLib.q_mod);
AggregatorLib.ecc_mul_add(buf, 12);
(buf[14], buf[15]) = (12043603334771816944347225124884756470325299194363478355813874206954792838604, 20876989663325185769959558161308080255124930647164313828076435600964837368667);
buf[16] = mulmod(buf[21], mulmod(buf[26], buf[7], AggregatorLib.q_mod), AggregatorLib.q_mod);
AggregatorLib.ecc_mul_add(buf, 12);
(buf[14], buf[15]) = (8835760121184379041071880710041248404231270719318400215110846502009823578694, 220905996781781061747659459820877219277288428760233586567595568280169477795);
buf[16] = mulmod(buf[21], buf[26], AggregatorLib.q_mod);
AggregatorLib.ecc_mul_add(buf, 12);
buf[17] = mulmod(buf[24], buf[23], AggregatorLib.q_mod);
(buf[14], buf[15]) = (19558008946148675579502090417523212662023637038296181889017974379744838430072, 8287524719528785807042992305180083214660253800303892098241762341036650004183);
buf[16] = mulmod(buf[21], mulmod(buf[17], buf[7], AggregatorLib.q_mod), AggregatorLib.q_mod);
AggregatorLib.ecc_mul_add(buf, 12);
(buf[14], buf[15]) = (5359759660029110933897793308875297353144826400531351697065083899272285951293, 11331343975490635825470093026807043344216724247762651129292123547157932719666);
buf[16] = mulmod(buf[21], buf[17], AggregatorLib.q_mod);
AggregatorLib.ecc_mul_add(buf, 12);
(buf[14], buf[15]) = (7612840083340379651268606554513400217220650957910262672477737060998475644508, 12799864150821916881889722587603716388098041944444528536340441543966429691221);
buf[16] = mulmod(buf[21], mulmod(buf[24], buf[7], AggregatorLib.q_mod), AggregatorLib.q_mod);
AggregatorLib.ecc_mul_add(buf, 12);
(buf[14], buf[15]) = (11490271559869560361665958110888057793918373188865157740601127426580513589676, 6805002345741803761891331874713593672826965075053321786985330671569913917590);
buf[16] = mulmod(buf[21], buf[24], AggregatorLib.q_mod);
AggregatorLib.ecc_mul_add(buf, 12);
buf[17] = mulmod(buf[23], buf[7], AggregatorLib.q_mod);
(buf[14], buf[15]) = (2392092517578365885190450227349919260074518610938353557759789703034857051883, 905738394663387305225100977108991626630412919130144583065303448455167332117);
buf[16] = mulmod(buf[21], buf[17], AggregatorLib.q_mod);
AggregatorLib.ecc_mul_add(buf, 12);
(buf[14], buf[15]) = (15353751959268809170113991974962191479364953527438854658393719343253989641001, 8305898761736093229182155393570204511970065815053688498700268261947168600149);
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
