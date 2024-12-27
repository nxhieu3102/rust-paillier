#![allow(dead_code)]

use curv::arithmetic::traits::*;
use curv::BigInt;
use kzen_paillier::paillier::Keypair;

// 1024 bit primes => 2048 bit modulus
pub static P2048: &str = "148677972634832330983979593310074301486537017973460461278300587514468301043894574906886127642530475786889672304776052879927627556769456140664043088700743909632312483413393134504352834240399191134336344285483935856491230340093391784574980688823380828143810804684752914935441384845195613674104960646037368551517";
pub static Q2048: &str = "158741574437007245654463598139927898730476924736461654463975966787719309357536545869203069369466212089132653564188443272208127277664424448947476335413293018778018615899291704693105620242763173357203898195318179150836424196645745308205164116144020613415407736216097185962171301808761138424668335445923774195463";
pub static N2048: &str = "23601375460155562757123678360900229644381030159964965932095920363097284825175029196457022864038449469086188985762066259059164844287276915193108505099612427967057134520230945630209577834878763915645946525724125804370016991193585261991964913084246563304755455418791629494251095184144084978275430600444710605147457044597210354635288909909182640243950968376955162386281524128586829759108414295175173359174297599533960370415928328418610692822180389889327103292184546896322100484378149887147731744901289563127581082141485046742100147976163228583170704180024449958168221243717383276594270459874555884125566472776234343167371";

// 2048 bit primes => 4096 bit modulus
pub static P4096: &str = "54012895487015803837782421918841304863093162502146915827099238255626761389465957752056702693431430972436786355954646022466841435632094385265559627938436498972714352765471698566168945062965812056432412175521672036039582393637684261505269548649599691053041645072024278713283987472744964393377089048380212183701013564638897218456903964669359622810875460724326972855594957135344351009076932272355015777958742805494234839710255927334289902051693131165245513596331706022111667560809760947628509288759753593140967096047486612859680010875340619186313770693509235798857494768621913543203586903819461926872265770592622637080247";
pub static Q4096: &str = "60110804761482905184172241999095064083721568391310132372880785562823040626081548259976195239057024762128798436684644401019565227508680839629752481384744855648596664223620474562582585419094571730852126918991494749938349375651158144545334949768160783962056913632707282062013023732986998195594940491859337992015569093391582644730733764652146222141495874869085082992832080902317418308778550853362446428222413647016439326663338175383509775221151568910938769471308411320393345489705012051577672571014388700476797545130036524629098427518061068575727892423981365405385986469525296662636940291427883820330312960173766723887143";
pub static N4096: &str = "3246758615222388102257247104619985257592790129095589210285276009429248256483846762934600391064503048539903536673803710898604266821127692553307361753316149607744596533947638369976896670599527959946456949729058671997201321029364087175491520869992605813032138070666142912786334578770232410719158199903915219886365963038477353646170462629197320969461918509765448690461526595960295577353920421639783555592907467785122476992591305198715822048909651296920289129580964452643808772386398216489780200158235271114140320078333479463828730923289630749950844692411371115829797899202089704002350025399751552212048387273162551252449279900043300405231911911403088435999645178423690062241837444313757921133439123090595809089406205378183174668004730796885645012612585689200392985339436110097924364054047371753194447028031925597558713228181086781152399656291395019275676908809117433906584203865571607578128934025711654282559310109420295931262272083976366943491672319050567929651567558548285963107610847891996140722185310234362659096832657024506723511060949620779357547927351440604423321590228598130693198375381347497839507868423146129670757985484273179950113558103417825488895000061485634292528378356202449380174380166345045052714420243023833347862564321";

pub static P3072: &str = "388502621207046378562148270340661433442288069306658269475419243203740574661686026004045215168031533385835304077328315825338124980249406646241155143782973413287547434488419922045037526101892248928724429388453332405226402069943524310919820760403307178541298050319018771647485012029422935007108399358478996829895933309086551313764236767844666873804924838863242737989846855568532778036794272145594286521107018558412837656935958973451794179888761314698718566429963539";
pub static Q3072: &str = "1193000508024484609159536216336752516688352215161440399611705357094088109035516981288406991876222430923795009748793900240653147867006573912582537001664834461269548662627651911455432314149807296330574032563525104702393407757204659492540011761123762234352697436193572732286941668060163167727024906107824232769511186150486118308100624046180217247113561071262517482676707090995444443652943781215539007335836115686656033307296839239648653568705144249666236620718265763";

pub trait KeySize {
    fn size() -> usize;
    fn keypair() -> Keypair {
        unimplemented!()
    }
}

pub struct KeySize512;
impl KeySize for KeySize512 {
    fn size() -> usize {
        512
    }
}

pub struct KeySize1024;
impl KeySize for KeySize1024 {
    fn size() -> usize {
        1024
    }
}

pub struct KeySize2048;
impl KeySize for KeySize2048 {
    fn size() -> usize {
        2048
    }
    fn keypair() -> Keypair {
        Keypair {
            p: BigInt::from_str_radix(P2048, 10).unwrap(),
            q: BigInt::from_str_radix(Q2048, 10).unwrap(),
        }
    }
}

pub struct KeySize3072;
impl KeySize for KeySize3072 {
    fn size() -> usize {
        3072
    }
    fn keypair() -> Keypair {
        Keypair {
            p: BigInt::from_str_radix(P3072, 10).unwrap(),
            q: BigInt::from_str_radix(Q3072, 10).unwrap(),
        }
    }
}

pub struct KeySize4096;
impl KeySize for KeySize4096 {
    fn size() -> usize {
        4096
    }
    fn keypair() -> Keypair {
        Keypair {
            p: BigInt::from_str_radix(P4096, 10).unwrap(),
            q: BigInt::from_str_radix(Q4096, 10).unwrap(),
        }
    }
}

pub struct KeySize448;

impl KeySize for KeySize448 {
    fn size() -> usize {
        448
    }
}

pub struct KeySize7680;

impl KeySize for crate::helpers::KeySize7680 {
    fn size() -> usize {
        448
    }
}


pub struct KeySize768;

impl KeySize for crate::helpers::KeySize768 {
    fn size() -> usize {
        448
    }
}


