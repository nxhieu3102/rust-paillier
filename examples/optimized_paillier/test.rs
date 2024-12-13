use curv::BigInt;
use kzen_paillier::optimized_paillier::*;
use curv::arithmetic::traits::*;
use kzen_paillier::optimized_paillier::{DecryptionKey, NGen};

pub struct PrecomputeTableParams {
    pub g: BigInt,
    pub block_size: usize,
    pub pow_size: usize,
    pub modulo: BigInt
}

pub struct NKeySize3072;

pub static PP3072: &str = "388502621207046378562148270340661433442288069306658269475419243203740574661686026004045215168031533385835304077328315825338124980249406646241155143782973413287547434488419922045037526101892248928724429388453332405226402069943524310919820760403307178541298050319018771647485012029422935007108399358478996829895933309086551313764236767844666873804924838863242737989846855568532778036794272145594286521107018558412837656935958973451794179888761314698718566429963539";
pub static PQ3072: &str = "1193000508024484609159536216336752516688352215161440399611705357094088109035516981288406991876222430923795009748793900240653147867006573912582537001664834461269548662627651911455432314149807296330574032563525104702393407757204659492540011761123762234352697436193572732286941668060163167727024906107824232769511186150486118308100624046180217247113561071262517482676707090995444443652943781215539007335836115686656033307296839239648653568705144249666236620718265763";
pub static DP3072: &str ="61700813231151522204235788263413612242612730984844737912740742528374724656569";
pub static DQ3072: &str ="105401434517560464129671227342277628028561470138415488726566128979979946586899";
impl NKeySize3072 {
    fn size() -> usize {
        3072
    }

    fn gen() -> NGen {
        let p: BigInt = BigInt::from_str_radix(PP3072, 10).unwrap();
        let q: BigInt = BigInt::from_str_radix(PQ3072, 10).unwrap();
        let n = BigInt::mul(&p, &q);
        NGen {
            alpha_size: 512,
            n,
            p,
            q,
            div_p: BigInt::from_str_radix(DP3072, 10).unwrap(),
            div_q: BigInt::from_str_radix(DQ3072, 10).unwrap(),
        }
    }

    fn dgen() -> DecryptionKey {
        let p: BigInt = BigInt::from_str_radix(PP3072, 10).unwrap();
        let q: BigInt = BigInt::from_str_radix(PQ3072, 10).unwrap();
        let n = BigInt::mul(&p, &q);

        DecryptionKey {
            alpha: BigInt::from_str_radix(DP3072, 10).unwrap(),
            nn: BigInt::mul(&p, &q),
            n,
            p,
            q
        }
    }

    fn pgen(bs: usize) -> PrecomputeTableParams {
        // g = h^n mod n^2
        let (ek, _dk) = Self::gen().keys();
        let g = BigInt::mod_pow(&ek.h, &ek.n, &ek.nn);
        PrecomputeTableParams {
            g,
            block_size: bs,
            pow_size: ek.alpha_size,
            modulo: ek.nn,
        }
    }

    fn string() -> String {
        "NKeySize3072".to_string()
    }

}
fn get_precompute_table(s: usize) -> PrecomputeTable{
    let params = NKeySize3072::pgen(s);
    let table = PrecomputeTable::new_dp(
        params.g.clone(),
        params.block_size,
        params.pow_size,
        params.modulo.clone(),
    );
    return table;
}

fn main() {
    for i in 1..33 {
        let table = get_precompute_table(i);
        println!("Table size {}: {}",i,  table.size_in_bytes());
    }
}
