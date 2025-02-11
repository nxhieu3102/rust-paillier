use std::mem;
use curv::arithmetic::{BitManipulation, Modulo, One};
use curv::BigInt;
use crate::optimized_paillier::{OptimizedPaillier, PowWithPrecomputeTable, PrecomputeTable};

// Precompute table to calculate: g^x (g is a constant)
impl PrecomputeTable {
    fn calculate_table(
        g: &BigInt,
        block_size: usize,
        pow_size: usize,
        modulo: &BigInt,
    ) -> Vec<Vec<BigInt>>
    {
        // let i_min = 1 as usize;
        let i_max = pow_size / block_size + if (pow_size % block_size) > 0 { 1 } else { 0 };
        // let j_min = 0 as usize;
        let j_max = (1 << block_size) - 1;

        // table[i][j] = [g^(2^(ib))]^j mod modulo
        let mut table = vec![vec![BigInt::one(); j_max + 1]; i_max + 1];

        for i in 0..=i_max {
            for j in 0..=j_max {
                let tmp1 = BigInt::mod_pow(
                    &BigInt::from(2),
                    &BigInt::from((i * block_size) as u32),
                    &modulo,
                );
                let tmp2 = BigInt::mod_pow(&g, &tmp1, &modulo);
                let tmp3 = BigInt::mod_pow(&tmp2, &BigInt::from(j as u32), &modulo);
                table[i][j] = tmp3;
            }
        }

        table
    }

    fn calculate_table_dp(
        g: &BigInt,
        block_size: usize,
        pow_size: usize,
        modulo: &BigInt,
    ) -> Vec<Vec<BigInt>>
    {
        // let i_min = 1 as usize;
        let i_max = pow_size / block_size + if (pow_size % block_size) > 0 { 1 } else { 0 };
        // let j_min = 0 as usize;
        let j_max = (1 << block_size) - 1;
        // table[i][j] = [g^(2^(ib))]^j mod modulo
        let mut table = vec![vec![BigInt::one(); j_max + 1]; i_max + 1];

        // base case 0: i = 0, j = 0, table[0][0] = 1

        // base case 1: i = 0, for all j, table[0][j] = [g^(2^(0b))]^j mod modulo = g^j mod modulo
        // table[0][j] = table[0][j - 1] * g mod modulo
        for j in 1..=j_max {
            table[0][j] = BigInt::mod_mul(&table[0][j - 1], &g, &modulo);
        }

        // base case 2: j = 0, for all i, table[i][0] = [g^(2^(ib))]^0 mod modulo = 1
        // already done because by default, all elements in table are 1

        // for all i > 0, table[i][1] = (table[i - 1][1])^(2^b), where b is block_size
        // 2^b as a constant
        let two_pow_b =
            BigInt::mod_pow(&BigInt::from(2), &BigInt::from(block_size as u32), &modulo);

        for i in 1..=i_max {
            table[i][1] = BigInt::mod_pow(&table[i - 1][1], &two_pow_b, &modulo);
        }


        // for i >= 1 and j >= 2: table[i][j] = table[i][j - 1] . table[i][1]
        for i in 1..=i_max {
            for j in 2..=j_max {
                table[i][j] = BigInt::mod_mul(&table[i][j - 1], &table[i][1], &modulo);
            }
        }

        table
    }

    pub fn new(g: BigInt, block_size: usize, pow_size: usize, modulo: BigInt) -> Self {
        let table = Self::calculate_table(&g, block_size, pow_size, &modulo);

        PrecomputeTable {
            table,
            block_size,
            pow_size,
            modulo,
        }
    }

    pub fn new_dp(g: BigInt, block_size: usize, pow_size: usize, modulo: BigInt) -> Self {
        let table = Self::calculate_table_dp(&g, block_size, pow_size, &modulo);

        PrecomputeTable {
            table,
            block_size,
            pow_size,
            modulo,
        }
    }
    pub fn size_in_bytes(&self) -> usize {
        let mut size = 0;
        for row in &self.table {
            size += row.len() * mem::size_of::<BigInt>();
        }
        size
    }

}

impl PowWithPrecomputeTable<PrecomputeTable, BigInt, usize> for OptimizedPaillier {
    fn calculate_precompute_table(
        g: BigInt,
        block_size: usize,
        pow_size: usize,
        modulo: BigInt,
    ) -> PrecomputeTable {
        PrecomputeTable::new(g, block_size, pow_size, modulo)
    }

    fn calculate_precompute_table_with_dp(
        g: BigInt,
        block_size: usize,
        pow_size: usize,
        modulo: BigInt,
    ) -> PrecomputeTable {
        PrecomputeTable::new_dp(g, block_size, pow_size, modulo)
    }

    fn convert_into_block(precompute_table: &PrecomputeTable, x: &BigInt) -> Vec<usize> {
        // convert bigint --> list of bits
        // block_size bits --> group (right to left)
        // each group --> usize/u64/...
        let block_size = precompute_table.block_size;
        let pow_size = precompute_table.pow_size;
        let num_block = pow_size / block_size + if (pow_size % block_size) > 0 { 1 } else { 0 };

        let mut result = vec![0; num_block];

        for bit_id in 0..pow_size {
            if x.test_bit(bit_id) {
                // bit_id in is the (bit_id % block_size) bit of group (bit_id / block_size)
                // turn on the (bit_id % block_size) bit of group (bit_id / block_size)
                let block_id = bit_id / block_size;
                let bit_id = bit_id % block_size;
                result[block_id] |= 1 << bit_id;
            }
        }

        result
    }

    fn pow(precompute_table: &PrecomputeTable, pow: &BigInt) -> BigInt {
        let pow_blocks = Self::convert_into_block(&precompute_table, &pow);
        let mut result = BigInt::one();

        for (id, pow_block) in pow_blocks.iter().enumerate() {
            result = BigInt::mod_mul(
                &result,
                &precompute_table.table[id][*pow_block],
                &precompute_table.modulo,
            );
        }

        result
    }
}