use p3_baby_bear::BabyBear;
use p3_field::{Field, PrimeCharacteristicRing, PrimeField32};

#[derive(Clone, Debug)]
pub struct ByteLookupTable {
    pub table: [BabyBear; 256],
}

impl Default for ByteLookupTable {
    fn default() -> Self {
        let table = core::array::from_fn(|i| BabyBear::from_u8(i as u8));
        Self { table }
    }
}

impl ByteLookupTable {
    pub fn contains_u8(&self, value: BabyBear) -> bool {
        let v = value.as_canonical_u32();
        v <= 255 && self.table[v as usize] == value
    }

    pub fn contains_u16_via_bytes(&self, value: BabyBear) -> bool {
        let x = value.as_canonical_u32();
        if x > u16::MAX as u32 {
            return false;
        }
        let lo = BabyBear::from_u8((x & 0xff) as u8);
        let hi = BabyBear::from_u8((x >> 8) as u8);
        self.contains_u8(lo) && self.contains_u8(hi)
    }

    pub fn all_limbs_in_u16_range<const N: usize>(&self, limbs: &[BabyBear; N]) -> bool {
        limbs.iter().all(|limb| self.contains_u16_via_bytes(*limb))
    }

    pub fn logup_multiset_pairs<const N: usize>(
        &self,
        limbs: &[BabyBear; N],
    ) -> Vec<(BabyBear, BabyBear)> {
        let mut pairs = Vec::with_capacity(2 * N);
        for limb in limbs {
            let x = limb.as_canonical_u32();
            let lo = BabyBear::from_u8((x & 0xff) as u8);
            let hi = BabyBear::from_u8((x >> 8) as u8);
            pairs.push((lo, lo));
            pairs.push((hi, hi));
        }
        pairs
    }

    pub fn verify_logup_pairs(&self, pairs: &[(BabyBear, BabyBear)], challenge: BabyBear) -> bool {
        self.logup_delta(pairs, challenge)
            .map(|delta| delta == BabyBear::ZERO)
            .unwrap_or(false)
    }

    pub fn logup_delta(
        &self,
        pairs: &[(BabyBear, BabyBear)],
        challenge: BabyBear,
    ) -> Option<BabyBear> {
        let mut acc = BabyBear::ZERO;
        for (witness, table_value) in pairs {
            if *witness == challenge || *table_value == challenge {
                return None;
            }
            if !self.contains_u8(*table_value) {
                return None;
            }
            acc += (challenge - *witness).inverse() - (challenge - *table_value).inverse();
        }
        Some(acc)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn logup_pairs_verify_for_honest_pairs() {
        let table = ByteLookupTable::default();
        let limbs = [BabyBear::from_u32(0x1234), BabyBear::from_u32(0xabcd)];
        let pairs = table.logup_multiset_pairs(&limbs);
        let challenge = BabyBear::from_u32(1 << 20);
        assert!(table.verify_logup_pairs(&pairs, challenge));
    }

    #[test]
    fn logup_pairs_reject_tamper() {
        let table = ByteLookupTable::default();
        let limbs = [BabyBear::from_u32(0x00ff)];
        let mut pairs = table.logup_multiset_pairs(&limbs);
        pairs[0].0 = BabyBear::from_u8(7);
        let challenge = BabyBear::from_u32((1 << 20) + 7);
        assert!(!table.verify_logup_pairs(&pairs, challenge));
    }
}
