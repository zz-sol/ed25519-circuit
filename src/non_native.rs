use crate::lookup::ByteLookupTable;
use num_bigint::BigUint;
use num_traits::{One, Zero};
use p3_baby_bear::BabyBear;
use p3_field::{PrimeCharacteristicRing, PrimeField32};

pub const LIMBS: usize = 16;

const MODULUS_LIMBS: [u32; LIMBS] = [
    65517, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535,
    65535, 65535, 32767,
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NonNativeFieldElement {
    pub limbs: [BabyBear; LIMBS],
}

impl NonNativeFieldElement {
    pub fn zero() -> Self {
        Self {
            limbs: [BabyBear::ZERO; LIMBS],
        }
    }

    pub fn one() -> Self {
        let mut limbs = [BabyBear::ZERO; LIMBS];
        limbs[0] = BabyBear::ONE;
        Self { limbs }
    }

    pub fn from_u32(x: u32) -> Self {
        Self::from_biguint(BigUint::from(x))
    }

    pub fn from_limbs_u32(limbs: [u32; LIMBS]) -> Self {
        let limbs = limbs.map(BabyBear::from_u32);
        Self { limbs }.normalize()
    }

    pub fn from_ed25519_le_bytes(bytes: [u8; 32]) -> Self {
        Self::from_biguint(BigUint::from_bytes_le(&bytes))
    }

    pub fn from_ed25519_le_bytes_strict(bytes: [u8; 32]) -> Option<Self> {
        let n = BigUint::from_bytes_le(&bytes);
        if n >= modulus() {
            return None;
        }
        Some(Self::from_biguint(n))
    }

    pub fn to_ed25519_le_bytes(self) -> [u8; 32] {
        let mut out = [0_u8; 32];
        let bytes = self.to_biguint().to_bytes_le();
        let n = bytes.len().min(32);
        out[..n].copy_from_slice(&bytes[..n]);
        out
    }

    pub fn add(self, rhs: Self) -> Self {
        let p = modulus();
        let out = (self.to_biguint() + rhs.to_biguint()) % &p;
        Self::from_biguint(out)
    }

    pub fn sub(self, rhs: Self) -> Self {
        let a = self.to_biguint();
        let b = rhs.to_biguint();
        let p = modulus();
        if a >= b {
            Self::from_biguint(a - b)
        } else {
            Self::from_biguint((&a + &p) - b)
        }
    }

    pub fn neg(self) -> Self {
        Self::zero().sub(self)
    }

    pub fn mul(self, rhs: Self) -> Self {
        let p = modulus();
        let out = (self.to_biguint() * rhs.to_biguint()) % &p;
        Self::from_biguint(out)
    }

    pub fn square(self) -> Self {
        self.mul(self)
    }

    pub fn pow_p_minus_2(self) -> Self {
        let p = modulus();
        let exp = &p - BigUint::from(2_u32);
        Self::from_biguint(self.to_biguint().modpow(&exp, &p))
    }

    pub fn inv(self) -> Self {
        self.pow_p_minus_2()
    }

    pub fn is_zero(self) -> bool {
        self.to_biguint().is_zero()
    }

    pub fn lookup_range_check(self, table: &ByteLookupTable) -> bool {
        table.all_limbs_in_u16_range(&self.limbs)
    }

    pub fn limbs_u32(self) -> [u32; LIMBS] {
        self.limbs.map(|x| x.as_canonical_u32())
    }

    pub fn normalize(self) -> Self {
        Self::from_biguint(self.to_biguint())
    }

    pub fn to_biguint(self) -> BigUint {
        let mut bytes = [0_u8; 32];
        for (i, limb) in self.limbs_u32().into_iter().enumerate() {
            bytes[2 * i] = (limb & 0xff) as u8;
            bytes[(2 * i) + 1] = (limb >> 8) as u8;
        }
        BigUint::from_bytes_le(&bytes)
    }

    pub fn from_biguint(mut n: BigUint) -> Self {
        let p = modulus();
        n %= &p;
        let mut bytes = n.to_bytes_le();
        bytes.resize(32, 0);

        let mut limbs = [0_u32; LIMBS];
        for i in 0..LIMBS {
            limbs[i] = (bytes[2 * i] as u32) | ((bytes[(2 * i) + 1] as u32) << 8);
        }
        // Ensure top bit is canonical for p = 2^255 - 19.
        limbs[15] &= 0x7fff;
        Self {
            limbs: limbs.map(BabyBear::from_u32),
        }
    }
}

fn modulus() -> BigUint {
    // p = 2^255 - 19
    (BigUint::one() << 255) - BigUint::from(19_u32)
}

#[allow(dead_code)]
fn modulus_limbs() -> [u32; LIMBS] {
    MODULUS_LIMBS
}

#[cfg(test)]
mod tests {
    use super::*;

    fn next_u64(state: &mut u64) -> u64 {
        // xorshift64*
        *state ^= *state >> 12;
        *state ^= *state << 25;
        *state ^= *state >> 27;
        state.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn random_fe(state: &mut u64) -> NonNativeFieldElement {
        loop {
            let mut bytes = [0_u8; 32];
            for chunk in bytes.chunks_exact_mut(8) {
                chunk.copy_from_slice(&next_u64(state).to_le_bytes());
            }
            // Sample in [0, 2^255) and reject if not canonical for ed25519 field.
            bytes[31] &= 0x7f;
            if let Some(fe) = NonNativeFieldElement::from_ed25519_le_bytes_strict(bytes) {
                return fe;
            }
        }
    }

    #[test]
    fn add_sub_roundtrip() {
        let a = NonNativeFieldElement::from_u32(42);
        let b = NonNativeFieldElement::from_u32(99);
        let c = a.add(b);
        assert_eq!(c.sub(b), a);
    }

    #[test]
    fn mul_inv_roundtrip() {
        let a = NonNativeFieldElement::from_u32(123456);
        let inv = a.inv();
        let one = a.mul(inv);
        assert_eq!(one, NonNativeFieldElement::one());
    }

    #[test]
    fn byte_lookup_range_check_accepts_canonical() {
        let table = ByteLookupTable::default();
        let a = NonNativeFieldElement::from_u32(7);
        assert!(a.lookup_range_check(&table));
    }

    #[test]
    fn strict_bytes_accepts_canonical_rejects_modulus() {
        let p_minus_1 = [
            0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0x7f,
        ];
        let p = [
            0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0x7f,
        ];
        assert!(NonNativeFieldElement::from_ed25519_le_bytes_strict(p_minus_1).is_some());
        assert!(NonNativeFieldElement::from_ed25519_le_bytes_strict(p).is_none());
    }

    #[test]
    fn random_add_sub_roundtrip_many() {
        let mut state = 0x9E37_79B9_7F4A_7C15;
        for _ in 0..512 {
            let a = random_fe(&mut state);
            let b = random_fe(&mut state);
            assert_eq!(a.add(b).sub(b), a);
            assert_eq!(a.sub(b).add(b), a);
        }
    }

    #[test]
    fn random_mul_matches_biguint_reference() {
        let mut state = 0xD1B5_4A32_D192_ED03;
        let p = modulus();
        for _ in 0..512 {
            let a = random_fe(&mut state);
            let b = random_fe(&mut state);
            let got = a.mul(b).to_biguint();
            let want = (a.to_biguint() * b.to_biguint()) % &p;
            assert_eq!(got, want);
        }
    }

    #[test]
    fn random_square_matches_mul_self() {
        let mut state = 0xA24B_AED4_963E_E407;
        for _ in 0..512 {
            let a = random_fe(&mut state);
            assert_eq!(a.square(), a.mul(a));
        }
    }

    #[test]
    fn random_inv_roundtrip_for_non_zero() {
        let mut state = 0x3C79_AC49_2BA7_B653;
        for _ in 0..512 {
            let mut a = random_fe(&mut state);
            if a.is_zero() {
                a = NonNativeFieldElement::one();
            }
            let inv = a.inv();
            assert_eq!(a.mul(inv), NonNativeFieldElement::one());
            assert_eq!(inv.mul(a), NonNativeFieldElement::one());
        }
    }
}
