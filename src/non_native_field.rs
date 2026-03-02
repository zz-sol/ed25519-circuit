use num_bigint::BigUint;
use num_traits::{One, Zero};
use p3_baby_bear::BabyBear;
use p3_field::PrimeField64;
use rand::RngCore;

pub mod air;
pub mod proof;
pub mod sound;

pub const LIMB_BITS: usize = 16;
pub const N_LIMBS: usize = 16;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ed25519BaseField {
    limbs: [BabyBear; N_LIMBS],
}

impl Ed25519BaseField {
    pub fn zero() -> Self {
        Self::from_u64(0)
    }

    pub fn one() -> Self {
        Self::from_u64(1)
    }

    pub fn from_u64(value: u64) -> Self {
        Self::from_biguint(BigUint::from(value))
    }

    pub fn random<R: RngCore>(rng: &mut R) -> Self {
        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes);
        bytes[31] &= 0x7f;
        Self::from_biguint(BigUint::from_bytes_le(&bytes))
    }

    pub fn from_bytes_le(bytes: [u8; 32]) -> Self {
        Self::from_biguint(BigUint::from_bytes_le(&bytes))
    }

    pub fn to_bytes_le(&self) -> [u8; 32] {
        let mut out = [0u8; 32];
        let bytes = self.to_biguint().to_bytes_le();
        out[..bytes.len()].copy_from_slice(&bytes);
        out
    }

    pub fn from_biguint(value: BigUint) -> Self {
        let reduced = value % Self::modulus();
        Self {
            limbs: Self::decompose_to_limbs(&reduced),
        }
    }

    pub fn to_biguint(&self) -> BigUint {
        let mut acc = BigUint::zero();
        for (i, limb) in self.limbs.iter().enumerate() {
            let v = limb.as_canonical_u64() as u16;
            acc += BigUint::from(v) << (i * LIMB_BITS);
        }
        acc
    }

    pub fn modulus() -> BigUint {
        (BigUint::one() << 255u32) - BigUint::from(19u32)
    }

    pub fn add_mod(&self, rhs: &Self) -> Self {
        Self::from_biguint(self.to_biguint() + rhs.to_biguint())
    }

    pub fn sub_mod(&self, rhs: &Self) -> Self {
        let p = Self::modulus();
        let lhs = self.to_biguint();
        let rhs_v = rhs.to_biguint();
        let out = if lhs >= rhs_v {
            lhs - rhs_v
        } else {
            lhs + p - rhs_v
        };
        Self::from_biguint(out)
    }

    pub fn neg_mod(&self) -> Self {
        if self.is_zero() {
            return Self::zero();
        }
        Self::from_biguint(Self::modulus() - self.to_biguint())
    }

    pub fn mul_mod(&self, rhs: &Self) -> Self {
        Self::from_biguint(self.to_biguint() * rhs.to_biguint())
    }

    pub fn square_mod(&self) -> Self {
        self.mul_mod(self)
    }

    pub fn inv_mod(&self) -> Option<Self> {
        if self.is_zero() {
            return None;
        }
        let p = Self::modulus();
        let exp = &p - BigUint::from(2u32);
        Some(Self::from_biguint(self.to_biguint().modpow(&exp, &p)))
    }

    pub fn is_zero(&self) -> bool {
        self.limbs.iter().all(|x| x.as_canonical_u64() == 0)
    }

    pub fn limbs(&self) -> &[BabyBear; N_LIMBS] {
        &self.limbs
    }

    fn decompose_to_limbs(value: &BigUint) -> [BabyBear; N_LIMBS] {
        let mask = (BigUint::one() << LIMB_BITS) - BigUint::one();
        let mut tmp = value.clone();
        let mut out = [BabyBear::new(0); N_LIMBS];

        for limb in &mut out {
            let limb_u16 = (&tmp & &mask).to_u32_digits().first().copied().unwrap_or(0) as u16;
            *limb = BabyBear::new(limb_u16 as u32);
            tmp >>= LIMB_BITS;
        }

        out
    }
}

#[cfg(test)]
mod tests {
    use super::Ed25519BaseField;
    use num_bigint::BigUint;
    use rand::{SeedableRng, rngs::SmallRng};

    #[test]
    fn randomized_field_arithmetic_matches_reference() {
        let mut rng = SmallRng::seed_from_u64(0xdecafbad_u64);
        let p = Ed25519BaseField::modulus();

        for _ in 0..256 {
            let a = Ed25519BaseField::random(&mut rng);
            let b = Ed25519BaseField::random(&mut rng);

            let a_ref = a.to_biguint();
            let b_ref = b.to_biguint();

            let add_ref = (&a_ref + &b_ref) % &p;
            let sub_ref = if a_ref >= b_ref {
                &a_ref - &b_ref
            } else {
                &a_ref + &p - &b_ref
            };
            let mul_ref = (&a_ref * &b_ref) % &p;

            assert_eq!(a.add_mod(&b).to_biguint(), add_ref);
            assert_eq!(a.sub_mod(&b).to_biguint(), sub_ref);
            assert_eq!(a.mul_mod(&b).to_biguint(), mul_ref);

            if !a.is_zero() {
                let inv = a.inv_mod().unwrap();
                let should_be_one = (&a_ref * inv.to_biguint()) % &p;
                assert_eq!(should_be_one, BigUint::from(1u32));
            }
        }
    }
}
