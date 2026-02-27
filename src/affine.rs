use num_bigint::BigUint;

use crate::non_native_field::Ed25519BaseField;
use crate::non_native_field::sound::{SoundFieldChip, SoundFieldError};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AffinePoint {
    pub x: Ed25519BaseField,
    pub y: Ed25519BaseField,
}

impl AffinePoint {
    pub fn identity() -> Self {
        Self {
            x: Ed25519BaseField::zero(),
            y: Ed25519BaseField::one(),
        }
    }

    pub fn basepoint() -> Self {
        Self {
            x: Ed25519BaseField::from_biguint(decimal_biguint(
                "15112221349535400772501151409588531511454012693041857206046113283949847762202",
            )),
            y: Ed25519BaseField::from_biguint(decimal_biguint(
                "46316835694926478169428394003475163141307993866256225615783033603165251855960",
            )),
        }
    }

    pub fn is_on_curve(&self) -> bool {
        // For ed25519 twisted Edwards: -x^2 + y^2 = 1 + d*x^2*y^2
        let x2 = self.x.square_mod();
        let y2 = self.y.square_mod();
        let lhs = y2.sub_mod(&x2);

        let d = curve_d();
        let rhs = Ed25519BaseField::one().add_mod(&d.mul_mod(&x2.mul_mod(&y2)));
        lhs == rhs
    }

    pub fn add(&self, rhs: &Self, chip: &mut SoundFieldChip) -> Result<Self, SoundFieldError> {
        // Affine formulas for a = -1 twisted Edwards curve.
        let x1y2 = chip.mul(&self.x, &rhs.y)?;
        let y1x2 = chip.mul(&self.y, &rhs.x)?;
        let y1y2 = chip.mul(&self.y, &rhs.y)?;
        let x1x2 = chip.mul(&self.x, &rhs.x)?;

        let x_num = chip.add(&x1y2, &y1x2)?;
        // y numerator uses -a*x1*x2, and ed25519 has a = -1.
        let y_num = chip.add(&y1y2, &x1x2)?;

        let d = curve_d();
        let xxyy = chip.mul(&x1x2, &y1y2)?;
        let dxxyy = chip.mul(&d, &xxyy)?;

        let x_den = chip.add(&Ed25519BaseField::one(), &dxxyy)?;
        let y_den = chip.sub(&Ed25519BaseField::one(), &dxxyy)?;

        let x_den_inv = chip.inv(&x_den)?;
        let y_den_inv = chip.inv(&y_den)?;

        let x3 = chip.mul(&x_num, &x_den_inv)?;
        let y3 = chip.mul(&y_num, &y_den_inv)?;

        Ok(Self { x: x3, y: y3 })
    }

    pub fn double(&self, chip: &mut SoundFieldChip) -> Result<Self, SoundFieldError> {
        self.add(self, chip)
    }

    pub fn scalar_mul_le(
        &self,
        scalar_le: [u8; 32],
        chip: &mut SoundFieldChip,
    ) -> Result<Self, SoundFieldError> {
        let mut acc = Self::identity();
        let mut cur = self.clone();

        for byte in scalar_le {
            for bit in 0..8 {
                if ((byte >> bit) & 1) == 1 {
                    acc = acc.add(&cur, chip)?;
                }
                cur = cur.double(chip)?;
            }
        }

        Ok(acc)
    }

    pub fn compress(&self) -> [u8; 32] {
        let mut out = self.y.to_bytes_le();
        let sign = (self.x.to_biguint() & BigUint::from(1u32)) == BigUint::from(1u32);
        if sign {
            out[31] |= 0x80;
        } else {
            out[31] &= 0x7f;
        }
        out
    }
}

fn curve_d() -> Ed25519BaseField {
    // d = -121665 / 121666 mod p
    let minus_121665 = Ed25519BaseField::from_u64(121665).neg_mod();
    let inv_121666 = Ed25519BaseField::from_u64(121666)
        .inv_mod()
        .expect("121666 must be invertible in ed25519 base field");
    minus_121665.mul_mod(&inv_121666)
}

fn decimal_biguint(decimal: &str) -> BigUint {
    BigUint::parse_bytes(decimal.as_bytes(), 10).expect("invalid decimal constant")
}

#[cfg(test)]
mod tests {
    use super::AffinePoint;
    use crate::non_native_field::sound::SoundFieldChip;
    use curve25519::{Scalar, constants::ED25519_BASEPOINT_POINT};
    use rand::{RngCore, SeedableRng, rngs::SmallRng};

    #[test]
    fn basepoint_is_on_curve() {
        assert!(AffinePoint::basepoint().is_on_curve());
    }

    #[test]
    fn randomized_scalar_mul_matches_reference() {
        let mut rng = SmallRng::seed_from_u64(0x1234_5678_9abc_def0);

        for _ in 0..40 {
            let mut k_bytes = [0u8; 32];
            rng.fill_bytes(&mut k_bytes);

            let mut chip = SoundFieldChip::default();
            let ours = AffinePoint::basepoint()
                .scalar_mul_le(k_bytes, &mut chip)
                .unwrap();

            let k = Scalar::from_bytes_mod_order(k_bytes);
            let reference = (ED25519_BASEPOINT_POINT * k).compress().to_bytes();

            assert_eq!(ours.compress(), reference);
        }
    }

    #[test]
    fn randomized_group_add_matches_reference() {
        let mut rng = SmallRng::seed_from_u64(0xfeed_beef_cafe_f00d);

        for _ in 0..30 {
            let mut a_bytes = [0u8; 32];
            let mut b_bytes = [0u8; 32];
            rng.fill_bytes(&mut a_bytes);
            rng.fill_bytes(&mut b_bytes);

            let mut chip = SoundFieldChip::default();
            let g = AffinePoint::basepoint();
            let pa = g.scalar_mul_le(a_bytes, &mut chip).unwrap();
            let pb = g.scalar_mul_le(b_bytes, &mut chip).unwrap();
            let sum = pa.add(&pb, &mut chip).unwrap();

            let a = Scalar::from_bytes_mod_order(a_bytes);
            let b = Scalar::from_bytes_mod_order(b_bytes);
            let reference = (ED25519_BASEPOINT_POINT * a + ED25519_BASEPOINT_POINT * b)
                .compress()
                .to_bytes();

            assert_eq!(sum.compress(), reference);
            assert!(sum.is_on_curve());
        }
    }
}
