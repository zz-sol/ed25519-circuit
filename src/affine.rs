use crate::non_native::NonNativeFieldElement;
use num_bigint::BigUint;
use num_traits::{One, Zero};

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AffinePoint {
    pub x: NonNativeFieldElement,
    pub y: NonNativeFieldElement,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AffineAddWitness {
    pub lhs: AffinePoint,
    pub rhs: AffinePoint,
    pub x1x2: NonNativeFieldElement,
    pub y1y2: NonNativeFieldElement,
    pub x1y2: NonNativeFieldElement,
    pub y1x2: NonNativeFieldElement,
    pub dxxyy: NonNativeFieldElement,
    pub x_num: NonNativeFieldElement,
    pub y_num: NonNativeFieldElement,
    pub x_den: NonNativeFieldElement,
    pub y_den: NonNativeFieldElement,
    pub x_den_inv: NonNativeFieldElement,
    pub y_den_inv: NonNativeFieldElement,
    pub out: AffinePoint,
}

const D_LIMBS: [u32; 16] = [
    30883, 4953, 19914, 30187, 55467, 16705, 2637, 112, 59544, 30585, 16505, 36039, 65139, 11119,
    27886, 20995,
];

const BASE_X_LIMBS: [u32; 16] = [
    54554, 36645, 11616, 51542, 42930, 38181, 51040, 26924, 56412, 64982, 57905, 49316, 21502,
    52590, 14035, 8553,
];

const BASE_Y_LIMBS: [u32; 16] = [
    26200, 26214, 26214, 26214, 26214, 26214, 26214, 26214, 26214, 26214, 26214, 26214, 26214,
    26214, 26214, 26214,
];

const SUBGROUP_ORDER_LE_BYTES: [u8; 32] = [
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
];

impl AffinePoint {
    pub fn identity() -> Self {
        Self {
            x: NonNativeFieldElement::zero(),
            y: NonNativeFieldElement::one(),
        }
    }

    pub fn d() -> NonNativeFieldElement {
        NonNativeFieldElement::from_limbs_u32(D_LIMBS)
    }

    pub fn is_on_curve(self) -> bool {
        let x2 = self.x.square();
        let y2 = self.y.square();
        let lhs = y2.sub(x2);
        let rhs = NonNativeFieldElement::one().add(Self::d().mul(x2).mul(y2));
        lhs == rhs
    }

    pub fn add(self, rhs: Self) -> Self {
        self.add_with_witness(rhs).out
    }

    pub fn add_with_witness(self, rhs: Self) -> AffineAddWitness {
        let x1x2 = self.x.mul(rhs.x);
        let y1y2 = self.y.mul(rhs.y);
        let x1y2 = self.x.mul(rhs.y);
        let y1x2 = self.y.mul(rhs.x);
        let dxxyy = Self::d().mul(x1x2).mul(y1y2);

        let one = NonNativeFieldElement::one();
        let x_num = x1y2.add(y1x2);
        let y_num = y1y2.add(x1x2);
        let x_den = one.add(dxxyy);
        let y_den = one.sub(dxxyy);
        let x_den_inv = x_den.inv();
        let y_den_inv = y_den.inv();

        let x3 = x_num.mul(x_den_inv);
        let y3 = y_num.mul(y_den_inv);
        AffineAddWitness {
            lhs: self,
            rhs,
            x1x2,
            y1y2,
            x1y2,
            y1x2,
            dxxyy,
            x_num,
            y_num,
            x_den,
            y_den,
            x_den_inv,
            y_den_inv,
            out: Self { x: x3, y: y3 },
        }
    }

    pub fn double(self) -> Self {
        self.add(self)
    }

    pub fn scalar_mul(self, scalar_le_bytes: [u8; 32]) -> Self {
        let mut acc = Self::identity();
        for i in (0..256).rev() {
            acc = acc.double();
            let bit = (scalar_le_bytes[i / 8] >> (i % 8)) & 1;
            if bit == 1 {
                acc = acc.add(self);
            }
        }
        acc
    }

    pub fn compress(self) -> [u8; 32] {
        let mut bytes = self.y.to_ed25519_le_bytes();
        let x_is_odd = (self.x.limbs_u32()[0] & 1) == 1;
        if x_is_odd {
            bytes[31] |= 0x80;
        }
        bytes
    }

    pub fn from_compressed_bytes_strict(mut bytes: [u8; 32]) -> Option<Self> {
        let x_sign = (bytes[31] >> 7) & 1;
        bytes[31] &= 0x7f;
        let y = NonNativeFieldElement::from_ed25519_le_bytes_strict(bytes)?;

        let one = NonNativeFieldElement::one();
        let y2 = y.square();
        let u = y2.sub(one);
        let v = Self::d().mul(y2).add(one);
        let x2 = u.mul(v.inv());

        let mut x = sqrt_mod_p(x2.to_biguint())?;
        let parity = x.clone() & BigUint::one();
        let want = BigUint::from(x_sign as u8);
        if x.is_zero() {
            // Canonical encoding requires sign bit 0 when x == 0.
            if x_sign == 1 {
                return None;
            }
        } else if parity != want {
            x = ed25519_modulus() - x;
        }

        let p = Self {
            x: NonNativeFieldElement::from_biguint(x),
            y,
        };
        if !p.is_on_curve() || !p.is_in_prime_order_subgroup() {
            return None;
        }
        Some(p)
    }

    pub fn is_in_prime_order_subgroup(self) -> bool {
        self.scalar_mul(SUBGROUP_ORDER_LE_BYTES) == Self::identity()
    }

    pub fn to_uncompressed_bytes(self) -> [u8; 64] {
        let mut out = [0_u8; 64];
        out[..32].copy_from_slice(&self.x.to_ed25519_le_bytes());
        out[32..].copy_from_slice(&self.y.to_ed25519_le_bytes());
        out
    }

    pub fn from_uncompressed_bytes_strict(bytes: [u8; 64]) -> Option<Self> {
        let mut x_bytes = [0_u8; 32];
        let mut y_bytes = [0_u8; 32];
        x_bytes.copy_from_slice(&bytes[..32]);
        y_bytes.copy_from_slice(&bytes[32..]);
        let x = NonNativeFieldElement::from_ed25519_le_bytes_strict(x_bytes)?;
        let y = NonNativeFieldElement::from_ed25519_le_bytes_strict(y_bytes)?;
        let p = Self { x, y };
        if !p.is_on_curve() || !p.is_in_prime_order_subgroup() {
            return None;
        }
        Some(p)
    }
}

impl AffineAddWitness {
    pub fn verify(self) -> bool {
        if !self.lhs.is_on_curve() || !self.rhs.is_on_curve() || !self.out.is_on_curve() {
            return false;
        }
        let d = AffinePoint::d();
        let one = NonNativeFieldElement::one();

        if self.x1x2 != self.lhs.x.mul(self.rhs.x) {
            return false;
        }
        if self.y1y2 != self.lhs.y.mul(self.rhs.y) {
            return false;
        }
        if self.x1y2 != self.lhs.x.mul(self.rhs.y) {
            return false;
        }
        if self.y1x2 != self.lhs.y.mul(self.rhs.x) {
            return false;
        }
        if self.dxxyy != d.mul(self.x1x2).mul(self.y1y2) {
            return false;
        }
        if self.x_num != self.x1y2.add(self.y1x2) {
            return false;
        }
        if self.y_num != self.y1y2.add(self.x1x2) {
            return false;
        }
        if self.x_den != one.add(self.dxxyy) {
            return false;
        }
        if self.y_den != one.sub(self.dxxyy) {
            return false;
        }
        if self.x_den.mul(self.x_den_inv) != one {
            return false;
        }
        if self.y_den.mul(self.y_den_inv) != one {
            return false;
        }
        if self.out.x != self.x_num.mul(self.x_den_inv) {
            return false;
        }
        if self.out.y != self.y_num.mul(self.y_den_inv) {
            return false;
        }
        true
    }
}

pub fn ed25519_basepoint_affine() -> AffinePoint {
    AffinePoint {
        x: NonNativeFieldElement::from_limbs_u32(BASE_X_LIMBS),
        y: NonNativeFieldElement::from_limbs_u32(BASE_Y_LIMBS),
    }
}

fn ed25519_modulus() -> BigUint {
    (BigUint::one() << 255) - BigUint::from(19_u32)
}

fn sqrt_mod_p(n: BigUint) -> Option<BigUint> {
    let p = ed25519_modulus();
    if n >= p {
        return None;
    }
    if n == BigUint::zero() {
        return Some(n);
    }
    let exp = (&p + BigUint::from(3_u8)) >> 3;
    let mut x = n.modpow(&exp, &p);
    if (&x * &x) % &p != n {
        let i = BigUint::from(2_u8).modpow(&((&p - BigUint::one()) >> 2), &p);
        x = (&x * i) % &p;
        if (&x * &x) % &p != n {
            return None;
        }
    }
    Some(x)
}

#[cfg(test)]
mod tests {
    use super::*;
    use curve25519::constants::ED25519_BASEPOINT_TABLE;
    use curve25519::edwards::CompressedEdwardsY;
    use curve25519::scalar::Scalar;

    #[test]
    fn basepoint_is_on_curve() {
        assert!(ed25519_basepoint_affine().is_on_curve());
    }

    #[test]
    fn scalar_mul_matches_curve25519_sol_basepoint() {
        let base = ed25519_basepoint_affine();
        let samples = [
            [0_u8; 32],
            [1_u8; 32],
            [2_u8; 32],
            [7_u8; 32],
            [42_u8; 32],
            [255_u8; 32],
        ];
        for scalar_bytes in samples {
            let ours = base.scalar_mul(scalar_bytes).compress();
            let scalar = Scalar::from_bytes_mod_order(scalar_bytes);
            let expected = (&scalar * ED25519_BASEPOINT_TABLE).compress().to_bytes();
            assert_eq!(ours, expected);
        }
    }

    #[test]
    fn add_witness_roundtrip() {
        let p = ed25519_basepoint_affine();
        let q = p.double();
        let w = p.add_with_witness(q);
        assert!(w.verify());
        assert_eq!(w.out, p.add(q));
    }

    #[test]
    fn add_witness_rejects_tamper() {
        let p = ed25519_basepoint_affine();
        let q = p.double();
        let mut w = p.add_with_witness(q);
        w.x_num = w.x_num.add(NonNativeFieldElement::one());
        assert!(!w.verify());
    }

    #[test]
    fn subgroup_check_accepts_basepoint() {
        let p = ed25519_basepoint_affine();
        assert!(p.is_in_prime_order_subgroup());
    }

    #[test]
    fn subgroup_check_rejects_low_order_point() {
        let minus_one = NonNativeFieldElement::from_ed25519_le_bytes([
            0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0x7f,
        ]);
        let torsion2 = AffinePoint {
            x: NonNativeFieldElement::zero(),
            y: minus_one,
        };
        assert!(torsion2.is_on_curve());
        assert!(!torsion2.is_in_prime_order_subgroup());
    }

    #[test]
    fn strict_uncompressed_point_roundtrip() {
        let p = ed25519_basepoint_affine().scalar_mul([9_u8; 32]);
        let bytes = p.to_uncompressed_bytes();
        let decoded = AffinePoint::from_uncompressed_bytes_strict(bytes).expect("decode");
        assert_eq!(decoded, p);
    }

    #[test]
    fn strict_uncompressed_point_rejects_low_order() {
        let minus_one = NonNativeFieldElement::from_ed25519_le_bytes([
            0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0x7f,
        ]);
        let torsion2 = AffinePoint {
            x: NonNativeFieldElement::zero(),
            y: minus_one,
        };
        let bytes = torsion2.to_uncompressed_bytes();
        assert!(AffinePoint::from_uncompressed_bytes_strict(bytes).is_none());
    }

    #[test]
    fn compressed_point_roundtrip() {
        let p = ed25519_basepoint_affine().scalar_mul([17_u8; 32]);
        let enc = p.compress();
        let dec = AffinePoint::from_compressed_bytes_strict(enc).expect("decode");
        assert_eq!(dec, p);
    }

    #[test]
    fn compressed_point_rejects_non_canonical_y() {
        let enc = [
            0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0x7f,
        ];
        assert!(AffinePoint::from_compressed_bytes_strict(enc).is_none());
    }

    #[test]
    fn compressed_point_rejects_x_zero_with_sign_bit_set() {
        // Identity encodes as y=1 with sign bit 0; sign bit 1 is non-canonical.
        let mut enc = [0_u8; 32];
        enc[0] = 1;
        enc[31] |= 0x80;
        assert!(AffinePoint::from_compressed_bytes_strict(enc).is_none());
    }

    #[test]
    fn compressed_decode_matches_curve25519_sol_for_samples() {
        let base = ed25519_basepoint_affine();
        let samples = [
            [1_u8; 32],
            [2_u8; 32],
            [7_u8; 32],
            [42_u8; 32],
            [200_u8; 32],
        ];
        for scalar_bytes in samples {
            let p = base.scalar_mul(scalar_bytes);
            let enc = p.compress();
            let ours = AffinePoint::from_compressed_bytes_strict(enc).expect("ours decode");
            let theirs = CompressedEdwardsY(enc)
                .decompress()
                .expect("curve25519 decode");
            assert_eq!(ours.compress(), theirs.compress().to_bytes());
        }
    }
}
