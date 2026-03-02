use num_bigint::BigUint;

use crate::non_native_field::Ed25519BaseField;
use crate::non_native_field::sound::{SoundFieldChip, SoundFieldCost, SoundFieldError};

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct GroupOpCost {
    pub field_adds: usize,
    pub field_subs: usize,
    pub field_muls: usize,
    pub field_invs: usize,
}

impl GroupOpCost {
    fn record_add(&mut self) {
        self.field_adds += 1;
    }

    fn record_sub(&mut self) {
        self.field_subs += 1;
    }

    fn record_mul(&mut self) {
        self.field_muls += 1;
    }

    fn record_inv(&mut self) {
        self.field_invs += 1;
    }

    fn merge(&mut self, rhs: &Self) {
        self.field_adds += rhs.field_adds;
        self.field_subs += rhs.field_subs;
        self.field_muls += rhs.field_muls;
        self.field_invs += rhs.field_invs;
    }

    pub fn modeled_field_cost(&self) -> SoundFieldCost {
        let add_unit = SoundFieldChip::add_cost();
        let mul_unit = SoundFieldChip::mul_cost();
        let add_like = self.field_adds + self.field_subs;
        // In current implementation, inv enforces x * inv = 1 via one mul_sound check.
        let mul_like = self.field_muls + self.field_invs;
        SoundFieldCost {
            rows: add_like * add_unit.rows + mul_like * mul_unit.rows,
            columns: add_unit.columns.max(mul_unit.columns),
            arithmetic_constraints: add_like * add_unit.arithmetic_constraints
                + mul_like * mul_unit.arithmetic_constraints,
            boolean_constraints: add_like * add_unit.boolean_constraints
                + mul_like * mul_unit.boolean_constraints,
            range_lookups: add_like * add_unit.range_lookups + mul_like * mul_unit.range_lookups,
            carry_lookups: add_like * add_unit.carry_lookups + mul_like * mul_unit.carry_lookups,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GroupOpOutput {
    pub point: AffinePoint,
    pub cost: GroupOpCost,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GroupCurveCheckOutput {
    pub is_on_curve: bool,
    pub cost: GroupOpCost,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BatchGroupOpOutput {
    pub points: Vec<AffinePoint>,
    pub cost: GroupOpCost,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BatchGroupSumOutput {
    pub points: Vec<AffinePoint>,
    pub sum: AffinePoint,
    pub cost: GroupOpCost,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GroupEquationCheckOutput {
    pub is_satisfied: bool,
    pub cost: GroupOpCost,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MsmCheckOutput {
    pub result: AffinePoint,
    pub is_satisfied: bool,
    pub cost: GroupOpCost,
}

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

    pub fn neg(&self) -> Self {
        Self {
            x: self.x.neg_mod(),
            y: self.y.clone(),
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

    pub fn is_on_curve_sound(&self, chip: &mut SoundFieldChip) -> Result<bool, SoundFieldError> {
        Ok(self.is_on_curve_sound_with_cost(chip)?.is_on_curve)
    }

    pub fn is_on_curve_sound_with_cost(
        &self,
        chip: &mut SoundFieldChip,
    ) -> Result<GroupCurveCheckOutput, SoundFieldError> {
        let mut cost = GroupOpCost::default();
        let x2 = chip.square(&self.x)?;
        cost.record_mul();
        let y2 = chip.square(&self.y)?;
        cost.record_mul();
        let lhs = chip.sub(&y2, &x2)?;
        cost.record_sub();
        let x2y2 = chip.mul(&x2, &y2)?;
        cost.record_mul();
        let dxy = chip.mul(&curve_d(), &x2y2)?;
        cost.record_mul();
        let rhs = chip.add(&Ed25519BaseField::one(), &dxy)?;
        cost.record_add();

        Ok(GroupCurveCheckOutput {
            is_on_curve: lhs == rhs,
            cost,
        })
    }

    pub fn add(&self, rhs: &Self, chip: &mut SoundFieldChip) -> Result<Self, SoundFieldError> {
        Ok(self.add_with_cost(rhs, chip)?.point)
    }

    pub fn add_with_cost(
        &self,
        rhs: &Self,
        chip: &mut SoundFieldChip,
    ) -> Result<GroupOpOutput, SoundFieldError> {
        let mut cost = GroupOpCost::default();
        // Affine formulas for a = -1 twisted Edwards curve.
        let x1y2 = chip.mul(&self.x, &rhs.y)?;
        cost.record_mul();
        let y1x2 = chip.mul(&self.y, &rhs.x)?;
        cost.record_mul();
        let y1y2 = chip.mul(&self.y, &rhs.y)?;
        cost.record_mul();
        let x1x2 = chip.mul(&self.x, &rhs.x)?;
        cost.record_mul();

        let x_num = chip.add(&x1y2, &y1x2)?;
        cost.record_add();
        // y numerator uses -a*x1*x2, and ed25519 has a = -1.
        let y_num = chip.add(&y1y2, &x1x2)?;
        cost.record_add();

        let d = curve_d();
        let xxyy = chip.mul(&x1x2, &y1y2)?;
        cost.record_mul();
        let dxxyy = chip.mul(&d, &xxyy)?;
        cost.record_mul();

        let x_den = chip.add(&Ed25519BaseField::one(), &dxxyy)?;
        cost.record_add();
        let y_den = chip.sub(&Ed25519BaseField::one(), &dxxyy)?;
        cost.record_sub();

        let x_den_inv = chip.inv(&x_den)?;
        cost.record_inv();
        let y_den_inv = chip.inv(&y_den)?;
        cost.record_inv();

        let x3 = chip.mul(&x_num, &x_den_inv)?;
        cost.record_mul();
        let y3 = chip.mul(&y_num, &y_den_inv)?;
        cost.record_mul();

        Ok(GroupOpOutput {
            point: Self { x: x3, y: y3 },
            cost,
        })
    }

    pub fn sub(&self, rhs: &Self, chip: &mut SoundFieldChip) -> Result<Self, SoundFieldError> {
        Ok(self.sub_with_cost(rhs, chip)?.point)
    }

    pub fn sub_with_cost(
        &self,
        rhs: &Self,
        chip: &mut SoundFieldChip,
    ) -> Result<GroupOpOutput, SoundFieldError> {
        self.add_with_cost(&rhs.neg(), chip)
    }

    pub fn double(&self, chip: &mut SoundFieldChip) -> Result<Self, SoundFieldError> {
        Ok(self.double_with_cost(chip)?.point)
    }

    pub fn double_with_cost(
        &self,
        chip: &mut SoundFieldChip,
    ) -> Result<GroupOpOutput, SoundFieldError> {
        self.add_with_cost(self, chip)
    }

    pub fn scalar_mul_le(
        &self,
        scalar_le: [u8; 32],
        chip: &mut SoundFieldChip,
    ) -> Result<Self, SoundFieldError> {
        Ok(self.scalar_mul_le_with_cost(scalar_le, chip)?.point)
    }

    pub fn scalar_mul_le_with_cost(
        &self,
        scalar_le: [u8; 32],
        chip: &mut SoundFieldChip,
    ) -> Result<GroupOpOutput, SoundFieldError> {
        let mut acc = Self::identity();
        let mut cur = self.clone();
        let mut total_cost = GroupOpCost::default();

        for byte in scalar_le {
            for bit in 0..8 {
                if ((byte >> bit) & 1) == 1 {
                    let out = acc.add_with_cost(&cur, chip)?;
                    acc = out.point;
                    total_cost.merge(&out.cost);
                }
                let out = cur.double_with_cost(chip)?;
                cur = out.point;
                total_cost.merge(&out.cost);
            }
        }

        Ok(GroupOpOutput {
            point: acc,
            cost: total_cost,
        })
    }

    pub fn scalar_mul_le_ladder(
        &self,
        scalar_le: [u8; 32],
        chip: &mut SoundFieldChip,
    ) -> Result<Self, SoundFieldError> {
        Ok(self.scalar_mul_le_ladder_with_cost(scalar_le, chip)?.point)
    }

    pub fn scalar_mul_le_ladder_with_cost(
        &self,
        scalar_le: [u8; 32],
        chip: &mut SoundFieldChip,
    ) -> Result<GroupOpOutput, SoundFieldError> {
        // Keep one verified scalar-mul path for affine formulas.
        self.scalar_mul_le_with_cost(scalar_le, chip)
    }

    pub fn batch_scalar_mul_basepoint_le_with_cost(
        scalars_le: &[[u8; 32]],
        chip: &mut SoundFieldChip,
    ) -> Result<BatchGroupOpOutput, SoundFieldError> {
        let base = Self::basepoint();
        let mut points = Vec::with_capacity(scalars_le.len());
        let mut cost = GroupOpCost::default();

        for scalar in scalars_le {
            let out = base.scalar_mul_le_with_cost(*scalar, chip)?;
            points.push(out.point);
            cost.merge(&out.cost);
        }

        Ok(BatchGroupOpOutput { points, cost })
    }

    pub fn batch_scalar_mul_basepoint_le_sum_with_cost(
        scalars_le: &[[u8; 32]],
        chip: &mut SoundFieldChip,
    ) -> Result<BatchGroupSumOutput, SoundFieldError> {
        let batch = Self::batch_scalar_mul_basepoint_le_with_cost(scalars_le, chip)?;
        let mut sum = Self::identity();
        let mut cost = batch.cost.clone();

        for point in &batch.points {
            let add = sum.add_with_cost(point, chip)?;
            sum = add.point;
            cost.merge(&add.cost);
        }

        Ok(BatchGroupSumOutput {
            points: batch.points,
            sum,
            cost,
        })
    }

    pub fn msm_with_cost(
        points: &[AffinePoint],
        scalars_le: &[[u8; 32]],
        chip: &mut SoundFieldChip,
    ) -> Result<GroupOpOutput, SoundFieldError> {
        if points.len() != scalars_le.len() {
            return Err(SoundFieldError::ConstraintViolation(
                "points/scalars length mismatch",
            ));
        }

        let mut acc = Self::identity();
        let mut cost = GroupOpCost::default();

        for (point, scalar) in points.iter().zip(scalars_le.iter()) {
            let term = point.scalar_mul_le_with_cost(*scalar, chip)?;
            cost.merge(&term.cost);

            let add = acc.add_with_cost(&term.point, chip)?;
            acc = add.point;
            cost.merge(&add.cost);
        }

        Ok(GroupOpOutput { point: acc, cost })
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

pub fn check_add_equation_sound(
    p: &AffinePoint,
    q: &AffinePoint,
    expected: &AffinePoint,
    chip: &mut SoundFieldChip,
) -> Result<GroupEquationCheckOutput, SoundFieldError> {
    let out = p.add_with_cost(q, chip)?;
    Ok(GroupEquationCheckOutput {
        is_satisfied: out.point == *expected,
        cost: out.cost,
    })
}

pub fn check_scalar_mul_equation_sound(
    point: &AffinePoint,
    scalar_le: [u8; 32],
    expected: &AffinePoint,
    chip: &mut SoundFieldChip,
) -> Result<GroupEquationCheckOutput, SoundFieldError> {
    let out = point.scalar_mul_le_with_cost(scalar_le, chip)?;
    Ok(GroupEquationCheckOutput {
        is_satisfied: out.point == *expected,
        cost: out.cost,
    })
}

pub fn check_msm_equation_sound(
    points: &[AffinePoint],
    scalars_le: &[[u8; 32]],
    expected: &AffinePoint,
    chip: &mut SoundFieldChip,
) -> Result<MsmCheckOutput, SoundFieldError> {
    let out = AffinePoint::msm_with_cost(points, scalars_le, chip)?;
    Ok(MsmCheckOutput {
        result: out.point.clone(),
        is_satisfied: out.point == *expected,
        cost: out.cost,
    })
}

#[cfg(test)]
mod tests {
    use super::{
        AffinePoint, GroupOpCost, check_add_equation_sound, check_msm_equation_sound,
        check_scalar_mul_equation_sound,
    };
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

    #[test]
    fn group_cost_accounting_sanity() {
        let mut chip = SoundFieldChip::default();
        let g = AffinePoint::basepoint();
        let add = g.add_with_cost(&g, &mut chip).unwrap();
        assert_eq!(
            add.cost,
            GroupOpCost {
                field_adds: 3,
                field_subs: 1,
                field_muls: 8,
                field_invs: 2,
            }
        );
        let modeled = add.cost.modeled_field_cost();
        assert!(modeled.arithmetic_constraints > 0);
    }

    #[test]
    fn randomized_group_sub_matches_reference() {
        let mut rng = SmallRng::seed_from_u64(0x4242_1234_9999_abcd);

        for _ in 0..20 {
            let mut a_bytes = [0u8; 32];
            let mut b_bytes = [0u8; 32];
            rng.fill_bytes(&mut a_bytes);
            rng.fill_bytes(&mut b_bytes);

            let mut chip = SoundFieldChip::default();
            let g = AffinePoint::basepoint();
            let pa = g.scalar_mul_le(a_bytes, &mut chip).unwrap();
            let pb = g.scalar_mul_le(b_bytes, &mut chip).unwrap();
            let diff = pa.sub(&pb, &mut chip).unwrap();

            let a = Scalar::from_bytes_mod_order(a_bytes);
            let b = Scalar::from_bytes_mod_order(b_bytes);
            let reference = (ED25519_BASEPOINT_POINT * a + ED25519_BASEPOINT_POINT * (-b))
                .compress()
                .to_bytes();

            assert_eq!(diff.compress(), reference);
        }
    }

    #[test]
    fn ladder_scalar_mul_matches_reference() {
        let mut rng = SmallRng::seed_from_u64(0xabab_cdcd_1212_3434);
        let g = AffinePoint::basepoint();

        for _ in 0..20 {
            let mut k_bytes = [0u8; 32];
            rng.fill_bytes(&mut k_bytes);
            let mut chip = SoundFieldChip::default();
            let ours = g.scalar_mul_le_ladder(k_bytes, &mut chip).unwrap();

            let k = Scalar::from_bytes_mod_order(k_bytes);
            let reference = (ED25519_BASEPOINT_POINT * k).compress().to_bytes();
            assert_eq!(ours.compress(), reference);
        }
    }

    #[test]
    fn ladder_cost_path_matches_standard_path() {
        let mut rng = SmallRng::seed_from_u64(0x0011_2233_4455_6677);
        let g = AffinePoint::basepoint();

        for _ in 0..8 {
            let mut k = [0u8; 32];
            rng.fill_bytes(&mut k);
            let mut chip1 = SoundFieldChip::default();
            let mut chip2 = SoundFieldChip::default();

            let a = g.scalar_mul_le_with_cost(k, &mut chip1).unwrap();
            let b = g.scalar_mul_le_ladder_with_cost(k, &mut chip2).unwrap();
            assert_eq!(a.point, b.point);
            assert_eq!(a.cost, b.cost);
        }
    }

    #[test]
    fn sound_curve_check_matches_native_check() {
        let mut rng = SmallRng::seed_from_u64(0xabab_0000_1212_7777);
        let g = AffinePoint::basepoint();
        let mut chip = SoundFieldChip::default();

        for _ in 0..12 {
            let mut k = [0u8; 32];
            rng.fill_bytes(&mut k);
            let p = g.scalar_mul_le(k, &mut chip).unwrap();
            let native = p.is_on_curve();
            let sound = p.is_on_curve_sound(&mut chip).unwrap();
            assert_eq!(native, sound);
            assert!(sound);
        }
    }

    #[test]
    fn batch_basepoint_scalar_mul_matches_reference() {
        let mut rng = SmallRng::seed_from_u64(0x9988_7766_5544_3322);
        let mut chip = SoundFieldChip::default();
        let mut scalars = Vec::new();
        for _ in 0..6 {
            let mut k = [0u8; 32];
            rng.fill_bytes(&mut k);
            scalars.push(k);
        }

        let batch =
            AffinePoint::batch_scalar_mul_basepoint_le_with_cost(&scalars, &mut chip).unwrap();
        assert_eq!(batch.points.len(), scalars.len());

        for (idx, k_bytes) in scalars.iter().enumerate() {
            let k = Scalar::from_bytes_mod_order(*k_bytes);
            let reference = (ED25519_BASEPOINT_POINT * k).compress().to_bytes();
            assert_eq!(batch.points[idx].compress(), reference);
        }
        assert!(batch.cost.field_muls > 0);
    }

    #[test]
    fn batch_basepoint_scalar_mul_sum_matches_reference() {
        let mut rng = SmallRng::seed_from_u64(0x0102_0304_0506_0708);
        let mut chip = SoundFieldChip::default();
        let mut scalars = Vec::new();
        for _ in 0..5 {
            let mut k = [0u8; 32];
            rng.fill_bytes(&mut k);
            scalars.push(k);
        }

        let out =
            AffinePoint::batch_scalar_mul_basepoint_le_sum_with_cost(&scalars, &mut chip).unwrap();
        assert_eq!(out.points.len(), scalars.len());

        let mut reference_sum = ED25519_BASEPOINT_POINT * Scalar::from_bytes_mod_order([0u8; 32]);
        for k in &scalars {
            reference_sum += ED25519_BASEPOINT_POINT * Scalar::from_bytes_mod_order(*k);
        }
        assert_eq!(out.sum.compress(), reference_sum.compress().to_bytes());
    }

    #[test]
    fn add_equation_check_detects_valid_and_invalid() {
        let mut rng = SmallRng::seed_from_u64(0x0abc_def0_1122_3344);
        let mut chip = SoundFieldChip::default();
        let g = AffinePoint::basepoint();

        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        rng.fill_bytes(&mut a);
        rng.fill_bytes(&mut b);
        let pa = g.scalar_mul_le(a, &mut chip).unwrap();
        let pb = g.scalar_mul_le(b, &mut chip).unwrap();
        let sum = pa.add(&pb, &mut chip).unwrap();

        let ok = check_add_equation_sound(&pa, &pb, &sum, &mut chip).unwrap();
        assert!(ok.is_satisfied);

        let bad = check_add_equation_sound(&pa, &pb, &pa, &mut chip).unwrap();
        assert!(!bad.is_satisfied);
    }

    #[test]
    fn scalar_mul_equation_check_detects_valid_and_invalid() {
        let mut rng = SmallRng::seed_from_u64(0x5566_7788_99aa_bbcc);
        let mut chip = SoundFieldChip::default();
        let g = AffinePoint::basepoint();

        let mut k = [0u8; 32];
        rng.fill_bytes(&mut k);
        let res = g.scalar_mul_le(k, &mut chip).unwrap();

        let ok = check_scalar_mul_equation_sound(&g, k, &res, &mut chip).unwrap();
        assert!(ok.is_satisfied);

        let bad =
            check_scalar_mul_equation_sound(&g, k, &AffinePoint::identity(), &mut chip).unwrap();
        assert!(!bad.is_satisfied);
    }

    #[test]
    fn msm_equation_check_matches_reference() {
        let mut rng = SmallRng::seed_from_u64(0x0f0e_0d0c_0b0a_0908);
        let mut chip = SoundFieldChip::default();
        let g = AffinePoint::basepoint();

        let mut points = Vec::new();
        let mut scalars = Vec::new();
        let mut expected_sum = AffinePoint::identity();
        for _ in 0..4 {
            let mut p_scalar = [0u8; 32];
            let mut k = [0u8; 32];
            rng.fill_bytes(&mut p_scalar);
            rng.fill_bytes(&mut k);
            let p = g.scalar_mul_le(p_scalar, &mut chip).unwrap();
            let term = p.scalar_mul_le(k, &mut chip).unwrap();
            expected_sum = expected_sum.add(&term, &mut chip).unwrap();

            points.push(p);
            scalars.push(k);
        }

        let ok = check_msm_equation_sound(&points, &scalars, &expected_sum, &mut chip).unwrap();
        assert!(ok.is_satisfied);
        let bad = check_msm_equation_sound(&points, &scalars, &AffinePoint::identity(), &mut chip)
            .unwrap();
        assert!(!bad.is_satisfied);
    }
}
