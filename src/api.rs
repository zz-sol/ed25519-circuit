use crate::affine::{
    AffinePoint, BatchGroupOpOutput, BatchGroupSumOutput, GroupCurveCheckOutput,
    GroupEquationCheckOutput, GroupOpOutput, MsmCheckOutput, check_add_equation_sound,
    check_msm_equation_sound, check_scalar_mul_equation_sound,
};
use crate::lookup::LookupEvent;
use crate::non_native_field::Ed25519BaseField;
use crate::non_native_field::air::{FieldAirOp, build_trace_for_ops, validate_trace_rows};
use crate::non_native_field::proof::{
    FieldAirProof, FieldAirProofSettings, prove_field_air_ops, prove_field_air_ops_with_seed,
    prove_field_air_ops_with_settings, verify_field_air_proof, verify_field_air_proof_for_ops,
    verify_field_air_proof_for_ops_with_seed, verify_field_air_proof_with_settings,
};
use crate::non_native_field::sound::{
    SoundFieldChip, SoundFieldCost, SoundFieldError, SoundFieldOpOutput,
};
use p3_baby_bear::BabyBear;
use p3_field::PrimeCharacteristicRing;
use p3_matrix::dense::RowMajorMatrix;

pub struct Ed25519CircuitApi {
    field_chip: SoundFieldChip,
}

impl Default for Ed25519CircuitApi {
    fn default() -> Self {
        Self {
            field_chip: SoundFieldChip::default(),
        }
    }
}

impl Ed25519CircuitApi {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn basepoint(&self) -> AffinePoint {
        AffinePoint::basepoint()
    }

    pub fn identity(&self) -> AffinePoint {
        AffinePoint::identity()
    }

    pub fn field_from_bytes_le(&self, bytes: [u8; 32]) -> Ed25519BaseField {
        Ed25519BaseField::from_bytes_le(bytes)
    }

    pub fn field_add(
        &mut self,
        a: &Ed25519BaseField,
        b: &Ed25519BaseField,
    ) -> Result<Ed25519BaseField, SoundFieldError> {
        self.field_chip.add(a, b)
    }

    pub fn field_sub(
        &mut self,
        a: &Ed25519BaseField,
        b: &Ed25519BaseField,
    ) -> Result<Ed25519BaseField, SoundFieldError> {
        self.field_chip.sub(a, b)
    }

    pub fn field_mul(
        &mut self,
        a: &Ed25519BaseField,
        b: &Ed25519BaseField,
    ) -> Result<Ed25519BaseField, SoundFieldError> {
        self.field_chip.mul(a, b)
    }

    pub fn field_inv(&mut self, x: &Ed25519BaseField) -> Result<Ed25519BaseField, SoundFieldError> {
        self.field_chip.inv(x)
    }

    pub fn field_add_sound(
        &mut self,
        a: &Ed25519BaseField,
        b: &Ed25519BaseField,
    ) -> Result<SoundFieldOpOutput, SoundFieldError> {
        self.field_chip.add_sound(a, b)
    }

    pub fn field_mul_sound(
        &mut self,
        a: &Ed25519BaseField,
        b: &Ed25519BaseField,
    ) -> Result<SoundFieldOpOutput, SoundFieldError> {
        self.field_chip.mul_sound(a, b)
    }

    pub fn field_add_sound_cost(&self) -> SoundFieldCost {
        SoundFieldChip::add_cost()
    }

    pub fn field_mul_sound_cost(&self) -> SoundFieldCost {
        SoundFieldChip::mul_cost()
    }

    pub fn affine_add(
        &mut self,
        p: &AffinePoint,
        q: &AffinePoint,
    ) -> Result<AffinePoint, SoundFieldError> {
        p.add(q, &mut self.field_chip)
    }

    pub fn affine_sub(
        &mut self,
        p: &AffinePoint,
        q: &AffinePoint,
    ) -> Result<AffinePoint, SoundFieldError> {
        p.sub(q, &mut self.field_chip)
    }

    pub fn affine_add_with_cost(
        &mut self,
        p: &AffinePoint,
        q: &AffinePoint,
    ) -> Result<GroupOpOutput, SoundFieldError> {
        p.add_with_cost(q, &mut self.field_chip)
    }

    pub fn affine_double(&mut self, p: &AffinePoint) -> Result<AffinePoint, SoundFieldError> {
        p.double(&mut self.field_chip)
    }

    pub fn affine_double_with_cost(
        &mut self,
        p: &AffinePoint,
    ) -> Result<GroupOpOutput, SoundFieldError> {
        p.double_with_cost(&mut self.field_chip)
    }

    pub fn affine_scalar_mul(
        &mut self,
        p: &AffinePoint,
        scalar_le: [u8; 32],
    ) -> Result<AffinePoint, SoundFieldError> {
        p.scalar_mul_le(scalar_le, &mut self.field_chip)
    }

    pub fn affine_scalar_mul_ladder(
        &mut self,
        p: &AffinePoint,
        scalar_le: [u8; 32],
    ) -> Result<AffinePoint, SoundFieldError> {
        p.scalar_mul_le_ladder(scalar_le, &mut self.field_chip)
    }

    pub fn affine_scalar_mul_with_cost(
        &mut self,
        p: &AffinePoint,
        scalar_le: [u8; 32],
    ) -> Result<GroupOpOutput, SoundFieldError> {
        p.scalar_mul_le_with_cost(scalar_le, &mut self.field_chip)
    }

    pub fn affine_scalar_mul_ladder_with_cost(
        &mut self,
        p: &AffinePoint,
        scalar_le: [u8; 32],
    ) -> Result<GroupOpOutput, SoundFieldError> {
        p.scalar_mul_le_ladder_with_cost(scalar_le, &mut self.field_chip)
    }

    pub fn is_on_curve(&self, p: &AffinePoint) -> bool {
        p.is_on_curve()
    }

    pub fn is_on_curve_sound(&mut self, p: &AffinePoint) -> Result<bool, SoundFieldError> {
        p.is_on_curve_sound(&mut self.field_chip)
    }

    pub fn is_on_curve_sound_with_cost(
        &mut self,
        p: &AffinePoint,
    ) -> Result<GroupCurveCheckOutput, SoundFieldError> {
        p.is_on_curve_sound_with_cost(&mut self.field_chip)
    }

    pub fn basepoint_batch_scalar_mul(
        &mut self,
        scalars_le: &[[u8; 32]],
    ) -> Result<Vec<AffinePoint>, SoundFieldError> {
        Ok(
            AffinePoint::batch_scalar_mul_basepoint_le_with_cost(scalars_le, &mut self.field_chip)?
                .points,
        )
    }

    pub fn basepoint_batch_scalar_mul_with_cost(
        &mut self,
        scalars_le: &[[u8; 32]],
    ) -> Result<BatchGroupOpOutput, SoundFieldError> {
        AffinePoint::batch_scalar_mul_basepoint_le_with_cost(scalars_le, &mut self.field_chip)
    }

    pub fn basepoint_batch_scalar_mul_sum_with_cost(
        &mut self,
        scalars_le: &[[u8; 32]],
    ) -> Result<BatchGroupSumOutput, SoundFieldError> {
        AffinePoint::batch_scalar_mul_basepoint_le_sum_with_cost(scalars_le, &mut self.field_chip)
    }

    pub fn check_add_equation_sound(
        &mut self,
        p: &AffinePoint,
        q: &AffinePoint,
        expected: &AffinePoint,
    ) -> Result<GroupEquationCheckOutput, SoundFieldError> {
        check_add_equation_sound(p, q, expected, &mut self.field_chip)
    }

    pub fn check_scalar_mul_equation_sound(
        &mut self,
        point: &AffinePoint,
        scalar_le: [u8; 32],
        expected: &AffinePoint,
    ) -> Result<GroupEquationCheckOutput, SoundFieldError> {
        check_scalar_mul_equation_sound(point, scalar_le, expected, &mut self.field_chip)
    }

    pub fn msm_with_cost(
        &mut self,
        points: &[AffinePoint],
        scalars_le: &[[u8; 32]],
    ) -> Result<GroupOpOutput, SoundFieldError> {
        AffinePoint::msm_with_cost(points, scalars_le, &mut self.field_chip)
    }

    pub fn check_msm_equation_sound(
        &mut self,
        points: &[AffinePoint],
        scalars_le: &[[u8; 32]],
        expected: &AffinePoint,
    ) -> Result<MsmCheckOutput, SoundFieldError> {
        check_msm_equation_sound(points, scalars_le, expected, &mut self.field_chip)
    }

    pub fn lookup_events(&self) -> &[LookupEvent] {
        self.field_chip.lookup_events()
    }

    pub fn clear_lookup_log(&mut self) {
        self.field_chip.clear_lookup_log();
    }

    pub fn clear_trace_cache(&mut self) {
        self.field_chip.clear_trace_cache();
    }

    pub fn field_ops_log(&self) -> &[FieldAirOp] {
        self.field_chip.field_ops()
    }

    pub fn take_field_ops_log(&mut self) -> Vec<FieldAirOp> {
        self.field_chip.take_field_ops()
    }

    pub fn build_field_air_trace(&self, ops: &[FieldAirOp]) -> RowMajorMatrix<BabyBear> {
        build_trace_for_ops(ops)
    }

    pub fn validate_field_air_trace(&self, trace: &RowMajorMatrix<BabyBear>) -> bool {
        validate_trace_rows(trace)
    }

    pub fn prove_field_air_ops(&self, ops: &[FieldAirOp]) -> FieldAirProof {
        prove_field_air_ops(ops)
    }

    pub fn prove_field_air_ops_with_settings(
        &self,
        ops: &[FieldAirOp],
        settings: FieldAirProofSettings,
    ) -> FieldAirProof {
        prove_field_air_ops_with_settings(ops, settings)
    }

    pub fn prove_logged_field_air_ops(&self) -> FieldAirProof {
        prove_field_air_ops(self.field_chip.field_ops())
    }

    pub fn prove_logged_field_air_ops_with_seed(&self, seed: BabyBear) -> FieldAirProof {
        prove_field_air_ops_with_seed(self.field_chip.field_ops(), seed)
    }

    pub fn prove_logged_field_air_ops_with_settings(
        &self,
        settings: FieldAirProofSettings,
    ) -> FieldAirProof {
        prove_field_air_ops_with_settings(self.field_chip.field_ops(), settings)
    }

    pub fn verify_field_air_proof(&self, proof: &FieldAirProof) -> bool {
        verify_field_air_proof(proof)
    }

    pub fn verify_field_air_proof_with_settings(
        &self,
        proof: &FieldAirProof,
        settings: FieldAirProofSettings,
    ) -> bool {
        verify_field_air_proof_with_settings(proof, settings)
    }

    pub fn verify_field_air_proof_for_ops(
        &self,
        proof: &FieldAirProof,
        ops: &[FieldAirOp],
    ) -> bool {
        verify_field_air_proof_for_ops(proof, ops)
    }

    pub fn verify_field_air_proof_for_logged_ops(&self, proof: &FieldAirProof) -> bool {
        verify_field_air_proof_for_ops(proof, self.field_chip.field_ops())
    }

    pub fn verify_field_air_proof_for_logged_ops_with_seed(
        &self,
        proof: &FieldAirProof,
        seed: BabyBear,
    ) -> bool {
        verify_field_air_proof_for_ops_with_seed(proof, self.field_chip.field_ops(), seed)
    }

    pub fn msm_statement_seed(
        points: &[AffinePoint],
        scalars_le: &[[u8; 32]],
        expected: &AffinePoint,
    ) -> BabyBear {
        let mut acc: u64 = 0x9e37_79b9_7f4a_7c15;
        acc = acc.wrapping_mul(131).wrapping_add(0x4d53_4d31); // "MSM1"
        for p in points {
            for b in p.compress() {
                acc = acc.wrapping_mul(131).wrapping_add(b as u64);
            }
        }
        for scalar in scalars_le {
            for &b in scalar {
                acc = acc.wrapping_mul(131).wrapping_add(b as u64);
            }
        }
        for b in expected.compress() {
            acc = acc.wrapping_mul(131).wrapping_add(b as u64);
        }
        BabyBear::from_u32((acc & 0xffff_ffff) as u32)
    }

    pub fn basepoint_batch_statement_seed(
        scalars_le: &[[u8; 32]],
        compressed_points: &[[u8; 32]],
    ) -> BabyBear {
        let mut acc: u64 = 0x9e37_79b9_7f4a_7c15;
        acc = acc.wrapping_mul(131).wrapping_add(0x4250_4231); // "BPB1"
        for scalar in scalars_le {
            for &b in scalar {
                acc = acc.wrapping_mul(131).wrapping_add(b as u64);
            }
        }
        for point in compressed_points {
            for &b in point {
                acc = acc.wrapping_mul(131).wrapping_add(b as u64);
            }
        }
        BabyBear::from_u32((acc & 0xffff_ffff) as u32)
    }

    pub fn basepoint_batch_sum_statement_seed(
        scalars_le: &[[u8; 32]],
        compressed_points: &[[u8; 32]],
        compressed_sum: &[u8; 32],
    ) -> BabyBear {
        let mut acc: u64 = 0x9e37_79b9_7f4a_7c15;
        acc = acc.wrapping_mul(131).wrapping_add(0x4253_4231); // "BSB1"
        for scalar in scalars_le {
            for &b in scalar {
                acc = acc.wrapping_mul(131).wrapping_add(b as u64);
            }
        }
        for point in compressed_points {
            for &b in point {
                acc = acc.wrapping_mul(131).wrapping_add(b as u64);
            }
        }
        for &b in compressed_sum {
            acc = acc.wrapping_mul(131).wrapping_add(b as u64);
        }
        BabyBear::from_u32((acc & 0xffff_ffff) as u32)
    }

    pub fn msm_result_statement_seed(
        points: &[AffinePoint],
        scalars_le: &[[u8; 32]],
        compressed_result: &[u8; 32],
    ) -> BabyBear {
        let mut acc: u64 = 0x9e37_79b9_7f4a_7c15;
        acc = acc.wrapping_mul(131).wrapping_add(0x4d53_5231); // "MSR1"
        for p in points {
            for b in p.compress() {
                acc = acc.wrapping_mul(131).wrapping_add(b as u64);
            }
        }
        for scalar in scalars_le {
            for &b in scalar {
                acc = acc.wrapping_mul(131).wrapping_add(b as u64);
            }
        }
        for &b in compressed_result {
            acc = acc.wrapping_mul(131).wrapping_add(b as u64);
        }
        BabyBear::from_u32((acc & 0xffff_ffff) as u32)
    }

    pub fn prove_msm_equation_with_field_air(
        &mut self,
        points: &[AffinePoint],
        scalars_le: &[[u8; 32]],
        expected: &AffinePoint,
    ) -> Result<(MsmCheckOutput, FieldAirProof), SoundFieldError> {
        self.clear_trace_cache();
        let out = self.check_msm_equation_sound(points, scalars_le, expected)?;
        if !out.is_satisfied {
            return Err(SoundFieldError::ConstraintViolation(
                "msm equation not satisfied",
            ));
        }
        let seed = Self::msm_statement_seed(points, scalars_le, expected);
        let proof = self.prove_logged_field_air_ops_with_seed(seed);
        Ok((out, proof))
    }

    pub fn verify_msm_equation_field_air_proof(
        proof: &FieldAirProof,
        points: &[AffinePoint],
        scalars_le: &[[u8; 32]],
        expected: &AffinePoint,
    ) -> bool {
        let seed = Self::msm_statement_seed(points, scalars_le, expected);
        let mut checker = SoundFieldChip::default();
        let out = match check_msm_equation_sound(points, scalars_le, expected, &mut checker) {
            Ok(v) => v,
            Err(_) => return false,
        };
        if !out.is_satisfied {
            return false;
        }
        verify_field_air_proof_for_ops_with_seed(proof, checker.field_ops(), seed)
    }

    pub fn prove_basepoint_batch_with_field_air(
        &mut self,
        scalars_le: &[[u8; 32]],
    ) -> Result<(BatchGroupOpOutput, FieldAirProof), SoundFieldError> {
        self.clear_trace_cache();
        let out = self.basepoint_batch_scalar_mul_with_cost(scalars_le)?;
        let compressed_points: Vec<[u8; 32]> = out.points.iter().map(|p| p.compress()).collect();
        let seed = Self::basepoint_batch_statement_seed(scalars_le, &compressed_points);
        let proof = self.prove_logged_field_air_ops_with_seed(seed);
        Ok((out, proof))
    }

    pub fn verify_basepoint_batch_field_air_proof(
        proof: &FieldAirProof,
        scalars_le: &[[u8; 32]],
        compressed_points: &[[u8; 32]],
    ) -> bool {
        let mut checker_api = Ed25519CircuitApi::new();
        let out = match checker_api.basepoint_batch_scalar_mul_with_cost(scalars_le) {
            Ok(v) => v,
            Err(_) => return false,
        };
        let recomputed: Vec<[u8; 32]> = out.points.iter().map(|p| p.compress()).collect();
        if recomputed.as_slice() != compressed_points {
            return false;
        }
        let seed = Self::basepoint_batch_statement_seed(scalars_le, compressed_points);
        verify_field_air_proof_for_ops_with_seed(proof, checker_api.field_ops_log(), seed)
    }

    pub fn prove_basepoint_batch_sum_with_field_air(
        &mut self,
        scalars_le: &[[u8; 32]],
    ) -> Result<(BatchGroupSumOutput, FieldAirProof), SoundFieldError> {
        self.clear_trace_cache();
        let out = self.basepoint_batch_scalar_mul_sum_with_cost(scalars_le)?;
        let compressed_points: Vec<[u8; 32]> = out.points.iter().map(|p| p.compress()).collect();
        let compressed_sum = out.sum.compress();
        let seed = Self::basepoint_batch_sum_statement_seed(
            scalars_le,
            &compressed_points,
            &compressed_sum,
        );
        let proof = self.prove_logged_field_air_ops_with_seed(seed);
        Ok((out, proof))
    }

    pub fn verify_basepoint_batch_sum_field_air_proof(
        proof: &FieldAirProof,
        scalars_le: &[[u8; 32]],
        compressed_points: &[[u8; 32]],
        compressed_sum: &[u8; 32],
    ) -> bool {
        let mut checker_api = Ed25519CircuitApi::new();
        let out = match checker_api.basepoint_batch_scalar_mul_sum_with_cost(scalars_le) {
            Ok(v) => v,
            Err(_) => return false,
        };
        let recomputed_points: Vec<[u8; 32]> = out.points.iter().map(|p| p.compress()).collect();
        let recomputed_sum = out.sum.compress();
        if recomputed_points.as_slice() != compressed_points {
            return false;
        }
        if &recomputed_sum != compressed_sum {
            return false;
        }
        let seed =
            Self::basepoint_batch_sum_statement_seed(scalars_le, compressed_points, compressed_sum);
        verify_field_air_proof_for_ops_with_seed(proof, checker_api.field_ops_log(), seed)
    }

    pub fn prove_msm_with_field_air(
        &mut self,
        points: &[AffinePoint],
        scalars_le: &[[u8; 32]],
    ) -> Result<(GroupOpOutput, FieldAirProof), SoundFieldError> {
        self.clear_trace_cache();
        let out = self.msm_with_cost(points, scalars_le)?;
        let compressed_result = out.point.compress();
        let seed = Self::msm_result_statement_seed(points, scalars_le, &compressed_result);
        let proof = self.prove_logged_field_air_ops_with_seed(seed);
        Ok((out, proof))
    }

    pub fn verify_msm_field_air_proof(
        proof: &FieldAirProof,
        points: &[AffinePoint],
        scalars_le: &[[u8; 32]],
        compressed_result: &[u8; 32],
    ) -> bool {
        let mut checker_api = Ed25519CircuitApi::new();
        let out = match checker_api.msm_with_cost(points, scalars_le) {
            Ok(v) => v,
            Err(_) => return false,
        };
        if &out.point.compress() != compressed_result {
            return false;
        }
        let seed = Self::msm_result_statement_seed(points, scalars_le, compressed_result);
        verify_field_air_proof_for_ops_with_seed(proof, checker_api.field_ops_log(), seed)
    }
}

#[cfg(test)]
mod tests {
    use rand::{RngCore, SeedableRng, rngs::SmallRng};

    use super::Ed25519CircuitApi;

    #[test]
    fn prove_verify_logged_trace_after_group_ops() {
        let mut rng = SmallRng::seed_from_u64(0x1234_1111_5678_2222);
        let mut api = Ed25519CircuitApi::new();
        let g = api.basepoint();

        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        rng.fill_bytes(&mut a);
        rng.fill_bytes(&mut b);

        let pa = api.affine_scalar_mul(&g, a).expect("scalar mul a");
        let pb = api.affine_scalar_mul(&g, b).expect("scalar mul b");
        let _sum = api.affine_add(&pa, &pb).expect("group add");

        assert!(!api.field_ops_log().is_empty());
        let proof = api.prove_logged_field_air_ops();
        assert!(api.verify_field_air_proof_for_logged_ops(&proof));
    }

    #[test]
    fn verify_for_logged_ops_fails_after_log_changes() {
        let mut rng = SmallRng::seed_from_u64(0x9abc_3333_def0_4444);
        let mut api = Ed25519CircuitApi::new();
        let g = api.basepoint();

        let mut k = [0u8; 32];
        rng.fill_bytes(&mut k);
        let _ = api.affine_scalar_mul(&g, k).expect("scalar mul");
        let proof = api.prove_logged_field_air_ops();
        assert!(api.verify_field_air_proof_for_logged_ops(&proof));

        api.clear_trace_cache();
        assert!(!api.verify_field_air_proof_for_logged_ops(&proof));
    }

    #[test]
    fn prove_verify_basepoint_batch_with_field_air_roundtrip() {
        let mut rng = SmallRng::seed_from_u64(0x7777_1111_8888_2222);
        let mut api = Ed25519CircuitApi::new();
        let mut scalars = Vec::new();
        for _ in 0..4 {
            let mut s = [0u8; 32];
            rng.fill_bytes(&mut s);
            scalars.push(s);
        }

        let (out, proof) = api
            .prove_basepoint_batch_with_field_air(&scalars)
            .expect("prove basepoint batch");
        let compressed: Vec<[u8; 32]> = out.points.iter().map(|p| p.compress()).collect();
        assert!(Ed25519CircuitApi::verify_basepoint_batch_field_air_proof(
            &proof,
            &scalars,
            &compressed
        ));
    }

    #[test]
    fn verify_basepoint_batch_with_field_air_rejects_wrong_outputs() {
        let mut rng = SmallRng::seed_from_u64(0x3333_aaaa_4444_bbbb);
        let mut api = Ed25519CircuitApi::new();
        let mut scalars = Vec::new();
        for _ in 0..3 {
            let mut s = [0u8; 32];
            rng.fill_bytes(&mut s);
            scalars.push(s);
        }

        let (out, proof) = api
            .prove_basepoint_batch_with_field_air(&scalars)
            .expect("prove basepoint batch");
        let mut compressed: Vec<[u8; 32]> = out.points.iter().map(|p| p.compress()).collect();
        compressed[0][0] ^= 1;

        assert!(!Ed25519CircuitApi::verify_basepoint_batch_field_air_proof(
            &proof,
            &scalars,
            &compressed
        ));
    }

    #[test]
    fn prove_verify_basepoint_batch_sum_with_field_air_roundtrip() {
        let mut rng = SmallRng::seed_from_u64(0x6666_1111_7777_2222);
        let mut api = Ed25519CircuitApi::new();
        let mut scalars = Vec::new();
        for _ in 0..4 {
            let mut s = [0u8; 32];
            rng.fill_bytes(&mut s);
            scalars.push(s);
        }

        let (out, proof) = api
            .prove_basepoint_batch_sum_with_field_air(&scalars)
            .expect("prove basepoint batch sum");
        let compressed_points: Vec<[u8; 32]> = out.points.iter().map(|p| p.compress()).collect();
        let compressed_sum = out.sum.compress();
        assert!(
            Ed25519CircuitApi::verify_basepoint_batch_sum_field_air_proof(
                &proof,
                &scalars,
                &compressed_points,
                &compressed_sum
            )
        );
    }

    #[test]
    fn prove_verify_msm_with_field_air_roundtrip() {
        let mut rng = SmallRng::seed_from_u64(0xaaaa_1111_bbbb_2222);
        let mut api = Ed25519CircuitApi::new();
        let g = api.basepoint();

        let mut points = Vec::new();
        let mut scalars = Vec::new();
        for _ in 0..3 {
            let mut p_scalar = [0u8; 32];
            let mut k = [0u8; 32];
            rng.fill_bytes(&mut p_scalar);
            rng.fill_bytes(&mut k);
            points.push(api.affine_scalar_mul(&g, p_scalar).expect("point gen"));
            scalars.push(k);
        }

        let (out, proof) = api
            .prove_msm_with_field_air(&points, &scalars)
            .expect("prove msm");
        let compressed = out.point.compress();
        assert!(Ed25519CircuitApi::verify_msm_field_air_proof(
            &proof,
            &points,
            &scalars,
            &compressed
        ));
    }

    #[test]
    fn verify_msm_with_field_air_rejects_wrong_result() {
        let mut rng = SmallRng::seed_from_u64(0xcccc_3333_dddd_4444);
        let mut api = Ed25519CircuitApi::new();
        let g = api.basepoint();

        let mut points = Vec::new();
        let mut scalars = Vec::new();
        for _ in 0..3 {
            let mut p_scalar = [0u8; 32];
            let mut k = [0u8; 32];
            rng.fill_bytes(&mut p_scalar);
            rng.fill_bytes(&mut k);
            points.push(api.affine_scalar_mul(&g, p_scalar).expect("point gen"));
            scalars.push(k);
        }

        let (out, proof) = api
            .prove_msm_with_field_air(&points, &scalars)
            .expect("prove msm");
        let mut compressed = out.point.compress();
        compressed[0] ^= 1;
        assert!(!Ed25519CircuitApi::verify_msm_field_air_proof(
            &proof,
            &points,
            &scalars,
            &compressed
        ));
    }
}
