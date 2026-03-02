use crate::affine::{
    AffinePoint, BatchGroupOpOutput, BatchGroupSumOutput, GroupCurveCheckOutput,
    GroupEquationCheckOutput, GroupOpOutput, MsmCheckOutput, check_add_equation_sound,
    check_msm_equation_sound, check_scalar_mul_equation_sound,
};
use crate::lookup::LookupEvent;
use crate::non_native_field::Ed25519BaseField;
use crate::non_native_field::air::{FieldAirOp, build_trace_for_ops, validate_trace_rows};
use crate::non_native_field::proof::{
    FieldAirProof, FieldAirProofSettings, prove_field_air_ops, prove_field_air_ops_with_settings,
    verify_field_air_proof, verify_field_air_proof_for_ops, verify_field_air_proof_with_settings,
};
use crate::non_native_field::sound::{
    SoundFieldChip, SoundFieldCost, SoundFieldError, SoundFieldOpOutput,
};
use p3_baby_bear::BabyBear;
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
}
