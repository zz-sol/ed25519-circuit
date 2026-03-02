//! ed25519-circuit
//!
//! This crate provides a circuit-oriented API for:
//! - non-native ed25519 base field arithmetic over BabyBear limbs,
//! - affine Edwards group add/double/scalar-mul built on those field ops,
//! - lookup logging that can be wired into a single AIR/proof pipeline.
//!
//! The current implementation focuses on arithmetic correctness and testability.
//! Full end-to-end proving is intentionally out of scope for this phase.

pub mod affine;
pub mod api;
pub mod lookup;
pub mod non_native_field;
pub mod pokos_api;

pub use affine::{
    AffinePoint, BatchGroupOpOutput, BatchGroupSumOutput, GroupCurveCheckOutput,
    GroupEquationCheckOutput, GroupOpCost, GroupOpOutput, MsmCheckOutput, check_add_equation_sound,
    check_msm_equation_sound, check_scalar_mul_equation_sound,
};
pub use api::Ed25519CircuitApi;
pub use non_native_field::air::{
    FieldAirOp, NON_NATIVE_FIELD_AIR_WIDTH, NON_NATIVE_FIELD_NUM_PUBLIC_VALUES, NonNativeFieldAir,
    build_trace_for_ops, compute_trace_public_values, compute_trace_public_values_with_seed,
    pad_trace_for_proof, rechain_trace_acc_with_seed, validate_trace_rows,
    validate_trace_rows_with_seed,
};
pub use non_native_field::proof::{
    FieldAirProof, FieldAirProofSettings, FieldAirStarkProof, prove_field_air_ops,
    prove_field_air_ops_with_seed, prove_field_air_ops_with_settings,
    prove_field_air_ops_with_settings_and_seed, verify_field_air_proof,
    verify_field_air_proof_for_ops, verify_field_air_proof_for_ops_with_seed,
    verify_field_air_proof_with_settings,
};
pub use non_native_field::sound::{
    SoundFieldChip, SoundFieldCost, SoundFieldError, SoundFieldOpOutput,
};
pub use non_native_field::{Ed25519BaseField, LIMB_BITS, N_LIMBS};
pub use pokos_api::{
    BasepointBatchMulProofRequest, BasepointBatchMulProofResponse,
    BasepointBatchMulProofVerifyRequest, BasepointBatchMulProofVerifyResponse,
    BasepointBatchMulRequest, BasepointBatchMulResponse, BasepointBatchMulSumProofRequest,
    BasepointBatchMulSumProofResponse, BasepointBatchMulSumProofVerifyRequest,
    BasepointBatchMulSumProofVerifyResponse, BasepointBatchMulSumResponse, MsmEquationCheckRequest,
    MsmEquationCheckResponse, MsmProofRequest, MsmProofResponse, MsmProofResultRequest,
    MsmProofResultResponse, MsmProofResultVerifyRequest, MsmProofResultVerifyResponse,
    MsmProofVerifyRequest, MsmProofVerifyResponse, MsmRequest, MsmResponse,
    basepoint_batch_mul_compressed, basepoint_batch_mul_prove, basepoint_batch_mul_sum_compressed,
    basepoint_batch_mul_sum_prove, basepoint_batch_mul_sum_verify_proof,
    basepoint_batch_mul_verify_proof, msm_compressed, msm_equation_check, msm_prove,
    msm_result_prove, msm_result_verify_proof, msm_verify_proof,
};
