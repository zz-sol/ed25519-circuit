#![forbid(unsafe_code)]

pub mod affine;
pub mod lookup;
pub mod non_native;
pub mod proof;
pub mod trace;

pub use affine::{AffineAddWitness, AffinePoint, ed25519_basepoint_affine};
pub use non_native::NonNativeFieldElement;
pub use proof::{
    AffineMulCodecError, AffineMulInstance, AffineMulInstanceEncoding, AffineMulProof,
    AffineMulProofBundle, AffineMulProofBundleV2, AffineMulProofSettings,
    deserialize_affine_mul_bundle, deserialize_affine_mul_bundle_v2,
    deserialize_affine_mul_instance, deserialize_affine_mul_instance_auto,
    deserialize_affine_mul_instance_compressed, deserialize_affine_mul_proof,
    downgrade_affine_mul_bundle_v2, prove_affine_mul, prove_affine_mul_batch,
    prove_affine_mul_bundle, prove_affine_mul_bundle_compressed, prove_affine_mul_bundle_v2,
    prove_affine_mul_with_settings, prove_basepoint_affine_mul,
    prove_basepoint_affine_mul_with_settings, recode_affine_mul_bundle_v2_instance,
    serialize_affine_mul_bundle, serialize_affine_mul_bundle_v2, serialize_affine_mul_instance,
    serialize_affine_mul_instance_compressed, serialize_affine_mul_proof,
    try_deserialize_affine_mul_instance, try_deserialize_affine_mul_instance_auto,
    try_deserialize_affine_mul_instance_compressed, upgrade_affine_mul_bundle_to_v2,
    verify_affine_mul, verify_affine_mul_attested, verify_affine_mul_attested_with_settings,
    verify_affine_mul_batch, verify_affine_mul_bundle, verify_affine_mul_bundle_auto,
    verify_affine_mul_bundle_v2, verify_affine_mul_with_settings, verify_basepoint_affine_mul,
    verify_basepoint_affine_mul_with_settings,
};
pub use trace::{AffineMulTraceStep, build_affine_mul_trace, verify_affine_mul_trace};
