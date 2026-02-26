#![forbid(unsafe_code)]

pub mod affine;
pub mod lookup;
pub mod non_native;
pub mod proof;
pub mod sound_affine;
pub mod trace;
pub mod sound_nonnative;

pub use affine::{AffineAddWitness, AffinePoint, ed25519_basepoint_affine};
pub use non_native::NonNativeFieldElement;
pub use proof::{
    AffineMulCodecError, AffineMulInstance, AffineMulInstanceEncoding, AffineMulProof,
    AffineMulProofBundle, AffineMulProofBundleV2, AffineMulProofSettings,
    AffineMulFullySoundProof, AffineMulSampledSoundProof, AffineMulSoundProofSettings,
    deserialize_affine_mul_bundle, deserialize_affine_mul_bundle_v2,
    deserialize_affine_mul_instance, deserialize_affine_mul_instance_auto,
    deserialize_affine_mul_instance_compressed, deserialize_affine_mul_proof,
    deserialize_affine_mul_fully_sound_proof, deserialize_affine_mul_sampled_sound_proof,
    downgrade_affine_mul_bundle_v2, prove_affine_mul, prove_affine_mul_batch,
    prove_affine_mul_bundle, prove_affine_mul_bundle_compressed, prove_affine_mul_bundle_v2, prove_affine_mul_sound,
    prove_affine_mul_fully_sound, prove_affine_mul_fully_sound_strict, prove_affine_mul_sound_with_settings,
    prove_affine_mul_with_settings, prove_basepoint_affine_mul, prove_basepoint_affine_mul_fully_sound,
    prove_basepoint_affine_mul_sound,
    prove_basepoint_affine_mul_with_settings, recode_affine_mul_bundle_v2_instance,
    serialize_affine_mul_bundle, serialize_affine_mul_bundle_v2, serialize_affine_mul_instance,
    serialize_affine_mul_instance_compressed, serialize_affine_mul_proof,
    serialize_affine_mul_fully_sound_proof, serialize_affine_mul_sampled_sound_proof,
    try_deserialize_affine_mul_instance, try_deserialize_affine_mul_instance_auto,
    try_deserialize_affine_mul_instance_compressed, upgrade_affine_mul_bundle_to_v2,
    verify_affine_mul, verify_affine_mul_attested, verify_affine_mul_attested_with_settings,
    verify_affine_mul_batch, verify_affine_mul_bundle, verify_affine_mul_bundle_auto,
    verify_affine_mul_bundle_v2, verify_affine_mul_fully_sound, verify_affine_mul_fully_sound_strict, verify_affine_mul_sound, verify_affine_mul_sound_with_settings,
    verify_affine_mul_with_settings, verify_basepoint_affine_mul, verify_basepoint_affine_mul_fully_sound,
    verify_basepoint_affine_mul_sound,
    verify_basepoint_affine_mul_with_settings,
};
pub use sound_nonnative::{
    SoundAddSubProof, SoundAddSubProofSettings, SoundMulModProof, SoundMulProof,
    SoundReduceProof, prove_nonnative_add,
    prove_nonnative_add_with_settings, prove_nonnative_sub, prove_nonnative_sub_with_settings,
    prove_nonnative_mul, prove_nonnative_mul_mod_p, prove_nonnative_mul_mod_p_with_settings,
    prove_nonnative_mul_with_settings, prove_nonnative_reduce, prove_nonnative_reduce_with_settings,
    verify_nonnative_add, verify_nonnative_add_with_settings, verify_nonnative_sub,
    verify_nonnative_sub_with_settings, verify_nonnative_mul, verify_nonnative_mul_mod_p,
    verify_nonnative_mul_mod_p_with_settings, verify_nonnative_mul_with_settings,
    verify_nonnative_reduce, verify_nonnative_reduce_with_settings,
};
pub use sound_affine::{
    SoundAffineAddProof, prove_affine_add_sound, prove_affine_add_sound_with_settings,
    verify_affine_add_sound, verify_affine_add_sound_with_settings,
};
pub use trace::{AffineMulTraceStep, build_affine_mul_trace, verify_affine_mul_trace};
