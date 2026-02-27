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

pub use affine::AffinePoint;
pub use api::Ed25519CircuitApi;
pub use non_native_field::sound::{
    SoundFieldChip, SoundFieldCost, SoundFieldError, SoundFieldOpOutput,
};
pub use non_native_field::{Ed25519BaseField, LIMB_BITS, N_LIMBS};
