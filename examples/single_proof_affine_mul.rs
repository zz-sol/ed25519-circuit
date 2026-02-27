use ed25519_circuit::{
    AffineMulProofSettings, prove_basepoint_affine_mul_single_unified_with_settings,
    verify_basepoint_affine_mul_single_unified_with_settings,
};
use std::time::Instant;

fn main() {
    let scalar_le_bytes = [42_u8; 32];
    let settings = AffineMulProofSettings::default();

    let t0 = Instant::now();
    let proof_bytes =
        prove_basepoint_affine_mul_single_unified_with_settings(scalar_le_bytes, settings)
            .expect("failed to generate single proof");
    let prove_elapsed = t0.elapsed();

    let t1 = Instant::now();
    let ok = verify_basepoint_affine_mul_single_unified_with_settings(
        scalar_le_bytes,
        &proof_bytes,
        settings,
    );
    let verify_elapsed = t1.elapsed();

    println!("single proof bytes: {}", proof_bytes.len());
    println!("prove time: {:?}", prove_elapsed);
    println!("verify time: {:?}", verify_elapsed);
    println!("verified: {}", ok);
}
