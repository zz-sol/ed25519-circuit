use ed25519_circuit::{
    SoundAddSubProofSettings, prove_basepoint_affine_mul_e2e_unified_with_settings,
    verify_basepoint_affine_mul_e2e_unified_with_settings,
};
use std::time::Instant;

fn main() {
    let scalar_le_bytes = [42_u8; 32];

    let settings = SoundAddSubProofSettings {
        log_blowup: 3,
        log_final_poly_len: 4,
        num_queries: 2,
        commit_proof_of_work_bits: 1,
        query_proof_of_work_bits: 1,
        rng_seed: 7,
    };

    let t0 = Instant::now();
    let proof_bytes =
        prove_basepoint_affine_mul_e2e_unified_with_settings(scalar_le_bytes, settings)
            .expect("failed to generate e2e proof");
    let prove_elapsed = t0.elapsed();

    let t1 = Instant::now();
    let ok = verify_basepoint_affine_mul_e2e_unified_with_settings(
        scalar_le_bytes,
        &proof_bytes,
        settings,
    );
    let verify_elapsed = t1.elapsed();

    println!("proof bytes: {}", proof_bytes.len());
    println!("prove time: {:?}", prove_elapsed);
    println!("verify time: {:?}", verify_elapsed);
    println!("verified: {}", ok);
}
