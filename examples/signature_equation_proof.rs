use curve25519::constants::ED25519_BASEPOINT_TABLE;
use curve25519::scalar::Scalar;
use ed25519_circuit::{
    Ed25519VerificationPolicy, prove_ed25519_signature_equation, verify_ed25519_signature_equation,
};
use std::time::Instant;

fn main() {
    let a_secret = Scalar::from(123_u64);
    let r_nonce = Scalar::from(45_u64);
    let public_key = (&a_secret * ED25519_BASEPOINT_TABLE).compress().to_bytes();
    let r = (&r_nonce * ED25519_BASEPOINT_TABLE).compress().to_bytes();
    let msg = b"ed25519 signature equation benchmark";

    let k = Scalar::from_bytes_mod_order(ed25519_circuit::derive_ed25519_challenge_scalar_mod_l(
        r, public_key, msg,
    ));
    let s = (r_nonce + (k * a_secret)).to_bytes();

    let t0 = Instant::now();
    let proof = prove_ed25519_signature_equation(
        public_key,
        r,
        s,
        msg,
        Ed25519VerificationPolicy::StrictRfc8032,
    )
    .expect("failed to prove signature equation");
    let prove_elapsed = t0.elapsed();

    let t1 = Instant::now();
    let ok = verify_ed25519_signature_equation(&proof);
    let verify_elapsed = t1.elapsed();

    println!("prove time: {:?}", prove_elapsed);
    println!("verify time: {:?}", verify_elapsed);
    println!("verified: {}", ok);
}
