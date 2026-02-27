use crate::affine::{AffinePoint, ed25519_basepoint_affine};
use crate::proof::{
    AffineMulInstance, AffineMulProofSettings, deserialize_affine_mul_instance_auto,
    deserialize_affine_mul_proof, deserialize_affine_mul_single_proof_blob,
    prove_affine_mul_single_unified_with_settings,
    prove_basepoint_affine_mul_single_unified_with_settings,
    verify_affine_mul_single_unified_with_settings,
    verify_basepoint_affine_mul_single_unified_with_settings,
};
use bincode::Options;
use curve25519::edwards::CompressedEdwardsY;
use curve25519::scalar::Scalar;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha512};

const MAX_SIG_EQ_PROOF_BYTES: usize = 128 * 1024 * 1024;
const CODEC_TAG_SIG_EQ_PROOF: &[u8; 4] = b"ESP1";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Ed25519VerificationPolicy {
    StrictRfc8032,
    Zip215,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ed25519SignatureProofSettings {
    pub mul_core: AffineMulProofSettings,
}

impl Default for Ed25519SignatureProofSettings {
    fn default() -> Self {
        Self {
            mul_core: AffineMulProofSettings::default(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ed25519SignatureEquationProof {
    pub policy: Ed25519VerificationPolicy,
    pub public_key_compressed: [u8; 32],
    pub r_compressed: [u8; 32],
    pub s_scalar_le_bytes: [u8; 32],
    pub message: Vec<u8>,
    pub k_scalar_le_bytes: [u8; 32],
    pub s_mul_base_proof: Vec<u8>,
    pub k_mul_public_key_proof: Vec<u8>,
    pub statement_hash: [u8; 32],
    pub settings: Ed25519SignatureProofSettings,
}

fn check_minimum_mul_policy(settings: AffineMulProofSettings) -> bool {
    settings.log_final_poly_len >= 4
        && settings.log_blowup >= 3
        && settings.num_queries >= 2
        && settings.commit_proof_of_work_bits >= 1
        && settings.query_proof_of_work_bits >= 1
}

pub fn scalar_order_le_bytes() -> [u8; 32] {
    [
        0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde,
        0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x10,
    ]
}

pub fn is_canonical_scalar_mod_l(scalar_le_bytes: [u8; 32]) -> bool {
    Option::<Scalar>::from(Scalar::from_canonical_bytes(scalar_le_bytes)).is_some()
}

pub fn add_scalars_mod_l(a_le_bytes: [u8; 32], b_le_bytes: [u8; 32]) -> [u8; 32] {
    let a = Scalar::from_bytes_mod_order(a_le_bytes);
    let b = Scalar::from_bytes_mod_order(b_le_bytes);
    (a + b).to_bytes()
}

pub fn mul_scalars_mod_l(a_le_bytes: [u8; 32], b_le_bytes: [u8; 32]) -> [u8; 32] {
    let a = Scalar::from_bytes_mod_order(a_le_bytes);
    let b = Scalar::from_bytes_mod_order(b_le_bytes);
    (a * b).to_bytes()
}

pub fn reduce_wide_scalar_mod_l(wide_le_bytes: [u8; 64]) -> [u8; 32] {
    Scalar::from_bytes_mod_order_wide(&wide_le_bytes).to_bytes()
}

pub fn derive_ed25519_challenge_scalar_mod_l(
    r_compressed: [u8; 32],
    public_key_compressed: [u8; 32],
    message: &[u8],
) -> [u8; 32] {
    let mut hasher = Sha512::new();
    hasher.update(r_compressed);
    hasher.update(public_key_compressed);
    hasher.update(message);
    let digest: [u8; 64] = hasher.finalize().into();
    reduce_wide_scalar_mod_l(digest)
}

pub fn decode_point_with_policy(
    compressed: [u8; 32],
    policy: Ed25519VerificationPolicy,
) -> Option<AffinePoint> {
    match policy {
        Ed25519VerificationPolicy::StrictRfc8032 => {
            AffinePoint::from_compressed_bytes_strict(compressed)
        }
        Ed25519VerificationPolicy::Zip215 => AffinePoint::from_compressed_bytes_relaxed(compressed),
    }
}

fn signature_statement_hash(
    policy: Ed25519VerificationPolicy,
    public_key_compressed: [u8; 32],
    r_compressed: [u8; 32],
    s_scalar_le_bytes: [u8; 32],
    message: &[u8],
    k_scalar_le_bytes: [u8; 32],
    settings: Ed25519SignatureProofSettings,
) -> Result<[u8; 32], String> {
    let mut hasher = sha2::Sha256::new();
    hasher.update(
        bincode::serialize(&policy).map_err(|e| format!("failed to serialize policy: {e}"))?,
    );
    hasher.update(public_key_compressed);
    hasher.update(r_compressed);
    hasher.update(s_scalar_le_bytes);
    hasher.update(
        bincode::serialize(message).map_err(|e| format!("failed to serialize message: {e}"))?,
    );
    hasher.update(k_scalar_le_bytes);
    hasher.update(
        bincode::serialize(&settings).map_err(|e| format!("failed to serialize settings: {e}"))?,
    );
    Ok(hasher.finalize().into())
}

fn output_point_from_single_blob(
    proof_bytes: &[u8],
    expected_instance: AffineMulInstance,
) -> Option<AffinePoint> {
    let blob = deserialize_affine_mul_single_proof_blob(proof_bytes).ok()?;
    let instance = deserialize_affine_mul_instance_auto(&blob.sealed_instance).ok()?;
    if instance != expected_instance {
        return None;
    }
    let proof = deserialize_affine_mul_proof(&blob.sealed_proof).ok()?;
    AffinePoint::from_compressed_bytes_strict(proof.output_compressed)
}

pub fn prove_ed25519_signature_equation_with_settings(
    public_key_compressed: [u8; 32],
    r_compressed: [u8; 32],
    s_scalar_le_bytes: [u8; 32],
    message: &[u8],
    policy: Ed25519VerificationPolicy,
    settings: Ed25519SignatureProofSettings,
) -> Result<Ed25519SignatureEquationProof, String> {
    if !check_minimum_mul_policy(settings.mul_core) {
        return Err("insufficient scalar-mul proof settings for sound policy".to_string());
    }
    if !is_canonical_scalar_mod_l(s_scalar_le_bytes) {
        return Err("S scalar is not canonical (must satisfy S < L)".to_string());
    }

    let Some(public_key) = decode_point_with_policy(public_key_compressed, policy) else {
        return Err("failed to decode public key under selected policy".to_string());
    };
    let Some(r_point) = decode_point_with_policy(r_compressed, policy) else {
        return Err("failed to decode R under selected policy".to_string());
    };

    let k_scalar_le_bytes =
        derive_ed25519_challenge_scalar_mod_l(r_compressed, public_key_compressed, message);

    let s_mul_base_proof = prove_basepoint_affine_mul_single_unified_with_settings(
        s_scalar_le_bytes,
        settings.mul_core,
    )?;
    let k_mul_public_key_instance = AffineMulInstance {
        base: public_key,
        scalar_le_bytes: k_scalar_le_bytes,
    };
    let k_mul_public_key_proof = prove_affine_mul_single_unified_with_settings(
        k_mul_public_key_instance,
        settings.mul_core,
    )?;

    let s_mul_base = ed25519_basepoint_affine().scalar_mul(s_scalar_le_bytes);
    let k_mul_public_key = public_key.scalar_mul(k_scalar_le_bytes);
    if r_point.add(k_mul_public_key) != s_mul_base {
        return Err("signature equation does not hold: [S]B != R + [k]A".to_string());
    }

    let statement_hash = signature_statement_hash(
        policy,
        public_key_compressed,
        r_compressed,
        s_scalar_le_bytes,
        message,
        k_scalar_le_bytes,
        settings,
    )?;

    Ok(Ed25519SignatureEquationProof {
        policy,
        public_key_compressed,
        r_compressed,
        s_scalar_le_bytes,
        message: message.to_vec(),
        k_scalar_le_bytes,
        s_mul_base_proof,
        k_mul_public_key_proof,
        statement_hash,
        settings,
    })
}

pub fn prove_ed25519_signature_equation(
    public_key_compressed: [u8; 32],
    r_compressed: [u8; 32],
    s_scalar_le_bytes: [u8; 32],
    message: &[u8],
    policy: Ed25519VerificationPolicy,
) -> Result<Ed25519SignatureEquationProof, String> {
    prove_ed25519_signature_equation_with_settings(
        public_key_compressed,
        r_compressed,
        s_scalar_le_bytes,
        message,
        policy,
        Ed25519SignatureProofSettings::default(),
    )
}

pub fn verify_ed25519_signature_equation_with_settings(
    proof: &Ed25519SignatureEquationProof,
    settings: Ed25519SignatureProofSettings,
) -> bool {
    if proof.settings != settings {
        return false;
    }
    if !check_minimum_mul_policy(settings.mul_core) {
        return false;
    }
    if !is_canonical_scalar_mod_l(proof.s_scalar_le_bytes) {
        return false;
    }
    let expected_hash = match signature_statement_hash(
        proof.policy,
        proof.public_key_compressed,
        proof.r_compressed,
        proof.s_scalar_le_bytes,
        &proof.message,
        proof.k_scalar_le_bytes,
        settings,
    ) {
        Ok(h) => h,
        Err(_) => return false,
    };
    if proof.statement_hash != expected_hash {
        return false;
    }

    let recomputed_k = derive_ed25519_challenge_scalar_mod_l(
        proof.r_compressed,
        proof.public_key_compressed,
        &proof.message,
    );
    if recomputed_k != proof.k_scalar_le_bytes {
        return false;
    }

    let Some(public_key) = decode_point_with_policy(proof.public_key_compressed, proof.policy)
    else {
        return false;
    };
    let Some(r_point) = decode_point_with_policy(proof.r_compressed, proof.policy) else {
        return false;
    };

    if !verify_basepoint_affine_mul_single_unified_with_settings(
        proof.s_scalar_le_bytes,
        &proof.s_mul_base_proof,
        settings.mul_core,
    ) {
        return false;
    }
    let k_mul_public_key_instance = AffineMulInstance {
        base: public_key,
        scalar_le_bytes: proof.k_scalar_le_bytes,
    };
    if !verify_affine_mul_single_unified_with_settings(
        &proof.k_mul_public_key_proof,
        settings.mul_core,
    ) {
        return false;
    }

    let Some(s_mul_base) = output_point_from_single_blob(
        &proof.s_mul_base_proof,
        AffineMulInstance {
            base: ed25519_basepoint_affine(),
            scalar_le_bytes: proof.s_scalar_le_bytes,
        },
    ) else {
        return false;
    };
    let Some(k_mul_public_key) =
        output_point_from_single_blob(&proof.k_mul_public_key_proof, k_mul_public_key_instance)
    else {
        return false;
    };
    r_point.add(k_mul_public_key) == s_mul_base
}

pub fn verify_ed25519_signature_equation(proof: &Ed25519SignatureEquationProof) -> bool {
    verify_ed25519_signature_equation_with_settings(proof, proof.settings)
}

pub fn serialize_ed25519_signature_equation_proof(
    proof: &Ed25519SignatureEquationProof,
) -> Result<Vec<u8>, String> {
    let payload = bincode::serialize(proof).map_err(|e| e.to_string())?;
    if payload.len() > MAX_SIG_EQ_PROOF_BYTES {
        return Err(
            "serialized signature-equation proof exceeds configured size limit".to_string(),
        );
    }
    let mut out = Vec::with_capacity(4 + payload.len());
    out.extend_from_slice(CODEC_TAG_SIG_EQ_PROOF);
    out.extend_from_slice(&payload);
    Ok(out)
}

pub fn deserialize_ed25519_signature_equation_proof(
    bytes: &[u8],
) -> Result<Ed25519SignatureEquationProof, String> {
    if bytes.len() > MAX_SIG_EQ_PROOF_BYTES {
        return Err(
            "serialized signature-equation proof exceeds configured size limit".to_string(),
        );
    }
    if bytes.len() < 4 || &bytes[..4] != CODEC_TAG_SIG_EQ_PROOF {
        return Err("invalid signature-equation proof codec header".to_string());
    }
    let payload = &bytes[4..];
    let opts = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .reject_trailing_bytes()
        .with_limit(MAX_SIG_EQ_PROOF_BYTES as u64);
    opts.deserialize(payload).map_err(|e| e.to_string())
}

pub fn verify_ed25519_signature_equation_native(
    public_key_compressed: [u8; 32],
    r_compressed: [u8; 32],
    s_scalar_le_bytes: [u8; 32],
    message: &[u8],
) -> bool {
    if !is_canonical_scalar_mod_l(s_scalar_le_bytes) {
        return false;
    }
    let Some(a) = CompressedEdwardsY(public_key_compressed).decompress() else {
        return false;
    };
    let Some(r) = CompressedEdwardsY(r_compressed).decompress() else {
        return false;
    };
    let s = Scalar::from_bytes_mod_order(s_scalar_le_bytes);
    let k = Scalar::from_bytes_mod_order(derive_ed25519_challenge_scalar_mod_l(
        r_compressed,
        public_key_compressed,
        message,
    ));
    let lhs = &s * curve25519::constants::ED25519_BASEPOINT_TABLE;
    let rhs = r + (k * a);
    lhs == rhs
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::affine::ed25519_basepoint_affine;

    fn scalar_from_u64(x: u64) -> [u8; 32] {
        Scalar::from(x).to_bytes()
    }

    #[test]
    fn scalar_canonical_bounds() {
        assert!(is_canonical_scalar_mod_l(Scalar::ZERO.to_bytes()));
        assert!(is_canonical_scalar_mod_l((Scalar::from(5u64)).to_bytes()));
        assert!(!is_canonical_scalar_mod_l(scalar_order_le_bytes()));
    }

    #[test]
    fn challenge_derivation_is_deterministic() {
        let r = [7_u8; 32];
        let a = [9_u8; 32];
        let msg = b"determinism";
        assert_eq!(
            derive_ed25519_challenge_scalar_mod_l(r, a, msg),
            derive_ed25519_challenge_scalar_mod_l(r, a, msg)
        );
    }

    #[test]
    fn strict_decode_rejects_low_order_point() {
        let minus_one = crate::NonNativeFieldElement::from_ed25519_le_bytes([
            236, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
            255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 127,
        ]);
        let torsion2 = AffinePoint {
            x: crate::NonNativeFieldElement::zero(),
            y: minus_one,
        };
        let enc = torsion2.compress();
        assert!(decode_point_with_policy(enc, Ed25519VerificationPolicy::StrictRfc8032).is_none());
        assert!(decode_point_with_policy(enc, Ed25519VerificationPolicy::Zip215).is_some());
    }

    #[test]
    fn signature_equation_proof_roundtrip() {
        let a_secret = Scalar::from(123u64);
        let r_nonce = Scalar::from(45u64);
        let public_key = (&a_secret * curve25519::constants::ED25519_BASEPOINT_TABLE)
            .compress()
            .to_bytes();
        let r = (&r_nonce * curve25519::constants::ED25519_BASEPOINT_TABLE)
            .compress()
            .to_bytes();
        let msg = b"signature equation proof test";
        let k =
            Scalar::from_bytes_mod_order(derive_ed25519_challenge_scalar_mod_l(r, public_key, msg));
        let s = (r_nonce + (k * a_secret)).to_bytes();

        let proof = prove_ed25519_signature_equation(
            public_key,
            r,
            s,
            msg,
            Ed25519VerificationPolicy::StrictRfc8032,
        )
        .expect("prove");
        assert!(verify_ed25519_signature_equation(&proof));

        let bytes = serialize_ed25519_signature_equation_proof(&proof).expect("serialize");
        let decoded = deserialize_ed25519_signature_equation_proof(&bytes).expect("deserialize");
        assert!(verify_ed25519_signature_equation(&decoded));
    }

    #[test]
    fn signature_equation_proof_rejects_tamper() {
        let base = ed25519_basepoint_affine();
        let public_key = base.scalar_mul(scalar_from_u64(3)).compress();
        let r = base.scalar_mul(scalar_from_u64(10)).compress();
        let msg = b"tamper";
        let k =
            Scalar::from_bytes_mod_order(derive_ed25519_challenge_scalar_mod_l(r, public_key, msg));
        let s = (Scalar::from(10u64) + (k * Scalar::from(3u64))).to_bytes();
        let mut proof = prove_ed25519_signature_equation(
            public_key,
            r,
            s,
            msg,
            Ed25519VerificationPolicy::StrictRfc8032,
        )
        .expect("prove");
        assert!(verify_ed25519_signature_equation(&proof));
        proof.statement_hash[0] ^= 1;
        assert!(!verify_ed25519_signature_equation(&proof));
    }

    #[test]
    fn native_equation_check_accepts_valid_relation() {
        let a_secret = Scalar::from(7u64);
        let r_nonce = Scalar::from(12u64);
        let public_key = (&a_secret * curve25519::constants::ED25519_BASEPOINT_TABLE)
            .compress()
            .to_bytes();
        let r = (&r_nonce * curve25519::constants::ED25519_BASEPOINT_TABLE)
            .compress()
            .to_bytes();
        let msg = b"native equation";
        let k =
            Scalar::from_bytes_mod_order(derive_ed25519_challenge_scalar_mod_l(r, public_key, msg));
        let s = (r_nonce + (k * a_secret)).to_bytes();
        assert!(verify_ed25519_signature_equation_native(
            public_key, r, s, msg
        ));
    }
}
