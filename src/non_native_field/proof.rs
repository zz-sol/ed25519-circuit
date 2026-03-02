use p3_baby_bear::BabyBear;
use p3_challenger::{HashChallenger, SerializingChallenger32};
use p3_commit::ExtensionMmcs;
use p3_dft::Radix2DitParallel;
use p3_field::PrimeCharacteristicRing;
use p3_field::extension::BinomialExtensionField;
use p3_fri::{FriParameters, TwoAdicFriPcs};
use p3_keccak::Keccak256Hash;
use p3_merkle_tree::MerkleTreeMmcs;
use p3_symmetric::{CompressionFunctionFromHasher, SerializingHasher};
use p3_uni_stark::{Proof, StarkConfig, prove, verify};

use crate::non_native_field::air::{
    FieldAirOp, NON_NATIVE_FIELD_NUM_PUBLIC_VALUES, NonNativeFieldAir, build_trace_for_ops,
    compute_trace_public_values_with_seed, pad_trace_for_proof, rechain_trace_acc_with_seed,
};

pub type Val = BabyBear;
type ByteHash = Keccak256Hash;
type FieldHash = SerializingHasher<ByteHash>;
type MyCompress = CompressionFunctionFromHasher<ByteHash, 2, 32>;
type ValMmcs = MerkleTreeMmcs<Val, u8, FieldHash, MyCompress, 32>;
type Challenge = BinomialExtensionField<Val, 4>;
type ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>;
type Challenger = SerializingChallenger32<Val, HashChallenger<u8, ByteHash, 32>>;
type Dft = Radix2DitParallel<Val>;
type Pcs = TwoAdicFriPcs<Val, Dft, ValMmcs, ChallengeMmcs>;

pub type FieldAirStarkConfig = StarkConfig<Pcs, Challenge, Challenger>;
pub type FieldAirStarkProof = Proof<FieldAirStarkConfig>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FieldAirProofSettings {
    pub log_blowup: usize,
    pub log_final_poly_len: usize,
    pub num_queries: usize,
    pub commit_proof_of_work_bits: usize,
    pub query_proof_of_work_bits: usize,
    pub rng_seed: u64,
}

impl Default for FieldAirProofSettings {
    fn default() -> Self {
        Self {
            log_blowup: 1,
            log_final_poly_len: 1,
            num_queries: 1,
            commit_proof_of_work_bits: 1,
            query_proof_of_work_bits: 1,
            rng_seed: 1,
        }
    }
}

pub struct FieldAirProof {
    pub proof: FieldAirStarkProof,
    pub settings: FieldAirProofSettings,
    pub public_values: [BabyBear; NON_NATIVE_FIELD_NUM_PUBLIC_VALUES],
}

pub fn prove_field_air_ops(ops: &[FieldAirOp]) -> FieldAirProof {
    prove_field_air_ops_with_settings(ops, FieldAirProofSettings::default())
}

pub fn prove_field_air_ops_with_seed(ops: &[FieldAirOp], seed: BabyBear) -> FieldAirProof {
    prove_field_air_ops_with_settings_and_seed(ops, FieldAirProofSettings::default(), seed)
}

pub fn prove_field_air_ops_with_settings(
    ops: &[FieldAirOp],
    settings: FieldAirProofSettings,
) -> FieldAirProof {
    prove_field_air_ops_with_settings_and_seed(ops, settings, BabyBear::ZERO)
}

pub fn prove_field_air_ops_with_settings_and_seed(
    ops: &[FieldAirOp],
    settings: FieldAirProofSettings,
    seed: BabyBear,
) -> FieldAirProof {
    let config = setup_config(settings);
    let air = NonNativeFieldAir;
    let trace = rechain_trace_acc_with_seed(build_trace_for_ops(ops), seed);
    let trace = pad_trace_for_proof(trace, 8);
    let public_values = compute_trace_public_values_with_seed(&trace, seed);
    let proof = prove(&config, &air, trace, &public_values);
    FieldAirProof {
        proof,
        settings,
        public_values,
    }
}

pub fn verify_field_air_proof(proof: &FieldAirProof) -> bool {
    verify_field_air_proof_with_settings(proof, proof.settings)
}

pub fn verify_field_air_proof_with_settings(
    proof: &FieldAirProof,
    settings: FieldAirProofSettings,
) -> bool {
    let config = setup_config(settings);
    let air = NonNativeFieldAir;
    verify(&config, &air, &proof.proof, &proof.public_values).is_ok()
}

pub fn verify_field_air_proof_for_ops(proof: &FieldAirProof, ops: &[FieldAirOp]) -> bool {
    verify_field_air_proof_for_ops_with_seed(proof, ops, BabyBear::ZERO)
}

pub fn verify_field_air_proof_for_ops_with_seed(
    proof: &FieldAirProof,
    ops: &[FieldAirOp],
    seed: BabyBear,
) -> bool {
    if proof.public_values[8] != seed {
        return false;
    }
    let trace = pad_trace_for_proof(build_trace_for_ops(ops), 8);
    let trace = rechain_trace_acc_with_seed(trace, seed);
    let expected = compute_trace_public_values_with_seed(&trace, seed);
    if proof.public_values != expected {
        return false;
    }
    verify_field_air_proof(proof)
}

fn setup_config(settings: FieldAirProofSettings) -> FieldAirStarkConfig {
    let byte_hash = ByteHash {};
    let field_hash = FieldHash::new(byte_hash);
    let compress = MyCompress::new(byte_hash);
    let val_mmcs = ValMmcs::new(field_hash, compress);
    let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());
    let fri_params = FriParameters {
        log_blowup: settings.log_blowup,
        log_final_poly_len: settings.log_final_poly_len,
        num_queries: settings.num_queries,
        commit_proof_of_work_bits: settings.commit_proof_of_work_bits,
        query_proof_of_work_bits: settings.query_proof_of_work_bits,
        mmcs: challenge_mmcs,
    };
    let pcs = Pcs::new(Dft::default(), val_mmcs, fri_params);
    let challenger = Challenger::from_hasher(settings.rng_seed.to_le_bytes().to_vec(), byte_hash);
    StarkConfig::new(pcs, challenger)
}

#[cfg(test)]
mod tests {
    use p3_baby_bear::BabyBear;
    use p3_field::PrimeCharacteristicRing;
    use rand::{SeedableRng, rngs::SmallRng};

    use super::{
        FieldAirProofSettings, prove_field_air_ops, prove_field_air_ops_with_seed,
        verify_field_air_proof, verify_field_air_proof_for_ops_with_seed,
        verify_field_air_proof_with_settings,
    };
    use crate::non_native_field::Ed25519BaseField;
    use crate::non_native_field::air::FieldAirOp;

    #[test]
    fn prove_verify_roundtrip() {
        let mut rng = SmallRng::seed_from_u64(0x7777_8888_9999_aaaa);
        let mut ops = Vec::new();
        for i in 0..12 {
            let a = Ed25519BaseField::random(&mut rng);
            let b = Ed25519BaseField::random(&mut rng);
            if i % 2 == 0 {
                ops.push(FieldAirOp::Add { a, b });
            } else {
                ops.push(FieldAirOp::Mul { a, b });
            }
        }

        let proof = prove_field_air_ops(&ops);
        assert!(verify_field_air_proof(&proof));
    }

    #[test]
    fn verify_fails_with_mismatched_settings() {
        let mut rng = SmallRng::seed_from_u64(0x1111_eeee_2222_dddd);
        let a = Ed25519BaseField::random(&mut rng);
        let b = Ed25519BaseField::random(&mut rng);
        let ops = vec![FieldAirOp::Mul { a, b }];

        let proof = prove_field_air_ops(&ops);
        let bad = FieldAirProofSettings {
            num_queries: proof.settings.num_queries + 1,
            ..proof.settings
        };
        assert!(!verify_field_air_proof_with_settings(&proof, bad));
    }

    #[test]
    fn seeded_statement_binding_roundtrip() {
        let mut rng = SmallRng::seed_from_u64(0x5555_aaaa_6666_bbbb);
        let a = Ed25519BaseField::random(&mut rng);
        let b = Ed25519BaseField::random(&mut rng);
        let ops = vec![FieldAirOp::Add { a, b }];
        let seed = BabyBear::from_u32(123456);

        let proof = prove_field_air_ops_with_seed(&ops, seed);
        assert!(verify_field_air_proof(&proof));
        assert!(verify_field_air_proof_for_ops_with_seed(&proof, &ops, seed));
        assert!(!verify_field_air_proof_for_ops_with_seed(
            &proof,
            &ops,
            BabyBear::from_u32(7)
        ));
    }
}
