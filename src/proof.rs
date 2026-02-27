use crate::affine::{AffinePoint, ed25519_basepoint_affine};
use crate::lookup::ByteLookupTable;
use crate::sound_affine::{
    SoundAffineAddProof, deserialize_sound_affine_add_proof, prove_affine_add_sound_with_settings,
    serialize_sound_affine_add_proof, verify_affine_add_sound_with_settings,
};
use crate::sound_nonnative::SoundAddSubProofSettings;
use crate::trace::{build_affine_mul_trace, scalar_bit_le, verify_affine_mul_trace};
use bincode::Options;
use p3_air::{Air, AirBuilder, BaseAir, PairBuilder};
use p3_baby_bear::BabyBear;
use p3_challenger::{HashChallenger, SerializingChallenger32};
use p3_commit::{ExtensionMmcs, Pcs as PcsTrait};
use p3_dft::Radix2DitParallel;
use p3_field::PrimeCharacteristicRing;
use p3_field::extension::BinomialExtensionField;
use p3_fri::{FriParameters, TwoAdicFriPcs};
use p3_keccak::Keccak256Hash;
use p3_matrix::Matrix;
use p3_matrix::dense::RowMajorMatrix;
use p3_merkle_tree::MerkleTreeMmcs;
use p3_symmetric::{CompressionFunctionFromHasher, SerializingHasher};
use p3_uni_stark::{
    PreprocessedVerifierKey, Proof, StarkConfig, prove_with_preprocessed, setup_preprocessed,
    verify_with_preprocessed,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::error::Error;
use std::fmt::{Display, Formatter};

const DEGREE_BITS: usize = 8;
const MAIN_WIDTH: usize = 130;
const PREP_WIDTH: usize = 164;

const COL_ACC_BEFORE_X: usize = 0;
const COL_ACC_BEFORE_Y: usize = 16;
const COL_ACC_DOUBLE_X: usize = 32;
const COL_ACC_DOUBLE_Y: usize = 48;
const COL_ACC_ADD_X: usize = 64;
const COL_ACC_ADD_Y: usize = 80;
const COL_ACC_SELECT_X: usize = 96;
const COL_ACC_SELECT_Y: usize = 112;
const COL_LOGUP_ACC_X: usize = 128;
const COL_LOGUP_ACC_Y: usize = 129;

const COL_PREP_BIT: usize = 0;
const COL_PREP_FINAL_SELECTOR: usize = 1;
const COL_PREP_BEFORE_X_BASE: usize = 2;
const COL_PREP_BEFORE_Y_BASE: usize = 18;
const COL_PREP_DOUBLE_X_BASE: usize = 34;
const COL_PREP_DOUBLE_Y_BASE: usize = 50;
const COL_PREP_ADD_X_BASE: usize = 66;
const COL_PREP_ADD_Y_BASE: usize = 82;
const COL_PREP_SELECT_X_BASE: usize = 98;
const COL_PREP_SELECT_Y_BASE: usize = 114;
const COL_PREP_FINAL_X_BASE: usize = 130;
const COL_PREP_FINAL_Y_BASE: usize = 146;
const COL_PREP_LOGUP_DELTA_X: usize = 162;
const COL_PREP_LOGUP_DELTA_Y: usize = 163;

const CORE_PREP_WIDTH: usize = 36;
const COL_CORE_PREP_BIT: usize = 0;
const COL_CORE_PREP_FINAL_SELECTOR: usize = 1;
const COL_CORE_PREP_FINAL_X_BASE: usize = 2;
const COL_CORE_PREP_FINAL_Y_BASE: usize = 18;
const COL_CORE_PREP_LOGUP_DELTA_X: usize = 34;
const COL_CORE_PREP_LOGUP_DELTA_Y: usize = 35;

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
type Commitment = <Pcs as PcsTrait<Challenge, Challenger>>::Commitment;
const MAX_PROOF_BYTES: usize = 16 * 1024 * 1024;
const MAX_INNER_PROOF_BYTES: usize = 8 * 1024 * 1024;
const MAX_SAMPLED_SOUND_PROOF_BYTES: usize = 256 * 1024 * 1024;
const MAX_FULLY_SOUND_PROOF_BYTES: usize = 512 * 1024 * 1024;
const CODEC_TAG_SAMPLED_SOUND_PROOF: &[u8; 4] = b"SSP1";
const CODEC_TAG_FULLY_SOUND_PROOF: &[u8; 4] = b"FSP1";
const CODEC_TAG_SAMPLED_SOUND_BUNDLE: &[u8; 4] = b"SSB1";
const CODEC_TAG_FULLY_SOUND_BUNDLE: &[u8; 4] = b"FSB1";

pub type AffineMulStarkConfig = StarkConfig<Pcs, Challenge, Challenger>;
pub type AffineMulStarkProof = Proof<AffineMulStarkConfig>;
pub type AffineMulPreprocessedVk = PreprocessedVerifierKey<AffineMulStarkConfig>;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AffineMulProofSettings {
    pub log_blowup: usize,
    pub log_final_poly_len: usize,
    pub num_queries: usize,
    pub commit_proof_of_work_bits: usize,
    pub query_proof_of_work_bits: usize,
    pub rng_seed: u64,
}

impl Default for AffineMulProofSettings {
    fn default() -> Self {
        Self {
            log_blowup: 3,
            log_final_poly_len: 4,
            num_queries: 2,
            commit_proof_of_work_bits: 1,
            query_proof_of_work_bits: 1,
            rng_seed: 7,
        }
    }
}

pub struct AffineMulProof {
    pub proof: AffineMulStarkProof,
    pub preprocessed_vk: AffineMulPreprocessedVk,
    pub settings: AffineMulProofSettings,
    pub output_compressed: [u8; 32],
    pub statement_hash: [u8; 32],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AffineMulSoundProofSettings {
    pub core: AffineMulProofSettings,
    pub arithmetic: SoundAddSubProofSettings,
    pub sampled_rows: usize,
}

impl Default for AffineMulSoundProofSettings {
    fn default() -> Self {
        Self {
            core: AffineMulProofSettings::default(),
            arithmetic: SoundAddSubProofSettings::default(),
            sampled_rows: 1,
        }
    }
}

pub struct AffineMulSampledSoundProof {
    pub settings: AffineMulSoundProofSettings,
    pub statement_hash: [u8; 32],
    pub core: AffineMulProof,
    pub sampled_rows: Vec<usize>,
    pub double_proofs: Vec<SoundAffineAddProof>,
    pub add_proofs: Vec<SoundAffineAddProof>,
}

pub struct AffineMulFullySoundProof {
    pub arithmetic_settings: SoundAddSubProofSettings,
    pub statement_hash: [u8; 32],
    pub sampled_rows: Vec<usize>,
    pub double_proofs: Vec<SoundAffineAddProof>,
    pub add_proofs: Vec<SoundAffineAddProof>,
    pub output_compressed: [u8; 32],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AffineMulInstance {
    pub base: AffinePoint,
    pub scalar_le_bytes: [u8; 32],
}

#[derive(Serialize, Deserialize)]
struct SerializableVk {
    width: usize,
    degree_bits: usize,
    commitment: Commitment,
}

#[derive(Serialize, Deserialize)]
struct SerializableAffineMulProof {
    proof_bytes: Vec<u8>,
    vk: SerializableVk,
    settings: AffineMulProofSettings,
    output_compressed: [u8; 32],
    statement_hash: [u8; 32],
}

#[derive(Serialize, Deserialize)]
struct SerializableAffineMulSampledSoundProof {
    settings: AffineMulSoundProofSettings,
    statement_hash: [u8; 32],
    core_bytes: Vec<u8>,
    sampled_rows: Vec<usize>,
    double_proofs: Vec<Vec<u8>>,
    add_proofs: Vec<Vec<u8>>,
}

#[derive(Serialize, Deserialize)]
struct SerializableAffineMulFullySoundProof {
    arithmetic_settings: SoundAddSubProofSettings,
    statement_hash: [u8; 32],
    sampled_rows: Vec<usize>,
    double_proofs: Vec<Vec<u8>>,
    add_proofs: Vec<Vec<u8>>,
    output_compressed: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AffineMulProofBundle {
    pub sealed_instance: Vec<u8>,
    pub sealed_proof: Vec<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum AffineMulInstanceEncoding {
    Uncompressed = 0,
    Compressed = 1,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AffineMulProofBundleV2 {
    pub instance_encoding: AffineMulInstanceEncoding,
    pub sealed_instance: Vec<u8>,
    pub sealed_proof: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AffineMulSampledSoundProofBundle {
    pub sealed_instance: Vec<u8>,
    pub sealed_proof: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AffineMulFullySoundProofBundle {
    pub sealed_instance: Vec<u8>,
    pub sealed_proof: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AffineMulE2eProofBlob {
    pub sealed_instance: Vec<u8>,
    pub sealed_proof: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AffineMulSingleProofBlob {
    pub sealed_instance: Vec<u8>,
    pub sealed_proof: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AffineMulCodecError {
    InvalidInstanceLength { expected: usize, got: usize },
    InvalidCompressedInstanceLength { expected: usize, got: usize },
    InvalidAffineBaseEncoding,
    InvalidCompressedAffineBaseEncoding,
    InvalidAutoInstanceLength { got: usize },
}

impl Display for AffineMulCodecError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidInstanceLength { expected, got } => {
                write!(
                    f,
                    "invalid affine mul instance length: expected {expected}, got {got}"
                )
            }
            Self::InvalidCompressedInstanceLength { expected, got } => write!(
                f,
                "invalid compressed affine mul instance length: expected {expected}, got {got}"
            ),
            Self::InvalidAffineBaseEncoding => write!(f, "invalid affine base encoding"),
            Self::InvalidCompressedAffineBaseEncoding => {
                write!(f, "invalid compressed affine base encoding")
            }
            Self::InvalidAutoInstanceLength { got } => {
                write!(f, "invalid affine mul instance length: got {got}")
            }
        }
    }
}

impl Error for AffineMulCodecError {}

#[derive(Clone, Debug)]
pub struct AffineMulAir {
    preprocessed: RowMajorMatrix<Val>,
}

impl AffineMulAir {
    pub fn new(preprocessed: RowMajorMatrix<Val>) -> Self {
        Self { preprocessed }
    }
}

impl BaseAir<Val> for AffineMulAir {
    fn width(&self) -> usize {
        MAIN_WIDTH
    }

    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<Val>> {
        Some(self.preprocessed.clone())
    }
}

impl<AB> Air<AB> for AffineMulAir
where
    AB: AirBuilder<F = Val> + PairBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let prep = builder.preprocessed();
        let local = main.row_slice(0).expect("local row");
        let next = main.row_slice(1).expect("next row");
        let local_prep = prep.row_slice(0).expect("local preprocessed row");

        let bit = local_prep[COL_PREP_BIT].clone();
        let final_sel = local_prep[COL_PREP_FINAL_SELECTOR].clone();
        let logup_delta_x = local_prep[COL_PREP_LOGUP_DELTA_X].clone();
        let logup_delta_y = local_prep[COL_PREP_LOGUP_DELTA_Y].clone();
        let logup_acc_x = local[COL_LOGUP_ACC_X].clone();
        let logup_acc_y = local[COL_LOGUP_ACC_Y].clone();
        builder.assert_bool(bit.clone());
        builder.assert_bool(final_sel.clone());

        for i in 0..16 {
            let before_x = local[COL_ACC_BEFORE_X + i].clone();
            let before_y = local[COL_ACC_BEFORE_Y + i].clone();
            let double_x = local[COL_ACC_DOUBLE_X + i].clone();
            let double_y = local[COL_ACC_DOUBLE_Y + i].clone();
            let add_x = local[COL_ACC_ADD_X + i].clone();
            let add_y = local[COL_ACC_ADD_Y + i].clone();
            let select_x = local[COL_ACC_SELECT_X + i].clone();
            let select_y = local[COL_ACC_SELECT_Y + i].clone();

            builder.assert_zero(before_x.clone() - local_prep[COL_PREP_BEFORE_X_BASE + i].clone());
            builder.assert_zero(before_y.clone() - local_prep[COL_PREP_BEFORE_Y_BASE + i].clone());
            builder.assert_zero(double_x.clone() - local_prep[COL_PREP_DOUBLE_X_BASE + i].clone());
            builder.assert_zero(double_y.clone() - local_prep[COL_PREP_DOUBLE_Y_BASE + i].clone());
            builder.assert_zero(add_x.clone() - local_prep[COL_PREP_ADD_X_BASE + i].clone());
            builder.assert_zero(add_y.clone() - local_prep[COL_PREP_ADD_Y_BASE + i].clone());
            builder.assert_zero(select_x.clone() - local_prep[COL_PREP_SELECT_X_BASE + i].clone());
            builder.assert_zero(select_y.clone() - local_prep[COL_PREP_SELECT_Y_BASE + i].clone());

            builder.assert_zero(
                select_x.clone() - (bit.clone() * add_x + (AB::Expr::ONE - bit.clone()) * double_x),
            );
            builder.assert_zero(
                select_y.clone() - (bit.clone() * add_y + (AB::Expr::ONE - bit.clone()) * double_y),
            );

            let expected_final_x = local_prep[COL_PREP_FINAL_X_BASE + i].clone();
            let expected_final_y = local_prep[COL_PREP_FINAL_Y_BASE + i].clone();
            builder.assert_zero(final_sel.clone() * (select_x - expected_final_x));
            builder.assert_zero(final_sel.clone() * (select_y - expected_final_y));

            let mut transition = builder.when_transition();
            transition.assert_zero(
                next[COL_ACC_BEFORE_X + i].clone() - local[COL_ACC_SELECT_X + i].clone(),
            );
            transition.assert_zero(
                next[COL_ACC_BEFORE_Y + i].clone() - local[COL_ACC_SELECT_Y + i].clone(),
            );
        }

        let mut transition = builder.when_transition();
        transition.assert_zero(logup_acc_x.clone() - logup_delta_x - next[COL_LOGUP_ACC_X].clone());
        transition.assert_zero(logup_acc_y.clone() - logup_delta_y - next[COL_LOGUP_ACC_Y].clone());

        builder.assert_zero(
            final_sel.clone() * (logup_acc_x - local_prep[COL_PREP_LOGUP_DELTA_X].clone()),
        );
        builder.assert_zero(
            final_sel.clone() * (logup_acc_y - local_prep[COL_PREP_LOGUP_DELTA_Y].clone()),
        );

        let mut first = builder.when_first_row();
        first.assert_zero(local[COL_ACC_BEFORE_X].clone());
        first.assert_zero(local[COL_ACC_BEFORE_Y].clone() - AB::Expr::ONE);
        first.assert_zero(local[COL_LOGUP_ACC_X].clone());
        first.assert_zero(local[COL_LOGUP_ACC_Y].clone());
        for i in 1..16 {
            first.assert_zero(local[COL_ACC_BEFORE_X + i].clone());
            first.assert_zero(local[COL_ACC_BEFORE_Y + i].clone());
        }
    }
}

#[derive(Clone, Debug)]
pub struct AffineMulCoreAir {
    preprocessed: RowMajorMatrix<Val>,
}

impl AffineMulCoreAir {
    pub fn new(preprocessed: RowMajorMatrix<Val>) -> Self {
        Self { preprocessed }
    }
}

impl BaseAir<Val> for AffineMulCoreAir {
    fn width(&self) -> usize {
        MAIN_WIDTH
    }

    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<Val>> {
        Some(self.preprocessed.clone())
    }
}

impl<AB> Air<AB> for AffineMulCoreAir
where
    AB: AirBuilder<F = Val> + PairBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let prep = builder.preprocessed();
        let local = main.row_slice(0).expect("local row");
        let next = main.row_slice(1).expect("next row");
        let local_prep = prep.row_slice(0).expect("local preprocessed row");

        let bit = local_prep[COL_CORE_PREP_BIT].clone();
        let final_sel = local_prep[COL_CORE_PREP_FINAL_SELECTOR].clone();
        let logup_delta_x = local_prep[COL_CORE_PREP_LOGUP_DELTA_X].clone();
        let logup_delta_y = local_prep[COL_CORE_PREP_LOGUP_DELTA_Y].clone();
        let logup_acc_x = local[COL_LOGUP_ACC_X].clone();
        let logup_acc_y = local[COL_LOGUP_ACC_Y].clone();
        builder.assert_bool(bit.clone());
        builder.assert_bool(final_sel.clone());

        for i in 0..16 {
            let double_x = local[COL_ACC_DOUBLE_X + i].clone();
            let double_y = local[COL_ACC_DOUBLE_Y + i].clone();
            let add_x = local[COL_ACC_ADD_X + i].clone();
            let add_y = local[COL_ACC_ADD_Y + i].clone();
            let select_x = local[COL_ACC_SELECT_X + i].clone();
            let select_y = local[COL_ACC_SELECT_Y + i].clone();

            builder.assert_zero(
                select_x.clone() - (bit.clone() * add_x + (AB::Expr::ONE - bit.clone()) * double_x),
            );
            builder.assert_zero(
                select_y.clone() - (bit.clone() * add_y + (AB::Expr::ONE - bit.clone()) * double_y),
            );

            let expected_final_x = local_prep[COL_CORE_PREP_FINAL_X_BASE + i].clone();
            let expected_final_y = local_prep[COL_CORE_PREP_FINAL_Y_BASE + i].clone();
            builder.assert_zero(final_sel.clone() * (select_x - expected_final_x));
            builder.assert_zero(final_sel.clone() * (select_y - expected_final_y));

            let mut transition = builder.when_transition();
            transition.assert_zero(
                next[COL_ACC_BEFORE_X + i].clone() - local[COL_ACC_SELECT_X + i].clone(),
            );
            transition.assert_zero(
                next[COL_ACC_BEFORE_Y + i].clone() - local[COL_ACC_SELECT_Y + i].clone(),
            );
        }

        let mut transition = builder.when_transition();
        transition.assert_zero(logup_acc_x.clone() - logup_delta_x - next[COL_LOGUP_ACC_X].clone());
        transition.assert_zero(logup_acc_y.clone() - logup_delta_y - next[COL_LOGUP_ACC_Y].clone());

        builder.assert_zero(
            final_sel.clone() * (logup_acc_x - local_prep[COL_CORE_PREP_LOGUP_DELTA_X].clone()),
        );
        builder.assert_zero(
            final_sel.clone() * (logup_acc_y - local_prep[COL_CORE_PREP_LOGUP_DELTA_Y].clone()),
        );

        let mut first = builder.when_first_row();
        first.assert_zero(local[COL_ACC_BEFORE_X].clone());
        first.assert_zero(local[COL_ACC_BEFORE_Y].clone() - AB::Expr::ONE);
        first.assert_zero(local[COL_LOGUP_ACC_X].clone());
        first.assert_zero(local[COL_LOGUP_ACC_Y].clone());
        for i in 1..16 {
            first.assert_zero(local[COL_ACC_BEFORE_X + i].clone());
            first.assert_zero(local[COL_ACC_BEFORE_Y + i].clone());
        }
    }
}

fn setup_config(settings: AffineMulProofSettings) -> AffineMulStarkConfig {
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
    AffineMulStarkConfig::new(pcs, challenger)
}

fn meets_minimum_policy(settings: AffineMulProofSettings) -> bool {
    settings.log_final_poly_len >= 4
        && settings.log_blowup >= 3
        && settings.num_queries >= 2
        && settings.commit_proof_of_work_bits >= 1
        && settings.query_proof_of_work_bits >= 1
}

fn row_logup_deltas(
    row: usize,
    step: &crate::trace::AffineMulTraceStep,
    byte_table: &ByteLookupTable,
) -> Result<(Val, Val), String> {
    let mut delta_x = Val::ZERO;
    let mut delta_y = Val::ZERO;
    let points = [
        step.acc_before,
        step.acc_after_double,
        step.acc_after_add_base,
        step.acc_after_select,
    ];
    for p in points {
        let x_pairs = byte_table.logup_multiset_pairs(&p.x.limbs);
        let y_pairs = byte_table.logup_multiset_pairs(&p.y.limbs);
        let challenge_x = Val::from_u32((1 << 20) + (row as u32 * 8) + 1);
        let challenge_y = Val::from_u32((1 << 20) + (row as u32 * 8) + 2);
        delta_x += byte_table
            .logup_delta(&x_pairs, challenge_x)
            .ok_or_else(|| format!("failed to compute x logup delta for row {row}"))?;
        delta_y += byte_table
            .logup_delta(&y_pairs, challenge_y)
            .ok_or_else(|| format!("failed to compute y logup delta for row {row}"))?;
    }
    Ok((delta_x, delta_y))
}

fn build_main_trace(
    trace: &[crate::trace::AffineMulTraceStep],
    deltas: &[(Val, Val)],
) -> RowMajorMatrix<Val> {
    let mut values = Vec::with_capacity(trace.len() * MAIN_WIDTH);
    let mut suffix_acc_x = vec![Val::ZERO; trace.len()];
    let mut suffix_acc_y = vec![Val::ZERO; trace.len()];
    let mut run_x = Val::ZERO;
    let mut run_y = Val::ZERO;
    for row in (0..trace.len()).rev() {
        run_x += deltas[row].0;
        run_y += deltas[row].1;
        suffix_acc_x[row] = run_x;
        suffix_acc_y[row] = run_y;
    }

    for (row, step) in trace.iter().enumerate() {
        for limb in step.acc_before.x.limbs_u32() {
            values.push(Val::from_u32(limb));
        }
        for limb in step.acc_before.y.limbs_u32() {
            values.push(Val::from_u32(limb));
        }
        for limb in step.acc_after_double.x.limbs_u32() {
            values.push(Val::from_u32(limb));
        }
        for limb in step.acc_after_double.y.limbs_u32() {
            values.push(Val::from_u32(limb));
        }
        for limb in step.acc_after_add_base.x.limbs_u32() {
            values.push(Val::from_u32(limb));
        }
        for limb in step.acc_after_add_base.y.limbs_u32() {
            values.push(Val::from_u32(limb));
        }
        for limb in step.acc_after_select.x.limbs_u32() {
            values.push(Val::from_u32(limb));
        }
        for limb in step.acc_after_select.y.limbs_u32() {
            values.push(Val::from_u32(limb));
        }
        values.push(suffix_acc_x[row]);
        values.push(suffix_acc_y[row]);
    }
    RowMajorMatrix::new(values, MAIN_WIDTH)
}

fn build_preprocessed_trace(
    scalar_le_bytes: [u8; 32],
    trace: &[crate::trace::AffineMulTraceStep],
    final_point: AffinePoint,
    deltas: &[(Val, Val)],
) -> RowMajorMatrix<Val> {
    let mut values = Vec::with_capacity(trace.len() * PREP_WIDTH);
    let final_x = final_point.x.limbs_u32();
    let final_y = final_point.y.limbs_u32();

    for (row, step) in trace.iter().enumerate() {
        let bit = scalar_bit_le(&scalar_le_bytes, step.bit_index);
        values.push(Val::from_bool(bit == 1));

        let is_last = row + 1 == trace.len();
        values.push(Val::from_bool(is_last));

        for limb in step.acc_before.x.limbs_u32() {
            values.push(Val::from_u32(limb));
        }
        for limb in step.acc_before.y.limbs_u32() {
            values.push(Val::from_u32(limb));
        }
        for limb in step.acc_after_double.x.limbs_u32() {
            values.push(Val::from_u32(limb));
        }
        for limb in step.acc_after_double.y.limbs_u32() {
            values.push(Val::from_u32(limb));
        }
        for limb in step.acc_after_add_base.x.limbs_u32() {
            values.push(Val::from_u32(limb));
        }
        for limb in step.acc_after_add_base.y.limbs_u32() {
            values.push(Val::from_u32(limb));
        }
        for limb in step.acc_after_select.x.limbs_u32() {
            values.push(Val::from_u32(limb));
        }
        for limb in step.acc_after_select.y.limbs_u32() {
            values.push(Val::from_u32(limb));
        }

        for &limb in &final_x {
            values.push(Val::from_u32(if is_last { limb } else { 0 }));
        }
        for &limb in &final_y {
            values.push(Val::from_u32(if is_last { limb } else { 0 }));
        }
        values.push(deltas[row].0);
        values.push(deltas[row].1);
    }

    RowMajorMatrix::new(values, PREP_WIDTH)
}

fn build_core_preprocessed_trace(
    scalar_le_bytes: [u8; 32],
    trace: &[crate::trace::AffineMulTraceStep],
    final_point: AffinePoint,
    deltas: &[(Val, Val)],
) -> RowMajorMatrix<Val> {
    let mut values = Vec::with_capacity(trace.len() * CORE_PREP_WIDTH);
    let final_x = final_point.x.limbs_u32();
    let final_y = final_point.y.limbs_u32();

    for (row, step) in trace.iter().enumerate() {
        let bit = scalar_bit_le(&scalar_le_bytes, step.bit_index);
        values.push(Val::from_bool(bit == 1));

        let is_last = row + 1 == trace.len();
        values.push(Val::from_bool(is_last));

        for &limb in &final_x {
            values.push(Val::from_u32(if is_last { limb } else { 0 }));
        }
        for &limb in &final_y {
            values.push(Val::from_u32(if is_last { limb } else { 0 }));
        }
        values.push(deltas[row].0);
        values.push(deltas[row].1);
    }

    RowMajorMatrix::new(values, CORE_PREP_WIDTH)
}

fn vk_matches(a: &AffineMulPreprocessedVk, b: &AffineMulPreprocessedVk) -> bool {
    a.commitment == b.commitment && a.degree_bits == b.degree_bits && a.width == b.width
}

fn to_serializable_vk(vk: &AffineMulPreprocessedVk) -> SerializableVk {
    SerializableVk {
        width: vk.width,
        degree_bits: vk.degree_bits,
        commitment: vk.commitment,
    }
}

fn from_serializable_vk(vk: SerializableVk) -> AffineMulPreprocessedVk {
    AffineMulPreprocessedVk {
        width: vk.width,
        degree_bits: vk.degree_bits,
        commitment: vk.commitment,
    }
}

fn statement_hash(
    instance: AffineMulInstance,
    output_compressed: [u8; 32],
    settings: AffineMulProofSettings,
    vk: &AffineMulPreprocessedVk,
) -> Result<[u8; 32], String> {
    let mut hasher = Sha256::new();
    hasher.update(serialize_affine_mul_instance(&instance));
    hasher.update(output_compressed);
    hasher.update(
        bincode::serialize(&settings)
            .map_err(|e| format!("failed to serialize settings for statement hash: {e}"))?,
    );
    hasher.update(
        bincode::serialize(&to_serializable_vk(vk))
            .map_err(|e| format!("failed to serialize vk for statement hash: {e}"))?,
    );
    Ok(hasher.finalize().into())
}

fn sample_rows_evenly(total_rows: usize, sample_count: usize) -> Vec<usize> {
    if total_rows == 0 || sample_count == 0 {
        return Vec::new();
    }
    if sample_count >= total_rows {
        return (0..total_rows).collect();
    }
    let mut rows = Vec::with_capacity(sample_count);
    for i in 0..sample_count {
        rows.push((i * total_rows) / sample_count);
    }
    rows.sort_unstable();
    rows.dedup();
    rows
}

fn encode_with_tag(tag: &[u8; 4], payload: Vec<u8>) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + payload.len());
    out.extend_from_slice(tag);
    out.extend_from_slice(&payload);
    out
}

fn split_tagged_payload<'a>(
    bytes: &'a [u8],
    expected_tag: &[u8; 4],
    size_limit: usize,
    what: &str,
) -> Result<&'a [u8], String> {
    if bytes.len() > size_limit {
        return Err(format!("{what} exceeds configured size limit"));
    }
    if bytes.len() < 4 || &bytes[..4] != expected_tag {
        return Err(format!("invalid {what} codec header"));
    }
    Ok(&bytes[4..])
}

fn meets_minimum_arithmetic_policy(settings: SoundAddSubProofSettings) -> bool {
    settings.log_final_poly_len >= 4
        && settings.log_blowup >= 3
        && settings.num_queries >= 2
        && settings.commit_proof_of_work_bits >= 1
        && settings.query_proof_of_work_bits >= 1
}

fn sampled_sound_statement_hash(
    instance: AffineMulInstance,
    settings: AffineMulSoundProofSettings,
    sampled_rows: &[usize],
    core_statement_hash: [u8; 32],
) -> Result<[u8; 32], String> {
    let mut hasher = Sha256::new();
    hasher.update(serialize_affine_mul_instance(&instance));
    hasher.update(
        bincode::serialize(&settings)
            .map_err(|e| format!("failed to serialize sampled sound settings: {e}"))?,
    );
    hasher.update(
        bincode::serialize(sampled_rows)
            .map_err(|e| format!("failed to serialize sampled rows: {e}"))?,
    );
    hasher.update(core_statement_hash);
    Ok(hasher.finalize().into())
}

fn fully_sound_statement_hash(
    instance: AffineMulInstance,
    arithmetic_settings: SoundAddSubProofSettings,
    sampled_rows: &[usize],
    output_compressed: [u8; 32],
) -> Result<[u8; 32], String> {
    let mut hasher = Sha256::new();
    hasher.update(serialize_affine_mul_instance(&instance));
    hasher.update(
        bincode::serialize(&arithmetic_settings)
            .map_err(|e| format!("failed to serialize arithmetic settings: {e}"))?,
    );
    hasher.update(
        bincode::serialize(sampled_rows)
            .map_err(|e| format!("failed to serialize sampled rows: {e}"))?,
    );
    hasher.update(output_compressed);
    Ok(hasher.finalize().into())
}

#[allow(clippy::type_complexity)]
fn build_full_arithmetic_chain(
    instance: AffineMulInstance,
    arithmetic_settings: SoundAddSubProofSettings,
) -> Result<
    (
        Vec<usize>,
        Vec<SoundAffineAddProof>,
        Vec<SoundAffineAddProof>,
        [u8; 32],
    ),
    String,
> {
    let trace = build_affine_mul_trace(instance.base, instance.scalar_le_bytes);
    let sampled_rows = (0..trace.len()).collect::<Vec<_>>();
    let mut double_proofs = Vec::with_capacity(trace.len());
    let mut add_proofs = Vec::with_capacity(trace.len());

    for (row, step) in trace.iter().enumerate() {
        let double_proof = prove_affine_add_sound_with_settings(
            step.acc_before,
            step.acc_before,
            arithmetic_settings,
        )?;
        if double_proof.out != step.acc_after_double {
            return Err(format!("double proof output mismatch at row {row}"));
        }
        let add_proof = prove_affine_add_sound_with_settings(
            step.acc_after_double,
            instance.base,
            arithmetic_settings,
        )?;
        if add_proof.out != step.acc_after_add_base {
            return Err(format!("add proof output mismatch at row {row}"));
        }
        double_proofs.push(double_proof);
        add_proofs.push(add_proof);
    }

    let output_compressed = trace
        .last()
        .ok_or_else(|| "trace is empty".to_string())?
        .acc_after_select
        .compress();
    Ok((sampled_rows, double_proofs, add_proofs, output_compressed))
}

pub fn serialize_affine_mul_instance(instance: &AffineMulInstance) -> Vec<u8> {
    let mut out = Vec::with_capacity(96);
    out.extend_from_slice(&instance.base.to_uncompressed_bytes());
    out.extend_from_slice(&instance.scalar_le_bytes);
    out
}

pub fn deserialize_affine_mul_instance(bytes: &[u8]) -> Result<AffineMulInstance, String> {
    try_deserialize_affine_mul_instance(bytes).map_err(|e| e.to_string())
}

pub fn try_deserialize_affine_mul_instance(
    bytes: &[u8],
) -> Result<AffineMulInstance, AffineMulCodecError> {
    if bytes.len() != 96 {
        return Err(AffineMulCodecError::InvalidInstanceLength {
            expected: 96,
            got: bytes.len(),
        });
    }
    let mut point_bytes = [0_u8; 64];
    let mut scalar = [0_u8; 32];
    point_bytes.copy_from_slice(&bytes[..64]);
    scalar.copy_from_slice(&bytes[64..96]);

    let base = AffinePoint::from_uncompressed_bytes_strict(point_bytes)
        .ok_or(AffineMulCodecError::InvalidAffineBaseEncoding)?;
    Ok(AffineMulInstance {
        base,
        scalar_le_bytes: scalar,
    })
}

pub fn serialize_affine_mul_instance_compressed(instance: &AffineMulInstance) -> Vec<u8> {
    let mut out = Vec::with_capacity(64);
    out.extend_from_slice(&instance.base.compress());
    out.extend_from_slice(&instance.scalar_le_bytes);
    out
}

pub fn deserialize_affine_mul_instance_compressed(
    bytes: &[u8],
) -> Result<AffineMulInstance, String> {
    try_deserialize_affine_mul_instance_compressed(bytes).map_err(|e| e.to_string())
}

pub fn try_deserialize_affine_mul_instance_compressed(
    bytes: &[u8],
) -> Result<AffineMulInstance, AffineMulCodecError> {
    if bytes.len() != 64 {
        return Err(AffineMulCodecError::InvalidCompressedInstanceLength {
            expected: 64,
            got: bytes.len(),
        });
    }
    let mut base_bytes = [0_u8; 32];
    let mut scalar = [0_u8; 32];
    base_bytes.copy_from_slice(&bytes[..32]);
    scalar.copy_from_slice(&bytes[32..64]);
    let base = AffinePoint::from_compressed_bytes_strict(base_bytes)
        .ok_or(AffineMulCodecError::InvalidCompressedAffineBaseEncoding)?;
    Ok(AffineMulInstance {
        base,
        scalar_le_bytes: scalar,
    })
}

pub fn deserialize_affine_mul_instance_auto(bytes: &[u8]) -> Result<AffineMulInstance, String> {
    try_deserialize_affine_mul_instance_auto(bytes).map_err(|e| e.to_string())
}

pub fn try_deserialize_affine_mul_instance_auto(
    bytes: &[u8],
) -> Result<AffineMulInstance, AffineMulCodecError> {
    match bytes.len() {
        64 => try_deserialize_affine_mul_instance_compressed(bytes),
        96 => try_deserialize_affine_mul_instance(bytes),
        _ => Err(AffineMulCodecError::InvalidAutoInstanceLength { got: bytes.len() }),
    }
}

pub fn serialize_affine_mul_proof(proof: &AffineMulProof) -> Result<Vec<u8>, String> {
    let proof_bytes = bincode::serialize(&proof.proof).map_err(|e| e.to_string())?;
    if proof_bytes.len() > MAX_INNER_PROOF_BYTES {
        return Err("inner affine mul proof exceeds configured size limit".to_string());
    }
    let serializable = SerializableAffineMulProof {
        proof_bytes,
        vk: to_serializable_vk(&proof.preprocessed_vk),
        settings: proof.settings,
        output_compressed: proof.output_compressed,
        statement_hash: proof.statement_hash,
    };
    let bytes = bincode::serialize(&serializable).map_err(|e| e.to_string())?;
    if bytes.len() > MAX_PROOF_BYTES {
        return Err("serialized affine mul proof exceeds configured size limit".to_string());
    }
    Ok(bytes)
}

pub fn deserialize_affine_mul_proof(bytes: &[u8]) -> Result<AffineMulProof, String> {
    if bytes.len() > MAX_PROOF_BYTES {
        return Err("serialized affine mul proof exceeds configured size limit".to_string());
    }
    let opts = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .reject_trailing_bytes()
        .with_limit(MAX_PROOF_BYTES as u64);
    let serializable: SerializableAffineMulProof =
        opts.deserialize(bytes).map_err(|e| e.to_string())?;
    if serializable.proof_bytes.len() > MAX_INNER_PROOF_BYTES {
        return Err("inner affine mul proof exceeds configured size limit".to_string());
    }
    let inner_opts = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .reject_trailing_bytes()
        .with_limit(MAX_INNER_PROOF_BYTES as u64);
    let proof: AffineMulStarkProof = inner_opts
        .deserialize(&serializable.proof_bytes)
        .map_err(|e| e.to_string())?;
    Ok(AffineMulProof {
        proof,
        preprocessed_vk: from_serializable_vk(serializable.vk),
        settings: serializable.settings,
        output_compressed: serializable.output_compressed,
        statement_hash: serializable.statement_hash,
    })
}

pub fn serialize_affine_mul_sampled_sound_proof(
    proof: &AffineMulSampledSoundProof,
) -> Result<Vec<u8>, String> {
    let mut double_proofs = Vec::with_capacity(proof.double_proofs.len());
    for p in &proof.double_proofs {
        double_proofs.push(serialize_sound_affine_add_proof(p)?);
    }
    let mut add_proofs = Vec::with_capacity(proof.add_proofs.len());
    for p in &proof.add_proofs {
        add_proofs.push(serialize_sound_affine_add_proof(p)?);
    }
    let serializable = SerializableAffineMulSampledSoundProof {
        settings: proof.settings,
        statement_hash: proof.statement_hash,
        core_bytes: serialize_affine_mul_proof(&proof.core)?,
        sampled_rows: proof.sampled_rows.clone(),
        double_proofs,
        add_proofs,
    };
    let payload = bincode::serialize(&serializable).map_err(|e| e.to_string())?;
    let bytes = encode_with_tag(CODEC_TAG_SAMPLED_SOUND_PROOF, payload);
    if bytes.len() > MAX_SAMPLED_SOUND_PROOF_BYTES {
        return Err("serialized sampled sound proof exceeds configured size limit".to_string());
    }
    Ok(bytes)
}

pub fn deserialize_affine_mul_sampled_sound_proof(
    bytes: &[u8],
) -> Result<AffineMulSampledSoundProof, String> {
    let payload = split_tagged_payload(
        bytes,
        CODEC_TAG_SAMPLED_SOUND_PROOF,
        MAX_SAMPLED_SOUND_PROOF_BYTES,
        "sampled sound proof",
    )?;
    let opts = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .reject_trailing_bytes()
        .with_limit((MAX_SAMPLED_SOUND_PROOF_BYTES - 4) as u64);
    let serializable: SerializableAffineMulSampledSoundProof =
        opts.deserialize(payload).map_err(|e| e.to_string())?;
    let mut double_proofs = Vec::with_capacity(serializable.double_proofs.len());
    for p in serializable.double_proofs {
        double_proofs.push(deserialize_sound_affine_add_proof(&p)?);
    }
    let mut add_proofs = Vec::with_capacity(serializable.add_proofs.len());
    for p in serializable.add_proofs {
        add_proofs.push(deserialize_sound_affine_add_proof(&p)?);
    }
    Ok(AffineMulSampledSoundProof {
        settings: serializable.settings,
        statement_hash: serializable.statement_hash,
        core: deserialize_affine_mul_proof(&serializable.core_bytes)?,
        sampled_rows: serializable.sampled_rows,
        double_proofs,
        add_proofs,
    })
}

pub fn serialize_affine_mul_fully_sound_proof(
    proof: &AffineMulFullySoundProof,
) -> Result<Vec<u8>, String> {
    let mut double_proofs = Vec::with_capacity(proof.double_proofs.len());
    for p in &proof.double_proofs {
        double_proofs.push(serialize_sound_affine_add_proof(p)?);
    }
    let mut add_proofs = Vec::with_capacity(proof.add_proofs.len());
    for p in &proof.add_proofs {
        add_proofs.push(serialize_sound_affine_add_proof(p)?);
    }
    let serializable = SerializableAffineMulFullySoundProof {
        arithmetic_settings: proof.arithmetic_settings,
        statement_hash: proof.statement_hash,
        sampled_rows: proof.sampled_rows.clone(),
        double_proofs,
        add_proofs,
        output_compressed: proof.output_compressed,
    };
    let payload = bincode::serialize(&serializable).map_err(|e| e.to_string())?;
    let bytes = encode_with_tag(CODEC_TAG_FULLY_SOUND_PROOF, payload);
    if bytes.len() > MAX_FULLY_SOUND_PROOF_BYTES {
        return Err("serialized fully sound proof exceeds configured size limit".to_string());
    }
    Ok(bytes)
}

pub fn deserialize_affine_mul_fully_sound_proof(
    bytes: &[u8],
) -> Result<AffineMulFullySoundProof, String> {
    let payload = split_tagged_payload(
        bytes,
        CODEC_TAG_FULLY_SOUND_PROOF,
        MAX_FULLY_SOUND_PROOF_BYTES,
        "fully sound proof",
    )?;
    let opts = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .reject_trailing_bytes()
        .with_limit((MAX_FULLY_SOUND_PROOF_BYTES - 4) as u64);
    let serializable: SerializableAffineMulFullySoundProof =
        opts.deserialize(payload).map_err(|e| e.to_string())?;
    let mut double_proofs = Vec::with_capacity(serializable.double_proofs.len());
    for p in serializable.double_proofs {
        double_proofs.push(deserialize_sound_affine_add_proof(&p)?);
    }
    let mut add_proofs = Vec::with_capacity(serializable.add_proofs.len());
    for p in serializable.add_proofs {
        add_proofs.push(deserialize_sound_affine_add_proof(&p)?);
    }
    Ok(AffineMulFullySoundProof {
        arithmetic_settings: serializable.arithmetic_settings,
        statement_hash: serializable.statement_hash,
        sampled_rows: serializable.sampled_rows,
        double_proofs,
        add_proofs,
        output_compressed: serializable.output_compressed,
    })
}

pub fn prove_affine_mul_bundle(
    instance: AffineMulInstance,
) -> Result<AffineMulProofBundle, String> {
    let proof = prove_affine_mul(instance)?;
    let sealed_instance = serialize_affine_mul_instance(&instance);
    let sealed_proof = serialize_affine_mul_proof(&proof)?;
    Ok(AffineMulProofBundle {
        sealed_instance,
        sealed_proof,
    })
}

pub fn verify_affine_mul_bundle(bundle: &AffineMulProofBundle) -> bool {
    let Ok(instance) = deserialize_affine_mul_instance(&bundle.sealed_instance) else {
        return false;
    };
    let Ok(proof) = deserialize_affine_mul_proof(&bundle.sealed_proof) else {
        return false;
    };
    verify_affine_mul(instance, &proof)
}

pub fn prove_affine_mul_bundle_compressed(
    instance: AffineMulInstance,
) -> Result<AffineMulProofBundle, String> {
    let proof = prove_affine_mul(instance)?;
    let sealed_instance = serialize_affine_mul_instance_compressed(&instance);
    let sealed_proof = serialize_affine_mul_proof(&proof)?;
    Ok(AffineMulProofBundle {
        sealed_instance,
        sealed_proof,
    })
}

pub fn verify_affine_mul_bundle_auto(bundle: &AffineMulProofBundle) -> bool {
    let Ok(instance) = deserialize_affine_mul_instance_auto(&bundle.sealed_instance) else {
        return false;
    };
    let Ok(proof) = deserialize_affine_mul_proof(&bundle.sealed_proof) else {
        return false;
    };
    verify_affine_mul(instance, &proof)
}

pub fn prove_affine_mul_bundle_v2(
    instance: AffineMulInstance,
    encoding: AffineMulInstanceEncoding,
) -> Result<AffineMulProofBundleV2, String> {
    let proof = prove_affine_mul(instance)?;
    let sealed_instance = match encoding {
        AffineMulInstanceEncoding::Uncompressed => serialize_affine_mul_instance(&instance),
        AffineMulInstanceEncoding::Compressed => {
            serialize_affine_mul_instance_compressed(&instance)
        }
    };
    let sealed_proof = serialize_affine_mul_proof(&proof)?;
    Ok(AffineMulProofBundleV2 {
        instance_encoding: encoding,
        sealed_instance,
        sealed_proof,
    })
}

pub fn verify_affine_mul_bundle_v2(bundle: &AffineMulProofBundleV2) -> bool {
    let instance = match bundle.instance_encoding {
        AffineMulInstanceEncoding::Uncompressed => {
            deserialize_affine_mul_instance(&bundle.sealed_instance)
        }
        AffineMulInstanceEncoding::Compressed => {
            deserialize_affine_mul_instance_compressed(&bundle.sealed_instance)
        }
    };
    let Ok(instance) = instance else {
        return false;
    };
    let Ok(proof) = deserialize_affine_mul_proof(&bundle.sealed_proof) else {
        return false;
    };
    verify_affine_mul(instance, &proof)
}

pub fn serialize_affine_mul_bundle_v2(bundle: &AffineMulProofBundleV2) -> Result<Vec<u8>, String> {
    let bytes = bincode::serialize(bundle).map_err(|e| e.to_string())?;
    if bytes.len() > 2 * MAX_PROOF_BYTES {
        return Err("serialized affine mul v2 bundle exceeds configured size limit".to_string());
    }
    Ok(bytes)
}

pub fn deserialize_affine_mul_bundle_v2(bytes: &[u8]) -> Result<AffineMulProofBundleV2, String> {
    if bytes.len() > 2 * MAX_PROOF_BYTES {
        return Err("serialized affine mul v2 bundle exceeds configured size limit".to_string());
    }
    let opts = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .reject_trailing_bytes()
        .with_limit((2 * MAX_PROOF_BYTES) as u64);
    opts.deserialize(bytes).map_err(|e| e.to_string())
}

pub fn serialize_affine_mul_bundle(bundle: &AffineMulProofBundle) -> Result<Vec<u8>, String> {
    let bytes = bincode::serialize(bundle).map_err(|e| e.to_string())?;
    if bytes.len() > 2 * MAX_PROOF_BYTES {
        return Err("serialized affine mul bundle exceeds configured size limit".to_string());
    }
    Ok(bytes)
}

pub fn deserialize_affine_mul_bundle(bytes: &[u8]) -> Result<AffineMulProofBundle, String> {
    if bytes.len() > 2 * MAX_PROOF_BYTES {
        return Err("serialized affine mul bundle exceeds configured size limit".to_string());
    }
    let opts = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .reject_trailing_bytes()
        .with_limit((2 * MAX_PROOF_BYTES) as u64);
    opts.deserialize(bytes).map_err(|e| e.to_string())
}

pub fn prove_affine_mul_sampled_sound_bundle(
    instance: AffineMulInstance,
) -> Result<AffineMulSampledSoundProofBundle, String> {
    prove_affine_mul_sampled_sound_bundle_with_settings(
        instance,
        AffineMulSoundProofSettings::default(),
    )
}

pub fn prove_affine_mul_sampled_sound_bundle_with_settings(
    instance: AffineMulInstance,
    settings: AffineMulSoundProofSettings,
) -> Result<AffineMulSampledSoundProofBundle, String> {
    let proof = prove_affine_mul_sound_with_settings(instance, settings)?;
    let sealed_instance = serialize_affine_mul_instance_compressed(&instance);
    let sealed_proof = serialize_affine_mul_sampled_sound_proof(&proof)?;
    Ok(AffineMulSampledSoundProofBundle {
        sealed_instance,
        sealed_proof,
    })
}

pub fn verify_affine_mul_sampled_sound_bundle(bundle: &AffineMulSampledSoundProofBundle) -> bool {
    verify_affine_mul_sampled_sound_bundle_with_settings(
        bundle,
        AffineMulSoundProofSettings::default(),
    )
}

pub fn verify_affine_mul_sampled_sound_bundle_with_settings(
    bundle: &AffineMulSampledSoundProofBundle,
    settings: AffineMulSoundProofSettings,
) -> bool {
    let Ok(instance) = deserialize_affine_mul_instance_auto(&bundle.sealed_instance) else {
        return false;
    };
    let Ok(proof) = deserialize_affine_mul_sampled_sound_proof(&bundle.sealed_proof) else {
        return false;
    };
    verify_affine_mul_sound_with_settings(instance, &proof, settings)
}

pub fn prove_affine_mul_fully_sound_bundle(
    instance: AffineMulInstance,
) -> Result<AffineMulFullySoundProofBundle, String> {
    prove_affine_mul_fully_sound_bundle_with_settings(instance, SoundAddSubProofSettings::default())
}

pub fn prove_affine_mul_fully_sound_bundle_with_settings(
    instance: AffineMulInstance,
    arithmetic_settings: SoundAddSubProofSettings,
) -> Result<AffineMulFullySoundProofBundle, String> {
    let proof = prove_affine_mul_fully_sound_with_settings(instance, arithmetic_settings)?;
    let sealed_instance = serialize_affine_mul_instance_compressed(&instance);
    let sealed_proof = serialize_affine_mul_fully_sound_proof(&proof)?;
    Ok(AffineMulFullySoundProofBundle {
        sealed_instance,
        sealed_proof,
    })
}

pub fn verify_affine_mul_fully_sound_bundle(bundle: &AffineMulFullySoundProofBundle) -> bool {
    verify_affine_mul_fully_sound_bundle_with_settings(bundle, SoundAddSubProofSettings::default())
}

pub fn verify_affine_mul_fully_sound_bundle_with_settings(
    bundle: &AffineMulFullySoundProofBundle,
    arithmetic_settings: SoundAddSubProofSettings,
) -> bool {
    let Ok(instance) = deserialize_affine_mul_instance_auto(&bundle.sealed_instance) else {
        return false;
    };
    let Ok(proof) = deserialize_affine_mul_fully_sound_proof(&bundle.sealed_proof) else {
        return false;
    };
    verify_affine_mul_fully_sound_with_settings(instance, &proof, arithmetic_settings)
}

pub fn serialize_affine_mul_sampled_sound_bundle(
    bundle: &AffineMulSampledSoundProofBundle,
) -> Result<Vec<u8>, String> {
    let payload = bincode::serialize(bundle).map_err(|e| e.to_string())?;
    let bytes = encode_with_tag(CODEC_TAG_SAMPLED_SOUND_BUNDLE, payload);
    if bytes.len() > 2 * MAX_SAMPLED_SOUND_PROOF_BYTES {
        return Err("serialized sampled-sound bundle exceeds configured size limit".to_string());
    }
    Ok(bytes)
}

pub fn deserialize_affine_mul_sampled_sound_bundle(
    bytes: &[u8],
) -> Result<AffineMulSampledSoundProofBundle, String> {
    let payload = split_tagged_payload(
        bytes,
        CODEC_TAG_SAMPLED_SOUND_BUNDLE,
        2 * MAX_SAMPLED_SOUND_PROOF_BYTES,
        "sampled-sound bundle",
    )?;
    let opts = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .reject_trailing_bytes()
        .with_limit((2 * MAX_SAMPLED_SOUND_PROOF_BYTES - 4) as u64);
    opts.deserialize(payload).map_err(|e| e.to_string())
}

pub fn serialize_affine_mul_fully_sound_bundle(
    bundle: &AffineMulFullySoundProofBundle,
) -> Result<Vec<u8>, String> {
    let payload = bincode::serialize(bundle).map_err(|e| e.to_string())?;
    let bytes = encode_with_tag(CODEC_TAG_FULLY_SOUND_BUNDLE, payload);
    if bytes.len() > 2 * MAX_FULLY_SOUND_PROOF_BYTES {
        return Err("serialized fully-sound bundle exceeds configured size limit".to_string());
    }
    Ok(bytes)
}

pub fn deserialize_affine_mul_fully_sound_bundle(
    bytes: &[u8],
) -> Result<AffineMulFullySoundProofBundle, String> {
    let payload = split_tagged_payload(
        bytes,
        CODEC_TAG_FULLY_SOUND_BUNDLE,
        2 * MAX_FULLY_SOUND_PROOF_BYTES,
        "fully-sound bundle",
    )?;
    let opts = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .reject_trailing_bytes()
        .with_limit((2 * MAX_FULLY_SOUND_PROOF_BYTES - 4) as u64);
    opts.deserialize(payload).map_err(|e| e.to_string())
}

pub fn prove_affine_mul_single_proof(
    instance: AffineMulInstance,
) -> Result<AffineMulSingleProofBlob, String> {
    prove_affine_mul_single_proof_with_settings(instance, AffineMulProofSettings::default())
}

pub fn prove_affine_mul_single_proof_with_settings(
    instance: AffineMulInstance,
    settings: AffineMulProofSettings,
) -> Result<AffineMulSingleProofBlob, String> {
    let proof = prove_affine_mul_core_with_settings(instance, settings)?;
    Ok(AffineMulSingleProofBlob {
        sealed_instance: serialize_affine_mul_instance_compressed(&instance),
        sealed_proof: serialize_affine_mul_proof(&proof)?,
    })
}

pub fn verify_affine_mul_single_proof(blob: &AffineMulSingleProofBlob) -> bool {
    verify_affine_mul_single_proof_with_settings(blob, AffineMulProofSettings::default())
}

pub fn verify_affine_mul_single_proof_with_settings(
    blob: &AffineMulSingleProofBlob,
    settings: AffineMulProofSettings,
) -> bool {
    let Ok(instance) = deserialize_affine_mul_instance_auto(&blob.sealed_instance) else {
        return false;
    };
    let Ok(proof) = deserialize_affine_mul_proof(&blob.sealed_proof) else {
        return false;
    };
    verify_affine_mul_core_with_settings(instance, &proof, settings)
}

pub fn serialize_affine_mul_single_proof_blob(
    blob: &AffineMulSingleProofBlob,
) -> Result<Vec<u8>, String> {
    let bytes = bincode::serialize(blob).map_err(|e| e.to_string())?;
    if bytes.len() > 2 * MAX_PROOF_BYTES {
        return Err("serialized single-proof blob exceeds configured size limit".to_string());
    }
    Ok(bytes)
}

pub fn deserialize_affine_mul_single_proof_blob(
    bytes: &[u8],
) -> Result<AffineMulSingleProofBlob, String> {
    if bytes.len() > 2 * MAX_PROOF_BYTES {
        return Err("serialized single-proof blob exceeds configured size limit".to_string());
    }
    let opts = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .reject_trailing_bytes()
        .with_limit((2 * MAX_PROOF_BYTES) as u64);
    opts.deserialize(bytes).map_err(|e| e.to_string())
}

pub fn prove_affine_mul_single_unified(instance: AffineMulInstance) -> Result<Vec<u8>, String> {
    let blob = prove_affine_mul_single_proof(instance)?;
    serialize_affine_mul_single_proof_blob(&blob)
}

pub fn prove_affine_mul_single_unified_with_settings(
    instance: AffineMulInstance,
    settings: AffineMulProofSettings,
) -> Result<Vec<u8>, String> {
    let blob = prove_affine_mul_single_proof_with_settings(instance, settings)?;
    serialize_affine_mul_single_proof_blob(&blob)
}

pub fn verify_affine_mul_single_unified(bytes: &[u8]) -> bool {
    let Ok(blob) = deserialize_affine_mul_single_proof_blob(bytes) else {
        return false;
    };
    verify_affine_mul_single_proof(&blob)
}

pub fn verify_affine_mul_single_unified_with_settings(
    bytes: &[u8],
    settings: AffineMulProofSettings,
) -> bool {
    let Ok(blob) = deserialize_affine_mul_single_proof_blob(bytes) else {
        return false;
    };
    verify_affine_mul_single_proof_with_settings(&blob, settings)
}

pub fn prove_basepoint_affine_mul_single_unified(
    scalar_le_bytes: [u8; 32],
) -> Result<Vec<u8>, String> {
    prove_affine_mul_single_unified(AffineMulInstance {
        base: ed25519_basepoint_affine(),
        scalar_le_bytes,
    })
}

pub fn prove_basepoint_affine_mul_single_unified_with_settings(
    scalar_le_bytes: [u8; 32],
    settings: AffineMulProofSettings,
) -> Result<Vec<u8>, String> {
    prove_affine_mul_single_unified_with_settings(
        AffineMulInstance {
            base: ed25519_basepoint_affine(),
            scalar_le_bytes,
        },
        settings,
    )
}

pub fn verify_basepoint_affine_mul_single_unified(scalar_le_bytes: [u8; 32], bytes: &[u8]) -> bool {
    let Ok(blob) = deserialize_affine_mul_single_proof_blob(bytes) else {
        return false;
    };
    let Ok(instance) = deserialize_affine_mul_instance_auto(&blob.sealed_instance) else {
        return false;
    };
    if instance.base != ed25519_basepoint_affine() || instance.scalar_le_bytes != scalar_le_bytes {
        return false;
    }
    verify_affine_mul_single_proof(&blob)
}

pub fn verify_basepoint_affine_mul_single_unified_with_settings(
    scalar_le_bytes: [u8; 32],
    bytes: &[u8],
    settings: AffineMulProofSettings,
) -> bool {
    let Ok(blob) = deserialize_affine_mul_single_proof_blob(bytes) else {
        return false;
    };
    let Ok(instance) = deserialize_affine_mul_instance_auto(&blob.sealed_instance) else {
        return false;
    };
    if instance.base != ed25519_basepoint_affine() || instance.scalar_le_bytes != scalar_le_bytes {
        return false;
    }
    verify_affine_mul_single_proof_with_settings(&blob, settings)
}

pub fn prove_affine_mul_e2e(instance: AffineMulInstance) -> Result<AffineMulE2eProofBlob, String> {
    let bundle = prove_affine_mul_fully_sound_bundle(instance)?;
    Ok(AffineMulE2eProofBlob {
        sealed_instance: bundle.sealed_instance,
        sealed_proof: bundle.sealed_proof,
    })
}

pub fn prove_affine_mul_e2e_with_settings(
    instance: AffineMulInstance,
    arithmetic_settings: SoundAddSubProofSettings,
) -> Result<AffineMulE2eProofBlob, String> {
    let bundle = prove_affine_mul_fully_sound_bundle_with_settings(instance, arithmetic_settings)?;
    Ok(AffineMulE2eProofBlob {
        sealed_instance: bundle.sealed_instance,
        sealed_proof: bundle.sealed_proof,
    })
}

pub fn verify_affine_mul_e2e(blob: &AffineMulE2eProofBlob) -> bool {
    let Ok(instance) = deserialize_affine_mul_instance_auto(&blob.sealed_instance) else {
        return false;
    };
    let Ok(proof) = deserialize_affine_mul_fully_sound_proof(&blob.sealed_proof) else {
        return false;
    };
    verify_affine_mul_fully_sound_strict_with_settings(
        instance,
        &proof,
        SoundAddSubProofSettings::default(),
    )
}

pub fn verify_affine_mul_e2e_with_settings(
    blob: &AffineMulE2eProofBlob,
    arithmetic_settings: SoundAddSubProofSettings,
) -> bool {
    let Ok(instance) = deserialize_affine_mul_instance_auto(&blob.sealed_instance) else {
        return false;
    };
    let Ok(proof) = deserialize_affine_mul_fully_sound_proof(&blob.sealed_proof) else {
        return false;
    };
    verify_affine_mul_fully_sound_strict_with_settings(instance, &proof, arithmetic_settings)
}

pub fn serialize_affine_mul_e2e_blob(blob: &AffineMulE2eProofBlob) -> Result<Vec<u8>, String> {
    let bytes = bincode::serialize(blob).map_err(|e| e.to_string())?;
    if bytes.len() > 2 * MAX_FULLY_SOUND_PROOF_BYTES {
        return Err("serialized e2e proof blob exceeds configured size limit".to_string());
    }
    Ok(bytes)
}

pub fn deserialize_affine_mul_e2e_blob(bytes: &[u8]) -> Result<AffineMulE2eProofBlob, String> {
    if bytes.len() > 2 * MAX_FULLY_SOUND_PROOF_BYTES {
        return Err("serialized e2e proof blob exceeds configured size limit".to_string());
    }
    let opts = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .reject_trailing_bytes()
        .with_limit((2 * MAX_FULLY_SOUND_PROOF_BYTES) as u64);
    opts.deserialize(bytes).map_err(|e| e.to_string())
}

pub fn prove_affine_mul_e2e_unified(instance: AffineMulInstance) -> Result<Vec<u8>, String> {
    let blob = prove_affine_mul_e2e(instance)?;
    serialize_affine_mul_e2e_blob(&blob)
}

pub fn prove_affine_mul_e2e_unified_with_settings(
    instance: AffineMulInstance,
    arithmetic_settings: SoundAddSubProofSettings,
) -> Result<Vec<u8>, String> {
    let blob = prove_affine_mul_e2e_with_settings(instance, arithmetic_settings)?;
    serialize_affine_mul_e2e_blob(&blob)
}

pub fn prove_basepoint_affine_mul_e2e_unified(
    scalar_le_bytes: [u8; 32],
) -> Result<Vec<u8>, String> {
    prove_affine_mul_e2e_unified(AffineMulInstance {
        base: ed25519_basepoint_affine(),
        scalar_le_bytes,
    })
}

pub fn prove_basepoint_affine_mul_e2e_unified_with_settings(
    scalar_le_bytes: [u8; 32],
    arithmetic_settings: SoundAddSubProofSettings,
) -> Result<Vec<u8>, String> {
    prove_affine_mul_e2e_unified_with_settings(
        AffineMulInstance {
            base: ed25519_basepoint_affine(),
            scalar_le_bytes,
        },
        arithmetic_settings,
    )
}

pub fn verify_affine_mul_e2e_unified(bytes: &[u8]) -> bool {
    let Ok(blob) = deserialize_affine_mul_e2e_blob(bytes) else {
        return false;
    };
    verify_affine_mul_e2e(&blob)
}

pub fn verify_affine_mul_e2e_unified_with_settings(
    bytes: &[u8],
    arithmetic_settings: SoundAddSubProofSettings,
) -> bool {
    let Ok(blob) = deserialize_affine_mul_e2e_blob(bytes) else {
        return false;
    };
    verify_affine_mul_e2e_with_settings(&blob, arithmetic_settings)
}

pub fn verify_basepoint_affine_mul_e2e_unified(scalar_le_bytes: [u8; 32], bytes: &[u8]) -> bool {
    let Ok(blob) = deserialize_affine_mul_e2e_blob(bytes) else {
        return false;
    };
    let Ok(instance) = deserialize_affine_mul_instance_auto(&blob.sealed_instance) else {
        return false;
    };
    if instance.base != ed25519_basepoint_affine() || instance.scalar_le_bytes != scalar_le_bytes {
        return false;
    }
    verify_affine_mul_e2e(&blob)
}

pub fn verify_basepoint_affine_mul_e2e_unified_with_settings(
    scalar_le_bytes: [u8; 32],
    bytes: &[u8],
    arithmetic_settings: SoundAddSubProofSettings,
) -> bool {
    let Ok(blob) = deserialize_affine_mul_e2e_blob(bytes) else {
        return false;
    };
    let Ok(instance) = deserialize_affine_mul_instance_auto(&blob.sealed_instance) else {
        return false;
    };
    if instance.base != ed25519_basepoint_affine() || instance.scalar_le_bytes != scalar_le_bytes {
        return false;
    }
    verify_affine_mul_e2e_with_settings(&blob, arithmetic_settings)
}

pub fn prove_affine_mul_batch(
    instances: &[AffineMulInstance],
) -> Result<Vec<AffineMulProofBundle>, String> {
    let mut out = Vec::with_capacity(instances.len());
    for instance in instances {
        out.push(prove_affine_mul_bundle(*instance)?);
    }
    Ok(out)
}

pub fn verify_affine_mul_batch(bundles: &[AffineMulProofBundle]) -> bool {
    bundles.iter().all(verify_affine_mul_bundle)
}

pub fn prove_basepoint_affine_mul(scalar_le_bytes: [u8; 32]) -> Result<AffineMulProof, String> {
    prove_affine_mul(AffineMulInstance {
        base: ed25519_basepoint_affine(),
        scalar_le_bytes,
    })
}

pub fn prove_basepoint_affine_mul_with_settings(
    scalar_le_bytes: [u8; 32],
    settings: AffineMulProofSettings,
) -> Result<AffineMulProof, String> {
    prove_affine_mul_with_settings(
        AffineMulInstance {
            base: ed25519_basepoint_affine(),
            scalar_le_bytes,
        },
        settings,
    )
}

pub fn prove_basepoint_affine_mul_sound(
    scalar_le_bytes: [u8; 32],
) -> Result<AffineMulSampledSoundProof, String> {
    prove_affine_mul_sound(AffineMulInstance {
        base: ed25519_basepoint_affine(),
        scalar_le_bytes,
    })
}

pub fn verify_basepoint_affine_mul_sound(
    scalar_le_bytes: [u8; 32],
    proof: &AffineMulSampledSoundProof,
) -> bool {
    verify_affine_mul_sound(
        AffineMulInstance {
            base: ed25519_basepoint_affine(),
            scalar_le_bytes,
        },
        proof,
    )
}

pub fn prove_basepoint_affine_mul_fully_sound(
    scalar_le_bytes: [u8; 32],
) -> Result<AffineMulFullySoundProof, String> {
    prove_affine_mul_fully_sound(AffineMulInstance {
        base: ed25519_basepoint_affine(),
        scalar_le_bytes,
    })
}

pub fn prove_basepoint_affine_mul_fully_sound_with_settings(
    scalar_le_bytes: [u8; 32],
    arithmetic_settings: SoundAddSubProofSettings,
) -> Result<AffineMulFullySoundProof, String> {
    prove_affine_mul_fully_sound_with_settings(
        AffineMulInstance {
            base: ed25519_basepoint_affine(),
            scalar_le_bytes,
        },
        arithmetic_settings,
    )
}

pub fn verify_basepoint_affine_mul_fully_sound(
    scalar_le_bytes: [u8; 32],
    proof: &AffineMulFullySoundProof,
) -> bool {
    verify_affine_mul_fully_sound(
        AffineMulInstance {
            base: ed25519_basepoint_affine(),
            scalar_le_bytes,
        },
        proof,
    )
}

pub fn verify_basepoint_affine_mul_fully_sound_with_settings(
    scalar_le_bytes: [u8; 32],
    proof: &AffineMulFullySoundProof,
    arithmetic_settings: SoundAddSubProofSettings,
) -> bool {
    verify_affine_mul_fully_sound_with_settings(
        AffineMulInstance {
            base: ed25519_basepoint_affine(),
            scalar_le_bytes,
        },
        proof,
        arithmetic_settings,
    )
}

pub fn prove_affine_mul(instance: AffineMulInstance) -> Result<AffineMulProof, String> {
    prove_affine_mul_with_settings(instance, AffineMulProofSettings::default())
}

pub fn prove_affine_mul_with_settings(
    instance: AffineMulInstance,
    settings: AffineMulProofSettings,
) -> Result<AffineMulProof, String> {
    if !meets_minimum_policy(settings) {
        return Err("proof settings do not meet minimum verifier policy".to_string());
    }
    if !instance.base.is_on_curve() {
        return Err("base point is not on ed25519 curve".to_string());
    }
    if !instance.base.is_in_prime_order_subgroup() {
        return Err("base point is not in the prime-order subgroup".to_string());
    }

    let trace = build_affine_mul_trace(instance.base, instance.scalar_le_bytes);
    let byte_table = ByteLookupTable::default();
    if !verify_affine_mul_trace(&trace, instance.base, instance.scalar_le_bytes, &byte_table) {
        return Err("internal trace consistency check failed".to_string());
    }
    let mut deltas = Vec::with_capacity(trace.len());
    for (row, step) in trace.iter().enumerate() {
        deltas.push(row_logup_deltas(row, step, &byte_table)?);
    }

    let final_point = trace
        .last()
        .ok_or_else(|| "trace is empty".to_string())?
        .acc_after_select;
    let output_compressed = final_point.compress();
    let main = build_main_trace(&trace, &deltas);
    let preprocessed =
        build_preprocessed_trace(instance.scalar_le_bytes, &trace, final_point, &deltas);
    let air = AffineMulAir::new(preprocessed);
    let config = setup_config(settings);

    let (prover_data, preprocessed_vk) =
        setup_preprocessed::<AffineMulStarkConfig, _>(&config, &air, DEGREE_BITS)
            .ok_or_else(|| "failed to setup preprocessed data for affine mul proof".to_string())?;

    let proof = prove_with_preprocessed(&config, &air, main, &[], Some(&prover_data));
    let statement_hash = statement_hash(instance, output_compressed, settings, &preprocessed_vk)?;
    Ok(AffineMulProof {
        proof,
        preprocessed_vk,
        settings,
        output_compressed,
        statement_hash,
    })
}

pub fn verify_basepoint_affine_mul(scalar_le_bytes: [u8; 32], proof: &AffineMulProof) -> bool {
    verify_affine_mul(
        AffineMulInstance {
            base: ed25519_basepoint_affine(),
            scalar_le_bytes,
        },
        proof,
    )
}

pub fn verify_basepoint_affine_mul_with_settings(
    scalar_le_bytes: [u8; 32],
    proof: &AffineMulProof,
    settings: AffineMulProofSettings,
) -> bool {
    verify_affine_mul_with_settings(
        AffineMulInstance {
            base: ed25519_basepoint_affine(),
            scalar_le_bytes,
        },
        proof,
        settings,
    )
}

pub fn verify_affine_mul(instance: AffineMulInstance, proof: &AffineMulProof) -> bool {
    let policy = AffineMulProofSettings::default();
    if proof.settings != policy {
        return false;
    }
    verify_affine_mul_with_settings(instance, proof, policy)
}

pub fn verify_affine_mul_with_settings(
    instance: AffineMulInstance,
    proof: &AffineMulProof,
    settings: AffineMulProofSettings,
) -> bool {
    if !meets_minimum_policy(settings) || proof.settings != settings {
        return false;
    }
    if !instance.base.is_on_curve() || !instance.base.is_in_prime_order_subgroup() {
        return false;
    }

    let trace = build_affine_mul_trace(instance.base, instance.scalar_le_bytes);
    let final_point = match trace.last() {
        Some(last) => last.acc_after_select,
        None => return false,
    };
    if final_point.compress() != proof.output_compressed {
        return false;
    }
    let expected_hash = match statement_hash(
        instance,
        proof.output_compressed,
        settings,
        &proof.preprocessed_vk,
    ) {
        Ok(h) => h,
        Err(_) => return false,
    };
    if proof.statement_hash != expected_hash {
        return false;
    }

    let mut deltas = Vec::with_capacity(trace.len());
    let byte_table = ByteLookupTable::default();
    for (row, step) in trace.iter().enumerate() {
        let Ok(delta) = row_logup_deltas(row, step, &byte_table) else {
            return false;
        };
        deltas.push(delta);
    }
    let preprocessed =
        build_preprocessed_trace(instance.scalar_le_bytes, &trace, final_point, &deltas);
    let air = AffineMulAir::new(preprocessed);
    let config = setup_config(settings);

    let Some((_, expected_vk)) =
        setup_preprocessed::<AffineMulStarkConfig, _>(&config, &air, DEGREE_BITS)
    else {
        return false;
    };

    if !vk_matches(&expected_vk, &proof.preprocessed_vk) {
        return false;
    }

    verify_with_preprocessed(
        &config,
        &air,
        &proof.proof,
        &[],
        Some(&proof.preprocessed_vk),
    )
    .is_ok()
}

fn prove_affine_mul_core_with_settings(
    instance: AffineMulInstance,
    settings: AffineMulProofSettings,
) -> Result<AffineMulProof, String> {
    if !meets_minimum_policy(settings) {
        return Err("proof settings do not meet minimum verifier policy".to_string());
    }
    if !instance.base.is_on_curve() {
        return Err("base point is not on ed25519 curve".to_string());
    }
    if !instance.base.is_in_prime_order_subgroup() {
        return Err("base point is not in the prime-order subgroup".to_string());
    }

    let trace = build_affine_mul_trace(instance.base, instance.scalar_le_bytes);
    let byte_table = ByteLookupTable::default();
    if !verify_affine_mul_trace(&trace, instance.base, instance.scalar_le_bytes, &byte_table) {
        return Err("internal trace consistency check failed".to_string());
    }
    let mut deltas = Vec::with_capacity(trace.len());
    for (row, step) in trace.iter().enumerate() {
        deltas.push(row_logup_deltas(row, step, &byte_table)?);
    }

    let final_point = trace
        .last()
        .ok_or_else(|| "trace is empty".to_string())?
        .acc_after_select;
    let output_compressed = final_point.compress();
    let main = build_main_trace(&trace, &deltas);
    let preprocessed =
        build_core_preprocessed_trace(instance.scalar_le_bytes, &trace, final_point, &deltas);
    let air = AffineMulCoreAir::new(preprocessed);
    let config = setup_config(settings);

    let (prover_data, preprocessed_vk) =
        setup_preprocessed::<AffineMulStarkConfig, _>(&config, &air, DEGREE_BITS)
            .ok_or_else(|| "failed to setup preprocessed data for affine mul proof".to_string())?;

    let proof = prove_with_preprocessed(&config, &air, main, &[], Some(&prover_data));
    let statement_hash = statement_hash(instance, output_compressed, settings, &preprocessed_vk)?;
    Ok(AffineMulProof {
        proof,
        preprocessed_vk,
        settings,
        output_compressed,
        statement_hash,
    })
}

fn verify_affine_mul_core_with_settings(
    instance: AffineMulInstance,
    proof: &AffineMulProof,
    settings: AffineMulProofSettings,
) -> bool {
    if !meets_minimum_policy(settings) || proof.settings != settings {
        return false;
    }
    if !instance.base.is_on_curve() || !instance.base.is_in_prime_order_subgroup() {
        return false;
    }

    let trace = build_affine_mul_trace(instance.base, instance.scalar_le_bytes);
    let final_point = match trace.last() {
        Some(last) => last.acc_after_select,
        None => return false,
    };
    if final_point.compress() != proof.output_compressed {
        return false;
    }
    let expected_hash = match statement_hash(
        instance,
        proof.output_compressed,
        settings,
        &proof.preprocessed_vk,
    ) {
        Ok(h) => h,
        Err(_) => return false,
    };
    if proof.statement_hash != expected_hash {
        return false;
    }

    let mut deltas = Vec::with_capacity(trace.len());
    let byte_table = ByteLookupTable::default();
    for (row, step) in trace.iter().enumerate() {
        let Ok(delta) = row_logup_deltas(row, step, &byte_table) else {
            return false;
        };
        deltas.push(delta);
    }
    let preprocessed =
        build_core_preprocessed_trace(instance.scalar_le_bytes, &trace, final_point, &deltas);
    let air = AffineMulCoreAir::new(preprocessed);
    let config = setup_config(settings);

    let Some((_, expected_vk)) =
        setup_preprocessed::<AffineMulStarkConfig, _>(&config, &air, DEGREE_BITS)
    else {
        return false;
    };

    if !vk_matches(&expected_vk, &proof.preprocessed_vk) {
        return false;
    }

    verify_with_preprocessed(
        &config,
        &air,
        &proof.proof,
        &[],
        Some(&proof.preprocessed_vk),
    )
    .is_ok()
}

pub fn prove_affine_mul_sound(
    instance: AffineMulInstance,
) -> Result<AffineMulSampledSoundProof, String> {
    prove_affine_mul_sound_with_settings(instance, AffineMulSoundProofSettings::default())
}

pub fn prove_affine_mul_sound_with_settings(
    instance: AffineMulInstance,
    settings: AffineMulSoundProofSettings,
) -> Result<AffineMulSampledSoundProof, String> {
    if settings.sampled_rows > 256 {
        return Err("sampled_rows must be <= 256".to_string());
    }
    if !meets_minimum_policy(settings.core) || !meets_minimum_arithmetic_policy(settings.arithmetic)
    {
        return Err("sound proof settings do not meet minimum verifier policy".to_string());
    }
    let core = prove_affine_mul_core_with_settings(instance, settings.core)?;
    let trace = build_affine_mul_trace(instance.base, instance.scalar_le_bytes);
    let sampled_rows = sample_rows_evenly(trace.len(), settings.sampled_rows);
    let mut double_proofs = Vec::with_capacity(sampled_rows.len());
    let mut add_proofs = Vec::with_capacity(sampled_rows.len());

    for &row in &sampled_rows {
        let step = trace
            .get(row)
            .ok_or_else(|| format!("sampled row out of bounds: {row}"))?;
        let double_proof = prove_affine_add_sound_with_settings(
            step.acc_before,
            step.acc_before,
            settings.arithmetic,
        )?;
        if double_proof.out != step.acc_after_double {
            return Err(format!("double proof output mismatch at row {row}"));
        }
        let add_proof = prove_affine_add_sound_with_settings(
            step.acc_after_double,
            instance.base,
            settings.arithmetic,
        )?;
        if add_proof.out != step.acc_after_add_base {
            return Err(format!("add proof output mismatch at row {row}"));
        }
        double_proofs.push(double_proof);
        add_proofs.push(add_proof);
    }

    let statement_hash =
        sampled_sound_statement_hash(instance, settings, &sampled_rows, core.statement_hash)?;
    Ok(AffineMulSampledSoundProof {
        settings,
        statement_hash,
        core,
        sampled_rows,
        double_proofs,
        add_proofs,
    })
}

pub fn verify_affine_mul_sound(
    instance: AffineMulInstance,
    proof: &AffineMulSampledSoundProof,
) -> bool {
    verify_affine_mul_sound_with_settings(instance, proof, AffineMulSoundProofSettings::default())
}

pub fn verify_affine_mul_sound_with_settings(
    instance: AffineMulInstance,
    proof: &AffineMulSampledSoundProof,
    settings: AffineMulSoundProofSettings,
) -> bool {
    if proof.settings != settings {
        return false;
    }
    if proof.sampled_rows.len() != proof.double_proofs.len()
        || proof.sampled_rows.len() != proof.add_proofs.len()
    {
        return false;
    }
    if !meets_minimum_policy(settings.core) || !meets_minimum_arithmetic_policy(settings.arithmetic)
    {
        return false;
    }
    if !verify_affine_mul_core_with_settings(instance, &proof.core, settings.core) {
        return false;
    }
    let expected_stmt = match sampled_sound_statement_hash(
        instance,
        settings,
        &proof.sampled_rows,
        proof.core.statement_hash,
    ) {
        Ok(v) => v,
        Err(_) => return false,
    };
    if proof.statement_hash != expected_stmt {
        return false;
    }
    let trace = build_affine_mul_trace(instance.base, instance.scalar_le_bytes);
    let expected_rows = sample_rows_evenly(trace.len(), settings.sampled_rows);
    if proof.sampled_rows != expected_rows {
        return false;
    }

    for (i, &row) in proof.sampled_rows.iter().enumerate() {
        let Some(step) = trace.get(row) else {
            return false;
        };
        let double_proof = &proof.double_proofs[i];
        if double_proof.lhs != step.acc_before
            || double_proof.rhs != step.acc_before
            || double_proof.out != step.acc_after_double
            || !verify_affine_add_sound_with_settings(double_proof, settings.arithmetic)
        {
            return false;
        }

        let add_proof = &proof.add_proofs[i];
        if add_proof.lhs != step.acc_after_double
            || add_proof.rhs != instance.base
            || add_proof.out != step.acc_after_add_base
            || !verify_affine_add_sound_with_settings(add_proof, settings.arithmetic)
        {
            return false;
        }
    }
    true
}

pub fn prove_affine_mul_fully_sound(
    instance: AffineMulInstance,
) -> Result<AffineMulFullySoundProof, String> {
    prove_affine_mul_fully_sound_with_settings(instance, SoundAddSubProofSettings::default())
}

pub fn prove_affine_mul_fully_sound_with_settings(
    instance: AffineMulInstance,
    arithmetic_settings: SoundAddSubProofSettings,
) -> Result<AffineMulFullySoundProof, String> {
    prove_affine_mul_fully_sound_strict_with_settings(instance, arithmetic_settings)
}

pub fn prove_affine_mul_fully_sound_strict(
    instance: AffineMulInstance,
) -> Result<AffineMulFullySoundProof, String> {
    prove_affine_mul_fully_sound_strict_with_settings(instance, SoundAddSubProofSettings::default())
}

pub fn prove_affine_mul_fully_sound_strict_with_settings(
    instance: AffineMulInstance,
    arithmetic_settings: SoundAddSubProofSettings,
) -> Result<AffineMulFullySoundProof, String> {
    if !instance.base.is_on_curve() {
        return Err("base point is not on ed25519 curve".to_string());
    }
    if !instance.base.is_in_prime_order_subgroup() {
        return Err("base point is not in the prime-order subgroup".to_string());
    }
    if !meets_minimum_arithmetic_policy(arithmetic_settings) {
        return Err("arithmetic settings do not meet minimum verifier policy".to_string());
    }
    let (sampled_rows, double_proofs, add_proofs, output_compressed) =
        build_full_arithmetic_chain(instance, arithmetic_settings)?;
    let statement_hash = fully_sound_statement_hash(
        instance,
        arithmetic_settings,
        &sampled_rows,
        output_compressed,
    )?;
    Ok(AffineMulFullySoundProof {
        arithmetic_settings,
        statement_hash,
        sampled_rows,
        double_proofs,
        add_proofs,
        output_compressed,
    })
}

pub fn verify_affine_mul_fully_sound(
    instance: AffineMulInstance,
    proof: &AffineMulFullySoundProof,
) -> bool {
    verify_affine_mul_fully_sound_with_settings(
        instance,
        proof,
        SoundAddSubProofSettings::default(),
    )
}

pub fn verify_affine_mul_fully_sound_with_settings(
    instance: AffineMulInstance,
    proof: &AffineMulFullySoundProof,
    arithmetic_settings: SoundAddSubProofSettings,
) -> bool {
    if proof.arithmetic_settings != arithmetic_settings {
        return false;
    }
    verify_affine_mul_fully_sound_strict_with_settings(instance, proof, arithmetic_settings)
}

pub fn verify_affine_mul_fully_sound_strict(
    instance: AffineMulInstance,
    proof: &AffineMulFullySoundProof,
) -> bool {
    verify_affine_mul_fully_sound_strict_with_settings(instance, proof, proof.arithmetic_settings)
}

pub fn verify_affine_mul_fully_sound_strict_with_settings(
    instance: AffineMulInstance,
    proof: &AffineMulFullySoundProof,
    arithmetic_settings: SoundAddSubProofSettings,
) -> bool {
    if proof.arithmetic_settings != arithmetic_settings {
        return false;
    }
    if !instance.base.is_on_curve() || !instance.base.is_in_prime_order_subgroup() {
        return false;
    }
    if !meets_minimum_arithmetic_policy(arithmetic_settings) {
        return false;
    }
    if proof.sampled_rows.len() != 256
        || proof.double_proofs.len() != 256
        || proof.add_proofs.len() != 256
    {
        return false;
    }
    for (i, row) in proof.sampled_rows.iter().enumerate() {
        if *row != i {
            return false;
        }
    }
    let mut acc = AffinePoint::identity();
    for row in 0..256usize {
        let double_proof = &proof.double_proofs[row];
        if double_proof.lhs != acc
            || double_proof.rhs != acc
            || !verify_affine_add_sound_with_settings(double_proof, arithmetic_settings)
        {
            return false;
        }

        let add_proof = &proof.add_proofs[row];
        if add_proof.lhs != double_proof.out
            || add_proof.rhs != instance.base
            || !verify_affine_add_sound_with_settings(add_proof, arithmetic_settings)
        {
            return false;
        }

        let bit_index = 255 - row;
        let bit = scalar_bit_le(&instance.scalar_le_bytes, bit_index);
        acc = if bit == 1 {
            add_proof.out
        } else {
            double_proof.out
        };
    }

    if acc.compress() != proof.output_compressed {
        return false;
    }
    let expected_stmt = match fully_sound_statement_hash(
        instance,
        arithmetic_settings,
        &proof.sampled_rows,
        proof.output_compressed,
    ) {
        Ok(v) => v,
        Err(_) => return false,
    };
    if proof.statement_hash != expected_stmt {
        return false;
    }
    true
}

#[cfg(all(test, feature = "prove-tests"))]
mod tests {
    use super::*;
    use crate::NonNativeFieldElement;
    use curve25519::constants::ED25519_BASEPOINT_POINT;
    use curve25519::scalar::Scalar;

    fn scalar_from_u64(x: u64) -> [u8; 32] {
        let mut out = [0_u8; 32];
        out[..8].copy_from_slice(&x.to_le_bytes());
        out
    }

    #[test]
    fn affine_mul_proof_roundtrip() {
        let scalar = [42_u8; 32];
        let proof = prove_basepoint_affine_mul(scalar).expect("prove");
        assert!(verify_basepoint_affine_mul(scalar, &proof));
    }

    #[test]
    fn affine_mul_proof_rejects_wrong_scalar() {
        let scalar = [9_u8; 32];
        let wrong = [10_u8; 32];
        let proof = prove_basepoint_affine_mul(scalar).expect("prove");
        assert!(!verify_basepoint_affine_mul(wrong, &proof));
    }

    #[test]
    fn affine_mul_proof_rejects_policy_mismatch() {
        let scalar = [11_u8; 32];
        let mut proof = prove_basepoint_affine_mul(scalar).expect("prove");
        proof.settings.rng_seed ^= 1;
        assert!(!verify_basepoint_affine_mul(scalar, &proof));
    }

    #[test]
    fn generic_affine_mul_proof_roundtrip() {
        let base = ed25519_basepoint_affine().scalar_mul(scalar_from_u64(2));
        let scalar = scalar_from_u64(17);
        let instance = AffineMulInstance {
            base,
            scalar_le_bytes: scalar,
        };
        let proof = prove_affine_mul(instance).expect("prove");
        assert!(verify_affine_mul(instance, &proof));
    }

    #[test]
    fn generic_affine_mul_matches_curve25519_sol() {
        let two_base = ED25519_BASEPOINT_POINT + ED25519_BASEPOINT_POINT;
        let base = ed25519_basepoint_affine().scalar_mul(scalar_from_u64(2));
        let scalar = scalar_from_u64(19);
        let instance = AffineMulInstance {
            base,
            scalar_le_bytes: scalar,
        };
        let proof = prove_affine_mul(instance).expect("prove");
        assert!(verify_affine_mul(instance, &proof));

        let expected = (Scalar::from_bytes_mod_order(scalar) * two_base)
            .compress()
            .to_bytes();
        assert_eq!(proof.output_compressed, expected);
    }

    #[test]
    fn affine_mul_instance_serialization_roundtrip() {
        let instance = AffineMulInstance {
            base: ed25519_basepoint_affine().scalar_mul(scalar_from_u64(5)),
            scalar_le_bytes: scalar_from_u64(12345),
        };
        let bytes = serialize_affine_mul_instance(&instance);
        let decoded = deserialize_affine_mul_instance(&bytes).expect("decode");
        assert_eq!(decoded, instance);
    }

    #[test]
    fn affine_mul_instance_compressed_serialization_roundtrip() {
        let instance = AffineMulInstance {
            base: ed25519_basepoint_affine().scalar_mul(scalar_from_u64(6)),
            scalar_le_bytes: scalar_from_u64(54321),
        };
        let bytes = serialize_affine_mul_instance_compressed(&instance);
        let decoded = deserialize_affine_mul_instance_compressed(&bytes).expect("decode");
        assert_eq!(decoded, instance);
    }

    #[test]
    fn compressed_instance_rejects_noncanonical_x_zero_sign() {
        let mut bytes = [0_u8; 64];
        bytes[0] = 1;
        bytes[31] |= 0x80;
        bytes[32..40].copy_from_slice(&7_u64.to_le_bytes());
        let err = deserialize_affine_mul_instance_compressed(&bytes).expect_err("must reject");
        assert!(err.contains("invalid compressed affine base encoding"));
    }

    #[test]
    fn instance_auto_decode_accepts_both_lengths() {
        let instance = AffineMulInstance {
            base: ed25519_basepoint_affine().scalar_mul(scalar_from_u64(8)),
            scalar_le_bytes: scalar_from_u64(123),
        };
        let uncompressed = serialize_affine_mul_instance(&instance);
        let compressed = serialize_affine_mul_instance_compressed(&instance);
        assert_eq!(
            deserialize_affine_mul_instance_auto(&uncompressed).expect("decode uncompressed"),
            instance
        );
        assert_eq!(
            deserialize_affine_mul_instance_auto(&compressed).expect("decode compressed"),
            instance
        );
    }

    #[test]
    fn typed_decode_errors_are_specific() {
        let err = try_deserialize_affine_mul_instance(&[0_u8; 95]).expect_err("must fail");
        assert_eq!(
            err,
            AffineMulCodecError::InvalidInstanceLength {
                expected: 96,
                got: 95
            }
        );

        let err =
            try_deserialize_affine_mul_instance_compressed(&[0_u8; 63]).expect_err("must fail");
        assert_eq!(
            err,
            AffineMulCodecError::InvalidCompressedInstanceLength {
                expected: 64,
                got: 63
            }
        );

        let err = try_deserialize_affine_mul_instance_auto(&[0_u8; 65]).expect_err("must fail");
        assert_eq!(
            err,
            AffineMulCodecError::InvalidAutoInstanceLength { got: 65 }
        );
    }

    #[test]
    fn sample_rows_evenly_is_stable() {
        assert_eq!(sample_rows_evenly(256, 0), Vec::<usize>::new());
        assert_eq!(sample_rows_evenly(8, 3), vec![0, 2, 5]);
        assert_eq!(sample_rows_evenly(4, 10), vec![0, 1, 2, 3]);
    }

    #[test]
    #[ignore = "expensive end-to-end proof; run explicitly when needed"]
    fn affine_mul_fully_sound_roundtrip() {
        let instance = AffineMulInstance {
            base: ed25519_basepoint_affine(),
            scalar_le_bytes: scalar_from_u64(5),
        };
        let proof = prove_affine_mul_fully_sound(instance).expect("prove");
        assert!(verify_affine_mul_fully_sound(instance, &proof));
        assert_eq!(proof.sampled_rows.len(), 256);
    }

    #[test]
    fn affine_mul_fully_sound_rejects_bad_row_indices() {
        let instance = AffineMulInstance {
            base: ed25519_basepoint_affine(),
            scalar_le_bytes: scalar_from_u64(7),
        };
        let mut proof = prove_affine_mul_fully_sound(instance).expect("prove");
        proof.sampled_rows[0] = 1;
        assert!(!verify_affine_mul_fully_sound(instance, &proof));
    }

    #[test]
    fn sampled_sound_verify_rejects_tampered_core_proof() {
        let instance = AffineMulInstance {
            base: ed25519_basepoint_affine(),
            scalar_le_bytes: scalar_from_u64(9),
        };
        let mut proof = prove_affine_mul_sound(instance).expect("prove");
        proof.core.settings.rng_seed ^= 1;
        assert!(!verify_affine_mul_sound(instance, &proof));
    }

    #[test]
    fn sampled_sound_verify_rejects_tampered_statement_hash() {
        let instance = AffineMulInstance {
            base: ed25519_basepoint_affine(),
            scalar_le_bytes: scalar_from_u64(10),
        };
        let mut proof = prove_affine_mul_sound(instance).expect("prove");
        proof.statement_hash[0] ^= 1;
        assert!(!verify_affine_mul_sound(instance, &proof));
    }

    #[test]
    fn basepoint_sampled_sound_roundtrip() {
        let scalar = scalar_from_u64(12);
        let proof = prove_basepoint_affine_mul_sound(scalar).expect("prove");
        assert!(verify_basepoint_affine_mul_sound(scalar, &proof));
    }

    #[test]
    fn sampled_sound_proof_serialization_roundtrip() {
        let scalar = scalar_from_u64(13);
        let proof = prove_basepoint_affine_mul_sound(scalar).expect("prove");
        let bytes = serialize_affine_mul_sampled_sound_proof(&proof).expect("encode");
        let decoded = deserialize_affine_mul_sampled_sound_proof(&bytes).expect("decode");
        assert!(verify_basepoint_affine_mul_sound(scalar, &decoded));
    }

    #[test]
    fn sampled_sound_bundle_roundtrip() {
        let instance = AffineMulInstance {
            base: ed25519_basepoint_affine(),
            scalar_le_bytes: scalar_from_u64(14),
        };
        let bundle = prove_affine_mul_sampled_sound_bundle(instance).expect("bundle");
        assert!(verify_affine_mul_sampled_sound_bundle(&bundle));

        let bytes = serialize_affine_mul_sampled_sound_bundle(&bundle).expect("encode");
        let decoded = deserialize_affine_mul_sampled_sound_bundle(&bytes).expect("decode");
        assert_eq!(decoded, bundle);
        assert!(verify_affine_mul_sampled_sound_bundle(&decoded));
    }

    #[test]
    fn sampled_sound_bundle_verify_rejects_settings_mismatch() {
        let instance = AffineMulInstance {
            base: ed25519_basepoint_affine(),
            scalar_le_bytes: scalar_from_u64(18),
        };
        let mut settings = AffineMulSoundProofSettings::default();
        settings.core.rng_seed = 4242;
        let bundle = prove_affine_mul_sampled_sound_bundle_with_settings(instance, settings)
            .expect("bundle");
        assert!(verify_affine_mul_sampled_sound_bundle_with_settings(
            &bundle, settings
        ));
        let mut wrong = settings;
        wrong.core.rng_seed ^= 1;
        assert!(!verify_affine_mul_sampled_sound_bundle_with_settings(
            &bundle, wrong
        ));
    }

    #[test]
    fn sampled_sound_proof_codec_rejects_bad_header() {
        let scalar = scalar_from_u64(16);
        let proof = prove_basepoint_affine_mul_sound(scalar).expect("prove");
        let mut bytes = serialize_affine_mul_sampled_sound_proof(&proof).expect("encode");
        bytes[0] ^= 1;
        let err = match deserialize_affine_mul_sampled_sound_proof(&bytes) {
            Ok(_) => panic!("must fail"),
            Err(e) => e,
        };
        assert!(err.contains("codec header"));
    }

    #[test]
    fn sampled_sound_bundle_codec_rejects_bad_header() {
        let instance = AffineMulInstance {
            base: ed25519_basepoint_affine(),
            scalar_le_bytes: scalar_from_u64(17),
        };
        let bundle = prove_affine_mul_sampled_sound_bundle(instance).expect("bundle");
        let mut bytes = serialize_affine_mul_sampled_sound_bundle(&bundle).expect("encode");
        bytes[0] ^= 1;
        let err = match deserialize_affine_mul_sampled_sound_bundle(&bytes) {
            Ok(_) => panic!("must fail"),
            Err(e) => e,
        };
        assert!(err.contains("codec header"));
    }

    #[test]
    #[ignore = "expensive end-to-end proof; run explicitly when needed"]
    fn e2e_blob_roundtrip() {
        let instance = AffineMulInstance {
            base: ed25519_basepoint_affine(),
            scalar_le_bytes: scalar_from_u64(19),
        };
        let blob = prove_affine_mul_e2e(instance).expect("prove");
        assert!(verify_affine_mul_e2e(&blob));
        let bytes = serialize_affine_mul_e2e_blob(&blob).expect("encode");
        let decoded = deserialize_affine_mul_e2e_blob(&bytes).expect("decode");
        assert_eq!(decoded, blob);
        assert!(verify_affine_mul_e2e(&decoded));
    }

    #[test]
    #[ignore = "expensive end-to-end proof; run explicitly when needed"]
    fn e2e_unified_rejects_settings_mismatch_fast() {
        let instance = AffineMulInstance {
            base: ed25519_basepoint_affine(),
            scalar_le_bytes: scalar_from_u64(20),
        };
        let mut s = SoundAddSubProofSettings::default();
        s.rng_seed = 2026;
        let bytes = prove_affine_mul_e2e_unified_with_settings(instance, s).expect("prove");
        assert!(verify_affine_mul_e2e_unified_with_settings(&bytes, s));
        let mut wrong = s;
        wrong.rng_seed ^= 1;
        assert!(!verify_affine_mul_e2e_unified_with_settings(&bytes, wrong));
    }

    #[test]
    fn e2e_unified_blob_codec_rejects_bad_header() {
        let blob = AffineMulE2eProofBlob {
            sealed_instance: vec![1, 2, 3],
            sealed_proof: vec![4, 5, 6],
        };
        let mut bytes = serialize_affine_mul_e2e_blob(&blob).expect("encode");
        bytes[0] ^= 1;
        assert!(deserialize_affine_mul_e2e_blob(&bytes).is_err());
    }

    #[test]
    fn verify_basepoint_e2e_unified_rejects_scalar_mismatch_fast() {
        let scalar = scalar_from_u64(21);
        let wrong = scalar_from_u64(22);
        let instance = AffineMulInstance {
            base: ed25519_basepoint_affine(),
            scalar_le_bytes: scalar,
        };
        let blob = AffineMulE2eProofBlob {
            sealed_instance: serialize_affine_mul_instance_compressed(&instance),
            sealed_proof: Vec::new(),
        };
        let bytes = serialize_affine_mul_e2e_blob(&blob).expect("encode");
        assert!(!verify_basepoint_affine_mul_e2e_unified(wrong, &bytes));
    }

    #[test]
    fn fully_sound_strict_verify_rejects_structural_mismatch() {
        let instance = AffineMulInstance {
            base: ed25519_basepoint_affine(),
            scalar_le_bytes: scalar_from_u64(1),
        };
        let proof = AffineMulFullySoundProof {
            arithmetic_settings: SoundAddSubProofSettings::default(),
            statement_hash: [0_u8; 32],
            sampled_rows: vec![0],
            double_proofs: Vec::new(),
            add_proofs: Vec::new(),
            output_compressed: [0_u8; 32],
        };
        assert!(!verify_affine_mul_fully_sound_strict(instance, &proof));
    }

    #[test]
    fn fully_sound_verify_rejects_tampered_statement_hash() {
        let instance = AffineMulInstance {
            base: ed25519_basepoint_affine(),
            scalar_le_bytes: scalar_from_u64(2),
        };
        let mut proof = prove_affine_mul_fully_sound(instance).expect("prove");
        proof.statement_hash[0] ^= 1;
        assert!(!verify_affine_mul_fully_sound(instance, &proof));
    }

    #[test]
    fn fully_sound_verify_rejects_settings_mismatch() {
        let mut s = SoundAddSubProofSettings::default();
        s.rng_seed = 12345;
        let proof = AffineMulFullySoundProof {
            arithmetic_settings: s,
            statement_hash: [0_u8; 32],
            sampled_rows: Vec::new(),
            double_proofs: Vec::new(),
            add_proofs: Vec::new(),
            output_compressed: [0_u8; 32],
        };
        let instance = AffineMulInstance {
            base: ed25519_basepoint_affine(),
            scalar_le_bytes: scalar_from_u64(3),
        };
        let mut wrong = s;
        wrong.rng_seed ^= 1;
        assert!(!verify_affine_mul_fully_sound_with_settings(
            instance, &proof, wrong
        ));
    }

    #[test]
    #[ignore = "expensive end-to-end proof; run explicitly when needed"]
    fn fully_sound_bundle_roundtrip() {
        let instance = AffineMulInstance {
            base: ed25519_basepoint_affine(),
            scalar_le_bytes: scalar_from_u64(15),
        };
        let bundle = prove_affine_mul_fully_sound_bundle(instance).expect("bundle");
        assert!(verify_affine_mul_fully_sound_bundle(&bundle));

        let bytes = serialize_affine_mul_fully_sound_bundle(&bundle).expect("encode");
        let decoded = deserialize_affine_mul_fully_sound_bundle(&bytes).expect("decode");
        assert_eq!(decoded, bundle);
        assert!(verify_affine_mul_fully_sound_bundle(&decoded));
    }

    #[test]
    #[ignore = "expensive end-to-end proof; run explicitly when needed"]
    fn fully_sound_proof_serialization_roundtrip() {
        let instance = AffineMulInstance {
            base: ed25519_basepoint_affine(),
            scalar_le_bytes: scalar_from_u64(4),
        };
        let proof = prove_affine_mul_fully_sound(instance).expect("prove");
        let bytes = serialize_affine_mul_fully_sound_proof(&proof).expect("encode");
        let decoded = deserialize_affine_mul_fully_sound_proof(&bytes).expect("decode");
        assert!(verify_affine_mul_fully_sound(instance, &decoded));
    }

    #[test]
    fn affine_mul_proof_serialization_roundtrip() {
        let instance = AffineMulInstance {
            base: ed25519_basepoint_affine().scalar_mul(scalar_from_u64(3)),
            scalar_le_bytes: scalar_from_u64(99),
        };
        let proof = prove_affine_mul(instance).expect("prove");
        let bytes = serialize_affine_mul_proof(&proof).expect("serialize");
        let decoded = deserialize_affine_mul_proof(&bytes).expect("deserialize");
        assert!(verify_affine_mul(instance, &decoded));
        assert_eq!(decoded.output_compressed, proof.output_compressed);
    }

    #[test]
    fn affine_mul_verify_rejects_tampered_output() {
        let instance = AffineMulInstance {
            base: ed25519_basepoint_affine().scalar_mul(scalar_from_u64(3)),
            scalar_le_bytes: scalar_from_u64(88),
        };
        let mut proof = prove_affine_mul(instance).expect("prove");
        proof.output_compressed[0] ^= 1;
        assert!(!verify_affine_mul(instance, &proof));
    }

    #[test]
    fn generic_affine_mul_rejects_low_order_base() {
        let minus_one = NonNativeFieldElement::from_ed25519_le_bytes([
            0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0x7f,
        ]);
        let low_order = AffinePoint {
            x: NonNativeFieldElement::zero(),
            y: minus_one,
        };
        let instance = AffineMulInstance {
            base: low_order,
            scalar_le_bytes: scalar_from_u64(5),
        };
        let result = prove_affine_mul(instance);
        assert!(result.is_err());
        assert!(result.err().expect("err").contains("prime-order subgroup"));
    }

    #[test]
    fn fully_sound_prove_rejects_low_order_base() {
        let minus_one = NonNativeFieldElement::from_ed25519_le_bytes([
            0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0x7f,
        ]);
        let low_order = AffinePoint {
            x: NonNativeFieldElement::zero(),
            y: minus_one,
        };
        let instance = AffineMulInstance {
            base: low_order,
            scalar_le_bytes: scalar_from_u64(5),
        };
        let result = prove_affine_mul_fully_sound(instance);
        assert!(result.is_err());
        assert!(result.err().expect("err").contains("prime-order subgroup"));
    }

    #[test]
    fn fully_sound_verify_rejects_low_order_base_instance() {
        let proof = AffineMulFullySoundProof {
            arithmetic_settings: SoundAddSubProofSettings::default(),
            statement_hash: [0_u8; 32],
            sampled_rows: Vec::new(),
            double_proofs: Vec::new(),
            add_proofs: Vec::new(),
            output_compressed: [0_u8; 32],
        };

        let minus_one = NonNativeFieldElement::from_ed25519_le_bytes([
            0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0x7f,
        ]);
        let low_order_instance = AffineMulInstance {
            base: AffinePoint {
                x: NonNativeFieldElement::zero(),
                y: minus_one,
            },
            scalar_le_bytes: scalar_from_u64(6),
        };
        assert!(!verify_affine_mul_fully_sound(low_order_instance, &proof));
    }

    #[test]
    fn affine_mul_bundle_roundtrip() {
        let instance = AffineMulInstance {
            base: ed25519_basepoint_affine().scalar_mul(scalar_from_u64(13)),
            scalar_le_bytes: scalar_from_u64(4242),
        };
        let bundle = prove_affine_mul_bundle(instance).expect("bundle");
        assert!(verify_affine_mul_bundle(&bundle));

        let serialized = serialize_affine_mul_bundle(&bundle).expect("serialize bundle");
        let decoded = deserialize_affine_mul_bundle(&serialized).expect("deserialize bundle");
        assert_eq!(decoded, bundle);
        assert!(verify_affine_mul_bundle(&decoded));
    }

    #[test]
    fn affine_mul_compressed_bundle_roundtrip() {
        let instance = AffineMulInstance {
            base: ed25519_basepoint_affine().scalar_mul(scalar_from_u64(12)),
            scalar_le_bytes: scalar_from_u64(31415),
        };
        let bundle = prove_affine_mul_bundle_compressed(instance).expect("bundle");
        assert!(verify_affine_mul_bundle_auto(&bundle));
        assert!(!verify_affine_mul_bundle(&bundle));
    }

    #[test]
    fn affine_mul_bundle_v2_roundtrip_uncompressed() {
        let instance = AffineMulInstance {
            base: ed25519_basepoint_affine().scalar_mul(scalar_from_u64(21)),
            scalar_le_bytes: scalar_from_u64(8080),
        };
        let bundle = prove_affine_mul_bundle_v2(instance, AffineMulInstanceEncoding::Uncompressed)
            .expect("bundle v2");
        assert!(verify_affine_mul_bundle_v2(&bundle));
        let bytes = serialize_affine_mul_bundle_v2(&bundle).expect("serialize");
        let decoded = deserialize_affine_mul_bundle_v2(&bytes).expect("deserialize");
        assert_eq!(decoded, bundle);
        assert!(verify_affine_mul_bundle_v2(&decoded));
    }

    #[test]
    fn affine_mul_bundle_v2_roundtrip_compressed() {
        let instance = AffineMulInstance {
            base: ed25519_basepoint_affine().scalar_mul(scalar_from_u64(34)),
            scalar_le_bytes: scalar_from_u64(9090),
        };
        let mut bundle =
            prove_affine_mul_bundle_v2(instance, AffineMulInstanceEncoding::Compressed)
                .expect("bundle v2");
        assert!(verify_affine_mul_bundle_v2(&bundle));
        bundle.sealed_proof[0] ^= 1;
        assert!(!verify_affine_mul_bundle_v2(&bundle));
    }

    #[test]
    fn affine_mul_bundle_rejects_malformed_instance() {
        let instance = AffineMulInstance {
            base: ed25519_basepoint_affine().scalar_mul(scalar_from_u64(9)),
            scalar_le_bytes: scalar_from_u64(77),
        };
        let mut bundle = prove_affine_mul_bundle(instance).expect("bundle");
        bundle.sealed_instance[0] ^= 1;
        assert!(!verify_affine_mul_bundle(&bundle));
    }

    #[test]
    fn deserialize_instance_rejects_non_canonical_field_element() {
        let instance = AffineMulInstance {
            base: ed25519_basepoint_affine(),
            scalar_le_bytes: scalar_from_u64(1),
        };
        let mut bytes = serialize_affine_mul_instance(&instance);
        bytes[..32].copy_from_slice(&[
            0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0x7f,
        ]);
        let err = deserialize_affine_mul_instance(&bytes).expect_err("must reject");
        assert!(err.contains("invalid affine base encoding"));
    }

    #[test]
    fn affine_mul_batch_roundtrip() {
        let instances = vec![
            AffineMulInstance {
                base: ed25519_basepoint_affine().scalar_mul(scalar_from_u64(2)),
                scalar_le_bytes: scalar_from_u64(101),
            },
            AffineMulInstance {
                base: ed25519_basepoint_affine().scalar_mul(scalar_from_u64(3)),
                scalar_le_bytes: scalar_from_u64(202),
            },
            AffineMulInstance {
                base: ed25519_basepoint_affine().scalar_mul(scalar_from_u64(7)),
                scalar_le_bytes: scalar_from_u64(303),
            },
        ];
        let bundles = prove_affine_mul_batch(&instances).expect("batch prove");
        assert_eq!(bundles.len(), instances.len());
        assert!(verify_affine_mul_batch(&bundles));
    }

    #[test]
    fn affine_mul_batch_rejects_if_one_bundle_is_tampered() {
        let instances = vec![
            AffineMulInstance {
                base: ed25519_basepoint_affine().scalar_mul(scalar_from_u64(4)),
                scalar_le_bytes: scalar_from_u64(111),
            },
            AffineMulInstance {
                base: ed25519_basepoint_affine().scalar_mul(scalar_from_u64(5)),
                scalar_le_bytes: scalar_from_u64(222),
            },
        ];
        let mut bundles = prove_affine_mul_batch(&instances).expect("batch prove");
        bundles[1].sealed_proof[10] ^= 1;
        assert!(!verify_affine_mul_batch(&bundles));
    }
}
