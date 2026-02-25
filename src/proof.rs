use crate::affine::{AffinePoint, ed25519_basepoint_affine};
use crate::lookup::ByteLookupTable;
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
                write!(f, "invalid affine mul instance length: expected {expected}, got {got}")
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

        for i in 0..16 {
            values.push(Val::from_u32(if is_last { final_x[i] } else { 0 }));
        }
        for i in 0..16 {
            values.push(Val::from_u32(if is_last { final_y[i] } else { 0 }));
        }
        values.push(deltas[row].0);
        values.push(deltas[row].1);
    }

    RowMajorMatrix::new(values, PREP_WIDTH)
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

pub fn upgrade_affine_mul_bundle_to_v2(
    bundle: &AffineMulProofBundle,
) -> Result<AffineMulProofBundleV2, String> {
    let instance_encoding = match bundle.sealed_instance.len() {
        96 => AffineMulInstanceEncoding::Uncompressed,
        64 => AffineMulInstanceEncoding::Compressed,
        _ => return Err("invalid affine mul instance length".to_string()),
    };
    Ok(AffineMulProofBundleV2 {
        instance_encoding,
        sealed_instance: bundle.sealed_instance.clone(),
        sealed_proof: bundle.sealed_proof.clone(),
    })
}

pub fn downgrade_affine_mul_bundle_v2(bundle: &AffineMulProofBundleV2) -> AffineMulProofBundle {
    AffineMulProofBundle {
        sealed_instance: bundle.sealed_instance.clone(),
        sealed_proof: bundle.sealed_proof.clone(),
    }
}

pub fn recode_affine_mul_bundle_v2_instance(
    bundle: &AffineMulProofBundleV2,
    target_encoding: AffineMulInstanceEncoding,
) -> Result<AffineMulProofBundleV2, String> {
    let instance = match bundle.instance_encoding {
        AffineMulInstanceEncoding::Uncompressed => deserialize_affine_mul_instance(&bundle.sealed_instance),
        AffineMulInstanceEncoding::Compressed => deserialize_affine_mul_instance_compressed(&bundle.sealed_instance),
    }?;
    let sealed_instance = match target_encoding {
        AffineMulInstanceEncoding::Uncompressed => serialize_affine_mul_instance(&instance),
        AffineMulInstanceEncoding::Compressed => serialize_affine_mul_instance_compressed(&instance),
    };
    Ok(AffineMulProofBundleV2 {
        instance_encoding: target_encoding,
        sealed_instance,
        sealed_proof: bundle.sealed_proof.clone(),
    })
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
    Ok(AffineMulProof {
        proof,
        preprocessed_vk,
        settings,
        output_compressed,
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

#[cfg(test)]
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

        let err = try_deserialize_affine_mul_instance_compressed(&[0_u8; 63]).expect_err("must fail");
        assert_eq!(
            err,
            AffineMulCodecError::InvalidCompressedInstanceLength {
                expected: 64,
                got: 63
            }
        );

        let err = try_deserialize_affine_mul_instance_auto(&[0_u8; 65]).expect_err("must fail");
        assert_eq!(err, AffineMulCodecError::InvalidAutoInstanceLength { got: 65 });
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
    fn bundle_upgrade_and_downgrade_roundtrip() {
        let instance = AffineMulInstance {
            base: ed25519_basepoint_affine().scalar_mul(scalar_from_u64(55)),
            scalar_le_bytes: scalar_from_u64(1212),
        };
        let v1 = prove_affine_mul_bundle(instance).expect("v1");
        let v2 = upgrade_affine_mul_bundle_to_v2(&v1).expect("upgrade");
        assert_eq!(v2.instance_encoding, AffineMulInstanceEncoding::Uncompressed);
        assert!(verify_affine_mul_bundle_v2(&v2));
        let downgraded = downgrade_affine_mul_bundle_v2(&v2);
        assert_eq!(downgraded, v1);
        assert!(verify_affine_mul_bundle(&downgraded));
    }

    #[test]
    fn bundle_v2_recode_instance_encoding_roundtrip() {
        let instance = AffineMulInstance {
            base: ed25519_basepoint_affine().scalar_mul(scalar_from_u64(66)),
            scalar_le_bytes: scalar_from_u64(3434),
        };
        let v2_u =
            prove_affine_mul_bundle_v2(instance, AffineMulInstanceEncoding::Uncompressed)
                .expect("v2");
        let v2_c =
            recode_affine_mul_bundle_v2_instance(&v2_u, AffineMulInstanceEncoding::Compressed)
                .expect("recode");
        assert_eq!(v2_c.instance_encoding, AffineMulInstanceEncoding::Compressed);
        assert!(verify_affine_mul_bundle_v2(&v2_c));
        let v2_u_back = recode_affine_mul_bundle_v2_instance(
            &v2_c,
            AffineMulInstanceEncoding::Uncompressed,
        )
        .expect("recode back");
        assert!(verify_affine_mul_bundle_v2(&v2_u_back));
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
