use bincode::Options;
use num_bigint::BigUint;
use p3_air::{Air, AirBuilder, BaseAir};
use p3_baby_bear::BabyBear;
use p3_challenger::{HashChallenger, SerializingChallenger32};
use p3_commit::ExtensionMmcs;
use p3_dft::Radix2DitParallel;
use p3_field::PrimeCharacteristicRing;
use p3_field::extension::BinomialExtensionField;
use p3_fri::{FriParameters, TwoAdicFriPcs};
use p3_keccak::Keccak256Hash;
use p3_matrix::Matrix;
use p3_matrix::dense::RowMajorMatrix;
use p3_merkle_tree::MerkleTreeMmcs;
use p3_symmetric::{CompressionFunctionFromHasher, SerializingHasher};
use p3_uni_stark::{Proof, StarkConfig, prove, verify};

const LIMBS: usize = 32;
const COL_A: usize = 0;
const COL_B: usize = COL_A + LIMBS;
const COL_C: usize = COL_B + LIMBS;
const COL_CARRY: usize = COL_C + LIMBS; // 33 columns carry_0..carry_32
const COL_Q: usize = COL_CARRY + (LIMBS + 1);
const COL_IS_SUB: usize = COL_Q + 1;
const COL_A_BITS: usize = COL_IS_SUB + 1;
const COL_B_BITS: usize = COL_A_BITS + (LIMBS * 8);
const COL_C_BITS: usize = COL_B_BITS + (LIMBS * 8);
const WIDTH: usize = COL_C_BITS + (LIMBS * 8);
const TRACE_ROWS: usize = 256;
const ADD_SUB_CARRY_BIAS: u8 = 2;

const MODULUS_LE_BYTES: [u8; 32] = [
    0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0x7f,
];

const MUL_COL_A: usize = 0;
const MUL_COL_B: usize = MUL_COL_A + 32;
const MUL_COL_D: usize = MUL_COL_B + 32; // 64-byte product
const MUL_COL_CARRY: usize = MUL_COL_D + 64; // 65 carries
const MUL_COL_A_BITS: usize = MUL_COL_CARRY + 65;
const MUL_COL_B_BITS: usize = MUL_COL_A_BITS + (32 * 8);
const MUL_COL_D_BITS: usize = MUL_COL_B_BITS + (32 * 8);
const MUL_COL_CARRY_BITS: usize = MUL_COL_D_BITS + (64 * 8);
const MUL_WIDTH: usize = MUL_COL_CARRY_BITS + (65 * 16);

const RED_COL_D: usize = 0; // 64 bytes
const RED_COL_R: usize = RED_COL_D + 64; // 32 bytes
const RED_COL_Q: usize = RED_COL_R + 32; // 32 bytes
const RED_COL_CARRY: usize = RED_COL_Q + 32; // 65 carries
const RED_COL_D_BITS: usize = RED_COL_CARRY + 65;
const RED_COL_R_BITS: usize = RED_COL_D_BITS + (64 * 8);
const RED_COL_Q_BITS: usize = RED_COL_R_BITS + (32 * 8);
const RED_COL_CARRY_BITS: usize = RED_COL_Q_BITS + (32 * 8);
const RED_WIDTH: usize = RED_COL_CARRY_BITS + (65 * 24);
const RED_CARRY_BIAS: u32 = 1 << 23;
const MAX_SOUND_NONNATIVE_PROOF_BYTES: usize = 64 * 1024 * 1024;

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

pub type SoundAddSubStarkConfig = StarkConfig<Pcs, Challenge, Challenger>;
pub type SoundAddSubStarkProof = Proof<SoundAddSubStarkConfig>;

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SoundAddSubProofSettings {
    pub log_blowup: usize,
    pub log_final_poly_len: usize,
    pub num_queries: usize,
    pub commit_proof_of_work_bits: usize,
    pub query_proof_of_work_bits: usize,
    pub rng_seed: u64,
}

impl Default for SoundAddSubProofSettings {
    fn default() -> Self {
        Self {
            log_blowup: 3,
            log_final_poly_len: 4,
            num_queries: 2,
            commit_proof_of_work_bits: 1,
            query_proof_of_work_bits: 1,
            rng_seed: 99,
        }
    }
}

#[derive(Clone, Debug)]
pub struct SoundAddSubAir;

impl BaseAir<Val> for SoundAddSubAir {
    fn width(&self) -> usize {
        WIDTH
    }
}

impl<AB> Air<AB> for SoundAddSubAir
where
    AB: AirBuilder<F = Val>,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0).expect("local row");

        let q = local[COL_Q].clone();
        let is_sub = local[COL_IS_SUB].clone();
        builder.assert_bool(q.clone());
        builder.assert_bool(is_sub.clone());

        // carry_0 = 0, carry_32 = 0 (biased encoding).
        let carry_bias = Val::from_u8(ADD_SUB_CARRY_BIAS);
        builder.assert_zero(local[COL_CARRY].clone() - carry_bias.clone());
        builder.assert_zero(local[COL_CARRY + LIMBS].clone() - carry_bias.clone());

        // actual carry_i in {-1,0,1,2} for i=1..31 => encoded in {1,2,3,4}.
        for i in 1..LIMBS {
            let c = local[COL_CARRY + i].clone();
            builder.assert_zero(
                (c.clone() - Val::from_u32(1))
                    * (c.clone() - Val::from_u32(2))
                    * (c.clone() - Val::from_u32(3))
                    * (c.clone() - Val::from_u32(4)),
            );
        }

        for i in 0..LIMBS {
            let a = local[COL_A + i].clone();
            let b = local[COL_B + i].clone();
            let c = local[COL_C + i].clone();

            let mut a_recomposed = AB::Expr::ZERO;
            let mut b_recomposed = AB::Expr::ZERO;
            let mut c_recomposed = AB::Expr::ZERO;
            for bit in 0..8 {
                let wa = local[COL_A_BITS + (i * 8) + bit].clone();
                let wb = local[COL_B_BITS + (i * 8) + bit].clone();
                let wc = local[COL_C_BITS + (i * 8) + bit].clone();
                builder.assert_bool(wa.clone());
                builder.assert_bool(wb.clone());
                builder.assert_bool(wc.clone());
                let w = Val::from_u32(1 << bit);
                a_recomposed += wa * w;
                b_recomposed += wb * w;
                c_recomposed += wc * w;
            }
            builder.assert_zero(a - a_recomposed);
            builder.assert_zero(b - b_recomposed);
            builder.assert_zero(c - c_recomposed);

            let carry_i = local[COL_CARRY + i].clone() - carry_bias.clone();
            let carry_next = local[COL_CARRY + i + 1].clone() - carry_bias.clone();
            let p_i = Val::from_u8(MODULUS_LE_BYTES[i]);

            let e_add = local[COL_A + i].clone()
                + local[COL_B + i].clone()
                + carry_i.clone()
                - local[COL_C + i].clone()
                - q.clone() * p_i
                - carry_next.clone() * Val::from_u32(256);
            let e_sub = local[COL_C + i].clone()
                + local[COL_B + i].clone()
                + carry_i
                - local[COL_A + i].clone()
                - q.clone() * p_i
                - carry_next * Val::from_u32(256);
            builder.assert_zero((AB::Expr::ONE - is_sub.clone()) * e_add + is_sub.clone() * e_sub);
        }
    }
}

#[derive(Clone, Debug)]
pub struct SoundMulAir;

impl BaseAir<Val> for SoundMulAir {
    fn width(&self) -> usize {
        MUL_WIDTH
    }
}

impl<AB> Air<AB> for SoundMulAir
where
    AB: AirBuilder<F = Val>,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0).expect("local row");

        builder.assert_zero(local[MUL_COL_CARRY].clone());
        builder.assert_zero(local[MUL_COL_CARRY + 64].clone());

        for i in 0..32 {
            let mut a_rec = AB::Expr::ZERO;
            let mut b_rec = AB::Expr::ZERO;
            for bit in 0..8 {
                let ba = local[MUL_COL_A_BITS + (i * 8) + bit].clone();
                let bb = local[MUL_COL_B_BITS + (i * 8) + bit].clone();
                builder.assert_bool(ba.clone());
                builder.assert_bool(bb.clone());
                let w = Val::from_u32(1 << bit);
                a_rec += ba * w;
                b_rec += bb * w;
            }
            builder.assert_zero(local[MUL_COL_A + i].clone() - a_rec);
            builder.assert_zero(local[MUL_COL_B + i].clone() - b_rec);
        }

        for k in 0usize..64 {
            let mut d_rec = AB::Expr::ZERO;
            for bit in 0..8 {
                let bd = local[MUL_COL_D_BITS + (k * 8) + bit].clone();
                builder.assert_bool(bd.clone());
                d_rec += bd * Val::from_u32(1 << bit);
            }
            builder.assert_zero(local[MUL_COL_D + k].clone() - d_rec);
        }

        for i in 0..65 {
            let mut c_rec = AB::Expr::ZERO;
            for bit in 0..16 {
                let bc = local[MUL_COL_CARRY_BITS + (i * 16) + bit].clone();
                builder.assert_bool(bc.clone());
                c_rec += bc * Val::from_u32(1 << bit);
            }
            builder.assert_zero(local[MUL_COL_CARRY + i].clone() - c_rec);
        }

        for k in 0usize..64 {
            let mut conv = AB::Expr::ZERO;
            let u_min = k.saturating_sub(31);
            let u_max = k.min(31);
            for u in u_min..=u_max {
                let v = k - u;
                conv += local[MUL_COL_A + u].clone() * local[MUL_COL_B + v].clone();
            }
            builder.assert_zero(
                conv + local[MUL_COL_CARRY + k].clone()
                    - local[MUL_COL_D + k].clone()
                    - local[MUL_COL_CARRY + k + 1].clone() * Val::from_u32(256),
            );
        }
    }
}

#[derive(Clone, Debug)]
pub struct SoundReduceAir;

impl BaseAir<Val> for SoundReduceAir {
    fn width(&self) -> usize {
        RED_WIDTH
    }
}

impl<AB> Air<AB> for SoundReduceAir
where
    AB: AirBuilder<F = Val>,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0).expect("local row");

        let bias = Val::from_u32(RED_CARRY_BIAS);
        builder.assert_zero(local[RED_COL_CARRY].clone() - bias.clone());
        builder.assert_zero(local[RED_COL_CARRY + 64].clone() - bias.clone());

        for i in 0..64 {
            let mut d_rec = AB::Expr::ZERO;
            for bit in 0..8 {
                let bd = local[RED_COL_D_BITS + (i * 8) + bit].clone();
                builder.assert_bool(bd.clone());
                d_rec += bd * Val::from_u32(1 << bit);
            }
            builder.assert_zero(local[RED_COL_D + i].clone() - d_rec);
        }
        for i in 0..32 {
            let mut r_rec = AB::Expr::ZERO;
            let mut q_rec = AB::Expr::ZERO;
            for bit in 0..8 {
                let br = local[RED_COL_R_BITS + (i * 8) + bit].clone();
                let bq = local[RED_COL_Q_BITS + (i * 8) + bit].clone();
                builder.assert_bool(br.clone());
                builder.assert_bool(bq.clone());
                let w = Val::from_u32(1 << bit);
                r_rec += br * w;
                q_rec += bq * w;
            }
            builder.assert_zero(local[RED_COL_R + i].clone() - r_rec);
            builder.assert_zero(local[RED_COL_Q + i].clone() - q_rec);
        }
        for i in 0..65 {
            let mut c_rec = AB::Expr::ZERO;
            for bit in 0..24 {
                let bc = local[RED_COL_CARRY_BITS + (i * 24) + bit].clone();
                builder.assert_bool(bc.clone());
                c_rec += bc * Val::from_u32(1 << bit);
            }
            builder.assert_zero(local[RED_COL_CARRY + i].clone() - c_rec);
        }

        // d_i + carry_i = r_i + sum_j q_j * p_{i-j} + 256*carry_{i+1}
        for i in 0usize..64 {
            let mut qxp = AB::Expr::ZERO;
            let j_min = i.saturating_sub(31);
            let j_max = i.min(31);
            for j in j_min..=j_max {
                let k = i - j;
                qxp += local[RED_COL_Q + j].clone() * Val::from_u8(MODULUS_LE_BYTES[k]);
            }
            let r_i = if i < 32 {
                local[RED_COL_R + i].clone().into()
            } else {
                AB::Expr::ZERO
            };
            let carry_i = local[RED_COL_CARRY + i].clone() - bias.clone();
            let carry_next = local[RED_COL_CARRY + i + 1].clone() - bias.clone();
            builder.assert_zero(local[RED_COL_D + i].clone() + carry_i - r_i - qxp - carry_next * Val::from_u32(256));
        }
    }
}

pub struct SoundAddSubProof {
    pub proof: SoundAddSubStarkProof,
    pub settings: SoundAddSubProofSettings,
    pub is_sub: bool,
    pub a: [u8; 32],
    pub b: [u8; 32],
    pub c: [u8; 32],
}

pub struct SoundMulProof {
    pub proof: SoundAddSubStarkProof,
    pub settings: SoundAddSubProofSettings,
    pub a: [u8; 32],
    pub b: [u8; 32],
    pub d: [u8; 64],
}

pub struct SoundReduceProof {
    pub proof: SoundAddSubStarkProof,
    pub settings: SoundAddSubProofSettings,
    pub d: [u8; 64],
    pub q: [u8; 32],
    pub r: [u8; 32],
}

pub struct SoundMulModProof {
    pub mul: SoundMulProof,
    pub reduce: SoundReduceProof,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct SerializableSoundAddSubProof {
    proof_bytes: Vec<u8>,
    settings: SoundAddSubProofSettings,
    is_sub: bool,
    a: [u8; 32],
    b: [u8; 32],
    c: [u8; 32],
}

#[derive(serde::Serialize, serde::Deserialize)]
struct SerializableSoundMulProof {
    proof_bytes: Vec<u8>,
    settings: SoundAddSubProofSettings,
    a: [u8; 32],
    b: [u8; 32],
    d: Vec<u8>,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct SerializableSoundReduceProof {
    proof_bytes: Vec<u8>,
    settings: SoundAddSubProofSettings,
    d: Vec<u8>,
    q: [u8; 32],
    r: [u8; 32],
}

#[derive(serde::Serialize, serde::Deserialize)]
struct SerializableSoundMulModProof {
    mul_bytes: Vec<u8>,
    reduce_bytes: Vec<u8>,
}

fn setup_config(settings: SoundAddSubProofSettings) -> SoundAddSubStarkConfig {
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
    SoundAddSubStarkConfig::new(pcs, challenger)
}

pub fn serialize_sound_add_sub_proof(proof: &SoundAddSubProof) -> Result<Vec<u8>, String> {
    let proof_bytes = bincode::serialize(&proof.proof).map_err(|e| e.to_string())?;
    let serializable = SerializableSoundAddSubProof {
        proof_bytes,
        settings: proof.settings,
        is_sub: proof.is_sub,
        a: proof.a,
        b: proof.b,
        c: proof.c,
    };
    let bytes = bincode::serialize(&serializable).map_err(|e| e.to_string())?;
    if bytes.len() > MAX_SOUND_NONNATIVE_PROOF_BYTES {
        return Err("serialized sound add/sub proof exceeds configured size limit".to_string());
    }
    Ok(bytes)
}

pub fn deserialize_sound_add_sub_proof(bytes: &[u8]) -> Result<SoundAddSubProof, String> {
    if bytes.len() > MAX_SOUND_NONNATIVE_PROOF_BYTES {
        return Err("serialized sound add/sub proof exceeds configured size limit".to_string());
    }
    let opts = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .reject_trailing_bytes()
        .with_limit(MAX_SOUND_NONNATIVE_PROOF_BYTES as u64);
    let serializable: SerializableSoundAddSubProof =
        opts.deserialize(bytes).map_err(|e| e.to_string())?;
    let inner_opts = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .reject_trailing_bytes()
        .with_limit(MAX_SOUND_NONNATIVE_PROOF_BYTES as u64);
    let proof_inner: SoundAddSubStarkProof = inner_opts
        .deserialize(&serializable.proof_bytes)
        .map_err(|e| e.to_string())?;
    Ok(SoundAddSubProof {
        proof: proof_inner,
        settings: serializable.settings,
        is_sub: serializable.is_sub,
        a: serializable.a,
        b: serializable.b,
        c: serializable.c,
    })
}

pub fn serialize_sound_mul_proof(proof: &SoundMulProof) -> Result<Vec<u8>, String> {
    let proof_bytes = bincode::serialize(&proof.proof).map_err(|e| e.to_string())?;
    let serializable = SerializableSoundMulProof {
        proof_bytes,
        settings: proof.settings,
        a: proof.a,
        b: proof.b,
        d: proof.d.to_vec(),
    };
    let bytes = bincode::serialize(&serializable).map_err(|e| e.to_string())?;
    if bytes.len() > MAX_SOUND_NONNATIVE_PROOF_BYTES {
        return Err("serialized sound mul proof exceeds configured size limit".to_string());
    }
    Ok(bytes)
}

pub fn deserialize_sound_mul_proof(bytes: &[u8]) -> Result<SoundMulProof, String> {
    if bytes.len() > MAX_SOUND_NONNATIVE_PROOF_BYTES {
        return Err("serialized sound mul proof exceeds configured size limit".to_string());
    }
    let opts = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .reject_trailing_bytes()
        .with_limit(MAX_SOUND_NONNATIVE_PROOF_BYTES as u64);
    let serializable: SerializableSoundMulProof =
        opts.deserialize(bytes).map_err(|e| e.to_string())?;
    if serializable.d.len() != 64 {
        return Err("invalid sound mul payload length".to_string());
    }
    let inner_opts = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .reject_trailing_bytes()
        .with_limit(MAX_SOUND_NONNATIVE_PROOF_BYTES as u64);
    let proof_inner: SoundAddSubStarkProof = inner_opts
        .deserialize(&serializable.proof_bytes)
        .map_err(|e| e.to_string())?;
    let mut d = [0_u8; 64];
    d.copy_from_slice(&serializable.d);
    Ok(SoundMulProof {
        proof: proof_inner,
        settings: serializable.settings,
        a: serializable.a,
        b: serializable.b,
        d,
    })
}

pub fn serialize_sound_reduce_proof(proof: &SoundReduceProof) -> Result<Vec<u8>, String> {
    let proof_bytes = bincode::serialize(&proof.proof).map_err(|e| e.to_string())?;
    let serializable = SerializableSoundReduceProof {
        proof_bytes,
        settings: proof.settings,
        d: proof.d.to_vec(),
        q: proof.q,
        r: proof.r,
    };
    let bytes = bincode::serialize(&serializable).map_err(|e| e.to_string())?;
    if bytes.len() > MAX_SOUND_NONNATIVE_PROOF_BYTES {
        return Err("serialized sound reduce proof exceeds configured size limit".to_string());
    }
    Ok(bytes)
}

pub fn deserialize_sound_reduce_proof(bytes: &[u8]) -> Result<SoundReduceProof, String> {
    if bytes.len() > MAX_SOUND_NONNATIVE_PROOF_BYTES {
        return Err("serialized sound reduce proof exceeds configured size limit".to_string());
    }
    let opts = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .reject_trailing_bytes()
        .with_limit(MAX_SOUND_NONNATIVE_PROOF_BYTES as u64);
    let serializable: SerializableSoundReduceProof =
        opts.deserialize(bytes).map_err(|e| e.to_string())?;
    if serializable.d.len() != 64 {
        return Err("invalid sound reduce payload length".to_string());
    }
    let inner_opts = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .reject_trailing_bytes()
        .with_limit(MAX_SOUND_NONNATIVE_PROOF_BYTES as u64);
    let proof_inner: SoundAddSubStarkProof = inner_opts
        .deserialize(&serializable.proof_bytes)
        .map_err(|e| e.to_string())?;
    let mut d = [0_u8; 64];
    d.copy_from_slice(&serializable.d);
    Ok(SoundReduceProof {
        proof: proof_inner,
        settings: serializable.settings,
        d,
        q: serializable.q,
        r: serializable.r,
    })
}

pub fn serialize_sound_mul_mod_proof(proof: &SoundMulModProof) -> Result<Vec<u8>, String> {
    let serializable = SerializableSoundMulModProof {
        mul_bytes: serialize_sound_mul_proof(&proof.mul)?,
        reduce_bytes: serialize_sound_reduce_proof(&proof.reduce)?,
    };
    let bytes = bincode::serialize(&serializable).map_err(|e| e.to_string())?;
    if bytes.len() > MAX_SOUND_NONNATIVE_PROOF_BYTES {
        return Err("serialized sound mul-mod proof exceeds configured size limit".to_string());
    }
    Ok(bytes)
}

pub fn deserialize_sound_mul_mod_proof(bytes: &[u8]) -> Result<SoundMulModProof, String> {
    if bytes.len() > MAX_SOUND_NONNATIVE_PROOF_BYTES {
        return Err("serialized sound mul-mod proof exceeds configured size limit".to_string());
    }
    let opts = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .reject_trailing_bytes()
        .with_limit(MAX_SOUND_NONNATIVE_PROOF_BYTES as u64);
    let serializable: SerializableSoundMulModProof =
        opts.deserialize(bytes).map_err(|e| e.to_string())?;
    let mul = deserialize_sound_mul_proof(&serializable.mul_bytes)?;
    let reduce = deserialize_sound_reduce_proof(&serializable.reduce_bytes)?;
    Ok(SoundMulModProof { mul, reduce })
}

fn add_mod_p(a: [u8; 32], b: [u8; 32]) -> ([u8; 32], u8) {
    let mut sum = [0_u16; 32];
    let mut carry = 0_u16;
    for i in 0..32 {
        let v = (a[i] as u16) + (b[i] as u16) + carry;
        sum[i] = v & 0xff;
        carry = v >> 8;
    }

    let mut ge_p = carry == 1;
    if !ge_p {
        for i in (0..32).rev() {
            if (sum[i] as u8) > MODULUS_LE_BYTES[i] {
                ge_p = true;
                break;
            }
            if (sum[i] as u8) < MODULUS_LE_BYTES[i] {
                break;
            }
        }
    }

    let mut out = [0_u8; 32];
    if ge_p {
        let mut borrow = 0_i16;
        for i in 0..32 {
            let v = (sum[i] as i16) - (MODULUS_LE_BYTES[i] as i16) - borrow;
            if v < 0 {
                out[i] = (v + 256) as u8;
                borrow = 1;
            } else {
                out[i] = v as u8;
                borrow = 0;
            }
        }
        (out, 1)
    } else {
        for i in 0..32 {
            out[i] = sum[i] as u8;
        }
        (out, 0)
    }
}

fn sub_mod_p(a: [u8; 32], b: [u8; 32]) -> ([u8; 32], u8) {
    let mut out = [0_u8; 32];
    let mut borrow = 0_i16;
    for i in 0..32 {
        let v = (a[i] as i16) - (b[i] as i16) - borrow;
        if v < 0 {
            out[i] = (v + 256) as u8;
            borrow = 1;
        } else {
            out[i] = v as u8;
            borrow = 0;
        }
    }
    if borrow == 0 {
        return (out, 0);
    }

    let mut carry = 0_u16;
    for i in 0..32 {
        let v = (out[i] as u16) + (MODULUS_LE_BYTES[i] as u16) + carry;
        out[i] = (v & 0xff) as u8;
        carry = v >> 8;
    }
    (out, 1)
}

fn carries_for_relation(a: [u8; 32], b: [u8; 32], c: [u8; 32], q: u8, is_sub: bool) -> [i8; 33] {
    let mut carries = [0_i8; 33];
    for i in 0..32 {
        let lhs0 = if is_sub { c[i] } else { a[i] } as i32;
        let rhs0 = if is_sub { a[i] } else { c[i] } as i32;
        let tmp = lhs0 + (b[i] as i32) + (carries[i] as i32)
            - rhs0
            - (q as i32) * (MODULUS_LE_BYTES[i] as i32);
        assert_eq!(tmp.rem_euclid(256), 0);
        let next = tmp / 256;
        assert!((-1..=2).contains(&next));
        carries[i + 1] = next as i8;
    }
    assert_eq!(carries[32], 0);
    carries
}

fn build_trace(
    a: [u8; 32],
    b: [u8; 32],
    c: [u8; 32],
    q: u8,
    is_sub: bool,
    carries: [i8; 33],
) -> RowMajorMatrix<Val> {
    let mut row = vec![Val::ZERO; WIDTH];
    for i in 0..32 {
        row[COL_A + i] = Val::from_u8(a[i]);
        row[COL_B + i] = Val::from_u8(b[i]);
        row[COL_C + i] = Val::from_u8(c[i]);
        let enc = (carries[i] as i16) + (ADD_SUB_CARRY_BIAS as i16);
        assert!((1..=4).contains(&enc) || i == 0 || i == 32);
        row[COL_CARRY + i] = Val::from_u8(enc as u8);

        for bit in 0..8 {
            row[COL_A_BITS + (i * 8) + bit] = Val::from_bool(((a[i] >> bit) & 1) == 1);
            row[COL_B_BITS + (i * 8) + bit] = Val::from_bool(((b[i] >> bit) & 1) == 1);
            row[COL_C_BITS + (i * 8) + bit] = Val::from_bool(((c[i] >> bit) & 1) == 1);
        }
    }
    row[COL_CARRY + 32] = Val::from_u8((carries[32] as i16 + ADD_SUB_CARRY_BIAS as i16) as u8);
    row[COL_Q] = Val::from_bool(q == 1);
    row[COL_IS_SUB] = Val::from_bool(is_sub);

    let mut values = Vec::with_capacity(TRACE_ROWS * WIDTH);
    for _ in 0..TRACE_ROWS {
        values.extend(row.iter().copied());
    }
    RowMajorMatrix::new(values, WIDTH)
}

fn mul_full(a: [u8; 32], b: [u8; 32]) -> ([u8; 64], [u16; 65]) {
    let mut conv = [0_u32; 64];
    for i in 0..32 {
        for j in 0..32 {
            conv[i + j] += (a[i] as u32) * (b[j] as u32);
        }
    }
    let mut d = [0_u8; 64];
    let mut carry = [0_u16; 65];
    for k in 0..64 {
        let total = conv[k] + (carry[k] as u32);
        d[k] = (total & 0xff) as u8;
        carry[k + 1] = (total >> 8) as u16;
    }
    (d, carry)
}

fn build_mul_trace(a: [u8; 32], b: [u8; 32], d: [u8; 64], carry: [u16; 65]) -> RowMajorMatrix<Val> {
    let mut row = vec![Val::ZERO; MUL_WIDTH];
    for i in 0..32 {
        row[MUL_COL_A + i] = Val::from_u8(a[i]);
        row[MUL_COL_B + i] = Val::from_u8(b[i]);
        for bit in 0..8 {
            row[MUL_COL_A_BITS + (i * 8) + bit] = Val::from_bool(((a[i] >> bit) & 1) == 1);
            row[MUL_COL_B_BITS + (i * 8) + bit] = Val::from_bool(((b[i] >> bit) & 1) == 1);
        }
    }
    for k in 0..64 {
        row[MUL_COL_D + k] = Val::from_u8(d[k]);
        for bit in 0..8 {
            row[MUL_COL_D_BITS + (k * 8) + bit] = Val::from_bool(((d[k] >> bit) & 1) == 1);
        }
    }
    for i in 0..65 {
        row[MUL_COL_CARRY + i] = Val::from_u32(carry[i] as u32);
        for bit in 0..16 {
            row[MUL_COL_CARRY_BITS + (i * 16) + bit] =
                Val::from_bool((((carry[i] >> bit) & 1) as u8) == 1);
        }
    }

    let mut values = Vec::with_capacity(TRACE_ROWS * MUL_WIDTH);
    for _ in 0..TRACE_ROWS {
        values.extend(row.iter().copied());
    }
    RowMajorMatrix::new(values, MUL_WIDTH)
}

fn divrem_mod_p_from_512(d: [u8; 64]) -> ([u8; 32], [u8; 32]) {
    let n = BigUint::from_bytes_le(&d);
    let p = BigUint::from_bytes_le(&MODULUS_LE_BYTES);
    let q = &n / &p;
    let r = &n % &p;
    let mut q_bytes = q.to_bytes_le();
    q_bytes.resize(32, 0);
    let mut r_bytes = r.to_bytes_le();
    r_bytes.resize(32, 0);
    let mut q_out = [0_u8; 32];
    let mut r_out = [0_u8; 32];
    q_out.copy_from_slice(&q_bytes[..32]);
    r_out.copy_from_slice(&r_bytes[..32]);
    (q_out, r_out)
}

fn carries_for_reduce(d: [u8; 64], q: [u8; 32], r: [u8; 32]) -> [i32; 65] {
    let mut carries = [0_i32; 65];
    for i in 0usize..64 {
        let mut qxp = 0_u32;
        let j_min = i.saturating_sub(31);
        let j_max = i.min(31);
        for j in j_min..=j_max {
            let k = i - j;
            qxp += (q[j] as u32) * (MODULUS_LE_BYTES[k] as u32);
        }
        let r_i = if i < 32 { r[i] as i32 } else { 0_i32 };
        let tmp = (d[i] as i32) + carries[i] - r_i - (qxp as i32);
        assert_eq!(tmp.rem_euclid(256), 0);
        carries[i + 1] = tmp / 256;
    }
    assert_eq!(carries[64], 0);
    carries
}

fn build_reduce_trace(d: [u8; 64], q: [u8; 32], r: [u8; 32], carries: [i32; 65]) -> RowMajorMatrix<Val> {
    let mut row = vec![Val::ZERO; RED_WIDTH];
    for i in 0..64 {
        row[RED_COL_D + i] = Val::from_u8(d[i]);
        for bit in 0..8 {
            row[RED_COL_D_BITS + (i * 8) + bit] = Val::from_bool(((d[i] >> bit) & 1) == 1);
        }
    }
    for i in 0..32 {
        row[RED_COL_R + i] = Val::from_u8(r[i]);
        row[RED_COL_Q + i] = Val::from_u8(q[i]);
        for bit in 0..8 {
            row[RED_COL_R_BITS + (i * 8) + bit] = Val::from_bool(((r[i] >> bit) & 1) == 1);
            row[RED_COL_Q_BITS + (i * 8) + bit] = Val::from_bool(((q[i] >> bit) & 1) == 1);
        }
    }
    for i in 0..65 {
        let enc = carries[i] + (RED_CARRY_BIAS as i32);
        assert!((0..(1 << 24)).contains(&enc));
        row[RED_COL_CARRY + i] = Val::from_u32(enc as u32);
        for bit in 0..24 {
            row[RED_COL_CARRY_BITS + (i * 24) + bit] =
                Val::from_bool((((enc >> bit) & 1) as u8) == 1);
        }
    }

    let mut values = Vec::with_capacity(TRACE_ROWS * RED_WIDTH);
    for _ in 0..TRACE_ROWS {
        values.extend(row.iter().copied());
    }
    RowMajorMatrix::new(values, RED_WIDTH)
}

pub fn prove_nonnative_add(a: [u8; 32], b: [u8; 32]) -> Result<SoundAddSubProof, String> {
    prove_nonnative_add_with_settings(a, b, SoundAddSubProofSettings::default())
}

pub fn prove_nonnative_add_with_settings(
    a: [u8; 32],
    b: [u8; 32],
    settings: SoundAddSubProofSettings,
) -> Result<SoundAddSubProof, String> {
    let (c, q) = add_mod_p(a, b);
    let is_sub = false;
    let carries = carries_for_relation(a, b, c, q, is_sub);
    let trace = build_trace(a, b, c, q, is_sub, carries);

    let air = SoundAddSubAir;
    let config = setup_config(settings);
    let proof = prove(&config, &air, trace, &[]);

    Ok(SoundAddSubProof {
        proof,
        settings,
        is_sub,
        a,
        b,
        c,
    })
}

pub fn verify_nonnative_add(proof: &SoundAddSubProof) -> bool {
    verify_nonnative_add_with_settings(proof, SoundAddSubProofSettings::default())
}

pub fn verify_nonnative_add_with_settings(
    proof: &SoundAddSubProof,
    settings: SoundAddSubProofSettings,
) -> bool {
    if proof.settings != settings || proof.is_sub {
        return false;
    }
    let (expected_c, _) = add_mod_p(proof.a, proof.b);
    if expected_c != proof.c {
        return false;
    }
    let air = SoundAddSubAir;
    let config = setup_config(settings);
    verify(&config, &air, &proof.proof, &[]).is_ok()
}

pub fn prove_nonnative_sub(a: [u8; 32], b: [u8; 32]) -> Result<SoundAddSubProof, String> {
    prove_nonnative_sub_with_settings(a, b, SoundAddSubProofSettings::default())
}

pub fn prove_nonnative_sub_with_settings(
    a: [u8; 32],
    b: [u8; 32],
    settings: SoundAddSubProofSettings,
) -> Result<SoundAddSubProof, String> {
    let (c, q) = sub_mod_p(a, b);
    let is_sub = true;
    let carries = carries_for_relation(a, b, c, q, is_sub);
    let trace = build_trace(a, b, c, q, is_sub, carries);

    let air = SoundAddSubAir;
    let config = setup_config(settings);
    let proof = prove(&config, &air, trace, &[]);

    Ok(SoundAddSubProof {
        proof,
        settings,
        is_sub,
        a,
        b,
        c,
    })
}

pub fn verify_nonnative_sub(proof: &SoundAddSubProof) -> bool {
    verify_nonnative_sub_with_settings(proof, SoundAddSubProofSettings::default())
}

pub fn verify_nonnative_sub_with_settings(
    proof: &SoundAddSubProof,
    settings: SoundAddSubProofSettings,
) -> bool {
    if proof.settings != settings || !proof.is_sub {
        return false;
    }
    let (expected_c, _) = sub_mod_p(proof.a, proof.b);
    if expected_c != proof.c {
        return false;
    }
    let air = SoundAddSubAir;
    let config = setup_config(settings);
    verify(&config, &air, &proof.proof, &[]).is_ok()
}

pub fn prove_nonnative_mul(a: [u8; 32], b: [u8; 32]) -> Result<SoundMulProof, String> {
    prove_nonnative_mul_with_settings(a, b, SoundAddSubProofSettings::default())
}

pub fn prove_nonnative_mul_with_settings(
    a: [u8; 32],
    b: [u8; 32],
    settings: SoundAddSubProofSettings,
) -> Result<SoundMulProof, String> {
    let (d, carry) = mul_full(a, b);
    let trace = build_mul_trace(a, b, d, carry);
    let air = SoundMulAir;
    let config = setup_config(settings);
    let proof = prove(&config, &air, trace, &[]);
    Ok(SoundMulProof {
        proof,
        settings,
        a,
        b,
        d,
    })
}

pub fn verify_nonnative_mul(proof: &SoundMulProof) -> bool {
    verify_nonnative_mul_with_settings(proof, SoundAddSubProofSettings::default())
}

pub fn verify_nonnative_mul_with_settings(
    proof: &SoundMulProof,
    settings: SoundAddSubProofSettings,
) -> bool {
    if proof.settings != settings {
        return false;
    }
    let expected = BigUint::from_bytes_le(&proof.a) * BigUint::from_bytes_le(&proof.b);
    let mut expected_bytes = expected.to_bytes_le();
    expected_bytes.resize(64, 0);
    if expected_bytes[..64] != proof.d {
        return false;
    }
    let air = SoundMulAir;
    let config = setup_config(settings);
    verify(&config, &air, &proof.proof, &[]).is_ok()
}

pub fn prove_nonnative_reduce(d: [u8; 64]) -> Result<SoundReduceProof, String> {
    prove_nonnative_reduce_with_settings(d, SoundAddSubProofSettings::default())
}

pub fn prove_nonnative_reduce_with_settings(
    d: [u8; 64],
    settings: SoundAddSubProofSettings,
) -> Result<SoundReduceProof, String> {
    let (q, r) = divrem_mod_p_from_512(d);
    let carries = carries_for_reduce(d, q, r);
    let trace = build_reduce_trace(d, q, r, carries);
    let air = SoundReduceAir;
    let config = setup_config(settings);
    let proof = prove(&config, &air, trace, &[]);
    Ok(SoundReduceProof {
        proof,
        settings,
        d,
        q,
        r,
    })
}

pub fn verify_nonnative_reduce(proof: &SoundReduceProof) -> bool {
    verify_nonnative_reduce_with_settings(proof, SoundAddSubProofSettings::default())
}

pub fn verify_nonnative_reduce_with_settings(
    proof: &SoundReduceProof,
    settings: SoundAddSubProofSettings,
) -> bool {
    if proof.settings != settings {
        return false;
    }
    let (expected_q, expected_r) = divrem_mod_p_from_512(proof.d);
    if expected_q != proof.q || expected_r != proof.r {
        return false;
    }
    let air = SoundReduceAir;
    let config = setup_config(settings);
    verify(&config, &air, &proof.proof, &[]).is_ok()
}

pub fn prove_nonnative_mul_mod_p(a: [u8; 32], b: [u8; 32]) -> Result<SoundMulModProof, String> {
    prove_nonnative_mul_mod_p_with_settings(a, b, SoundAddSubProofSettings::default())
}

pub fn prove_nonnative_mul_mod_p_with_settings(
    a: [u8; 32],
    b: [u8; 32],
    settings: SoundAddSubProofSettings,
) -> Result<SoundMulModProof, String> {
    let mul = prove_nonnative_mul_with_settings(a, b, settings)?;
    let reduce = prove_nonnative_reduce_with_settings(mul.d, settings)?;
    Ok(SoundMulModProof { mul, reduce })
}

pub fn verify_nonnative_mul_mod_p(proof: &SoundMulModProof) -> bool {
    verify_nonnative_mul_mod_p_with_settings(proof, SoundAddSubProofSettings::default())
}

pub fn verify_nonnative_mul_mod_p_with_settings(
    proof: &SoundMulModProof,
    settings: SoundAddSubProofSettings,
) -> bool {
    if proof.mul.settings != settings || proof.reduce.settings != settings {
        return false;
    }
    if proof.mul.d != proof.reduce.d {
        return false;
    }
    if !verify_nonnative_mul_with_settings(&proof.mul, settings) {
        return false;
    }
    if !verify_nonnative_reduce_with_settings(&proof.reduce, settings) {
        return false;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    fn from_u64(x: u64) -> [u8; 32] {
        let mut out = [0_u8; 32];
        out[..8].copy_from_slice(&x.to_le_bytes());
        out
    }

    #[test]
    fn add_sound_air_roundtrip() {
        let a = from_u64(123456789);
        let b = from_u64(987654321);
        let proof = prove_nonnative_add(a, b).expect("prove");
        assert!(verify_nonnative_add(&proof));
    }

    #[test]
    fn add_sound_air_rejects_tampered_output() {
        let a = from_u64(1111);
        let b = from_u64(2222);
        let mut proof = prove_nonnative_add(a, b).expect("prove");
        proof.c[0] ^= 1;
        assert!(!verify_nonnative_add(&proof));
    }

    #[test]
    fn add_sound_air_handles_modulus_wrap() {
        let a = MODULUS_LE_BYTES;
        let b = from_u64(5);
        let proof = prove_nonnative_add(a, b).expect("prove");
        assert!(verify_nonnative_add(&proof));
        assert_eq!(proof.c[0], 5);
    }

    #[test]
    fn sub_sound_air_roundtrip() {
        let a = from_u64(987654321);
        let b = from_u64(123456789);
        let proof = prove_nonnative_sub(a, b).expect("prove");
        assert!(verify_nonnative_sub(&proof));
    }

    #[test]
    fn sub_sound_air_handles_underflow_wrap() {
        let a = from_u64(5);
        let b = from_u64(9);
        let proof = prove_nonnative_sub(a, b).expect("prove");
        assert!(verify_nonnative_sub(&proof));
    }

    #[test]
    fn sub_sound_air_rejects_tampered_output() {
        let a = from_u64(3333);
        let b = from_u64(2222);
        let mut proof = prove_nonnative_sub(a, b).expect("prove");
        proof.c[0] ^= 1;
        assert!(!verify_nonnative_sub(&proof));
    }

    #[test]
    fn mul_sound_air_roundtrip() {
        let a = from_u64(1234567);
        let b = from_u64(8901234);
        let proof = prove_nonnative_mul(a, b).expect("prove");
        assert!(verify_nonnative_mul(&proof));
    }

    #[test]
    fn mul_sound_air_rejects_tampered_output() {
        let a = from_u64(777);
        let b = from_u64(888);
        let mut proof = prove_nonnative_mul(a, b).expect("prove");
        proof.d[0] ^= 1;
        assert!(!verify_nonnative_mul(&proof));
    }

    #[test]
    fn reduce_sound_air_roundtrip() {
        let a = from_u64(1_234_567);
        let b = from_u64(8_901_234);
        let mul = prove_nonnative_mul(a, b).expect("prove mul");
        let reduce = prove_nonnative_reduce(mul.d).expect("prove reduce");
        assert!(verify_nonnative_reduce(&reduce));
    }

    #[test]
    fn reduce_sound_air_rejects_tampered_output() {
        let a = from_u64(4567);
        let b = from_u64(8901);
        let mul = prove_nonnative_mul(a, b).expect("prove mul");
        let mut reduce = prove_nonnative_reduce(mul.d).expect("prove reduce");
        reduce.r[0] ^= 1;
        assert!(!verify_nonnative_reduce(&reduce));
    }

    #[test]
    fn mul_mod_sound_air_roundtrip() {
        let a = from_u64(13_579);
        let b = from_u64(24_680);
        let proof = prove_nonnative_mul_mod_p(a, b).expect("prove");
        assert!(verify_nonnative_mul_mod_p(&proof));

        let expected =
            (BigUint::from_bytes_le(&a) * BigUint::from_bytes_le(&b)) % BigUint::from_bytes_le(&MODULUS_LE_BYTES);
        let mut expected_r = expected.to_bytes_le();
        expected_r.resize(32, 0);
        assert_eq!(proof.reduce.r[..], expected_r[..32]);
    }

    #[test]
    fn mul_mod_sound_air_rejects_link_tamper() {
        let a = from_u64(1234);
        let b = from_u64(5678);
        let mut proof = prove_nonnative_mul_mod_p(a, b).expect("prove");
        proof.reduce.d[0] ^= 1;
        assert!(!verify_nonnative_mul_mod_p(&proof));
    }
}
