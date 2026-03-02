use num_bigint::BigUint;
use num_traits::One;
use p3_air::{Air, AirBuilder, AirBuilderWithPublicValues, BaseAir, BaseAirWithPublicValues};
use p3_baby_bear::BabyBear;
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use p3_matrix::Matrix;
use p3_matrix::dense::RowMajorMatrix;

use crate::non_native_field::{Ed25519BaseField, LIMB_BITS, N_LIMBS};

const SEL_ADD_COL: usize = 0;
const SEL_MUL_COL: usize = 1;
const Q_COL: usize = 2;
const A_BASE: usize = 3;
const B_BASE: usize = A_BASE + N_LIMBS;
const OUT_BASE: usize = B_BASE + N_LIMBS;
const ADD_CARRY_BASE: usize = OUT_BASE + N_LIMBS;
const PROD_BASE: usize = ADD_CARRY_BASE + (N_LIMBS + 1);
const MUL_CARRY_BASE: usize = PROD_BASE + 32;

pub const NON_NATIVE_FIELD_AIR_WIDTH: usize = MUL_CARRY_BASE + 32;
pub const NON_NATIVE_FIELD_NUM_PUBLIC_VALUES: usize = 7;

#[derive(Clone, Debug)]
pub enum FieldAirOp {
    Add {
        a: Ed25519BaseField,
        b: Ed25519BaseField,
    },
    Mul {
        a: Ed25519BaseField,
        b: Ed25519BaseField,
    },
}

#[derive(Clone, Debug, Default)]
pub struct NonNativeFieldAir;

impl BaseAir<BabyBear> for NonNativeFieldAir {
    fn width(&self) -> usize {
        NON_NATIVE_FIELD_AIR_WIDTH
    }
}

impl BaseAirWithPublicValues<BabyBear> for NonNativeFieldAir {
    fn num_public_values(&self) -> usize {
        NON_NATIVE_FIELD_NUM_PUBLIC_VALUES
    }
}

impl<AB: AirBuilderWithPublicValues<F = BabyBear>> Air<AB> for NonNativeFieldAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let row = main.row_slice(0).expect("local row");

        let sel_add = row[SEL_ADD_COL].clone();
        let sel_mul = row[SEL_MUL_COL].clone();

        // One-hot selectors.
        builder.assert_zero(sel_add.clone() * (AB::Expr::ONE - sel_add.clone()));
        builder.assert_zero(sel_mul.clone() * (AB::Expr::ONE - sel_mul.clone()));
        builder.assert_zero(sel_add.clone() * sel_mul.clone());

        constrain_add_row::<AB>(builder, &row, sel_add.clone().into());
        constrain_mul_row::<AB>(builder, &row, sel_mul.clone().into());

        let public = builder.public_values().to_vec();
        let mut first = builder.when_first_row();
        first.assert_eq(public[0].clone(), row_fingerprint_expr::<AB>(&row));
        first.assert_eq(public[1].clone(), pack_limbs_expr::<AB>(&row, A_BASE));
        first.assert_eq(public[2].clone(), pack_limbs_expr::<AB>(&row, B_BASE));

        let mut last = builder.when_last_row();
        last.assert_eq(public[3].clone(), pack_limbs_expr::<AB>(&row, OUT_BASE));
        last.assert_eq(public[4].clone(), row[SEL_ADD_COL].clone());
        last.assert_eq(public[5].clone(), row[SEL_MUL_COL].clone());
        last.assert_eq(public[6].clone(), row[Q_COL].clone());
    }
}

fn constrain_add_row<AB: AirBuilder<F = BabyBear>>(
    builder: &mut AB,
    row: &[AB::Var],
    sel: AB::Expr,
) {
    let p_limbs = modulus_limbs();
    let two16 = BabyBear::from_u32(1 << 16);
    let q = row[Q_COL].clone();
    builder.assert_zero(sel.clone() * q.clone() * (q - BabyBear::ONE));

    // add_carry[0] = 0, add_carry[16] = 0
    builder.assert_zero(sel.clone() * row[ADD_CARRY_BASE].clone());
    builder.assert_zero(sel.clone() * row[ADD_CARRY_BASE + N_LIMBS].clone());

    for i in 0..N_LIMBS {
        let lhs =
            row[A_BASE + i].clone() + row[B_BASE + i].clone() + row[ADD_CARRY_BASE + i].clone();
        let rhs = row[OUT_BASE + i].clone()
            + row[Q_COL].clone() * BabyBear::from_u16(p_limbs[i])
            + row[ADD_CARRY_BASE + i + 1].clone() * two16;
        builder.assert_zero(sel.clone() * (lhs - rhs));
    }
}

fn constrain_mul_row<AB: AirBuilder<F = BabyBear>>(
    builder: &mut AB,
    row: &[AB::Var],
    sel: AB::Expr,
) {
    let two16 = BabyBear::from_u32(1 << 16);
    builder.assert_zero(sel.clone() * row[MUL_CARRY_BASE].clone());

    for n in 0..31 {
        let mut conv = AB::Expr::ZERO;
        for i in 0..N_LIMBS {
            let j = n as isize - i as isize;
            if (0..N_LIMBS as isize).contains(&j) {
                conv += row[A_BASE + i].clone() * row[B_BASE + j as usize].clone();
            }
        }
        let lhs = conv + row[MUL_CARRY_BASE + n].clone();
        let rhs = row[PROD_BASE + n].clone() + row[MUL_CARRY_BASE + n + 1].clone() * two16;
        builder.assert_zero(sel.clone() * (lhs - rhs));
    }
    builder.assert_zero(
        sel.clone() * (row[MUL_CARRY_BASE + 31].clone() - row[PROD_BASE + 31].clone()),
    );

    // Folded pseudo-Mersenne relation:
    // low + 38*high = out + q*p
    let mut low = AB::Expr::ZERO;
    let mut high = AB::Expr::ZERO;
    let mut out = AB::Expr::ZERO;
    let mut p_expr = AB::Expr::ZERO;

    for i in 0..N_LIMBS {
        let c = pow2_16(i);
        low += row[PROD_BASE + i].clone() * c;
        high += row[PROD_BASE + 16 + i].clone() * c;
        out += row[OUT_BASE + i].clone() * c;
        p_expr += BabyBear::from_u16(modulus_limbs()[i]) * c;
    }

    let folded = low + high * BabyBear::from_u32(38);
    let rhs = out + row[Q_COL].clone() * p_expr;
    builder.assert_zero(sel * (folded - rhs));
}

fn pow2_16(exp: usize) -> BabyBear {
    let mut out = BabyBear::ONE;
    let step = BabyBear::from_u32(1 << 16);
    for _ in 0..exp {
        out *= step;
    }
    out
}

fn pack_limbs_expr<AB: AirBuilder<F = BabyBear>>(row: &[AB::Var], base: usize) -> AB::Expr {
    let mut acc = AB::Expr::ZERO;
    for i in 0..N_LIMBS {
        acc += row[base + i].clone() * pow2_16(i);
    }
    acc
}

fn row_fingerprint_expr<AB: AirBuilder<F = BabyBear>>(row: &[AB::Var]) -> AB::Expr {
    row[SEL_ADD_COL].clone()
        + row[SEL_MUL_COL].clone() * BabyBear::from_u32(3)
        + row[Q_COL].clone() * BabyBear::from_u32(5)
        + pack_limbs_expr::<AB>(row, A_BASE)
        + pack_limbs_expr::<AB>(row, B_BASE)
}

fn modulus_limbs() -> [u16; N_LIMBS] {
    let p = Ed25519BaseField::modulus();
    let mut out = [0u16; N_LIMBS];
    let mut tmp = p;
    let mask = (BigUint::one() << LIMB_BITS) - BigUint::one();
    for limb in &mut out {
        *limb = (&tmp & &mask).to_u32_digits().first().copied().unwrap_or(0) as u16;
        tmp >>= LIMB_BITS;
    }
    out
}

pub fn build_add_row(a: &Ed25519BaseField, b: &Ed25519BaseField) -> Vec<BabyBear> {
    let mut row = vec![BabyBear::ZERO; NON_NATIVE_FIELD_AIR_WIDTH];
    row[SEL_ADD_COL] = BabyBear::ONE;

    let a_limbs = to_limbs(a);
    let b_limbs = to_limbs(b);
    let p_limbs = modulus_limbs();

    let sum = a.to_biguint() + b.to_biguint();
    let p = Ed25519BaseField::modulus();
    let q = u16::from(sum >= p);
    let out = if q == 1 { sum - &p } else { sum };
    let out_fe = Ed25519BaseField::from_biguint(out);
    let out_limbs = to_limbs(&out_fe);

    row[Q_COL] = BabyBear::from_u16(q);

    for i in 0..N_LIMBS {
        row[A_BASE + i] = BabyBear::from_u16(a_limbs[i]);
        row[B_BASE + i] = BabyBear::from_u16(b_limbs[i]);
        row[OUT_BASE + i] = BabyBear::from_u16(out_limbs[i]);
    }

    let mut carries = [0i64; N_LIMBS + 1];
    for i in 0..N_LIMBS {
        let delta = a_limbs[i] as i64 + b_limbs[i] as i64 + carries[i]
            - out_limbs[i] as i64
            - (q as i64) * p_limbs[i] as i64;
        carries[i + 1] = delta / (1 << LIMB_BITS);
    }
    for i in 0..=N_LIMBS {
        row[ADD_CARRY_BASE + i] = BabyBear::from_i64(carries[i]);
    }
    row
}

pub fn build_mul_row(a: &Ed25519BaseField, b: &Ed25519BaseField) -> Vec<BabyBear> {
    let mut row = vec![BabyBear::ZERO; NON_NATIVE_FIELD_AIR_WIDTH];
    row[SEL_MUL_COL] = BabyBear::ONE;

    let a_limbs = to_limbs(a);
    let b_limbs = to_limbs(b);
    for i in 0..N_LIMBS {
        row[A_BASE + i] = BabyBear::from_u16(a_limbs[i]);
        row[B_BASE + i] = BabyBear::from_u16(b_limbs[i]);
    }

    let prod = a.to_biguint() * b.to_biguint();
    let mut prod_limbs = [0u16; 32];
    {
        let mut tmp = prod.clone();
        let mask = (BigUint::one() << LIMB_BITS) - BigUint::one();
        for limb in &mut prod_limbs {
            *limb = (&tmp & &mask).to_u32_digits().first().copied().unwrap_or(0) as u16;
            tmp >>= LIMB_BITS;
        }
    }
    for i in 0..32 {
        row[PROD_BASE + i] = BabyBear::from_u16(prod_limbs[i]);
    }

    let p = Ed25519BaseField::modulus();
    let out = &prod % &p;
    let out_fe = Ed25519BaseField::from_biguint(out.clone());
    let out_limbs = to_limbs(&out_fe);
    for i in 0..N_LIMBS {
        row[OUT_BASE + i] = BabyBear::from_u16(out_limbs[i]);
    }

    let folded = {
        let two_256 = BigUint::one() << 256u32;
        let low = &prod % &two_256;
        let high = &prod >> 256u32;
        low + BigUint::from(38u32) * high
    };
    let q = ((&folded - &out) / &p)
        .to_u32_digits()
        .first()
        .copied()
        .unwrap_or(0) as u16;
    row[Q_COL] = BabyBear::from_u16(q);

    let mut carries = [0i64; 32];
    for n in 0..31 {
        let mut conv = 0i64;
        for i in 0..N_LIMBS {
            let j = n as isize - i as isize;
            if (0..N_LIMBS as isize).contains(&j) {
                conv += (a_limbs[i] as i64) * (b_limbs[j as usize] as i64);
            }
        }
        let delta = conv + carries[n] - prod_limbs[n] as i64;
        carries[n + 1] = delta / (1 << LIMB_BITS);
    }
    for i in 0..32 {
        row[MUL_CARRY_BASE + i] = BabyBear::from_i64(carries[i]);
    }

    row
}

pub fn build_trace_for_ops(ops: &[FieldAirOp]) -> RowMajorMatrix<BabyBear> {
    let mut values = Vec::with_capacity(ops.len() * NON_NATIVE_FIELD_AIR_WIDTH);
    for op in ops {
        let row = match op {
            FieldAirOp::Add { a, b } => build_add_row(a, b),
            FieldAirOp::Mul { a, b } => build_mul_row(a, b),
        };
        values.extend_from_slice(&row);
    }
    RowMajorMatrix::new(values, NON_NATIVE_FIELD_AIR_WIDTH)
}

pub fn compute_trace_public_values(
    trace: &RowMajorMatrix<BabyBear>,
) -> [BabyBear; NON_NATIVE_FIELD_NUM_PUBLIC_VALUES] {
    let mut out = [BabyBear::ZERO; NON_NATIVE_FIELD_NUM_PUBLIC_VALUES];
    if trace.height() == 0 {
        return out;
    }

    let first = trace.row_slice(0).expect("first row");
    let last = trace.row_slice(trace.height() - 1).expect("last row");

    out[0] = row_fingerprint_value(&first);
    out[1] = pack_limbs_value(&first, A_BASE);
    out[2] = pack_limbs_value(&first, B_BASE);
    out[3] = pack_limbs_value(&last, OUT_BASE);
    out[4] = last[SEL_ADD_COL];
    out[5] = last[SEL_MUL_COL];
    out[6] = last[Q_COL];
    out
}

pub fn validate_trace_rows(trace: &RowMajorMatrix<BabyBear>) -> bool {
    let air = NonNativeFieldAir;
    let public_values = compute_trace_public_values(trace);
    for r in 0..trace.height() {
        let row = trace.row_slice(r).expect("row exists").to_vec();
        let is_first = r == 0;
        let is_last = r + 1 == trace.height();
        if !validate_row(&air, row, public_values.to_vec(), is_first, is_last) {
            return false;
        }
    }
    true
}

fn validate_row(
    air: &NonNativeFieldAir,
    row: Vec<BabyBear>,
    public_values: Vec<BabyBear>,
    is_first: bool,
    is_last: bool,
) -> bool {
    #[derive(Clone)]
    struct RowChecker {
        main: RowMajorMatrix<BabyBear>,
        public_values: Vec<BabyBear>,
        is_first: bool,
        is_last: bool,
        violated: bool,
    }

    impl AirBuilder for RowChecker {
        type F = BabyBear;
        type Expr = BabyBear;
        type Var = BabyBear;
        type M = RowMajorMatrix<BabyBear>;

        fn main(&self) -> Self::M {
            self.main.clone()
        }
        fn is_first_row(&self) -> Self::Expr {
            if self.is_first {
                BabyBear::ONE
            } else {
                BabyBear::ZERO
            }
        }
        fn is_last_row(&self) -> Self::Expr {
            if self.is_last {
                BabyBear::ONE
            } else {
                BabyBear::ZERO
            }
        }
        fn is_transition_window(&self, _size: usize) -> Self::Expr {
            BabyBear::ZERO
        }
        fn assert_zero<I: Into<Self::Expr>>(&mut self, x: I) {
            if x.into() != BabyBear::ZERO {
                self.violated = true;
            }
        }
    }

    impl AirBuilderWithPublicValues for RowChecker {
        type PublicVar = BabyBear;

        fn public_values(&self) -> &[Self::PublicVar] {
            &self.public_values
        }
    }

    let matrix = RowMajorMatrix::new(row, NON_NATIVE_FIELD_AIR_WIDTH);
    let mut checker = RowChecker {
        main: matrix,
        public_values,
        is_first,
        is_last,
        violated: false,
    };
    air.eval(&mut checker);
    !checker.violated
}

fn to_limbs(x: &Ed25519BaseField) -> [u16; N_LIMBS] {
    let mut out = [0u16; N_LIMBS];
    for (i, limb) in x.limbs().iter().enumerate() {
        out[i] = limb.as_canonical_u64() as u16;
    }
    out
}

fn pack_limbs_value(row: &[BabyBear], base: usize) -> BabyBear {
    let mut acc = BabyBear::ZERO;
    for i in 0..N_LIMBS {
        acc += row[base + i] * pow2_16(i);
    }
    acc
}

fn row_fingerprint_value(row: &[BabyBear]) -> BabyBear {
    row[SEL_ADD_COL]
        + row[SEL_MUL_COL] * BabyBear::from_u32(3)
        + row[Q_COL] * BabyBear::from_u32(5)
        + pack_limbs_value(row, A_BASE)
        + pack_limbs_value(row, B_BASE)
}

#[cfg(test)]
mod tests {
    use p3_air::Air;
    use p3_air::{AirBuilder, AirBuilderWithPublicValues};
    use p3_baby_bear::BabyBear;
    use p3_field::PrimeCharacteristicRing;
    use p3_matrix::dense::RowMajorMatrix;
    use rand::{SeedableRng, rngs::SmallRng};

    use super::{
        FieldAirOp, NON_NATIVE_FIELD_AIR_WIDTH, NON_NATIVE_FIELD_NUM_PUBLIC_VALUES,
        NonNativeFieldAir, build_add_row, build_mul_row, build_trace_for_ops,
        compute_trace_public_values, validate_trace_rows,
    };
    use crate::non_native_field::Ed25519BaseField;

    #[derive(Clone)]
    struct Checker {
        main: RowMajorMatrix<BabyBear>,
        public_values: Vec<BabyBear>,
        violated: bool,
    }

    impl AirBuilder for Checker {
        type F = BabyBear;
        type Expr = BabyBear;
        type Var = BabyBear;
        type M = RowMajorMatrix<BabyBear>;

        fn main(&self) -> Self::M {
            self.main.clone()
        }

        fn is_first_row(&self) -> Self::Expr {
            BabyBear::ONE
        }

        fn is_last_row(&self) -> Self::Expr {
            BabyBear::ONE
        }

        fn is_transition_window(&self, _size: usize) -> Self::Expr {
            BabyBear::ZERO
        }

        fn assert_zero<I: Into<Self::Expr>>(&mut self, x: I) {
            if x.into() != BabyBear::ZERO {
                self.violated = true;
            }
        }
    }

    impl AirBuilderWithPublicValues for Checker {
        type PublicVar = BabyBear;

        fn public_values(&self) -> &[Self::PublicVar] {
            &self.public_values
        }
    }

    #[test]
    fn add_row_satisfies_air() {
        let mut rng = SmallRng::seed_from_u64(0x1234_abcd);
        let a = Ed25519BaseField::random(&mut rng);
        let b = Ed25519BaseField::random(&mut rng);
        let row = build_add_row(&a, &b);
        let matrix = RowMajorMatrix::new(row, NON_NATIVE_FIELD_AIR_WIDTH);
        let public_values = compute_trace_public_values(&matrix);
        let mut checker = Checker {
            main: matrix,
            public_values: public_values.to_vec(),
            violated: false,
        };
        NonNativeFieldAir.eval(&mut checker);
        assert!(!checker.violated);
    }

    #[test]
    fn mul_row_satisfies_air() {
        let mut rng = SmallRng::seed_from_u64(0x5678_dcba);
        let a = Ed25519BaseField::random(&mut rng);
        let b = Ed25519BaseField::random(&mut rng);
        let row = build_mul_row(&a, &b);
        let matrix = RowMajorMatrix::new(row, NON_NATIVE_FIELD_AIR_WIDTH);
        let public_values = compute_trace_public_values(&matrix);
        let mut checker = Checker {
            main: matrix,
            public_values: public_values.to_vec(),
            violated: false,
        };
        NonNativeFieldAir.eval(&mut checker);
        assert!(!checker.violated);
    }

    #[test]
    fn tampered_row_violates_air() {
        let mut rng = SmallRng::seed_from_u64(0xabcd_5678);
        let a = Ed25519BaseField::random(&mut rng);
        let b = Ed25519BaseField::random(&mut rng);
        let mut row = build_add_row(&a, &b);
        row[super::OUT_BASE] += BabyBear::ONE;
        let matrix = RowMajorMatrix::new(row, NON_NATIVE_FIELD_AIR_WIDTH);
        let public_values = compute_trace_public_values(&matrix);
        let mut checker = Checker {
            main: matrix,
            public_values: public_values.to_vec(),
            violated: false,
        };
        NonNativeFieldAir.eval(&mut checker);
        assert!(checker.violated);
    }

    #[test]
    fn mixed_trace_satisfies_air() {
        let mut rng = SmallRng::seed_from_u64(0xface_b00c_1234_5678);
        let mut ops = Vec::new();
        for i in 0..10 {
            let a = Ed25519BaseField::random(&mut rng);
            let b = Ed25519BaseField::random(&mut rng);
            if i % 2 == 0 {
                ops.push(FieldAirOp::Add { a, b });
            } else {
                ops.push(FieldAirOp::Mul { a, b });
            }
        }
        let trace = build_trace_for_ops(&ops);
        assert!(validate_trace_rows(&trace));
    }

    #[test]
    fn public_values_shape_matches_constant() {
        let mut rng = SmallRng::seed_from_u64(0x4444_5555_6666_7777);
        let a = Ed25519BaseField::random(&mut rng);
        let b = Ed25519BaseField::random(&mut rng);
        let row = build_mul_row(&a, &b);
        let matrix = RowMajorMatrix::new(row, NON_NATIVE_FIELD_AIR_WIDTH);
        let public_values = compute_trace_public_values(&matrix);
        assert_eq!(public_values.len(), NON_NATIVE_FIELD_NUM_PUBLIC_VALUES);
    }
}
