use num_bigint::BigUint;
use num_traits::{One, Zero};
use p3_field::PrimeField64;
use std::collections::HashSet;

use crate::lookup::{LookupEvent, RangeLookupTable};
use crate::non_native_field::{Ed25519BaseField, LIMB_BITS, N_LIMBS};

const BASE: i128 = 1i128 << LIMB_BITS;
const ADD_CARRY_BOUND: i64 = 4;
const MUL_CARRY_BOUND: i128 = 1i128 << 24;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SoundFieldError {
    ConstraintViolation(&'static str),
    LimbOutOfRange { limb_index: usize, value: u16 },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SoundFieldCost {
    pub rows: usize,
    pub columns: usize,
    pub arithmetic_constraints: usize,
    pub boolean_constraints: usize,
    pub range_lookups: usize,
    pub carry_lookups: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SoundFieldOpOutput {
    pub value: Ed25519BaseField,
    pub cost: SoundFieldCost,
}

#[derive(Clone, Debug)]
struct AddWitness {
    carries: [i64; N_LIMBS + 1],
}

#[derive(Clone, Debug)]
struct MulWitness {
    prod_limbs: [u16; 32],
    carries: [i128; 32],
}

#[derive(Clone, Debug)]
pub struct SoundFieldChip {
    table: RangeLookupTable,
    lookup_log: Vec<LookupEvent>,
    introduced_values: HashSet<[u16; N_LIMBS]>,
    add_carry_transition_table: SignedCarryTransitionLookupTable,
    mul_carry_transition_table: SignedCarryTransitionLookupTable,
}

impl Default for SoundFieldChip {
    fn default() -> Self {
        Self::new(LIMB_BITS)
    }
}

impl SoundFieldChip {
    pub fn new(limb_bits: usize) -> Self {
        Self {
            table: RangeLookupTable::new(limb_bits),
            lookup_log: Vec::new(),
            introduced_values: HashSet::new(),
            add_carry_transition_table: SignedCarryTransitionLookupTable::new(
                -(ADD_CARRY_BOUND as i128),
                ADD_CARRY_BOUND as i128,
            ),
            mul_carry_transition_table: SignedCarryTransitionLookupTable::new(
                -MUL_CARRY_BOUND,
                MUL_CARRY_BOUND,
            ),
        }
    }

    pub fn lookup_events(&self) -> &[LookupEvent] {
        &self.lookup_log
    }

    pub fn clear_lookup_log(&mut self) {
        self.lookup_log.clear();
    }

    pub fn clear_trace_cache(&mut self) {
        self.clear_lookup_log();
        self.introduced_values.clear();
    }

    pub fn add(
        &mut self,
        lhs: &Ed25519BaseField,
        rhs: &Ed25519BaseField,
    ) -> Result<Ed25519BaseField, SoundFieldError> {
        Ok(self.add_sound(lhs, rhs)?.value)
    }

    pub fn sub(
        &mut self,
        lhs: &Ed25519BaseField,
        rhs: &Ed25519BaseField,
    ) -> Result<Ed25519BaseField, SoundFieldError> {
        let neg_rhs = rhs.neg_mod();
        Ok(self.add_sound(lhs, &neg_rhs)?.value)
    }

    pub fn mul(
        &mut self,
        lhs: &Ed25519BaseField,
        rhs: &Ed25519BaseField,
    ) -> Result<Ed25519BaseField, SoundFieldError> {
        Ok(self.mul_sound(lhs, rhs)?.value)
    }

    pub fn square(&mut self, x: &Ed25519BaseField) -> Result<Ed25519BaseField, SoundFieldError> {
        self.mul(x, x)
    }

    pub fn inv(&mut self, x: &Ed25519BaseField) -> Result<Ed25519BaseField, SoundFieldError> {
        let candidate = x
            .inv_mod()
            .ok_or(SoundFieldError::ConstraintViolation("non-invertible"))?;
        let check = self.mul_sound(x, &candidate)?;
        if check.value != Ed25519BaseField::one() {
            return Err(SoundFieldError::ConstraintViolation(
                "inverse relation check failed",
            ));
        }
        Ok(candidate)
    }

    pub fn add_sound(
        &mut self,
        lhs: &Ed25519BaseField,
        rhs: &Ed25519BaseField,
    ) -> Result<SoundFieldOpOutput, SoundFieldError> {
        let a_limbs = to_u16_limbs(lhs);
        let b_limbs = to_u16_limbs(rhs);
        self.introduce_limbs(&a_limbs)?;
        self.introduce_limbs(&b_limbs)?;

        let (out, witness) = self.build_add_witness(&a_limbs, &b_limbs)?;
        let out_limbs = to_u16_limbs(&out);
        self.introduce_limbs(&out_limbs)?;
        self.verify_add_constraints(&a_limbs, &b_limbs, &out_limbs, &witness)?;

        Ok(SoundFieldOpOutput {
            value: out,
            cost: Self::add_cost(),
        })
    }

    pub fn mul_sound(
        &mut self,
        lhs: &Ed25519BaseField,
        rhs: &Ed25519BaseField,
    ) -> Result<SoundFieldOpOutput, SoundFieldError> {
        let a_limbs = to_u16_limbs(lhs);
        let b_limbs = to_u16_limbs(rhs);
        self.introduce_limbs(&a_limbs)?;
        self.introduce_limbs(&b_limbs)?;

        let (out, witness) = self.build_mul_witness(lhs, rhs)?;
        let out_limbs = to_u16_limbs(&out);

        self.introduce_limbs(&out_limbs)?;
        self.verify_mul_constraints(&a_limbs, &b_limbs, &out_limbs, &witness)?;

        Ok(SoundFieldOpOutput {
            value: out,
            cost: Self::mul_cost(),
        })
    }

    pub fn add_cost() -> SoundFieldCost {
        SoundFieldCost {
            rows: N_LIMBS,
            // a_i, b_i, out_i, p_i, carry_i, carry_{i+1}
            columns: 6,
            arithmetic_constraints: N_LIMBS,
            // q is derived from the top-limb relation; no boolean witness bit.
            boolean_constraints: 0,
            // Steady-state per-op lookups, assuming inputs were already introduced in trace.
            range_lookups: N_LIMBS,
            // Packed carry-transition lookups.
            carry_lookups: N_LIMBS,
        }
    }

    pub fn mul_cost() -> SoundFieldCost {
        SoundFieldCost {
            // 31 convolution rows + 1 folded reduction relation.
            rows: 32,
            // conv_ab_n, prod_n, carry_n, carry_{n+1}
            columns: 4,
            arithmetic_constraints: 32,
            // q is derived from folded relation.
            boolean_constraints: 0,
            // Steady-state per-op lookups, assuming inputs were already introduced in trace.
            range_lookups: N_LIMBS,
            // Packed carry-transition lookups for 31 transitions.
            carry_lookups: 31,
        }
    }

    fn build_add_witness(
        &self,
        a_limbs: &[u16; N_LIMBS],
        b_limbs: &[u16; N_LIMBS],
    ) -> Result<(Ed25519BaseField, AddWitness), SoundFieldError> {
        let p = Ed25519BaseField::modulus();
        let a = limbs_to_biguint(a_limbs);
        let b = limbs_to_biguint(b_limbs);
        let sum = &a + &b;
        let q = u8::from(sum >= p);
        let out = if q == 1 { sum - &p } else { sum };
        let out_fe = Ed25519BaseField::from_biguint(out);
        let out_limbs = to_u16_limbs(&out_fe);
        let p_limbs = modulus_limbs();

        let mut carries = [0i64; N_LIMBS + 1];
        for i in 0..N_LIMBS {
            let delta = a_limbs[i] as i64 + b_limbs[i] as i64 + carries[i]
                - out_limbs[i] as i64
                - (q as i64) * p_limbs[i] as i64;
            if delta % (BASE as i64) != 0 {
                return Err(SoundFieldError::ConstraintViolation(
                    "add carry transition not divisible by base",
                ));
            }
            carries[i + 1] = delta / (BASE as i64);
        }

        Ok((out_fe, AddWitness { carries }))
    }

    fn verify_add_constraints(
        &mut self,
        a_limbs: &[u16; N_LIMBS],
        b_limbs: &[u16; N_LIMBS],
        out_limbs: &[u16; N_LIMBS],
        witness: &AddWitness,
    ) -> Result<(), SoundFieldError> {
        let p_limbs = modulus_limbs();
        if witness.carries[0] != 0 || witness.carries[N_LIMBS] != 0 {
            return Err(SoundFieldError::ConstraintViolation(
                "add boundary carries must be zero",
            ));
        }

        for i in 0..N_LIMBS {
            self.lookup_add_carry_transition(
                witness.carries[i] as i128,
                witness.carries[i + 1] as i128,
            )?;
        }

        // Derive q from the top-limb relation; for p = 2^255 - 19, p_limbs[15] = 32767.
        let top = N_LIMBS - 1;
        let numerator = a_limbs[top] as i64 + b_limbs[top] as i64 + witness.carries[top]
            - out_limbs[top] as i64
            - (BASE as i64) * witness.carries[N_LIMBS];
        if numerator % (p_limbs[top] as i64) != 0 {
            return Err(SoundFieldError::ConstraintViolation(
                "derived q is not integral",
            ));
        }
        let q = numerator / (p_limbs[top] as i64);
        if !(0..=1).contains(&q) {
            return Err(SoundFieldError::ConstraintViolation(
                "derived q must be in {0,1}",
            ));
        }

        for i in 0..N_LIMBS {
            let lhs = a_limbs[i] as i64 + b_limbs[i] as i64 + witness.carries[i];
            let rhs = out_limbs[i] as i64
                + q * p_limbs[i] as i64
                + (BASE as i64) * witness.carries[i + 1];
            if lhs != rhs {
                return Err(SoundFieldError::ConstraintViolation(
                    "add limb equation violated",
                ));
            }
        }
        Ok(())
    }

    fn build_mul_witness(
        &self,
        lhs: &Ed25519BaseField,
        rhs: &Ed25519BaseField,
    ) -> Result<(Ed25519BaseField, MulWitness), SoundFieldError> {
        let a = lhs.to_biguint();
        let b = rhs.to_biguint();
        let prod = &a * &b;
        let p = Ed25519BaseField::modulus();
        let out = &prod % &p;
        let out_fe = Ed25519BaseField::from_biguint(out.clone());
        let prod_limbs = biguint_to_32_limbs(&prod);

        let folded = fold_by_38_mod_p(&prod);
        if folded < out {
            return Err(SoundFieldError::ConstraintViolation(
                "folded value must be >= output",
            ));
        }
        let delta = &folded - &out;
        let q_big = &delta / &p;
        let q = q_big.to_u32_digits().first().copied().unwrap_or(0) as u8;
        if q > 2 {
            return Err(SoundFieldError::ConstraintViolation(
                "q for folded reduction must be in {0,1,2}",
            ));
        }

        let a_limbs = to_u16_limbs(lhs);
        let b_limbs = to_u16_limbs(rhs);
        let conv_ab = convolution_16(&a_limbs, &b_limbs);

        let mut carries = [0i128; 32];
        for n in 0..31 {
            let delta = conv_ab[n] + carries[n] - prod_limbs[n] as i128;
            if delta % BASE != 0 {
                return Err(SoundFieldError::ConstraintViolation(
                    "mul carry transition not divisible by base",
                ));
            }
            carries[n + 1] = delta / BASE;
        }
        let _ = q;
        Ok((
            out_fe,
            MulWitness {
                prod_limbs,
                carries,
            },
        ))
    }

    fn verify_mul_constraints(
        &mut self,
        a_limbs: &[u16; N_LIMBS],
        b_limbs: &[u16; N_LIMBS],
        out_limbs: &[u16; N_LIMBS],
        witness: &MulWitness,
    ) -> Result<(), SoundFieldError> {
        let conv_ab = convolution_16(a_limbs, b_limbs);
        if witness.carries[0] != 0 {
            return Err(SoundFieldError::ConstraintViolation(
                "mul carry[0] must be zero",
            ));
        }
        for i in 0..31 {
            self.lookup_mul_carry_transition(witness.carries[i], witness.carries[i + 1])?;
        }

        for n in 0..31 {
            let lhs_n = conv_ab[n] + witness.carries[n];
            let rhs_n = witness.prod_limbs[n] as i128 + BASE * witness.carries[n + 1];
            if lhs_n != rhs_n {
                return Err(SoundFieldError::ConstraintViolation(
                    "mul limb equation violated",
                ));
            }
        }

        if witness.carries[31] != witness.prod_limbs[31] as i128 {
            return Err(SoundFieldError::ConstraintViolation(
                "mul high-limb boundary violated",
            ));
        }

        let prod = limbs32_to_biguint(&witness.prod_limbs);
        let folded = fold_by_38_mod_p(&prod);
        let out = limbs_to_biguint(out_limbs);
        let p = Ed25519BaseField::modulus();
        if folded < out {
            return Err(SoundFieldError::ConstraintViolation(
                "folded value must be >= output",
            ));
        }
        let delta = &folded - &out;
        if (&delta % &p) != BigUint::zero() {
            return Err(SoundFieldError::ConstraintViolation(
                "folded-output difference must be divisible by p",
            ));
        }
        let q = (&delta / &p).to_u32_digits().first().copied().unwrap_or(0);
        if q > 2 {
            return Err(SoundFieldError::ConstraintViolation(
                "derived q for folded reduction must be in {0,1,2}",
            ));
        }

        Ok(())
    }

    fn introduce_limbs(&mut self, limbs: &[u16; N_LIMBS]) -> Result<(), SoundFieldError> {
        if !self.introduced_values.insert(*limbs) {
            return Ok(());
        }
        self.lookup_limbs(limbs)
    }

    fn lookup_limbs<const N: usize>(&mut self, limbs: &[u16; N]) -> Result<(), SoundFieldError> {
        for (idx, &value) in limbs.iter().enumerate() {
            if !self.table.contains(value) {
                return Err(SoundFieldError::LimbOutOfRange {
                    limb_index: idx,
                    value,
                });
            }
            self.lookup_log.push(LookupEvent {
                limb_index: idx,
                value,
            });
        }
        Ok(())
    }

    fn lookup_add_carry_transition(&mut self, from: i128, to: i128) -> Result<(), SoundFieldError> {
        if !self.add_carry_transition_table.contains(from, to) {
            return Err(SoundFieldError::ConstraintViolation(
                "add carry transition out of table range",
            ));
        }
        Ok(())
    }

    fn lookup_mul_carry_transition(&mut self, from: i128, to: i128) -> Result<(), SoundFieldError> {
        if !self.mul_carry_transition_table.contains(from, to) {
            return Err(SoundFieldError::ConstraintViolation(
                "mul carry transition out of table range",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
struct SignedCarryTransitionLookupTable {
    min: i128,
    max: i128,
}

impl SignedCarryTransitionLookupTable {
    fn new(min: i128, max: i128) -> Self {
        assert!(min <= max, "invalid carry lookup range");
        Self { min, max }
    }

    fn contains(&self, from: i128, to: i128) -> bool {
        self.min <= from && from <= self.max && self.min <= to && to <= self.max
    }
}

fn to_u16_limbs(value: &Ed25519BaseField) -> [u16; N_LIMBS] {
    let mut out = [0u16; N_LIMBS];
    for (i, limb) in value.limbs().iter().enumerate() {
        out[i] = limb.as_canonical_u64() as u16;
    }
    out
}

fn modulus_limbs() -> [u16; N_LIMBS] {
    biguint_to_limbs(&Ed25519BaseField::modulus())
}

fn biguint_to_limbs(value: &BigUint) -> [u16; N_LIMBS] {
    let mut out = [0u16; N_LIMBS];
    let mut tmp = value.clone();
    let mask = (BigUint::one() << LIMB_BITS) - BigUint::one();
    for limb in &mut out {
        *limb = (&tmp & &mask).to_u32_digits().first().copied().unwrap_or(0) as u16;
        tmp >>= LIMB_BITS;
    }
    out
}

fn limbs_to_biguint(limbs: &[u16; N_LIMBS]) -> BigUint {
    let mut acc = BigUint::zero();
    for (i, &limb) in limbs.iter().enumerate() {
        acc += BigUint::from(limb) << (i * LIMB_BITS);
    }
    acc
}

fn convolution_16(a: &[u16; N_LIMBS], b: &[u16; N_LIMBS]) -> [i128; 31] {
    let mut out = [0i128; 31];
    for i in 0..N_LIMBS {
        for j in 0..N_LIMBS {
            out[i + j] += (a[i] as i128) * (b[j] as i128);
        }
    }
    out
}

fn biguint_to_32_limbs(value: &BigUint) -> [u16; 32] {
    let mut out = [0u16; 32];
    let mut tmp = value.clone();
    let mask = (BigUint::one() << LIMB_BITS) - BigUint::one();
    for limb in &mut out {
        *limb = (&tmp & &mask).to_u32_digits().first().copied().unwrap_or(0) as u16;
        tmp >>= LIMB_BITS;
    }
    out
}

fn limbs32_to_biguint(limbs: &[u16; 32]) -> BigUint {
    let mut acc = BigUint::zero();
    for (i, &limb) in limbs.iter().enumerate() {
        acc += BigUint::from(limb) << (i * LIMB_BITS);
    }
    acc
}

fn fold_by_38_mod_p(x: &BigUint) -> BigUint {
    let two_256 = BigUint::one() << 256u32;

    let low = x % &two_256;
    let high = x >> 256u32;
    let s = low + BigUint::from(38u32) * high;

    let s_low = &s % &two_256;
    let s_high = s >> 256u32;
    s_low + BigUint::from(38u32) * s_high
}

#[cfg(test)]
mod tests {
    use rand::{SeedableRng, rngs::SmallRng};

    use super::SoundFieldChip;
    use crate::non_native_field::Ed25519BaseField;

    #[test]
    fn randomized_sound_add_matches_reference() {
        let mut rng = SmallRng::seed_from_u64(0x11aa22bb33cc44dd);
        let p = Ed25519BaseField::modulus();
        let mut chip = SoundFieldChip::default();

        for _ in 0..256 {
            let a = Ed25519BaseField::random(&mut rng);
            let b = Ed25519BaseField::random(&mut rng);
            let expected = (a.to_biguint() + b.to_biguint()) % &p;
            let out = chip.add_sound(&a, &b).expect("sound add must verify");
            assert_eq!(out.value.to_biguint(), expected);
        }
    }

    #[test]
    fn randomized_sound_mul_matches_reference() {
        let mut rng = SmallRng::seed_from_u64(0x5566778899aabbcc);
        let p = Ed25519BaseField::modulus();
        let mut chip = SoundFieldChip::default();

        for _ in 0..128 {
            let a = Ed25519BaseField::random(&mut rng);
            let b = Ed25519BaseField::random(&mut rng);
            let expected = (a.to_biguint() * b.to_biguint()) % &p;
            let out = chip.mul_sound(&a, &b).expect("sound mul must verify");
            assert_eq!(out.value.to_biguint(), expected);
        }
    }

    #[test]
    fn reports_expected_costs() {
        let add = SoundFieldChip::add_cost();
        assert_eq!(add.rows, 16);
        assert_eq!(add.boolean_constraints, 0);
        assert_eq!(add.range_lookups, 16);
        assert_eq!(add.carry_lookups, 16);

        let mul = SoundFieldChip::mul_cost();
        assert_eq!(mul.rows, 32);
        assert_eq!(mul.range_lookups, 16);
        assert_eq!(mul.carry_lookups, 31);
    }

    #[test]
    fn amortized_range_lookups_reuse_introduced_inputs() {
        let mut rng = SmallRng::seed_from_u64(0x1020_3040_5060_7080);
        let a = Ed25519BaseField::random(&mut rng);
        let b = Ed25519BaseField::random(&mut rng);
        let mut chip = SoundFieldChip::default();

        let _ = chip.add_sound(&a, &b).expect("first add");
        let first = chip.lookup_events().len();
        // a, b, out each introduced once.
        assert!(first >= 48);

        let _ = chip.add_sound(&a, &b).expect("second add");
        let second = chip.lookup_events().len();
        // Second add should only introduce the new output value in steady state.
        assert!(second <= first + 16);
    }
}
