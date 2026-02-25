use crate::affine::{AffineAddWitness, AffinePoint};
use crate::lookup::ByteLookupTable;
use p3_baby_bear::BabyBear;
use p3_field::PrimeCharacteristicRing;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AffineMulTraceStep {
    pub bit_index: usize,
    pub bit: u8,
    pub acc_before: AffinePoint,
    pub double_witness: AffineAddWitness,
    pub acc_after_double: AffinePoint,
    pub add_witness: AffineAddWitness,
    pub acc_after_add_base: AffinePoint,
    pub acc_after_select: AffinePoint,
}

pub fn scalar_bit_le(scalar_le_bytes: &[u8; 32], bit_index: usize) -> u8 {
    (scalar_le_bytes[bit_index / 8] >> (bit_index % 8)) & 1
}

pub fn build_affine_mul_trace(
    base: AffinePoint,
    scalar_le_bytes: [u8; 32],
) -> Vec<AffineMulTraceStep> {
    let mut trace = Vec::with_capacity(256);
    let mut acc = AffinePoint::identity();

    for bit_index in (0..256).rev() {
        let bit = scalar_bit_le(&scalar_le_bytes, bit_index);
        let acc_before = acc;
        let double_witness = acc_before.add_with_witness(acc_before);
        let acc_after_double = double_witness.out;
        let add_witness = acc_after_double.add_with_witness(base);
        let acc_after_add_base = add_witness.out;
        acc = if bit == 1 {
            acc_after_add_base
        } else {
            acc_after_double
        };

        trace.push(AffineMulTraceStep {
            bit_index,
            bit,
            acc_before,
            double_witness,
            acc_after_double,
            add_witness,
            acc_after_add_base,
            acc_after_select: acc,
        });
    }

    trace
}

pub fn verify_affine_mul_trace(
    trace: &[AffineMulTraceStep],
    base: AffinePoint,
    scalar_le_bytes: [u8; 32],
    byte_table: &ByteLookupTable,
) -> bool {
    if trace.len() != 256 {
        return false;
    }

    let mut expected_acc = AffinePoint::identity();

    for (row, step) in trace.iter().enumerate() {
        let expected_bit_index = 255 - row;
        if step.bit_index != expected_bit_index {
            return false;
        }

        let bit = scalar_bit_le(&scalar_le_bytes, step.bit_index);
        if step.bit != bit || step.bit > 1 {
            return false;
        }

        if step.acc_before != expected_acc {
            return false;
        }

        if !step.acc_before.is_on_curve()
            || !step.acc_after_double.is_on_curve()
            || !step.acc_after_add_base.is_on_curve()
            || !step.acc_after_select.is_on_curve()
        {
            return false;
        }

        if step.double_witness.lhs != step.acc_before || step.double_witness.rhs != step.acc_before
        {
            return false;
        }
        if !step.double_witness.verify() || step.acc_after_double != step.double_witness.out {
            return false;
        }

        if step.add_witness.lhs != step.acc_after_double || step.add_witness.rhs != base {
            return false;
        }
        if !step.add_witness.verify() || step.acc_after_add_base != step.add_witness.out {
            return false;
        }

        let selected = if step.bit == 1 {
            step.acc_after_add_base
        } else {
            step.acc_after_double
        };
        if step.acc_after_select != selected {
            return false;
        }

        // Lookup-based limb range checks (16-bit limbs through byte lookups).
        let points = [
            step.acc_before,
            step.acc_after_double,
            step.acc_after_add_base,
            step.acc_after_select,
        ];
        for p in points {
            if !p.x.lookup_range_check(byte_table) || !p.y.lookup_range_check(byte_table) {
                return false;
            }

            // LogUp-style multiset accounting handle: witness values are emitted as
            // (witness_value, table_value) pairs for x and y limbs.
            let x_pairs = byte_table.logup_multiset_pairs(&p.x.limbs);
            let y_pairs = byte_table.logup_multiset_pairs(&p.y.limbs);
            if x_pairs.len() != 32 || y_pairs.len() != 32 {
                return false;
            }
            let challenge_x = BabyBear::from_u32((1 << 20) + (row as u32 * 8) + 1);
            let challenge_y = BabyBear::from_u32((1 << 20) + (row as u32 * 8) + 2);
            if !byte_table.verify_logup_pairs(&x_pairs, challenge_x)
                || !byte_table.verify_logup_pairs(&y_pairs, challenge_y)
            {
                return false;
            }
        }

        expected_acc = step.acc_after_select;
    }

    expected_acc == base.scalar_mul(scalar_le_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::affine::ed25519_basepoint_affine;
    use curve25519::constants::ED25519_BASEPOINT_TABLE;
    use curve25519::scalar::Scalar;

    #[test]
    fn affine_mul_trace_roundtrip() {
        let base = ed25519_basepoint_affine();
        let scalar = [42_u8; 32];
        let trace = build_affine_mul_trace(base, scalar);
        let table = ByteLookupTable::default();
        assert!(verify_affine_mul_trace(&trace, base, scalar, &table));
    }

    #[test]
    fn affine_mul_trace_rejects_tamper() {
        let base = ed25519_basepoint_affine();
        let scalar = [99_u8; 32];
        let mut trace = build_affine_mul_trace(base, scalar);
        trace[10].acc_after_select.x = trace[10]
            .acc_after_select
            .x
            .add(crate::NonNativeFieldElement::one());
        let table = ByteLookupTable::default();
        assert!(!verify_affine_mul_trace(&trace, base, scalar, &table));
    }

    #[test]
    fn affine_mul_trace_rejects_witness_tamper() {
        let base = ed25519_basepoint_affine();
        let scalar = [77_u8; 32];
        let mut trace = build_affine_mul_trace(base, scalar);
        trace[5].add_witness.x_num = trace[5]
            .add_witness
            .x_num
            .add(crate::NonNativeFieldElement::one());
        let table = ByteLookupTable::default();
        assert!(!verify_affine_mul_trace(&trace, base, scalar, &table));
    }

    #[test]
    fn final_trace_output_matches_curve25519_sol() {
        let base = ed25519_basepoint_affine();
        let samples = [
            [0_u8; 32],
            [1_u8; 32],
            [2_u8; 32],
            [3_u8; 32],
            [7_u8; 32],
            [42_u8; 32],
            [255_u8; 32],
        ];
        for scalar in samples {
            let trace = build_affine_mul_trace(base, scalar);
            let ours = trace
                .last()
                .expect("trace has rows")
                .acc_after_select
                .compress();
            let expected = (&Scalar::from_bytes_mod_order(scalar) * ED25519_BASEPOINT_TABLE)
                .compress()
                .to_bytes();
            assert_eq!(ours, expected);
        }
    }
}
