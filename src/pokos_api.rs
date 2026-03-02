use crate::affine::{AffinePoint, GroupOpCost};
use crate::api::Ed25519CircuitApi;
use crate::non_native_field::proof::FieldAirProof;
use crate::non_native_field::sound::SoundFieldError;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BasepointBatchMulRequest {
    pub scalars_le: Vec<[u8; 32]>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BasepointBatchMulResponse {
    pub compressed_points: Vec<[u8; 32]>,
    pub cost: GroupOpCost,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BasepointBatchMulSumResponse {
    pub compressed_points: Vec<[u8; 32]>,
    pub compressed_sum: [u8; 32],
    pub cost: GroupOpCost,
}

pub struct BasepointBatchMulProofRequest {
    pub scalars_le: Vec<[u8; 32]>,
}

pub struct BasepointBatchMulProofResponse {
    pub compressed_points: Vec<[u8; 32]>,
    pub cost: GroupOpCost,
    pub proof: FieldAirProof,
}

pub struct BasepointBatchMulProofVerifyRequest {
    pub proof: FieldAirProof,
    pub scalars_le: Vec<[u8; 32]>,
    pub compressed_points: Vec<[u8; 32]>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BasepointBatchMulProofVerifyResponse {
    pub is_valid: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MsmRequest {
    pub points: Vec<AffinePoint>,
    pub scalars_le: Vec<[u8; 32]>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MsmResponse {
    pub compressed_result: [u8; 32],
    pub cost: GroupOpCost,
}

pub struct MsmProofResultRequest {
    pub points: Vec<AffinePoint>,
    pub scalars_le: Vec<[u8; 32]>,
}

pub struct MsmProofResultResponse {
    pub compressed_result: [u8; 32],
    pub cost: GroupOpCost,
    pub proof: FieldAirProof,
}

pub struct MsmProofResultVerifyRequest {
    pub proof: FieldAirProof,
    pub points: Vec<AffinePoint>,
    pub scalars_le: Vec<[u8; 32]>,
    pub compressed_result: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MsmProofResultVerifyResponse {
    pub is_valid: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MsmEquationCheckRequest {
    pub points: Vec<AffinePoint>,
    pub scalars_le: Vec<[u8; 32]>,
    pub expected: AffinePoint,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MsmEquationCheckResponse {
    pub is_satisfied: bool,
    pub compressed_result: [u8; 32],
    pub cost: GroupOpCost,
}

pub struct MsmProofRequest {
    pub points: Vec<AffinePoint>,
    pub scalars_le: Vec<[u8; 32]>,
    pub expected: AffinePoint,
}

pub struct MsmProofResponse {
    pub is_satisfied: bool,
    pub compressed_result: [u8; 32],
    pub cost: GroupOpCost,
    pub proof: FieldAirProof,
}

pub struct MsmProofVerifyRequest {
    pub proof: FieldAirProof,
    pub points: Vec<AffinePoint>,
    pub scalars_le: Vec<[u8; 32]>,
    pub expected: AffinePoint,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MsmProofVerifyResponse {
    pub is_valid: bool,
}

pub struct BasepointBatchMulSumProofRequest {
    pub scalars_le: Vec<[u8; 32]>,
}

pub struct BasepointBatchMulSumProofResponse {
    pub compressed_points: Vec<[u8; 32]>,
    pub compressed_sum: [u8; 32],
    pub cost: GroupOpCost,
    pub proof: FieldAirProof,
}

pub struct BasepointBatchMulSumProofVerifyRequest {
    pub proof: FieldAirProof,
    pub scalars_le: Vec<[u8; 32]>,
    pub compressed_points: Vec<[u8; 32]>,
    pub compressed_sum: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BasepointBatchMulSumProofVerifyResponse {
    pub is_valid: bool,
}

pub fn basepoint_batch_mul_compressed(
    request: &BasepointBatchMulRequest,
) -> Result<BasepointBatchMulResponse, SoundFieldError> {
    let mut api = Ed25519CircuitApi::new();
    let out = api.basepoint_batch_scalar_mul_with_cost(&request.scalars_le)?;
    let compressed_points = out.points.iter().map(|p| p.compress()).collect();
    Ok(BasepointBatchMulResponse {
        compressed_points,
        cost: out.cost,
    })
}

pub fn basepoint_batch_mul_sum_compressed(
    request: &BasepointBatchMulRequest,
) -> Result<BasepointBatchMulSumResponse, SoundFieldError> {
    let mut api = Ed25519CircuitApi::new();
    let out = api.basepoint_batch_scalar_mul_sum_with_cost(&request.scalars_le)?;
    let compressed_points = out.points.iter().map(|p| p.compress()).collect();
    Ok(BasepointBatchMulSumResponse {
        compressed_points,
        compressed_sum: out.sum.compress(),
        cost: out.cost,
    })
}

pub fn basepoint_batch_mul_prove(
    request: &BasepointBatchMulProofRequest,
) -> Result<BasepointBatchMulProofResponse, SoundFieldError> {
    let mut api = Ed25519CircuitApi::new();
    let (out, proof) = api.prove_basepoint_batch_with_field_air(&request.scalars_le)?;
    let compressed_points = out.points.iter().map(|p| p.compress()).collect();
    Ok(BasepointBatchMulProofResponse {
        compressed_points,
        cost: out.cost,
        proof,
    })
}

pub fn basepoint_batch_mul_verify_proof(
    request: BasepointBatchMulProofVerifyRequest,
) -> BasepointBatchMulProofVerifyResponse {
    let is_valid = Ed25519CircuitApi::verify_basepoint_batch_field_air_proof(
        &request.proof,
        &request.scalars_le,
        &request.compressed_points,
    );
    BasepointBatchMulProofVerifyResponse { is_valid }
}

pub fn basepoint_batch_mul_sum_prove(
    request: &BasepointBatchMulSumProofRequest,
) -> Result<BasepointBatchMulSumProofResponse, SoundFieldError> {
    let mut api = Ed25519CircuitApi::new();
    let (out, proof) = api.prove_basepoint_batch_sum_with_field_air(&request.scalars_le)?;
    let compressed_points = out.points.iter().map(|p| p.compress()).collect();
    Ok(BasepointBatchMulSumProofResponse {
        compressed_points,
        compressed_sum: out.sum.compress(),
        cost: out.cost,
        proof,
    })
}

pub fn basepoint_batch_mul_sum_verify_proof(
    request: BasepointBatchMulSumProofVerifyRequest,
) -> BasepointBatchMulSumProofVerifyResponse {
    let is_valid = Ed25519CircuitApi::verify_basepoint_batch_sum_field_air_proof(
        &request.proof,
        &request.scalars_le,
        &request.compressed_points,
        &request.compressed_sum,
    );
    BasepointBatchMulSumProofVerifyResponse { is_valid }
}

pub fn msm_compressed(request: &MsmRequest) -> Result<MsmResponse, SoundFieldError> {
    let mut api = Ed25519CircuitApi::new();
    let out = api.msm_with_cost(&request.points, &request.scalars_le)?;
    Ok(MsmResponse {
        compressed_result: out.point.compress(),
        cost: out.cost,
    })
}

pub fn msm_result_prove(
    request: &MsmProofResultRequest,
) -> Result<MsmProofResultResponse, SoundFieldError> {
    let mut api = Ed25519CircuitApi::new();
    let (out, proof) = api.prove_msm_with_field_air(&request.points, &request.scalars_le)?;
    Ok(MsmProofResultResponse {
        compressed_result: out.point.compress(),
        cost: out.cost,
        proof,
    })
}

pub fn msm_result_verify_proof(
    request: MsmProofResultVerifyRequest,
) -> MsmProofResultVerifyResponse {
    let is_valid = Ed25519CircuitApi::verify_msm_field_air_proof(
        &request.proof,
        &request.points,
        &request.scalars_le,
        &request.compressed_result,
    );
    MsmProofResultVerifyResponse { is_valid }
}

pub fn msm_equation_check(
    request: &MsmEquationCheckRequest,
) -> Result<MsmEquationCheckResponse, SoundFieldError> {
    let mut api = Ed25519CircuitApi::new();
    let out =
        api.check_msm_equation_sound(&request.points, &request.scalars_le, &request.expected)?;
    Ok(MsmEquationCheckResponse {
        is_satisfied: out.is_satisfied,
        compressed_result: out.result.compress(),
        cost: out.cost,
    })
}

pub fn msm_prove(request: &MsmProofRequest) -> Result<MsmProofResponse, SoundFieldError> {
    let mut api = Ed25519CircuitApi::new();
    let (out, proof) = api.prove_msm_equation_with_field_air(
        &request.points,
        &request.scalars_le,
        &request.expected,
    )?;
    Ok(MsmProofResponse {
        is_satisfied: out.is_satisfied,
        compressed_result: out.result.compress(),
        cost: out.cost,
        proof,
    })
}

pub fn msm_verify_proof(request: MsmProofVerifyRequest) -> MsmProofVerifyResponse {
    let is_valid = Ed25519CircuitApi::verify_msm_equation_field_air_proof(
        &request.proof,
        &request.points,
        &request.scalars_le,
        &request.expected,
    );
    MsmProofVerifyResponse { is_valid }
}

#[cfg(test)]
mod tests {
    use super::{
        BasepointBatchMulProofRequest, BasepointBatchMulProofVerifyRequest,
        BasepointBatchMulRequest, BasepointBatchMulSumProofRequest,
        BasepointBatchMulSumProofVerifyRequest, MsmEquationCheckRequest, MsmProofRequest,
        MsmProofResultRequest, MsmProofResultVerifyRequest, MsmProofVerifyRequest, MsmRequest,
        basepoint_batch_mul_compressed, basepoint_batch_mul_prove,
        basepoint_batch_mul_sum_compressed, basepoint_batch_mul_sum_prove,
        basepoint_batch_mul_sum_verify_proof, basepoint_batch_mul_verify_proof, msm_compressed,
        msm_equation_check, msm_prove, msm_result_prove, msm_result_verify_proof, msm_verify_proof,
    };
    use crate::affine::AffinePoint;
    use curve25519::{Scalar, constants::ED25519_BASEPOINT_POINT};
    use rand::{RngCore, SeedableRng, rngs::SmallRng};

    #[test]
    fn pokos_batch_api_matches_reference() {
        let mut rng = SmallRng::seed_from_u64(0x1111_2222_3333_4444);
        let mut scalars = Vec::new();
        for _ in 0..8 {
            let mut s = [0u8; 32];
            rng.fill_bytes(&mut s);
            scalars.push(s);
        }

        let resp = basepoint_batch_mul_compressed(&BasepointBatchMulRequest {
            scalars_le: scalars.clone(),
        })
        .unwrap();
        assert_eq!(resp.compressed_points.len(), scalars.len());
        assert!(resp.cost.field_muls > 0);

        for (i, s) in scalars.iter().enumerate() {
            let k = Scalar::from_bytes_mod_order(*s);
            let reference = (ED25519_BASEPOINT_POINT * k).compress().to_bytes();
            assert_eq!(resp.compressed_points[i], reference);
        }
    }

    #[test]
    fn pokos_batch_sum_api_matches_reference() {
        let mut rng = SmallRng::seed_from_u64(0x9999_aaaa_bbbb_cccc);
        let mut scalars = Vec::new();
        for _ in 0..6 {
            let mut s = [0u8; 32];
            rng.fill_bytes(&mut s);
            scalars.push(s);
        }

        let resp = basepoint_batch_mul_sum_compressed(&BasepointBatchMulRequest {
            scalars_le: scalars.clone(),
        })
        .unwrap();
        assert_eq!(resp.compressed_points.len(), scalars.len());

        let mut sum = ED25519_BASEPOINT_POINT * Scalar::from_bytes_mod_order([0u8; 32]);
        for s in &scalars {
            sum += ED25519_BASEPOINT_POINT * Scalar::from_bytes_mod_order(*s);
        }
        assert_eq!(resp.compressed_sum, sum.compress().to_bytes());
    }

    #[test]
    fn pokos_msm_api_matches_reference() {
        let mut rng = SmallRng::seed_from_u64(0x1212_3434_5656_7878);
        let g = AffinePoint::basepoint();
        let mut chip = crate::non_native_field::sound::SoundFieldChip::default();

        let mut points = Vec::new();
        let mut scalars = Vec::new();
        let mut reference = ED25519_BASEPOINT_POINT * Scalar::from_bytes_mod_order([0u8; 32]);
        for _ in 0..5 {
            let mut p_scalar = [0u8; 32];
            let mut k = [0u8; 32];
            rng.fill_bytes(&mut p_scalar);
            rng.fill_bytes(&mut k);
            let p = g.scalar_mul_le(p_scalar, &mut chip).unwrap();
            let k_sc = Scalar::from_bytes_mod_order(k);
            let p_sc = Scalar::from_bytes_mod_order(p_scalar);
            reference += (ED25519_BASEPOINT_POINT * p_sc) * k_sc;

            points.push(p);
            scalars.push(k);
        }

        let out = msm_compressed(&MsmRequest {
            points,
            scalars_le: scalars,
        })
        .unwrap();
        assert_eq!(out.compressed_result, reference.compress().to_bytes());
    }

    #[test]
    fn pokos_msm_equation_check_detects_invalid() {
        let mut rng = SmallRng::seed_from_u64(0xa1a2_a3a4_a5a6_a7a8);
        let g = AffinePoint::basepoint();
        let mut chip = crate::non_native_field::sound::SoundFieldChip::default();

        let mut points = Vec::new();
        let mut scalars = Vec::new();
        let mut expected = AffinePoint::identity();
        for _ in 0..3 {
            let mut p_scalar = [0u8; 32];
            let mut k = [0u8; 32];
            rng.fill_bytes(&mut p_scalar);
            rng.fill_bytes(&mut k);
            let p = g.scalar_mul_le(p_scalar, &mut chip).unwrap();
            let term = p.scalar_mul_le(k, &mut chip).unwrap();
            expected = expected.add(&term, &mut chip).unwrap();
            points.push(p);
            scalars.push(k);
        }

        let ok = msm_equation_check(&MsmEquationCheckRequest {
            points: points.clone(),
            scalars_le: scalars.clone(),
            expected: expected.clone(),
        })
        .unwrap();
        assert!(ok.is_satisfied);

        let bad = msm_equation_check(&MsmEquationCheckRequest {
            points,
            scalars_le: scalars,
            expected: AffinePoint::identity(),
        })
        .unwrap();
        assert!(!bad.is_satisfied);
    }

    #[test]
    fn pokos_msm_proof_roundtrip() {
        let mut rng = SmallRng::seed_from_u64(0x1357_2468_abcd_ef01);
        let g = AffinePoint::basepoint();
        let mut chip = crate::non_native_field::sound::SoundFieldChip::default();

        let mut points = Vec::new();
        let mut scalars = Vec::new();
        let mut expected = AffinePoint::identity();
        for _ in 0..3 {
            let mut p_scalar = [0u8; 32];
            let mut k = [0u8; 32];
            rng.fill_bytes(&mut p_scalar);
            rng.fill_bytes(&mut k);
            let p = g.scalar_mul_le(p_scalar, &mut chip).unwrap();
            let term = p.scalar_mul_le(k, &mut chip).unwrap();
            expected = expected.add(&term, &mut chip).unwrap();
            points.push(p);
            scalars.push(k);
        }

        let prove = msm_prove(&MsmProofRequest {
            points: points.clone(),
            scalars_le: scalars.clone(),
            expected: expected.clone(),
        })
        .unwrap();
        assert!(prove.is_satisfied);

        let verify = msm_verify_proof(MsmProofVerifyRequest {
            proof: prove.proof,
            points,
            scalars_le: scalars,
            expected,
        });
        assert!(verify.is_valid);
    }

    #[test]
    fn pokos_msm_proof_rejects_wrong_statement() {
        let mut rng = SmallRng::seed_from_u64(0x2468_1357_aaaa_5555);
        let g = AffinePoint::basepoint();
        let mut chip = crate::non_native_field::sound::SoundFieldChip::default();

        let mut points = Vec::new();
        let mut scalars = Vec::new();
        let mut expected = AffinePoint::identity();
        for _ in 0..3 {
            let mut p_scalar = [0u8; 32];
            let mut k = [0u8; 32];
            rng.fill_bytes(&mut p_scalar);
            rng.fill_bytes(&mut k);
            let p = g.scalar_mul_le(p_scalar, &mut chip).unwrap();
            let term = p.scalar_mul_le(k, &mut chip).unwrap();
            expected = expected.add(&term, &mut chip).unwrap();
            points.push(p);
            scalars.push(k);
        }

        let prove = msm_prove(&MsmProofRequest {
            points: points.clone(),
            scalars_le: scalars.clone(),
            expected: expected.clone(),
        })
        .unwrap();

        let verify = msm_verify_proof(MsmProofVerifyRequest {
            proof: prove.proof,
            points,
            scalars_le: scalars,
            expected: AffinePoint::identity(),
        });
        assert!(!verify.is_valid);
    }

    #[test]
    fn pokos_basepoint_batch_proof_roundtrip() {
        let mut rng = SmallRng::seed_from_u64(0x1111_aaaa_2222_bbbb);
        let mut scalars = Vec::new();
        for _ in 0..4 {
            let mut s = [0u8; 32];
            rng.fill_bytes(&mut s);
            scalars.push(s);
        }

        let prove = basepoint_batch_mul_prove(&BasepointBatchMulProofRequest {
            scalars_le: scalars.clone(),
        })
        .unwrap();
        let verify = basepoint_batch_mul_verify_proof(BasepointBatchMulProofVerifyRequest {
            proof: prove.proof,
            scalars_le: scalars,
            compressed_points: prove.compressed_points,
        });
        assert!(verify.is_valid);
    }

    #[test]
    fn pokos_basepoint_batch_proof_rejects_wrong_outputs() {
        let mut rng = SmallRng::seed_from_u64(0x3333_cccc_4444_dddd);
        let mut scalars = Vec::new();
        for _ in 0..3 {
            let mut s = [0u8; 32];
            rng.fill_bytes(&mut s);
            scalars.push(s);
        }

        let prove = basepoint_batch_mul_prove(&BasepointBatchMulProofRequest {
            scalars_le: scalars.clone(),
        })
        .unwrap();
        let mut wrong_points = prove.compressed_points;
        wrong_points[0][0] ^= 1;

        let verify = basepoint_batch_mul_verify_proof(BasepointBatchMulProofVerifyRequest {
            proof: prove.proof,
            scalars_le: scalars,
            compressed_points: wrong_points,
        });
        assert!(!verify.is_valid);
    }

    #[test]
    fn pokos_msm_result_proof_roundtrip() {
        let mut rng = SmallRng::seed_from_u64(0x7777_8888_9999_aaaa);
        let g = AffinePoint::basepoint();
        let mut chip = crate::non_native_field::sound::SoundFieldChip::default();

        let mut points = Vec::new();
        let mut scalars = Vec::new();
        for _ in 0..3 {
            let mut p_scalar = [0u8; 32];
            let mut k = [0u8; 32];
            rng.fill_bytes(&mut p_scalar);
            rng.fill_bytes(&mut k);
            points.push(g.scalar_mul_le(p_scalar, &mut chip).unwrap());
            scalars.push(k);
        }

        let prove = msm_result_prove(&MsmProofResultRequest {
            points: points.clone(),
            scalars_le: scalars.clone(),
        })
        .unwrap();
        let verify = msm_result_verify_proof(MsmProofResultVerifyRequest {
            proof: prove.proof,
            points,
            scalars_le: scalars,
            compressed_result: prove.compressed_result,
        });
        assert!(verify.is_valid);
    }

    #[test]
    fn pokos_basepoint_batch_sum_proof_roundtrip() {
        let mut rng = SmallRng::seed_from_u64(0xbbbb_cccc_dddd_eeee);
        let mut scalars = Vec::new();
        for _ in 0..4 {
            let mut s = [0u8; 32];
            rng.fill_bytes(&mut s);
            scalars.push(s);
        }

        let prove = basepoint_batch_mul_sum_prove(&BasepointBatchMulSumProofRequest {
            scalars_le: scalars.clone(),
        })
        .unwrap();
        let verify = basepoint_batch_mul_sum_verify_proof(BasepointBatchMulSumProofVerifyRequest {
            proof: prove.proof,
            scalars_le: scalars,
            compressed_points: prove.compressed_points,
            compressed_sum: prove.compressed_sum,
        });
        assert!(verify.is_valid);
    }
}
