use crate::affine::AffinePoint;
use crate::non_native::NonNativeFieldElement;
use crate::sound_nonnative::{
    SoundAddSubProof, SoundAddSubProofSettings, SoundMulModProof, prove_nonnative_add_with_settings,
    prove_nonnative_mul_mod_p_with_settings, prove_nonnative_sub_with_settings,
    verify_nonnative_add_with_settings, verify_nonnative_mul_mod_p_with_settings,
    verify_nonnative_sub_with_settings,
};

pub struct SoundAffineAddProof {
    pub settings: SoundAddSubProofSettings,
    pub lhs: AffinePoint,
    pub rhs: AffinePoint,
    pub out: AffinePoint,
    pub x1x2: SoundMulModProof,
    pub y1y2: SoundMulModProof,
    pub x1y2: SoundMulModProof,
    pub y1x2: SoundMulModProof,
    pub d_mul_x1x2: SoundMulModProof,
    pub dxxyy: SoundMulModProof,
    pub x_num: SoundAddSubProof,
    pub y_num: SoundAddSubProof,
    pub x_den: SoundAddSubProof,
    pub y_den: SoundAddSubProof,
    pub x_den_inv_check: SoundMulModProof,
    pub y_den_inv_check: SoundMulModProof,
    pub out_x: SoundMulModProof,
    pub out_y: SoundMulModProof,
}

fn fe_bytes(x: NonNativeFieldElement) -> [u8; 32] {
    x.to_ed25519_le_bytes()
}

fn one_bytes() -> [u8; 32] {
    NonNativeFieldElement::one().to_ed25519_le_bytes()
}

fn d_bytes() -> [u8; 32] {
    AffinePoint::d().to_ed25519_le_bytes()
}

pub fn prove_affine_add_sound(
    lhs: AffinePoint,
    rhs: AffinePoint,
) -> Result<SoundAffineAddProof, String> {
    prove_affine_add_sound_with_settings(lhs, rhs, SoundAddSubProofSettings::default())
}

pub fn prove_affine_add_sound_with_settings(
    lhs: AffinePoint,
    rhs: AffinePoint,
    settings: SoundAddSubProofSettings,
) -> Result<SoundAffineAddProof, String> {
    let w = lhs.add_with_witness(rhs);

    let x1x2 = prove_nonnative_mul_mod_p_with_settings(fe_bytes(lhs.x), fe_bytes(rhs.x), settings)?;
    let y1y2 = prove_nonnative_mul_mod_p_with_settings(fe_bytes(lhs.y), fe_bytes(rhs.y), settings)?;
    let x1y2 = prove_nonnative_mul_mod_p_with_settings(fe_bytes(lhs.x), fe_bytes(rhs.y), settings)?;
    let y1x2 = prove_nonnative_mul_mod_p_with_settings(fe_bytes(lhs.y), fe_bytes(rhs.x), settings)?;
    let d_mul_x1x2 =
        prove_nonnative_mul_mod_p_with_settings(d_bytes(), x1x2.reduce.r, settings)?;
    let dxxyy =
        prove_nonnative_mul_mod_p_with_settings(d_mul_x1x2.reduce.r, y1y2.reduce.r, settings)?;

    let x_num = prove_nonnative_add_with_settings(x1y2.reduce.r, y1x2.reduce.r, settings)?;
    let y_num = prove_nonnative_add_with_settings(y1y2.reduce.r, x1x2.reduce.r, settings)?;
    let x_den = prove_nonnative_add_with_settings(one_bytes(), dxxyy.reduce.r, settings)?;
    let y_den = prove_nonnative_sub_with_settings(one_bytes(), dxxyy.reduce.r, settings)?;

    let x_den_inv_check =
        prove_nonnative_mul_mod_p_with_settings(x_den.c, fe_bytes(w.x_den_inv), settings)?;
    let y_den_inv_check =
        prove_nonnative_mul_mod_p_with_settings(y_den.c, fe_bytes(w.y_den_inv), settings)?;
    let out_x = prove_nonnative_mul_mod_p_with_settings(x_num.c, fe_bytes(w.x_den_inv), settings)?;
    let out_y = prove_nonnative_mul_mod_p_with_settings(y_num.c, fe_bytes(w.y_den_inv), settings)?;

    if x1x2.reduce.r != fe_bytes(w.x1x2)
        || y1y2.reduce.r != fe_bytes(w.y1y2)
        || x1y2.reduce.r != fe_bytes(w.x1y2)
        || y1x2.reduce.r != fe_bytes(w.y1x2)
        || dxxyy.reduce.r != fe_bytes(w.dxxyy)
        || x_num.c != fe_bytes(w.x_num)
        || y_num.c != fe_bytes(w.y_num)
        || x_den.c != fe_bytes(w.x_den)
        || y_den.c != fe_bytes(w.y_den)
        || x_den_inv_check.reduce.r != one_bytes()
        || y_den_inv_check.reduce.r != one_bytes()
        || out_x.reduce.r != fe_bytes(w.out.x)
        || out_y.reduce.r != fe_bytes(w.out.y)
    {
        return Err("internal affine add soundness linkage check failed".to_string());
    }

    Ok(SoundAffineAddProof {
        settings,
        lhs,
        rhs,
        out: w.out,
        x1x2,
        y1y2,
        x1y2,
        y1x2,
        d_mul_x1x2,
        dxxyy,
        x_num,
        y_num,
        x_den,
        y_den,
        x_den_inv_check,
        y_den_inv_check,
        out_x,
        out_y,
    })
}

pub fn verify_affine_add_sound(proof: &SoundAffineAddProof) -> bool {
    verify_affine_add_sound_with_settings(proof, SoundAddSubProofSettings::default())
}

pub fn verify_affine_add_sound_with_settings(
    proof: &SoundAffineAddProof,
    settings: SoundAddSubProofSettings,
) -> bool {
    if proof.settings != settings {
        return false;
    }
    if !proof.lhs.is_on_curve() || !proof.rhs.is_on_curve() || !proof.out.is_on_curve() {
        return false;
    }

    let lhs_x = fe_bytes(proof.lhs.x);
    let lhs_y = fe_bytes(proof.lhs.y);
    let rhs_x = fe_bytes(proof.rhs.x);
    let rhs_y = fe_bytes(proof.rhs.y);
    let out_x_expected = fe_bytes(proof.out.x);
    let out_y_expected = fe_bytes(proof.out.y);
    let one = one_bytes();
    let d = d_bytes();

    let mul_ok = |p: &SoundMulModProof| verify_nonnative_mul_mod_p_with_settings(p, settings);
    let add_ok = |p: &SoundAddSubProof| verify_nonnative_add_with_settings(p, settings);
    let sub_ok = |p: &SoundAddSubProof| verify_nonnative_sub_with_settings(p, settings);

    if !mul_ok(&proof.x1x2)
        || !mul_ok(&proof.y1y2)
        || !mul_ok(&proof.x1y2)
        || !mul_ok(&proof.y1x2)
        || !mul_ok(&proof.d_mul_x1x2)
        || !mul_ok(&proof.dxxyy)
        || !add_ok(&proof.x_num)
        || !add_ok(&proof.y_num)
        || !add_ok(&proof.x_den)
        || !sub_ok(&proof.y_den)
        || !mul_ok(&proof.x_den_inv_check)
        || !mul_ok(&proof.y_den_inv_check)
        || !mul_ok(&proof.out_x)
        || !mul_ok(&proof.out_y)
    {
        return false;
    }

    if proof.x1x2.mul.a != lhs_x || proof.x1x2.mul.b != rhs_x {
        return false;
    }
    if proof.y1y2.mul.a != lhs_y || proof.y1y2.mul.b != rhs_y {
        return false;
    }
    if proof.x1y2.mul.a != lhs_x || proof.x1y2.mul.b != rhs_y {
        return false;
    }
    if proof.y1x2.mul.a != lhs_y || proof.y1x2.mul.b != rhs_x {
        return false;
    }
    if proof.d_mul_x1x2.mul.a != d || proof.d_mul_x1x2.mul.b != proof.x1x2.reduce.r {
        return false;
    }
    if proof.dxxyy.mul.a != proof.d_mul_x1x2.reduce.r || proof.dxxyy.mul.b != proof.y1y2.reduce.r {
        return false;
    }

    if proof.x_num.a != proof.x1y2.reduce.r || proof.x_num.b != proof.y1x2.reduce.r {
        return false;
    }
    if proof.y_num.a != proof.y1y2.reduce.r || proof.y_num.b != proof.x1x2.reduce.r {
        return false;
    }
    if proof.x_den.a != one || proof.x_den.b != proof.dxxyy.reduce.r {
        return false;
    }
    if proof.y_den.a != one || proof.y_den.b != proof.dxxyy.reduce.r {
        return false;
    }

    if proof.x_den_inv_check.mul.a != proof.x_den.c || proof.x_den_inv_check.reduce.r != one {
        return false;
    }
    if proof.y_den_inv_check.mul.a != proof.y_den.c || proof.y_den_inv_check.reduce.r != one {
        return false;
    }

    if proof.out_x.mul.a != proof.x_num.c
        || proof.out_x.reduce.r != out_x_expected
        || proof.out_y.mul.a != proof.y_num.c
        || proof.out_y.reduce.r != out_y_expected
    {
        return false;
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::affine::ed25519_basepoint_affine;

    fn scalar_from_u64(x: u64) -> [u8; 32] {
        let mut out = [0_u8; 32];
        out[..8].copy_from_slice(&x.to_le_bytes());
        out
    }

    #[test]
    fn sound_affine_add_roundtrip() {
        let base = ed25519_basepoint_affine();
        let lhs = base.scalar_mul(scalar_from_u64(11));
        let rhs = base.scalar_mul(scalar_from_u64(29));
        let proof = prove_affine_add_sound(lhs, rhs).expect("prove");
        assert!(verify_affine_add_sound(&proof));
        assert_eq!(proof.out, lhs.add(rhs));
    }

    #[test]
    fn sound_affine_add_rejects_tamper() {
        let base = ed25519_basepoint_affine();
        let lhs = base.scalar_mul(scalar_from_u64(3));
        let rhs = base.scalar_mul(scalar_from_u64(5));
        let mut proof = prove_affine_add_sound(lhs, rhs).expect("prove");
        proof.out_x.reduce.r[0] ^= 1;
        assert!(!verify_affine_add_sound(&proof));
    }
}
