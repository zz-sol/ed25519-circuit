use crate::affine::AffinePoint;
use crate::lookup::LookupEvent;
use crate::non_native_field::Ed25519BaseField;
use crate::non_native_field::sound::{
    SoundFieldChip, SoundFieldCost, SoundFieldError, SoundFieldOpOutput,
};

pub struct Ed25519CircuitApi {
    field_chip: SoundFieldChip,
}

impl Default for Ed25519CircuitApi {
    fn default() -> Self {
        Self {
            field_chip: SoundFieldChip::default(),
        }
    }
}

impl Ed25519CircuitApi {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn basepoint(&self) -> AffinePoint {
        AffinePoint::basepoint()
    }

    pub fn identity(&self) -> AffinePoint {
        AffinePoint::identity()
    }

    pub fn field_from_bytes_le(&self, bytes: [u8; 32]) -> Ed25519BaseField {
        Ed25519BaseField::from_bytes_le(bytes)
    }

    pub fn field_add(
        &mut self,
        a: &Ed25519BaseField,
        b: &Ed25519BaseField,
    ) -> Result<Ed25519BaseField, SoundFieldError> {
        self.field_chip.add(a, b)
    }

    pub fn field_sub(
        &mut self,
        a: &Ed25519BaseField,
        b: &Ed25519BaseField,
    ) -> Result<Ed25519BaseField, SoundFieldError> {
        self.field_chip.sub(a, b)
    }

    pub fn field_mul(
        &mut self,
        a: &Ed25519BaseField,
        b: &Ed25519BaseField,
    ) -> Result<Ed25519BaseField, SoundFieldError> {
        self.field_chip.mul(a, b)
    }

    pub fn field_inv(&mut self, x: &Ed25519BaseField) -> Result<Ed25519BaseField, SoundFieldError> {
        self.field_chip.inv(x)
    }

    pub fn field_add_sound(
        &mut self,
        a: &Ed25519BaseField,
        b: &Ed25519BaseField,
    ) -> Result<SoundFieldOpOutput, SoundFieldError> {
        self.field_chip.add_sound(a, b)
    }

    pub fn field_mul_sound(
        &mut self,
        a: &Ed25519BaseField,
        b: &Ed25519BaseField,
    ) -> Result<SoundFieldOpOutput, SoundFieldError> {
        self.field_chip.mul_sound(a, b)
    }

    pub fn field_add_sound_cost(&self) -> SoundFieldCost {
        SoundFieldChip::add_cost()
    }

    pub fn field_mul_sound_cost(&self) -> SoundFieldCost {
        SoundFieldChip::mul_cost()
    }

    pub fn affine_add(
        &mut self,
        p: &AffinePoint,
        q: &AffinePoint,
    ) -> Result<AffinePoint, SoundFieldError> {
        p.add(q, &mut self.field_chip)
    }

    pub fn affine_double(&mut self, p: &AffinePoint) -> Result<AffinePoint, SoundFieldError> {
        p.double(&mut self.field_chip)
    }

    pub fn affine_scalar_mul(
        &mut self,
        p: &AffinePoint,
        scalar_le: [u8; 32],
    ) -> Result<AffinePoint, SoundFieldError> {
        p.scalar_mul_le(scalar_le, &mut self.field_chip)
    }

    pub fn is_on_curve(&self, p: &AffinePoint) -> bool {
        p.is_on_curve()
    }

    pub fn lookup_events(&self) -> &[LookupEvent] {
        self.field_chip.lookup_events()
    }

    pub fn clear_lookup_log(&mut self) {
        self.field_chip.clear_lookup_log();
    }

    pub fn clear_trace_cache(&mut self) {
        self.field_chip.clear_trace_cache();
    }
}
