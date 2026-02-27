#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LookupEvent {
    pub limb_index: usize,
    pub value: u16,
}

#[derive(Clone, Debug)]
pub struct RangeLookupTable {
    limb_bits: usize,
    max_value: u16,
}

impl RangeLookupTable {
    pub fn new(limb_bits: usize) -> Self {
        assert!(
            limb_bits > 0 && limb_bits <= 16,
            "limb_bits must be in 1..=16"
        );
        let max_value = ((1u32 << limb_bits) - 1) as u16;
        Self {
            limb_bits,
            max_value,
        }
    }

    pub fn limb_bits(&self) -> usize {
        self.limb_bits
    }

    pub fn contains(&self, value: u16) -> bool {
        value <= self.max_value
    }
}
