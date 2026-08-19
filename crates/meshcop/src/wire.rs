//! Internal fixed-width wire-value readers.

pub(crate) fn read_u16(value: &[u8]) -> Option<u16> {
    let bytes: [u8; 2] = value.try_into().ok()?;
    Some(u16::from_be_bytes(bytes))
}

pub(crate) fn read_u32(value: &[u8]) -> Option<u32> {
    let bytes: [u8; 4] = value.try_into().ok()?;
    Some(u32::from_be_bytes(bytes))
}

pub(crate) fn read_u64(value: &[u8]) -> Option<u64> {
    let bytes: [u8; 8] = value.try_into().ok()?;
    Some(u64::from_be_bytes(bytes))
}
