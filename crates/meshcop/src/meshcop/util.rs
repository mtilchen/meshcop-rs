//! MeshCoP TLV assembly helpers.

use crate::{Result, tlv::TlvEntry};

pub(crate) fn append_tlv(out: &mut Vec<u8>, ty: u8, value: &[u8]) -> Result<()> {
    Ok(TlvEntry::new(ty, value).encode(out)?)
}

pub(crate) fn append_u8(out: &mut Vec<u8>, ty: u8, value: u8) -> Result<()> {
    append_tlv(out, ty, &[value])
}

pub(crate) fn append_u16(out: &mut Vec<u8>, ty: u8, value: u16) -> Result<()> {
    append_tlv(out, ty, &value.to_be_bytes())
}

pub(crate) fn append_u32(out: &mut Vec<u8>, ty: u8, value: u32) -> Result<()> {
    append_tlv(out, ty, &value.to_be_bytes())
}

pub(crate) fn append_tlv_u8_length(out: &mut Vec<u8>, ty: u8, value: &[u8]) {
    out.push(ty);
    out.push(value.len() as u8);
    out.extend_from_slice(value);
}

pub(crate) fn append_u16_u8_length(out: &mut Vec<u8>, ty: u8, value: u16) {
    append_tlv_u8_length(out, ty, &value.to_be_bytes());
}
