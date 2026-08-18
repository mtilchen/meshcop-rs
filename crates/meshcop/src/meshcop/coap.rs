//! Minimal CoAP message codec.

use crate::{Result, error::Error};

use super::constants::COAP_OPTION_URI_PATH;

/// CoAP message type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CoapType {
    /// Confirmable.
    Confirmable = 0,
    /// Non-confirmable.
    NonConfirmable = 1,
    /// Acknowledgement.
    Acknowledgement = 2,
    /// Reset.
    Reset = 3,
}

impl TryFrom<u8> for CoapType {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            0 => Ok(Self::Confirmable),
            1 => Ok(Self::NonConfirmable),
            2 => Ok(Self::Acknowledgement),
            3 => Ok(Self::Reset),
            _ => Err(Error::Dataset("invalid CoAP type".to_string())),
        }
    }
}

/// CoAP method/response code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CoapCode(pub u8);

impl CoapCode {
    /// Empty code.
    pub const EMPTY: Self = Self(0x00);
    /// POST method.
    pub const POST: Self = Self(0x02);
    /// 2.04 Changed response.
    pub const CHANGED: Self = Self(0x44);
    /// 2.05 Content response.
    pub const CONTENT: Self = Self(0x45);
}

/// One CoAP option.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoapOption {
    /// Option number.
    pub number: u16,
    /// Option value.
    pub value: Vec<u8>,
}

/// Minimal CoAP message representation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoapMessage {
    /// Message type.
    pub ty: CoapType,
    /// Method or response code.
    pub code: CoapCode,
    /// Message ID.
    pub message_id: u16,
    /// Token.
    pub token: Vec<u8>,
    /// Options in ascending option-number order.
    pub options: Vec<CoapOption>,
    /// Payload bytes.
    pub payload: Vec<u8>,
}

impl CoapMessage {
    /// Creates an empty acknowledgement for a confirmable CoAP message.
    pub fn empty_ack(message_id: u16) -> Self {
        Self {
            ty: CoapType::Acknowledgement,
            code: CoapCode::EMPTY,
            message_id,
            token: Vec::new(),
            options: Vec::new(),
            payload: Vec::new(),
        }
    }

    /// Creates a payload-less 2.04 Changed acknowledgement for `request`.
    pub fn empty_changed_response(request: &Self) -> Self {
        Self {
            ty: CoapType::Acknowledgement,
            code: CoapCode::CHANGED,
            message_id: request.message_id,
            token: request.token.clone(),
            options: Vec::new(),
            payload: Vec::new(),
        }
    }

    /// Creates a POST request for a CoAP resource.
    pub fn post_request(
        ty: CoapType,
        message_id: u16,
        token: impl Into<Vec<u8>>,
        uri_path: &str,
        payload: Vec<u8>,
    ) -> Result<Self> {
        let mut message = Self {
            ty,
            code: CoapCode::POST,
            message_id,
            token: token.into(),
            options: Vec::new(),
            payload,
        };
        message.set_uri_path(uri_path)?;
        Ok(message)
    }

    /// Replaces the Uri-Path options with `uri_path`.
    pub fn set_uri_path(&mut self, uri_path: &str) -> Result<()> {
        self.options
            .retain(|option| option.number != COAP_OPTION_URI_PATH);

        let trimmed = uri_path.strip_prefix('/').unwrap_or(uri_path);
        if trimmed.is_empty() {
            return Ok(());
        }

        for segment in trimmed.split('/') {
            if segment.is_empty() {
                return Err(Error::Dataset(
                    "CoAP Uri-Path has an empty segment".to_string(),
                ));
            }
            self.options.push(CoapOption {
                number: COAP_OPTION_URI_PATH,
                value: segment.as_bytes().to_vec(),
            });
        }
        Ok(())
    }

    /// Returns the Uri-Path reconstructed from CoAP options.
    pub fn uri_path(&self) -> Result<Option<String>> {
        let mut segments = Vec::new();
        for option in &self.options {
            if option.number == COAP_OPTION_URI_PATH {
                segments.push(
                    core::str::from_utf8(&option.value)
                        .map_err(|_| Error::Dataset("CoAP Uri-Path is not UTF-8".to_string()))?,
                );
            }
        }
        if segments.is_empty() {
            Ok(None)
        } else {
            Ok(Some(format!("/{}", segments.join("/"))))
        }
    }

    /// Encodes this CoAP message.
    pub fn encode(&self) -> Result<Vec<u8>> {
        if self.token.len() > 8 {
            return Err(Error::Dataset("CoAP token length > 8".to_string()));
        }
        let mut out = Vec::new();
        out.push((1 << 6) | ((self.ty as u8) << 4) | self.token.len() as u8);
        out.push(self.code.0);
        out.extend_from_slice(&self.message_id.to_be_bytes());
        out.extend_from_slice(&self.token);

        let mut last_number = 0u16;
        let mut options: Vec<_> = self.options.iter().cloned().enumerate().collect();
        options.sort_by_key(|(idx, option)| (option.number, *idx));
        for (_, option) in options {
            let delta = option
                .number
                .checked_sub(last_number)
                .ok_or_else(|| Error::Dataset("CoAP option numbers decreased".to_string()))?;
            encode_option_header(delta, option.value.len(), &mut out)?;
            out.extend_from_slice(&option.value);
            last_number = option.number;
        }

        if !self.payload.is_empty() {
            out.push(0xff);
            out.extend_from_slice(&self.payload);
        }
        Ok(out)
    }

    /// Decodes a CoAP message.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 4 {
            return Err(Error::Dataset("CoAP header is truncated".to_string()));
        }
        if bytes[0] >> 6 != 1 {
            return Err(Error::Dataset("unsupported CoAP version".to_string()));
        }
        let token_len = (bytes[0] & 0x0f) as usize;
        if token_len > 8 || bytes.len() < 4 + token_len {
            return Err(Error::Dataset("invalid CoAP token length".to_string()));
        }

        let ty = CoapType::try_from((bytes[0] >> 4) & 0x03)?;
        let code = CoapCode(bytes[1]);
        let message_id = u16::from_be_bytes([bytes[2], bytes[3]]);
        let token = bytes[4..4 + token_len].to_vec();
        let mut last_number = 0u16;
        let mut options = Vec::new();
        let mut payload = Vec::new();

        // Consume the option region as a shrinking slice rather than with
        // index arithmetic: every iteration provably strips at least the
        // header byte, so a malformed message can only error, never stall.
        let mut rest = &bytes[4 + token_len..];
        while let Some((&first, after_header)) = rest.split_first() {
            if first == 0xff {
                payload.extend_from_slice(after_header);
                break;
            }
            let (delta, used_delta) = decode_extended_nibble(first >> 4, after_header)?;
            let after_delta = &after_header[used_delta..];
            let (length, used_len) = decode_extended_nibble(first & 0x0f, after_delta)?;
            let after_length = &after_delta[used_len..];
            if after_length.len() < length as usize {
                return Err(Error::Dataset("CoAP option value is truncated".to_string()));
            }
            last_number = last_number
                .checked_add(delta)
                .ok_or_else(|| Error::Dataset("CoAP option number overflow".to_string()))?;
            options.push(CoapOption {
                number: last_number,
                value: after_length[..length as usize].to_vec(),
            });
            rest = &after_length[length as usize..];
        }

        Ok(Self {
            ty,
            code,
            message_id,
            token,
            options,
            payload,
        })
    }

    /// Returns true for an empty acknowledgement matching `message_id`.
    pub fn is_empty_ack_for(&self, message_id: u16) -> bool {
        self.ty == CoapType::Acknowledgement
            && self.code == CoapCode::EMPTY
            && self.message_id == message_id
            && self.token.is_empty()
            && self.options.is_empty()
            && self.payload.is_empty()
    }
}
fn encode_option_header(delta: u16, length: usize, out: &mut Vec<u8>) -> Result<()> {
    let (delta_nibble, mut delta_extra) = encode_extended_nibble(delta)?;
    let (len_nibble, mut len_extra) = encode_extended_nibble(
        u16::try_from(length).map_err(|_| Error::Dataset("CoAP option too long".to_string()))?,
    )?;
    out.push((delta_nibble << 4) | len_nibble);
    out.append(&mut delta_extra);
    out.append(&mut len_extra);
    Ok(())
}

fn encode_extended_nibble(value: u16) -> Result<(u8, Vec<u8>)> {
    match value {
        0..=12 => Ok((value as u8, Vec::new())),
        13..=268 => Ok((13, vec![(value - 13) as u8])),
        269..=u16::MAX => {
            let adjusted = value - 269;
            Ok((14, adjusted.to_be_bytes().to_vec()))
        }
    }
}

fn decode_extended_nibble(nibble: u8, bytes: &[u8]) -> Result<(u16, usize)> {
    match nibble {
        0..=12 => Ok((nibble as u16, 0)),
        13 => bytes
            .first()
            .map(|byte| (*byte as u16 + 13, 1))
            .ok_or_else(|| Error::Dataset("CoAP option extension is truncated".to_string())),
        14 => {
            if bytes.len() < 2 {
                return Err(Error::Dataset(
                    "CoAP option extension is truncated".to_string(),
                ));
            }
            let value = u16::from_be_bytes([bytes[0], bytes[1]])
                .checked_add(269)
                .ok_or_else(|| Error::Dataset("CoAP option extension overflow".to_string()))?;
            Ok((value, 2))
        }
        _ => Err(Error::Dataset("reserved CoAP option nibble".to_string())),
    }
}
