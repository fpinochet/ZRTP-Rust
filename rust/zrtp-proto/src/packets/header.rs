/*
 * Copyright 2006 - 2018, Werner Dittmann
 * Copyright 2026 - Francisco F. Pinochet
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

use nom::{
    bytes::complete::take,
    number::complete::be_u16,
    IResult,
};

/// The ZRTP Magic number as defined in RFC 6189.
pub const ZRTP_MAGIC: u32 = 0x5a525450;

/// The ZRTP ID (first 16 bits of the header).
pub const ZRTP_ID: u16 = 0x505a;

/// The common ZRTP packet header structure.
/// 
/// Every ZRTP packet starts with this 12-byte header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZrtpPacketHeader {
    /// Must be equal to ZRTP_ID (0x505a).
    pub zrtp_id: u16,
    /// The length of the packet in 32-bit words, including the header.
    pub length: u16,
    /// The 8-character message type string (e.g., "Hello   ").
    pub message_type: [u8; 8],
}

impl ZrtpPacketHeader {
    /// Parses a ZRTP packet header from the given input bytes.
    pub fn parse(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, zrtp_id) = be_u16(input)?;
        let (input, length) = be_u16(input)?;
        let (input, msg_type_bytes) = take(8usize)(input)?;
        
        let mut message_type = [0u8; 8];
        message_type.copy_from_slice(msg_type_bytes);

        Ok((input, Self {
            zrtp_id,
            length,
            message_type,
        }))
    }

    /// Serializes the ZRTP packet header into its byte representation.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(12);
        bytes.extend_from_slice(&self.zrtp_id.to_be_bytes());
        bytes.extend_from_slice(&self.length.to_be_bytes());
        bytes.extend_from_slice(&self.message_type);
        bytes
    }
}
