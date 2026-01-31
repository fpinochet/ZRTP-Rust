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

use super::header::ZrtpPacketHeader;
use nom::{
    bytes::complete::take,
    number::complete::be_u32,
    IResult,
};

/// The GoClear packet is used to switch back to unencrypted mode.
/// 
/// Defined in RFC 6189 Section 5.5.
#[derive(Debug, Clone)]
pub struct GoClearPacket {
    /// Common ZRTP header.
    pub header: ZrtpPacketHeader,
    /// HMAC protecting the GoClear request.
    pub clear_hmac: [u8; 8],
}

impl GoClearPacket {
    /// The message type identifier for GoClear packets.
    pub const MESSAGE_TYPE: [u8; 8] = *b"GoClear ";

    /// Parses a GoClear packet from the given input bytes.
    pub fn parse(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, header) = ZrtpPacketHeader::parse(input)?;
        let (input, clear_hmac_bytes) = take(8usize)(input)?;
        let mut clear_hmac = [0u8; 8];
        clear_hmac.copy_from_slice(clear_hmac_bytes);
        Ok((input, Self { header, clear_hmac }))
    }

    /// Serializes the GoClear packet into its byte representation.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = self.header.to_bytes();
        bytes.extend_from_slice(&self.clear_hmac);
        bytes
    }
}

/// The Error packet is sent when a protocol error occurs.
/// 
/// Defined in RFC 6189 Section 5.9.
#[derive(Debug, Clone)]
pub struct ErrorPacket {
    /// Common ZRTP header.
    pub header: ZrtpPacketHeader,
    /// The error code as defined in RFC 6189 Section 5.9.1.
    pub error_code: u32,
}

impl ErrorPacket {
    /// The message type identifier for Error packets.
    pub const MESSAGE_TYPE: [u8; 8] = *b"Error   ";

    /// Parses an Error packet from the given input bytes.
    pub fn parse(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, header) = ZrtpPacketHeader::parse(input)?;
        let (input, error_code) = be_u32(input)?;
        Ok((input, Self { header, error_code }))
    }

    /// Serializes the Error packet into its byte representation.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = self.header.to_bytes();
        bytes.extend_from_slice(&self.error_code.to_be_bytes());
        bytes
    }
}

/// The Generic Ack packet is used to acknowledge receipt of certain packets (e.g., Hello).
/// 
/// Defined in RFC 6189 Section 5.10.
#[derive(Debug, Clone)]
pub struct GenericAckPacket {
    /// Common ZRTP header.
    pub header: ZrtpPacketHeader,
}

impl GenericAckPacket {
    /// The message type identifier for HelloAck packets.
    pub const MESSAGE_TYPE_HELLO_ACK: [u8; 8] = *b"HelloAck";
    /// The message type identifier for CommitAck packets.
    pub const MESSAGE_TYPE_COMMIT_ACK: [u8; 8] = *b"CommitAk";
    /// The message type identifier for Conf2Ack packets.
    pub const MESSAGE_TYPE_CONF2_ACK: [u8; 8] = *b"Conf2Ack";

    /// Parses a Generic Ack packet from the given input bytes.
    pub fn parse(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, header) = ZrtpPacketHeader::parse(input)?;
        Ok((input, Self { header }))
    }

    /// Serializes the Generic Ack packet into its byte representation.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.header.to_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_goclear_packet_codec() {
        let goclear = GoClearPacket {
            header: ZrtpPacketHeader {
                zrtp_id: crate::packets::header::ZRTP_ID,
                length: 4,
                message_type: GoClearPacket::MESSAGE_TYPE,
            },
            clear_hmac: [0xEE; 8],
        };
        
        let bytes = goclear.to_bytes();
        let (rem, parsed) = GoClearPacket::parse(&bytes).unwrap();
        
        assert_eq!(rem.len(), 0);
        assert_eq!(parsed.clear_hmac, goclear.clear_hmac);
    }

    #[test]
    fn test_error_packet_codec() {
        let error = ErrorPacket {
            header: ZrtpPacketHeader {
                zrtp_id: crate::packets::header::ZRTP_ID,
                length: 4,
                message_type: ErrorPacket::MESSAGE_TYPE,
            },
            error_code: 0xDeadBeef,
        };
        
        let bytes = error.to_bytes();
        let (rem, parsed) = ErrorPacket::parse(&bytes).unwrap();
        
        assert_eq!(rem.len(), 0);
        assert_eq!(parsed.error_code, error.error_code);
    }

    #[test]
    fn test_ack_packet_codec() {
        let ack = GenericAckPacket {
            header: ZrtpPacketHeader {
                zrtp_id: crate::packets::header::ZRTP_ID,
                length: 3,
                message_type: GenericAckPacket::MESSAGE_TYPE_HELLO_ACK,
            },
        };
        
        let bytes = ack.to_bytes();
        let (rem, parsed) = GenericAckPacket::parse(&bytes).unwrap();
        
        assert_eq!(rem.len(), 0);
        assert_eq!(parsed.header.message_type, GenericAckPacket::MESSAGE_TYPE_HELLO_ACK);
    }
}
