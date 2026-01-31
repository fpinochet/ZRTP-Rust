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

/// The Confirm packet is used to confirm the keys and state.
/// 
/// Defined in RFC 6189 Section 5.4.
#[derive(Debug, Clone)]
pub struct ConfirmPacket {
    /// Common ZRTP header.
    pub header: ZrtpPacketHeader,
    /// HMAC of the packet, protecting its integrity.
    pub hmac: [u8; 8],
    /// Initialization Vector for the encrypted part.
    pub iv: [u8; 16],
    /// The H0 hash value.
    pub hash_h0: [u8; 32],
    /// Unused filler bytes.
    pub filler: [u8; 2],
    /// Length of the signature, if present.
    pub sig_length: u8,
    /// Flags (e.g., SAS verified).
    pub flags: u8,
    /// Cache expiration time.
    pub exp_time: u32,
}

impl ConfirmPacket {
    /// The message type identifier for Confirm1 packets.
    pub const MESSAGE_TYPE_CONF1: [u8; 8] = *b"Confirm1";
    /// The message type identifier for Confirm2 packets.
    pub const MESSAGE_TYPE_CONF2: [u8; 8] = *b"Confirm2";

    /// Parses a Confirm packet from the given input bytes.
    pub fn parse(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, header) = ZrtpPacketHeader::parse(input)?;
        let (input, hmac_bytes) = take(8usize)(input)?;
        let (input, iv_bytes) = take(16usize)(input)?;
        let (input, hash_h0_bytes) = take(32usize)(input)?;
        let (input, filler_bytes) = take(2usize)(input)?;
        let (input, sig_length_bytes) = take(1usize)(input)?;
        let (input, flags_bytes) = take(1usize)(input)?;
        let (input, exp_time) = be_u32(input)?;

        let mut hmac = [0u8; 8];
        hmac.copy_from_slice(hmac_bytes);

        let mut iv = [0u8; 16];
        iv.copy_from_slice(iv_bytes);

        let mut hash_h0 = [0u8; 32];
        hash_h0.copy_from_slice(hash_h0_bytes);

        let mut filler = [0u8; 2];
        filler.copy_from_slice(filler_bytes);

        Ok((input, Self {
            header,
            hmac,
            iv,
            hash_h0,
            filler,
            sig_length: sig_length_bytes[0],
            flags: flags_bytes[0],
            exp_time,
        }))
    }

    /// Serializes the Confirm packet into its byte representation.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = self.header.to_bytes();
        bytes.extend_from_slice(&self.hmac);
        bytes.extend_from_slice(&self.iv);
        bytes.extend_from_slice(&self.hash_h0);
        bytes.extend_from_slice(&self.filler);
        bytes.push(self.sig_length);
        bytes.push(self.flags);
        bytes.extend_from_slice(&self.exp_time.to_be_bytes());
        bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_confirm_packet_codec() {
        let confirm = ConfirmPacket {
            header: ZrtpPacketHeader {
                zrtp_id: crate::packets::header::ZRTP_ID,
                length: 19,
                message_type: ConfirmPacket::MESSAGE_TYPE_CONF1,
            },
            hmac: [0xBB; 8],
            iv: [0xCC; 16],
            hash_h0: [0xDD; 32],
            filler: [0x00; 2],
            sig_length: 0,
            flags: 0x01,
            exp_time: 0x12345678,
        };
        
        let bytes = confirm.to_bytes();
        let (rem, parsed) = ConfirmPacket::parse(&bytes).unwrap();
        
        assert_eq!(rem.len(), 0);
        assert_eq!(parsed.hmac, confirm.hmac);
        assert_eq!(parsed.hash_h0, confirm.hash_h0);
        assert_eq!(parsed.exp_time, confirm.exp_time);
    }
}
