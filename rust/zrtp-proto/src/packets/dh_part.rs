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
    IResult,
};

/// The DHPart packet is used to exchange Diffie-Hellman public values.
/// 
/// Defined in RFC 6189 Section 5.3.
#[derive(Debug, Clone)]
pub struct DHPartPacket {
    /// Common ZRTP header.
    pub header: ZrtpPacketHeader,
    /// The H1 hash value.
    pub hash_h1: [u8; 32],
    /// Retention Secret 1 ID.
    pub rs1_id: [u8; 8],
    /// Retention Secret 2 ID.
    pub rs2_id: [u8; 8],
    /// Auxiliary Secret ID.
    pub aux_secret_id: [u8; 8],
    /// PBX Secret ID.
    pub pbx_secret_id: [u8; 8],
    /// The DH public value.
    pub public_value: Vec<u8>,
    /// The HMAC of the packet.
    pub mac: [u8; 8],
}

impl DHPartPacket {
    /// The message type identifier for DHPart1 packets.
    pub const MESSAGE_TYPE_DH1: [u8; 8] = *b"DHPart1 ";
    /// The message type identifier for DHPart2 packets.
    pub const MESSAGE_TYPE_DH2: [u8; 8] = *b"DHPart2 ";

    /// Parses a DHPart packet from the given input bytes.
    pub fn parse(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, header) = ZrtpPacketHeader::parse(input)?;
        let (input, hash_h1_bytes) = take(32usize)(input)?;
        let (input, rs1_id_bytes) = take(8usize)(input)?;
        let (input, rs2_id_bytes) = take(8usize)(input)?;
        let (input, aux_secret_id_bytes) = take(8usize)(input)?;
        let (input, pbx_secret_id_bytes) = take(8usize)(input)?;

        let mut hash_h1 = [0u8; 32];
        hash_h1.copy_from_slice(hash_h1_bytes);

        let mut rs1_id = [0u8; 8];
        rs1_id.copy_from_slice(rs1_id_bytes);

        let mut rs2_id = [0u8; 8];
        rs2_id.copy_from_slice(rs2_id_bytes);

        let mut aux_secret_id = [0u8; 8];
        aux_secret_id.copy_from_slice(aux_secret_id_bytes);

        let mut pbx_secret_id = [0u8; 8];
        pbx_secret_id.copy_from_slice(pbx_secret_id_bytes);

        // Public value length: Total - Header(12) - H1(32) - 4IDs(32) - MAC(8) = Total - 84
        let pub_val_len = (header.length as usize * 4).saturating_sub(84);
        let (input, public_value_bytes) = take(pub_val_len)(input)?;
        
        let (input, mac_bytes) = take(8usize)(input)?;
        let mut mac = [0u8; 8];
        mac.copy_from_slice(mac_bytes);

        Ok((input, Self {
            header,
            hash_h1,
            rs1_id,
            rs2_id,
            aux_secret_id,
            pbx_secret_id,
            public_value: public_value_bytes.to_vec(),
            mac,
        }))
    }

    /// Serializes the DHPart packet into its byte representation.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = self.header.to_bytes();
        bytes.extend_from_slice(&self.hash_h1);
        bytes.extend_from_slice(&self.rs1_id);
        bytes.extend_from_slice(&self.rs2_id);
        bytes.extend_from_slice(&self.aux_secret_id);
        bytes.extend_from_slice(&self.pbx_secret_id);
        bytes.extend_from_slice(&self.public_value);
        bytes.extend_from_slice(&self.mac);
        bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dh_part_packet_codec() {
        let dh = DHPartPacket {
            header: ZrtpPacketHeader {
                zrtp_id: crate::packets::header::ZRTP_ID,
                length: 23, // 84 (fixed) + 8 (dummy pub) = 92 bytes / 4 = 23 words
                message_type: DHPartPacket::MESSAGE_TYPE_DH1,
            },
            hash_h1: [0x66; 32],
            rs1_id: [0x77; 8],
            rs2_id: [0x88; 8],
            aux_secret_id: [0x99; 8],
            pbx_secret_id: [0xAA; 8],
            public_value: vec![0xBB; 8],
            mac: [0xCC; 8],
        };
        
        let bytes = dh.to_bytes();
        let (rem, parsed) = DHPartPacket::parse(&bytes).unwrap();
        
        assert_eq!(rem.len(), 0);
        assert_eq!(parsed.hash_h1, dh.hash_h1);
        assert_eq!(parsed.public_value, dh.public_value);
        assert_eq!(parsed.mac, dh.mac);
    }
}
