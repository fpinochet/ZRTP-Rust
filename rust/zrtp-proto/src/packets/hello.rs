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

/// The Hello packet is used in the discovery phase to find peer capabilities.
/// 
/// Defined in RFC 6189 Section 5.1.
#[derive(Debug, Clone)]
pub struct HelloPacket {
    /// Common ZRTP header.
    pub header: ZrtpPacketHeader,
    /// The ZRTP protocol version supported.
    pub version: [u8; 4],
    /// Client identifier string.
    pub client_id: [u8; 16],
    /// The H3 hash value for the multi-stream mode.
    pub hash_h3: [u8; 32],
    /// The ZID of the endpoint.
    pub zid: [u8; 12],
    /// Algorithm flags and other options.
    pub flags: u8,
    
    // Algorithm counts
    pub num_hash: u8,
    pub num_cipher: u8,
    pub num_auth: u8,
    pub num_key_agreement: u8,
    pub num_sas: u8,

    /// Lists of algorithms (identifiers like b"S256", b"AES1", etc.)
    pub algs: Vec<u8>,
    
    /// The HMAC of the packet.
    pub hmac: [u8; 8],
}

impl HelloPacket {
    /// The message type identifier for Hello packets.
    pub const MESSAGE_TYPE: [u8; 8] = *b"Hello   ";

    /// Parses a Hello packet from the given input bytes.
    pub fn parse(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, header) = ZrtpPacketHeader::parse(input)?;
        let (input, version_bytes) = take(4usize)(input)?;
        let (input, client_id_bytes) = take(16usize)(input)?;
        let (input, hash_h3_bytes) = take(32usize)(input)?;
        let (input, zid_bytes) = take(12usize)(input)?;
        let (input, flags) = take(1usize)(input)?;
        
        let (input, counts) = take(3usize)(input)?;
        let num_hash = (counts[0] >> 4) & 0x0F;
        let num_cipher = counts[0] & 0x0F;
        let num_auth = (counts[1] >> 4) & 0x0F;
        let num_key_agreement = counts[1] & 0x0F;
        let num_sas = (counts[2] >> 4) & 0x0F;

        // Total algorithms = num_hash + num_cipher + num_auth + num_key_agreement + num_sas
        let total_algs = (num_hash + num_cipher + num_auth + num_key_agreement + num_sas) as usize;
        let (input, algs_bytes) = take(total_algs * 4)(input)?;
        
        let (input, hmac_bytes) = take(8usize)(input)?;

        let mut version = [0u8; 4];
        version.copy_from_slice(version_bytes);
        let mut client_id = [0u8; 16];
        client_id.copy_from_slice(client_id_bytes);
        let mut hash_h3 = [0u8; 32];
        hash_h3.copy_from_slice(hash_h3_bytes);
        let mut zid = [0u8; 12];
        zid.copy_from_slice(zid_bytes);
        let mut hmac = [0u8; 8];
        hmac.copy_from_slice(hmac_bytes);

        Ok((input, Self {
            header,
            version,
            client_id,
            hash_h3,
            zid,
            flags: flags[0],
            num_hash,
            num_cipher,
            num_auth,
            num_key_agreement,
            num_sas,
            algs: algs_bytes.to_vec(),
            hmac,
        }))
    }

    /// Serializes the Hello packet into its byte representation.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = self.header.to_bytes();
        bytes.extend_from_slice(&self.version);
        bytes.extend_from_slice(&self.client_id);
        bytes.extend_from_slice(&self.hash_h3);
        bytes.extend_from_slice(&self.zid);
        bytes.push(self.flags);
        
        bytes.push((self.num_hash << 4) | (self.num_cipher & 0x0F));
        bytes.push((self.num_auth << 4) | (self.num_key_agreement & 0x0F));
        bytes.push((self.num_sas << 4)); // and 4 bits reserved

        bytes.extend_from_slice(&self.algs);
        bytes.extend_from_slice(&self.hmac);
        bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hello_packet_codec() {
        let mut client_id = [0u8; 16];
        client_id[..16].copy_from_slice(b"ZRTP-Rust-Tester");

        let hello = HelloPacket {
            header: ZrtpPacketHeader {
                zrtp_id: crate::packets::header::ZRTP_ID,
                length: 27,
                message_type: HelloPacket::MESSAGE_TYPE,
            },
            version: *b"1.10",
            client_id,
            hash_h3: [0u8; 32],
            zid: [0x11; 12],
            flags: 0,
            num_hash: 1,
            num_cipher: 1,
            num_auth: 1,
            num_key_agreement: 1,
            num_sas: 1,
            algs: vec![
                b'S', b'2', b'5', b'6',
                b'A', b'E', b'S', b'1',
                b'H', b'S', b'3', b'2',
                b'X', b'2', b'5', b'5',
                b'B', b'3', b'2', b' ',
            ],
            hmac: [0xAA; 8],
        };
        
        // Adjust length: 12 (hdr) + 4 (ver) + 16 (cid) + 32 (h3) + 12 (zid) + 1 (flags) + 3 (counts) + 20 (algs) + 8 (hmac) = 108 bytes
        // 108 / 4 = 27 words.
        
        let bytes = hello.to_bytes();
        let (rem, parsed) = HelloPacket::parse(&bytes).unwrap();
        
        assert_eq!(rem.len(), 0);
        assert_eq!(parsed.header.zrtp_id, crate::packets::header::ZRTP_ID);
        assert_eq!(parsed.zid, hello.zid);
        assert_eq!(parsed.version, hello.version);
        assert_eq!(parsed.algs, hello.algs);
        assert_eq!(parsed.hmac, hello.hmac);
    }
}
