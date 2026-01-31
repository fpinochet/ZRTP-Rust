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
    /// Numbers of algorithms supported (Hash, Cipher, Auth, KeyAgreement, SAS).
    pub alg_counts: [u8; 3], // num_hash, num_cipher, num_auth (roughly)
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
        let (input, alg_counts_bytes) = take(3usize)(input)?;

        let mut version = [0u8; 4];
        version.copy_from_slice(version_bytes);

        let mut client_id = [0u8; 16];
        client_id.copy_from_slice(client_id_bytes);

        let mut hash_h3 = [0u8; 32];
        hash_h3.copy_from_slice(hash_h3_bytes);

        let mut zid = [0u8; 12];
        zid.copy_from_slice(zid_bytes);

        let mut alg_counts = [0u8; 3];
        alg_counts.copy_from_slice(alg_counts_bytes);

        Ok((input, Self {
            header,
            version,
            client_id,
            hash_h3,
            zid,
            flags: flags[0],
            alg_counts,
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
        bytes.extend_from_slice(&self.alg_counts);
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
            alg_counts: [0x01, 0x01, 0x01],
        };
        
        let bytes = hello.to_bytes();
        let (rem, parsed) = HelloPacket::parse(&bytes).unwrap();
        
        assert_eq!(rem.len(), 0);
        assert_eq!(parsed.header.zrtp_id, crate::packets::header::ZRTP_ID);
        assert_eq!(parsed.zid, hello.zid);
        assert_eq!(parsed.version, hello.version);
    }
}
