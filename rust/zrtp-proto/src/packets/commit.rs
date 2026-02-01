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

/// The Commit packet is used to negotiate cryptographic algorithms.
/// 
/// Defined in RFC 6189 Section 5.2.
#[derive(Debug, Clone)]
pub struct CommitPacket {
    /// Common ZRTP header.
    pub header: ZrtpPacketHeader,
    /// The H2 hash value.
    pub hash_h2: [u8; 32],
    /// The ZID of the endpoint.
    pub zid: [u8; 12],
    /// Selected hash algorithm (e.g., "S256").
    pub hash_alg: [u8; 4],
    /// Selected cipher algorithm (e.g., "AES1").
    pub cipher_alg: [u8; 4],
    /// Selected auth tag algorithm (e.g., "HS32").
    pub auth_tag_alg: [u8; 4],
    /// Selected key agreement algorithm (e.g., "DH3k").
    pub key_agreement_alg: [u8; 4],
    /// Selected SAS algorithm (e.g., "B32 ").
    pub sas_alg: [u8; 4],
    /// Hashing Value Initiator.
    pub hvi: [u8; 32],
    /// Message Authentication Code for the Commit packet.
    pub mac: [u8; 8],
}

impl CommitPacket {
    /// The message type identifier for Commit packets.
    pub const MESSAGE_TYPE: [u8; 8] = *b"Commit  ";

    /// Parses a Commit packet from the given input bytes.
    pub fn parse(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, header) = ZrtpPacketHeader::parse(input)?;
        let (input, hash_h2_bytes) = take(32usize)(input)?;
        let (input, zid_bytes) = take(12usize)(input)?;
        let (input, hash_alg_bytes) = take(4usize)(input)?;
        let (input, cipher_alg_bytes) = take(4usize)(input)?;
        let (input, auth_tag_alg_bytes) = take(4usize)(input)?;
        let (input, key_agreement_alg_bytes) = take(4usize)(input)?;
        let (input, sas_alg_bytes) = take(4usize)(input)?;
        let (input, hvi_bytes) = take(32usize)(input)?;
        let (input, mac_bytes) = take(8usize)(input)?;

        let mut hash_h2 = [0u8; 32];
        hash_h2.copy_from_slice(hash_h2_bytes);

        let mut zid = [0u8; 12];
        zid.copy_from_slice(zid_bytes);

        let mut hash_alg = [0u8; 4];
        hash_alg.copy_from_slice(hash_alg_bytes);

        let mut cipher_alg = [0u8; 4];
        cipher_alg.copy_from_slice(cipher_alg_bytes);

        let mut auth_tag_alg = [0u8; 4];
        auth_tag_alg.copy_from_slice(auth_tag_alg_bytes);

        let mut key_agreement_alg = [0u8; 4];
        key_agreement_alg.copy_from_slice(key_agreement_alg_bytes);

        let mut sas_alg = [0u8; 4];
        sas_alg.copy_from_slice(sas_alg_bytes);

        let mut hvi = [0u8; 32];
        hvi.copy_from_slice(hvi_bytes);

        let mut mac = [0u8; 8];
        mac.copy_from_slice(mac_bytes);

        Ok((input, Self {
            header,
            hash_h2,
            zid,
            hash_alg,
            cipher_alg,
            auth_tag_alg,
            key_agreement_alg,
            sas_alg,
            hvi,
            mac,
        }))
    }

    /// Serializes the Commit packet into its byte representation.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = self.header.to_bytes();
        bytes.extend_from_slice(&self.hash_h2);
        bytes.extend_from_slice(&self.zid);
        bytes.extend_from_slice(&self.hash_alg);
        bytes.extend_from_slice(&self.cipher_alg);
        bytes.extend_from_slice(&self.auth_tag_alg);
        bytes.extend_from_slice(&self.key_agreement_alg);
        bytes.extend_from_slice(&self.sas_alg);
        bytes.extend_from_slice(&self.hvi);
        bytes.extend_from_slice(&self.mac);
        bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_commit_packet_codec() {
        let commit = CommitPacket {
            header: ZrtpPacketHeader {
                zrtp_id: crate::packets::header::ZRTP_ID,
                length: 29,
                message_type: CommitPacket::MESSAGE_TYPE,
            },
            hash_h2: [0x22; 32],
            zid: [0x33; 12],
            hash_alg: *b"S256",
            cipher_alg: *b"AES1",
            auth_tag_alg: *b"HS32",
            key_agreement_alg: *b"X255",
            sas_alg: *b"B32 ",
            hvi: [0x44; 32],
            mac: [0x55; 8],
        };
        
        let bytes = commit.to_bytes();
        let (rem, parsed) = CommitPacket::parse(&bytes).unwrap();
        
        assert_eq!(rem.len(), 0);
        assert_eq!(parsed.zid, commit.zid);
        assert_eq!(parsed.hash_alg, commit.hash_alg);
        assert_eq!(parsed.hvi, commit.hvi);
    }
}
