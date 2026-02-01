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

use crate::traits::Hash;
use anyhow::Result;

/// A structure holding all derived keys for a ZRTP session.
pub struct ZrtpKeys {
    /// SRTP master key for initiator.
    pub srtp_key_i: Vec<u8>,
    /// SRTP master salt for initiator.
    pub srtp_salt_i: Vec<u8>,
    /// SRTP master key for responder.
    pub srtp_key_r: Vec<u8>,
    /// SRTP master salt for responder.
    pub srtp_salt_r: Vec<u8>,
    /// HMAC key used for Confirm packets by initiator.
    pub confirm_key_i: Vec<u8>,
    /// HMAC key used for Confirm packets by responder.
    pub confirm_key_r: Vec<u8>,
    /// Hash of the SAS (Short Authentication String).
    pub sas_hash: Vec<u8>,
    /// ZRTP session key.
    pub zrtp_session: Vec<u8>,
    /// Exported key for application use.
    pub exported_key: Vec<u8>,
    /// New retained secret RS1.
    pub new_rs1: Vec<u8>,
}

/// Derives the S0 intermediate secret as defined in RFC 6189 Section 4.4.1.
/// 
/// S0 = hash(1 | DHResult | "ZRTP-KDF" | ZIDi | ZIDr | total_hash | len(s1) | s1 | len(s2) | s2 | len(s3) | s3)
pub fn derive_s0(
    hash: &dyn Hash,
    dh_result: &[u8],
    zrtp_kdf_str: &[u8],
    zid_i: &[u8; 12],
    zid_r: &[u8; 12],
    total_hash: &[u8],
    s1: Option<&[u8]>,
    s2: Option<&[u8]>,
    s3: Option<&[u8]>,
) -> Vec<u8> {
    let mut data = Vec::new();
    
    // counter = 1
    data.extend_from_slice(&1u32.to_be_bytes());
    data.extend_from_slice(dh_result);
    data.extend_from_slice(zrtp_kdf_str);
    data.extend_from_slice(zid_i);
    data.extend_from_slice(zid_r);
    data.extend_from_slice(total_hash);
    
    for s in &[s1, s2, s3] {
        if let Some(secret) = s {
            data.extend_from_slice(&(secret.len() as u32).to_be_bytes());
            data.extend_from_slice(secret);
        } else {
            data.extend_from_slice(&0u32.to_be_bytes());
        }
    }
    
    hash.digest(&data)
}

/// Derives all session keys from S0 as defined in RFC 6189 Section 4.5.1.
pub fn derive_session_keys(
    hash: &dyn Hash,
    s0: &[u8],
    zid_i: &[u8; 12],
    zid_r: &[u8; 12],
    total_hash: &[u8],
    key_len: usize,
) -> Result<ZrtpKeys> {
    let mut context = Vec::new();
    context.extend_from_slice(zid_i);
    context.extend_from_slice(zid_r);
    context.extend_from_slice(total_hash);
    
    let srtp_key_i = hash.kdf(s0, b"Initiator SRTP master key", &context, key_len);
    let srtp_salt_i = hash.kdf(s0, b"Initiator SRTP master salt", &context, 14);
    
    let srtp_key_r = hash.kdf(s0, b"Responder SRTP master key", &context, key_len);
    let srtp_salt_r = hash.kdf(s0, b"Responder SRTP master salt", &context, 14);
    
    let confirm_key_i = hash.kdf(s0, b"Initiator ZRTP key", &context, key_len);
    let confirm_key_r = hash.kdf(s0, b"Responder ZRTP key", &context, key_len);
    
    let sas_hash = hash.kdf(s0, b"SAS", &context, 32);
    let zrtp_session = hash.kdf(s0, b"ZRTP session key", &context, 32);
    let exported_key = hash.kdf(s0, b"Exported key", &context, 32);
    let new_rs1 = hash.kdf(s0, b"retained secret", &context, 32);
    
    Ok(ZrtpKeys {
        srtp_key_i,
        srtp_salt_i,
        srtp_key_r,
        srtp_salt_r,
        confirm_key_i,
        confirm_key_r,
        sas_hash,
        zrtp_session,
        exported_key,
        new_rs1,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backends::Sha256;

    #[test]
    fn test_s0_derivation() {
        let hash = Sha256;
        let dh_result = vec![0xAA; 32];
        let zid_i = [0x11; 12];
        let zid_r = [0x22; 12];
        let total_hash = vec![0x33; 32];
        
        let s0 = derive_s0(
            &hash,
            &dh_result,
            b"ZRTP-HMAC-KDF",
            &zid_i,
            &zid_r,
            &total_hash,
            None, None, None
        );
        assert_eq!(s0.len(), 32);
    }
}
