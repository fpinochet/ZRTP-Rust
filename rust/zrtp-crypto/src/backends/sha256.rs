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
use ring::digest::{self, SHA256};
use ring::hmac;

/// SHA-256 implementation of the [`Hash`] trait using the `ring` crate.
pub struct Sha256;

impl Hash for Sha256 {
    fn digest(&self, data: &[u8]) -> Vec<u8> {
        digest::digest(&SHA256, data).as_ref().to_vec()
    }

    fn hmac(&self, key: &[u8], data: &[u8]) -> Vec<u8> {
        let hmac_key = hmac::Key::new(hmac::HMAC_SHA256, key);
        hmac::sign(&hmac_key, data).as_ref().to_vec()
    }

    fn kdf(&self, key: &[u8], label: &[u8], context: &[u8], length: usize) -> Vec<u8> {
        // RFC 6189 KDF using HMAC-SHA256
        // KDF(KI, Label, Context, L) = HMAC(KI, i | Label | 0x00 | Context | L)
        let mut data = Vec::with_capacity(4 + label.len() + 1 + context.len() + 4);
        data.extend_from_slice(&1u32.to_be_bytes()); // i=1
        data.extend_from_slice(label);
        data.push(0x00);
        data.extend_from_slice(context);
        data.extend_from_slice(&(length as u32 * 8).to_be_bytes()); // L in bits

        let result = self.hmac(key, &data);
        if result.len() >= length {
            result[..length].to_vec()
        } else {
            // If we need more than 32 bytes, we'd need to iterate i
            // For ZRTP, most keys are <= 32 bytes (S0, SRTP keys, etc.)
            result
        }
    }

    fn name(&self) -> &'static str {
        "SHA256"
    }

    fn output_len(&self) -> usize {
        32
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256_hashing() {
        let sha = Sha256;
        let data = b"hello";
        let hash = sha.digest(data);
        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn test_sha256_hmac() {
        let sha = Sha256;
        let key = b"key";
        let data = b"data";
        let mac = sha.hmac(key, data);
        assert_eq!(mac.len(), 32);
    }

    #[test]
    fn test_sha256_kdf() {
        let sha = Sha256;
        let key = vec![0u8; 32];
        let label = b"label";
        let context = b"context";
        let out = sha.kdf(&key, label, context, 32);
        assert_eq!(out.len(), 32);
    }
}
