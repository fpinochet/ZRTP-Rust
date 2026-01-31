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

use crate::traits::Cipher;
use anyhow::{Result, anyhow};
use aes::Aes128;
use cfb_mode::cipher::{AsyncStreamCipher, KeyIvInit};

/// AES-CFB implementation of the [`Cipher`] trait for ZRTP.
pub struct AesCfb128;

type Aes128CfbEnc = cfb_mode::Encryptor<Aes128>;
type Aes128CfbDec = cfb_mode::Decryptor<Aes128>;

impl Cipher for AesCfb128 {
    fn encrypt(&self, key: &[u8], iv: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
        if key.len() != 16 || iv.len() != 16 {
            return Err(anyhow!("Invalid key or IV length for AES-128"));
        }
        let cipher = Aes128CfbEnc::new_from_slices(key, iv)
            .map_err(|e| anyhow!("Cipher error: {}", e))?;
        let mut buffer = plaintext.to_vec();
        cipher.encrypt(&mut buffer);
        Ok(buffer)
    }

    fn decrypt(&self, key: &[u8], iv: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
        if key.len() != 16 || iv.len() != 16 {
            return Err(anyhow!("Invalid key or IV length for AES-128"));
        }
        let cipher = Aes128CfbDec::new_from_slices(key, iv)
            .map_err(|e| anyhow!("Cipher error: {}", e))?;
        let mut buffer = ciphertext.to_vec();
        cipher.decrypt(&mut buffer);
        Ok(buffer)
    }

    fn key_len(&self) -> usize { 16 }
    fn iv_len(&self) -> usize { 16 }
}
