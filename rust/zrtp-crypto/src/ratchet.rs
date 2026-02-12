/*
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

/// A symmetric ratchet for continuous forward secrecy.
/// 
/// This structure implements a one-way chain of cryptographic keys
/// using HMAC-SHA256. Each step produces a new message key and 
/// updates the internal chain key, ensuring that even if a message 
/// key is compromised, future keys remain secured.
pub struct ZrtpRatchet {
    chain_key: Vec<u8>,
}

impl ZrtpRatchet {
    /// Label used for ratcheting the chain key.
    const LABEL_RATCHET_CHAIN: &'static [u8] = b"ratchet chain";
    /// Label used for deriving the message key.
    const LABEL_RATCHET_MSG: &'static [u8] = b"ratchet msg";

    /// Creates a new ratchet initialized with the given root key.
    pub fn new(root_key: Vec<u8>) -> Self {
        Self {
            chain_key: root_key,
        }
    }

    /// Advances the ratchet and returns the next message key.
    /// 
    /// This method performs two HMAC operations:
    /// 1. Updates the chain key: CK_{n+1} = HMAC(CK_n, "ratchet chain")
    /// 2. Derives the message key: MK_{n+1} = HMAC(CK_{n+1}, "ratchet msg")
    /// 
    /// The security rationale is that MK cannot be used to find CK or MK-1.
    pub fn next_key(&mut self, hash: &dyn Hash) -> Vec<u8> {
        // Step 1: Advance the chain key
        self.chain_key = hash.hmac(&self.chain_key, Self::LABEL_RATCHET_CHAIN);
        
        // Step 2: Derive the message key from the new chain key
        hash.hmac(&self.chain_key, Self::LABEL_RATCHET_MSG)
    }

    /// Resets the ratchet with a new root key (e.g., after a new DH exchange).
    pub fn reset(&mut self, new_root_key: Vec<u8>) {
        self.chain_key = new_root_key;
    }

    /// Returns a copy of the current chain key (for persistence/debugging).
    pub fn chain_key(&self) -> &[u8] {
        &self.chain_key
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backends::Sha256;

    #[test]
    fn test_ratchet_progression() {
        let hash = Sha256;
        let root_key = vec![0x42; 32];
        let mut ratchet = ZrtpRatchet::new(root_key.clone());

        let key1 = ratchet.next_key(&hash);
        let key2 = ratchet.next_key(&hash);

        assert_ne!(key1, key2);
        assert_ne!(key1, root_key);
        assert_eq!(key1.len(), 32);
        assert_eq!(key2.len(), 32);
    }

    #[test]
    fn test_ratchet_determinism() {
        let hash = Sha256;
        let root_key = vec![0x42; 32];
        
        let mut ratchet1 = ZrtpRatchet::new(root_key.clone());
        let mut ratchet2 = ZrtpRatchet::new(root_key.clone());

        assert_eq!(ratchet1.next_key(&hash), ratchet2.next_key(&hash));
        assert_eq!(ratchet1.next_key(&hash), ratchet2.next_key(&hash));
    }
}
