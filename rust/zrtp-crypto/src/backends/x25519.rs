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

use crate::traits::DiffieHellman;
use anyhow::{Result, anyhow};
use x25519_dalek::{EphemeralSecret, PublicKey};
use rand_core::OsRng;

/// X25519 implementation of the [`DiffieHellman`] trait using the `x25519-dalek` crate.
/// 
/// Note: ZRTP manages public key exchange and shared secret computation at different 
/// protocol stages.
#[derive(Default)]
pub struct X25519 {
    secret: Option<EphemeralSecret>,
}

impl DiffieHellman for X25519 {
    fn generate_keypair(&mut self) -> Result<Vec<u8>> {
        let secret = EphemeralSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);
        self.secret = Some(secret);
        Ok(public.as_bytes().to_vec())
    }

    fn compute_shared_secret(&mut self, peer_public_key: &[u8]) -> Result<Vec<u8>> {
        let secret = self.secret.take().ok_or_else(|| anyhow!("Keypair not generated"))?;
        let peer_pub_bytes: [u8; 32] = peer_public_key.try_into()
            .map_err(|_| anyhow!("Invalid public key length"))?;
        let peer_pub = PublicKey::from(peer_pub_bytes);
        
        let shared_secret = secret.diffie_hellman(&peer_pub);
        Ok(shared_secret.as_bytes().to_vec())
    }

    fn name(&self) -> &'static str {
        "X25519"
    }
}
