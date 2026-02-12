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

use anyhow::Result;

/// Trait for cryptographic hash functions used in ZRTP.
/// 
/// Supported algorithms usually include SHA-256 (mandatory) and SHA-384.
pub trait Hash {
    /// Computes the message digest of the given data.
    fn digest(&self, data: &[u8]) -> Vec<u8>;
    /// Computes the HMAC of the given data using the provided key.
    fn hmac(&self, key: &[u8], data: &[u8]) -> Vec<u8>;
    /// Key Derivation Function as defined in RFC 6189 Section 4.5.
    fn kdf(&self, key: &[u8], label: &[u8], context: &[u8], length: usize) -> Vec<u8>;
    /// Returns the algorithm name (e.g., "SHA256").
    fn name(&self) -> &'static str;
    /// Returns the output length of the hash function in bytes.
    fn output_len(&self) -> usize;
}

/// Trait for Diffie-Hellman key agreement algorithms.
/// 
/// Supported algorithms may include DH-3072, X25519, and P-256.
pub trait DiffieHellman {
    /// Generates a new ephemeral keypair and returns the public key.
    fn generate_keypair(&mut self) -> Result<Vec<u8>>; 
    /// Computes the shared secret using our private key and the peer's public key.
    fn compute_shared_secret(&mut self, peer_public_key: &[u8]) -> Result<Vec<u8>>;
    /// Returns the algorithm name (e.g., "X255").
    fn name(&self) -> &'static str;
}

/// Trait for Post-Quantum Key Encapsulation Mechanisms (KEM).
/// 
/// Supported algorithms include ML-KEM-768 (Kyber).
pub trait KeyEncapsulation {
    /// Generates a keypair and returns the public key and private key.
    fn generate_keypair(&mut self) -> Result<(Vec<u8>, Vec<u8>)>;
    /// Encapsulates a shared secret using the peer's public key.
    /// Returns (ciphertext, shared_secret).
    fn encapsulate(&self, peer_public_key: &[u8]) -> Result<(Vec<u8>, Vec<u8>)>;
    /// Decapsulates the shared secret using our private key and the provided ciphertext.
    fn decapsulate(&self, private_key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>>;
    /// Returns the algorithm name (e.g., "KYB1").
    fn name(&self) -> &'static str;
    /// Returns the length of the public key in bytes.
    fn public_key_len(&self) -> usize;
    /// Returns the length of the ciphertext in bytes.
    fn ciphertext_len(&self) -> usize;
}

/// Trait for digital signatures, used for ephemeral key authentication.
/// 
/// Supported algorithms include Falcon-512.
pub trait Signature {
    /// Generates a signing keypair.
    fn generate_keypair(&mut self) -> Result<(Vec<u8>, Vec<u8>)>;
    /// Signs the given data using the private key.
    fn sign(&self, private_key: &[u8], data: &[u8]) -> Result<Vec<u8>>;
    /// Verifies the signature of the data using the public key.
    fn verify(&self, public_key: &[u8], data: &[u8], signature: &[u8]) -> Result<()>;
    /// Returns the algorithm name (e.g., "FAL5").
    fn name(&self) -> &'static str;
    /// Returns the signature length in bytes.
    fn signature_len(&self) -> usize;
}

/// Trait for symmetric encryption ciphers used for Confirm packets.
pub trait Cipher {
    /// Encrypts the plaintext using the given key and IV.
    fn encrypt(&self, key: &[u8], iv: &[u8], plaintext: &[u8]) -> Result<Vec<u8>>;
    /// Decrypts the ciphertext using the given key and IV.
    fn decrypt(&self, key: &[u8], iv: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>>;
    /// Returns the required key length in bytes.
    fn key_len(&self) -> usize;
    /// Returns the required IV length in bytes.
    fn iv_len(&self) -> usize;
}
