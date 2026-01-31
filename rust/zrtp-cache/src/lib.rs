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

use std::collections::HashMap;

/// Trait for ZID cache (retained secret storage).
/// 
/// The cache persists secrets across sessions to prevent man-in-the-middle attacks.
pub trait ZidCache {
    /// Stores a secret for a given peer ZID.
    fn get_secret(&self, zid: &[u8; 12], name: &str) -> Option<Vec<u8>>;
    /// Retrieves a secret for a given peer ZID.
    fn store_secret(&mut self, zid: &[u8; 12], name: &str, secret: &[u8]);
}

/// A simple in-memory implementation of the [`ZidCache`] trait.
/// 
/// Note: This implementation does not persist data to disk.
pub struct InMemoryCache {
    cache: HashMap<([u8; 12], String), Vec<u8>>,
}

impl InMemoryCache {
    /// Creates a new, empty in-memory cache.
    pub fn new() -> Self {
        Self {
            cache: HashMap::new(),
        }
    }
}

impl ZidCache for InMemoryCache {
    fn get_secret(&self, zid: &[u8; 12], name: &str) -> Option<Vec<u8>> {
        self.cache.get(&(*zid, name.to_string())).cloned()
    }

    fn store_secret(&mut self, zid: &[u8; 12], name: &str, secret: &[u8]) {
        self.cache.insert((*zid, name.to_string()), secret.to_vec());
    }
}
