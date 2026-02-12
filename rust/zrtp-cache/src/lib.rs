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
use std::fs::{File, OpenOptions};
use std::io::{Read, Write, Seek, SeekFrom};
use rusqlite::params;

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
#[derive(Debug, Clone, Default)]
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

/// A persistent implementation of the [`ZidCache`] trait using SQLite.
pub struct SqliteCache {
    conn: rusqlite::Connection,
}

impl SqliteCache {
    /// Creates a new SQLite cache at the given path.
    pub fn new<P: AsRef<std::path::Path>>(path: P) -> anyhow::Result<Self> {
        let conn = rusqlite::Connection::open(path)?;
        conn.execute(
            "CREATE TABLE IF NOT EXISTS zrtp_cache (
                zid BLOB NOT NULL,
                name TEXT NOT NULL,
                value BLOB NOT NULL,
                PRIMARY KEY (zid, name)
            )",
            [],
        )?;
        Ok(Self { conn })
    }
}

impl ZidCache for SqliteCache {
    fn get_secret(&self, zid: &[u8; 12], name: &str) -> Option<Vec<u8>> {
        let mut stmt = self.conn.prepare("SELECT value FROM zrtp_cache WHERE zid = ? AND name = ?").ok()?;
        let res: Vec<u8> = stmt.query_row(params![zid.as_slice(), name], |row| row.get(0)).ok()?;
        Some(res)
    }

    fn store_secret(&mut self, zid: &[u8; 12], name: &str, secret: &[u8]) {
        let _ = self.conn.execute(
            "INSERT OR REPLACE INTO zrtp_cache (zid, name, value) VALUES (?, ?, ?)",
            params![zid.as_slice(), name, secret],
        );
    }
}

/// A bit-compatible version of the ZRTP V2 cache record.
/// 
/// Matches `zidrecord2_t` (128 bytes) from the original C++ implementation.
/// 
/// # Structural Layout
/// - `version`: Cache version (usually 2).
/// - `flags`: Record flags (Valid=0x01, OwnZID=0x20).
/// - `identifier`: 12-byte ZID of the peer (or own ZID).
/// - `rs1_data`: 32-byte retained secret 1.
/// - `rs2_data`: 32-byte retained secret 2.
/// - `mitm_key`: 32-byte MiTM key.
#[repr(C, packed)]
#[derive(Clone, Copy)]
struct ZidRecordV2 {
    version: u8,
    flags: u8,
    filler1: u8,
    filler2: u8,
    identifier: [u8; 12],
    rs1_interval: [u8; 8],
    rs1_data: [u8; 32],
    rs2_interval: [u8; 8],
    rs2_data: [u8; 32],
    mitm_key: [u8; 32],
}

impl ZidRecordV2 {
    const VALID: u8 = 0x01;
    const OWN_ZID: u8 = 0x20;
    
    fn new_empty() -> Self {
        Self {
            version: 2,
            flags: 0,
            filler1: 0,
            filler2: 0,
            identifier: [0u8; 12],
            rs1_interval: [0u8; 8],
            rs1_data: [0u8; 32],
            rs2_interval: [0u8; 8],
            rs2_data: [0u8; 32],
            mitm_key: [0u8; 32],
        }
    }
}

/// A legacy-compatible binary file cache.
pub struct BinaryFileCache {
    file: std::sync::Mutex<File>,
}

impl BinaryFileCache {
    /// Opens or creates a binary ZID cache at the given path.
    pub fn new<P: AsRef<std::path::Path>>(path: P, own_zid: Option<[u8; 12]>) -> anyhow::Result<Self> {
        #[allow(clippy::suspicious_open_options)]
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(path)?;

        if file.metadata()?.len() < 128 {
            // New file, write own ZID record
            let mut rec = ZidRecordV2::new_empty();
            rec.flags = ZidRecordV2::OWN_ZID;
            if let Some(zid) = own_zid {
                rec.identifier = zid;
            }
            unsafe {
                let bytes = std::slice::from_raw_parts(&rec as *const _ as *const u8, 128);
                file.write_all(bytes)?;
            }
        }
        
        Ok(Self { file: std::sync::Mutex::new(file) })
    }

    fn find_record(file: &mut File, zid: &[u8; 12]) -> Option<(ZidRecordV2, u64)> {
        let mut rec = ZidRecordV2::new_empty();
        let size = 128;
        let mut offset = size as u64; // skip own ZID

        loop {
            if file.seek(SeekFrom::Start(offset)).is_err() { break; }
            unsafe {
                let bytes = std::slice::from_raw_parts_mut(&mut rec as *mut _ as *mut u8, size);
                if file.read_exact(bytes).is_err() { break; }
            }
            
            if (rec.flags & ZidRecordV2::VALID) != 0 && &rec.identifier == zid {
                return Some((rec, offset));
            }
            offset += size as u64;
        }
        None
    }
}

impl ZidCache for BinaryFileCache {
    fn get_secret(&self, zid: &[u8; 12], name: &str) -> Option<Vec<u8>> {
        let mut file = self.file.lock().unwrap();
        let (rec, _) = Self::find_record(&mut file, zid)?;
        match name {
            "rs1" => Some(rec.rs1_data.to_vec()),
            "rs2" => Some(rec.rs2_data.to_vec()),
            "mitm" => Some(rec.mitm_key.to_vec()),
            _ => None,
        }
    }

    fn store_secret(&mut self, zid: &[u8; 12], name: &str, secret: &[u8]) {
        let mut file = self.file.lock().unwrap();
        let (mut rec, offset) = Self::find_record(&mut file, zid).unwrap_or_else(|| {
            let mut r = ZidRecordV2::new_empty();
            r.flags = ZidRecordV2::VALID;
            r.identifier = *zid;
            (r, file.metadata().unwrap().len())
        });

        match name {
            "rs1" => rec.rs1_data.copy_from_slice(secret),
            "rs2" => rec.rs2_data.copy_from_slice(secret),
            "mitm" => rec.mitm_key.copy_from_slice(secret),
            _ => return,
        }

        let _ = file.seek(SeekFrom::Start(offset));
        unsafe {
            let bytes = std::slice::from_raw_parts(&rec as *const _ as *const u8, 128);
            let _ = file.write_all(bytes);
        }
    }
}
