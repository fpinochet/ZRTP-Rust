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

/// Options for configuring ZRTP enhancements.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ZrtpOptions {
    /// Enable Symmetric Ratchet for continuous forward secrecy.
    pub enable_ratchet: bool,
    /// Interval for periodic ratcheting (e.g., in seconds or packet counts).
    /// Note: Implementation specific, but suggested 1s or 100 packets.
    pub ratchet_interval: u32,
    /// Enable Post-Quantum Hybrid (PQH) key agreement (ML-KEM/Kyber).
    pub enable_pqc_kem: bool,
    /// Enable automated identity verification using PQ signatures (Falcon).
    pub enable_pqc_sig: bool,
    /// Enable application-layer fragmentation for large packets.
    pub enable_fragmentation: bool,
    /// Threshold in bytes to trigger fragmentation (default: 1200).
    pub fragmentation_threshold: u16,
    /// Enable adaptive retransmission timers based on RTT.
    pub enable_adaptive_timer: bool,
    /// Enable Survival Mode to prevent audio drops during interception attempts.
    /// When enabled, cryptographic failures trigger warnings instead of disconnects.
    pub enable_survival_mode: bool,
}

impl Default for ZrtpOptions {
    fn default() -> Self {
        Self {
            enable_ratchet: false,
            ratchet_interval: 100, // example: every 100 packets
            enable_pqc_kem: false,
            enable_pqc_sig: false,
            enable_fragmentation: true,
            fragmentation_threshold: 1200,
            enable_adaptive_timer: true,
            enable_survival_mode: true,
        }
    }
}

impl ZrtpOptions {
    /// Returns a high-security profile with all enhancements enabled.
    pub fn high_security() -> Self {
        Self {
            enable_ratchet: true,
            ratchet_interval: 50,
            enable_pqc_kem: true,
            enable_pqc_sig: true,
            enable_fragmentation: true,
            fragmentation_threshold: 1200,
            enable_adaptive_timer: true,
            enable_survival_mode: true,
        }
    }
}
