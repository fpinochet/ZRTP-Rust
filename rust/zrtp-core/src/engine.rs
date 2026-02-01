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

use crate::state::{ZrtpState, ZrtpEvent, ZrtpObserver};
use zrtp_proto::packets::*;
use zrtp_crypto::traits::*;
use std::collections::VecDeque;

/// The role of the endpoint in the ZRTP handshake.
pub enum Role {
    /// Initiates the DH exchange.
    Initiator,
    /// Responds to the DH exchange.
    Responder,
    /// Role not yet determined.
    None,
}

/// The main ZRTP protocol engine context.
/// 
/// This struct manages the state machine, cryptographic providers, 
/// retransmission logic, and message queuing.
pub struct ZrtpContext {
    /// Current protocol state.
    pub state: ZrtpState,
    /// Current role (Initiator/Responder).
    pub role: Role,
    /// Our local ZID.
    pub zid: [u8; 12],
    /// Peer's ZID (learnt during Hello exchange).
    pub peer_zid: Option<[u8; 12]>,
    /// Our local HVI.
    pub own_hvi: [u8; 32],
    /// Peer's HVI.
    pub peer_hvi: Option<[u8; 32]>,
    /// Cryptographic hash provider.
    pub hash_provider: Box<dyn Hash>,
    /// Key agreement provider.
    pub dh_provider: Box<dyn DiffieHellman>,
    /// Cipher provider for Confirm packets.
    pub cipher_provider: Box<dyn Cipher>,
    /// Retention secret cache (ZID cache).
    pub cache: Box<dyn zrtp_cache::ZidCache>,
    /// Protocol observer for callbacks.
    pub observer: Option<Box<dyn ZrtpObserver>>,
    
    /// The last sent packet for retransmission.
    pub sent_packet: Option<Vec<u8>>,
    /// Number of retransmission attempts.
    pub retry_count: u32,
    
    /// Queue of packets ready to be sent to the network.
    pub message_queue: VecDeque<Vec<u8>>,

    /// Cached peer Hello packet for HVI/KDF.
    pub peer_hello: Option<HelloPacket>,
    /// Our Hello packet data (raw bytes).
    pub own_hello_data: Option<Vec<u8>>,
    /// Raw bytes of peer's Hello packet (for HMAC check).
    pub peer_hello_data: Option<Vec<u8>>,
    /// Raw bytes of peer's Commit packet (for HMAC check).
    pub peer_commit_data: Option<Vec<u8>>,
    /// Raw bytes of peer's DHPart packet (for HMAC check).
    pub peer_dh_data: Option<Vec<u8>>,

    /// Our DH public key.
    pub own_public_key: Option<Vec<u8>>,
    /// Peer's DH public key.
    pub peer_public_key: Option<Vec<u8>>,
    /// Total hash of messages (H).
    pub total_hash: Vec<u8>,
    /// Hash chain (H0, H1, H2, H3).
    pub hash_chain: Vec<[u8; 32]>,
    /// Peer's revealed hash chain (H1, H2).
    pub peer_h1: Option<[u8; 32]>,
    pub peer_h2: Option<[u8; 32]>,
    
    /// Derived keys for the session.
    pub derived_keys: Option<zrtp_crypto::kdf::ZrtpKeys>,
}

impl ZrtpContext {
    /// Creates a new ZRTP context with the given ZID and crypto providers.
    pub fn new(
        zid: [u8; 12],
        hash: Box<dyn Hash>,
        dh: Box<dyn DiffieHellman>,
        cipher: Box<dyn Cipher>,
        cache: Box<dyn zrtp_cache::ZidCache>
    ) -> Self {
        let hash_chain = Self::generate_hash_chain(&*hash);
        Self {
            state: ZrtpState::Initial,
            role: Role::None,
            zid,
            peer_zid: None,
            own_hvi: [0u8; 32],
            peer_hvi: None,
            hash_provider: hash,
            dh_provider: dh,
            cipher_provider: cipher,
            cache,
            observer: None,
            sent_packet: None,
            retry_count: 0,
            message_queue: VecDeque::new(),
            peer_hello: None,
            own_hello_data: None,
            peer_hello_data: None,
            peer_commit_data: None,
            peer_dh_data: None,
            own_public_key: None,
            peer_public_key: None,
            total_hash: Vec::new(),
            hash_chain,
            peer_h1: None,
            peer_h2: None,
            derived_keys: None,
        }
    }

    fn generate_hash_chain(hash: &dyn Hash) -> Vec<[u8; 32]> {
        use rand_core::{RngCore, OsRng};
        let mut h0 = [0u8; 32];
        OsRng.fill_bytes(&mut h0);
        
        let h1_vec = hash.digest(&h0);
        let mut h1 = [0u8; 32];
        h1.copy_from_slice(&h1_vec);
        
        let h2_vec = hash.digest(&h1);
        let mut h2 = [0u8; 32];
        h2.copy_from_slice(&h2_vec);
        
        let h3_vec = hash.digest(&h2);
        let mut h3 = [0u8; 32];
        h3.copy_from_slice(&h3_vec);
        
        vec![h0, h1, h2, h3]
    }

    /// Prepares a Hello packet with current settings.
    pub fn prepare_hello(&self) -> HelloPacket {
        let mut client_id = [0u8; 16];
        client_id[..14].copy_from_slice(b"ZRTP-Rust-001 ");

        let mut hello = HelloPacket {
            header: ZrtpPacketHeader {
                zrtp_id: ZRTP_ID,
                length: 27, // Hello is 27 words
                message_type: HelloPacket::MESSAGE_TYPE,
            },
            version: *b"1.10",
            client_id,
            hash_h3: self.hash_chain[3],
            zid: self.zid,
            flags: 0,
            num_hash: 1,
            num_cipher: 1,
            num_auth: 1,
            num_key_agreement: 1,
            num_sas: 1,
            algs: vec![
                b'S', b'2', b'5', b'6',
                b'A', b'E', b'S', b'1',
                b'H', b'S', b'3', b'2',
                b'X', b'2', b'5', b'5',
                b'B', b'3', b'2', b' ',
            ],
            hmac: [0u8; 8], // Will be computed if version supports it
        };

        // Hello HMAC: Keyed by H2 (Self)
        let bytes = hello.to_bytes();
        let mac_len = bytes.len() - 8;
        let h2 = self.hash_chain[2];
        let mac = self.hash_provider.hmac(&h2, &bytes[..mac_len]);
        hello.hmac.copy_from_slice(&mac[..8]);

        hello
    }

    /// Queues a packet for sending and stores it for potential retransmission.
    pub fn send_packet(&mut self, packet_data: Vec<u8>) {
        self.sent_packet = Some(packet_data.clone());
        self.message_queue.push_back(packet_data);
    }

    /// Prepares a Commit packet based on the peer's Hello.
    pub fn prepare_commit(&mut self, _peer_hello: &HelloPacket) -> CommitPacket {
        // Generate our DH keypair if not already done
        if self.own_public_key.is_none() {
            if let Ok(pub_key) = self.dh_provider.generate_keypair() {
                self.own_public_key = Some(pub_key);
            }
        }

        let mut hvi = [0u8; 32];
        if let Some(ref pub_key) = self.own_public_key {
            // Create a mock DHPart2 to compute HVI
            let dh2 = DHPartPacket {
                header: ZrtpPacketHeader {
                    zrtp_id: ZRTP_ID,
                    length: 29,
                    message_type: DHPartPacket::MESSAGE_TYPE_DH2,
                },
                hash_h1: self.hash_chain[1],
                rs1_id: [0u8; 8],
                rs2_id: [0u8; 8],
                aux_secret_id: [0u8; 8],
                pbx_secret_id: [0u8; 8],
                public_value: pub_key.clone(),
                mac: [0u8; 8],
            };
            
            // Compute HMAC for DHPart2
            let mut dh2_bytes = dh2.to_bytes();
            let mac_len = dh2_bytes.len() - 8;
            let h0 = self.hash_chain[0];
            let mac = self.hash_provider.hmac(&h0, &dh2_bytes[..mac_len]);
            dh2_bytes[mac_len..].copy_from_slice(&mac[..8]);

            let mut data = dh2_bytes;
            if let Some(ref peer_hello_data) = self.peer_hello_data {
                data.extend_from_slice(peer_hello_data);
            }
            let hash = self.hash_provider.digest(&data);
            hvi.copy_from_slice(&hash);
            self.own_hvi = hvi;
        }

        let mut commit_pkt = CommitPacket {
            header: ZrtpPacketHeader {
                zrtp_id: ZRTP_ID,
                length: 29,
                message_type: CommitPacket::MESSAGE_TYPE,
            },
            hash_h2: self.hash_chain[2], // H2
            zid: self.zid,
            hash_alg: *b"S256",
            cipher_alg: *b"AES1",
            auth_tag_alg: *b"HS32",
            key_agreement_alg: *b"X255",
            sas_alg: *b"B32 ",
            hvi,
            mac: [0u8; 8],
        };

        // Commit HMAC: Keyed by H1 (Self)
        let bytes = commit_pkt.to_bytes();
        let mac_len = bytes.len() - 8;
        let h1 = self.hash_chain[1];
        let mac = self.hash_provider.hmac(&h1, &bytes[..mac_len]);
        commit_pkt.mac.copy_from_slice(&mac[..8]);

        // Accumulate total_hash: hash(Hello_I | Hello_R | Commit)
        // For Initiator, we have Hello_I (ours), Hello_R (peer's), and Commit (ours)
        if let (Some(ref own_hello), Some(ref peer_hello_bytes)) = (self.own_hello_data.as_ref(), self.peer_hello_data.as_ref()) {
            let mut data = own_hello.to_vec(); // Hello_I
            data.extend_from_slice(peer_hello_bytes); // Hello_R
            data.extend_from_slice(&commit_pkt.to_bytes()); // Commit (including MAC)
            self.total_hash = self.hash_provider.digest(&data);
        }

        commit_pkt
    }

    /// Primary entry point for protocol events. Handles state transitions.
    /// Processes a ZRTP event.
    /// 
    /// This method implements the state machine transitions as described in
    /// RFC 6189 Section 5 (The ZRTP State Machine).
    pub fn handle_event(&mut self, event: ZrtpEvent, packet_data: Option<&[u8]>) {
        let old_state = self.state;
        match (self.state, event) {
            (ZrtpState::Initial, ZrtpEvent::Start) => {
                let hello = self.prepare_hello();
                let bytes = hello.to_bytes();
                self.own_hello_data = Some(bytes.clone());
                self.send_packet(bytes);
                self.state = ZrtpState::Discovery;
            }
            (ZrtpState::Discovery, ZrtpEvent::HelloReceived) => {
                if let Some(data) = packet_data {
                    if let Ok((_, hello)) = HelloPacket::parse(data) {
                        self.peer_zid = Some(hello.zid);
                        self.peer_hello = Some(hello);
                        self.peer_hello_data = Some(data.to_vec());
                        self.role = Role::Initiator;
                        // Send HelloAck
                        let ack = GenericAckPacket {
                            header: ZrtpPacketHeader {
                                zrtp_id: ZRTP_ID,
                                length: 3,
                                message_type: GenericAckPacket::MESSAGE_TYPE_HELLO_ACK,
                            }
                        };
                        self.send_packet(ack.to_bytes());
                        self.state = ZrtpState::AckSent;
                    }
                }
            }
            (ZrtpState::Discovery, ZrtpEvent::HelloAckReceived) => {
                self.state = ZrtpState::AckDetected;
            }
            (ZrtpState::AckSent, ZrtpEvent::HelloAckReceived) => {
                // Peer acked our Hello, we are initiator
                self.role = Role::Initiator;
                if let Some(peer_hello) = self.peer_hello.clone() {
                    let commit = self.prepare_commit(&peer_hello);
                    self.send_packet(commit.to_bytes());
                    self.state = ZrtpState::CommitSent;
                }
            }
            (ZrtpState::AckDetected, ZrtpEvent::HelloReceived) => {
                // We received peer's Hello after they acked ours
                self.state = ZrtpState::WaitCommit;
            }
            (ZrtpState::AckSent, ZrtpEvent::CommitReceived) | (ZrtpState::AckDetected, ZrtpEvent::CommitReceived) | (ZrtpState::WaitCommit, ZrtpEvent::CommitReceived) => {
                if let Some(data) = packet_data {
                    if let Ok((_, received_commit)) = CommitPacket::parse(data) {
                        // Store commit and transition to responder
                        self.role = Role::Responder;
                        self.peer_commit_data = Some(data.to_vec());
                        self.peer_h2 = Some(received_commit.hash_h2);

                        // Verify HVI: hash(My Hello | Initiator's public key)
                        // Note: Responder doesn't have Initiator's public key yet!
                        // Initiator's public key arrives in DHPart2.
                        // So we store the HVI from Commit and verify it when DHPart2 arrives.
                        self.peer_hvi = Some(received_commit.hvi);

                        // Accumulate total_hash: hash(Hello_I | Hello_R | Commit)
                        if let (Some(ref peer_hello_data), Some(ref own_hello)) = (self.peer_hello_data.as_ref(), self.own_hello_data.as_ref()) {
                            let mut hash_data = peer_hello_data.to_vec(); // Hello_I (from peer)
                            hash_data.extend_from_slice(own_hello); // Hello_R (ours)
                            hash_data.extend_from_slice(data); // Commit (the raw bytes received)
                            self.total_hash = self.hash_provider.digest(&hash_data);
                        }
                        
                        // Generate DH keypair if needed
                        if self.own_public_key.is_none() {
                            if let Ok(pub_key) = self.dh_provider.generate_keypair() {
                                self.own_public_key = Some(pub_key);
                            }
                        }

                        // Send DHPart1
                        let dh1 = DHPartPacket {
                            header: ZrtpPacketHeader {
                                zrtp_id: ZRTP_ID,
                                length: 29,
                                message_type: DHPartPacket::MESSAGE_TYPE_DH1,
                            },
                            hash_h1: self.hash_chain[1], // H1
                            rs1_id: [0u8; 8],
                            rs2_id: [0u8; 8],
                            aux_secret_id: [0u8; 8],
                            pbx_secret_id: [0u8; 8],
                            public_value: self.own_public_key.clone().unwrap(),
                            mac: [0u8; 8],
                        };

                        // DHPart1 HMAC: Keyed by H0 (Self)
                        let bytes = dh1.to_bytes();
                        let mac_len = bytes.len() - 8;
                        let h0 = self.hash_chain[0];
                        let mac = self.hash_provider.hmac(&h0, &bytes[..mac_len]);
                        let mut dh1_with_mac = dh1;
                        dh1_with_mac.mac.copy_from_slice(&mac[..8]);

                        self.send_packet(dh1_with_mac.to_bytes());
                        self.state = ZrtpState::WaitDHPart2;
                    }
                }
            }
            (ZrtpState::CommitSent, ZrtpEvent::DHPart1Received) => {
                if let Some(data) = packet_data {
                    if let Ok((_, dh1)) = DHPartPacket::parse(data) {
                        self.peer_dh_data = Some(data.to_vec());
                        self.peer_h1 = Some(dh1.hash_h1);

                        // Initiator verification: H1 -> H2 -> H3
                        if let Some(ref peer_hello) = self.peer_hello {
                            let h2 = self.hash_provider.digest(&dh1.hash_h1);
                            let h3 = self.hash_provider.digest(&h2);
                            if h3 != peer_hello.hash_h3 {
                                log::error!("Hash chain verification (H1->H2->H3) failed!");
                                self.state = ZrtpState::Error;
                                return;
                            }
                            self.peer_h2 = Some(h2.clone().try_into().unwrap());

                            // Verify Hello HMAC using peer_h2
                            // RFC 6189 Section 9.1: The Hello HMAC is verified using H2
                            // once H2 is revealed in the Commit packet.
                            if let Some(ref hello_data) = self.peer_hello_data {
                                // MAC is the last 8 bytes of the Hello packet
                                let mac_len = hello_data.len() - 8;
                                let mac = self.hash_provider.hmac(&h2, &hello_data[..mac_len]);
                                if mac[..8] != hello_data[mac_len..] {
                                    log::error!("Hello HMAC verification failed!");
                                    self.state = ZrtpState::Error;
                                    return;
                                }
                            }
                        }

                        self.peer_public_key = Some(dh1.public_value);
                        
                        // Send DHPart2
                        let dh2 = DHPartPacket {
                            header: ZrtpPacketHeader {
                                zrtp_id: ZRTP_ID,
                                length: 29,
                                message_type: DHPartPacket::MESSAGE_TYPE_DH2,
                            },
                            hash_h1: self.hash_chain[1], // H1
                            rs1_id: [0u8; 8],
                            rs2_id: [0u8; 8],
                            aux_secret_id: [0u8; 8],
                            pbx_secret_id: [0u8; 8],
                            public_value: self.own_public_key.clone().unwrap(),
                            mac: [0u8; 8],
                        };

                        // DHPart2 HMAC: Keyed by H0 (Self)
                        let bytes = dh2.to_bytes();
                        let mac_len = bytes.len() - 8;
                        let h0 = self.hash_chain[0];
                        let mac = self.hash_provider.hmac(&h0, &bytes[..mac_len]);
                        let mut dh2_with_mac = dh2;
                        dh2_with_mac.mac.copy_from_slice(&mac[..8]);

                        self.send_packet(dh2_with_mac.to_bytes());
                            
                            // Compute shared secret and transition to wait Confirm1
                            if let Some(ref peer_pub) = self.peer_public_key {
                                if let Ok(shared) = self.dh_provider.compute_shared_secret(peer_pub) {
                                    let zid_i = &self.zid;
                                    let zid_r = self.peer_zid.as_ref().unwrap();
                                    
                                    // Fetch retained secrets from cache
                                    let rs1 = self.cache.get_secret(zid_r, "rs1");
                                    let rs2 = self.cache.get_secret(zid_r, "rs2");

                                    let s0 = zrtp_crypto::kdf::derive_s0(
                                        &*self.hash_provider,
                                        &shared,
                                        b"ZRTP-HMAC-KDF",
                                        zid_i,
                                        zid_r,
                                        &self.total_hash,
                                        rs1.as_deref(), rs2.as_deref(), None
                                    );
                                    // RFC 6189 Section 4.5.1: Deriving Session Keys from S0
                                    let keys = zrtp_crypto::kdf::derive_session_keys(
                                        &*self.hash_provider,
                                        &s0,
                                        zid_i,
                                        zid_r,
                                        &self.total_hash,
                                        16 // AES-128
                                    ).ok();
                                    self.derived_keys = keys;
                                    if let Some(ref k) = self.derived_keys {
                                        self.cache.store_secret(zid_r, "rs1", &k.new_rs1);
                                    }
                                }
                            }
                            self.state = ZrtpState::WaitConfirm1;
                        }
                }
            }
            (ZrtpState::WaitDHPart2, ZrtpEvent::DHPart2Received) => {
                if let Some(data) = packet_data {
                    if let Ok((_, dh2)) = DHPartPacket::parse(data) {
                        self.peer_dh_data = Some(data.to_vec());
                        self.peer_h1 = Some(dh2.hash_h1);

                        // Responder verification: H1 -> H2
                        if let Some(h2_expected) = self.peer_h2 {
                            let h2_computed = self.hash_provider.digest(&dh2.hash_h1);
                            if h2_computed != h2_expected {
                                log::error!("Hash chain verification (H1->H2) failed!");
                                self.state = ZrtpState::Error;
                                return;
                            }

                            // Verify Commit HMAC using peer_h1
                            if let Some(ref commit_data) = self.peer_commit_data {
                                let mac_len = commit_data.len() - 8;
                                let mac = self.hash_provider.hmac(&dh2.hash_h1, &commit_data[..mac_len]);
                                if mac[..8] != commit_data[mac_len..] {
                                    log::error!("Commit HMAC verification failed!");
                                    self.state = ZrtpState::Error;
                                    return;
                                }
                            }
                        }

                        self.peer_public_key = Some(dh2.public_value);
                        
                        if let (Some(ref peer_hvi), Some(ref peer_dh_bytes), Some(ref own_hello)) = (self.peer_hvi, self.peer_dh_data.as_ref(), self.own_hello_data.as_ref()) {
                            let mut data = peer_dh_bytes.to_vec();
                            data.extend_from_slice(own_hello); // My Hello (Responder)
                            let hash = self.hash_provider.digest(&data);
                            if hash != *peer_hvi {
                                log::error!("HVI verification failed!");
                                self.state = ZrtpState::Error;
                                return;
                            }
                        }

                        // Compute shared secret
                        if let Some(ref peer_pub) = self.peer_public_key {
                            if let Ok(shared) = self.dh_provider.compute_shared_secret(peer_pub) {
                                // Derive S0 and session keys
                                let zid_i = self.peer_zid.as_ref().unwrap();
                                let zid_r = &self.zid;
                                // Fetch retained secrets from cache
                                let rs1 = self.cache.get_secret(zid_i, "rs1");
                                let rs2 = self.cache.get_secret(zid_i, "rs2");

                                let s0 = zrtp_crypto::kdf::derive_s0(
                                    &*self.hash_provider,
                                    &shared,
                                    b"ZRTP-HMAC-KDF",
                                    zid_i,
                                    zid_r,
                                    &self.total_hash,
                                    rs1.as_deref(), rs2.as_deref(), None
                                );
                                let keys = zrtp_crypto::kdf::derive_session_keys(
                                    &*self.hash_provider,
                                    &s0,
                                    zid_i,
                                    zid_r,
                                    &self.total_hash,
                                    16 // AES-128
                                ).ok();
                                self.derived_keys = keys;
                                if let Some(ref k) = self.derived_keys {
                                    self.cache.store_secret(zid_i, "rs1", &k.new_rs1);
                                }
                            }
                        }
                        
                        // Send Confirm1
                        let mut conf1 = ConfirmPacket {
                            header: ZrtpPacketHeader {
                                zrtp_id: ZRTP_ID,
                                length: 19,
                                message_type: ConfirmPacket::MESSAGE_TYPE_CONF1,
                            },
                            hmac: [0u8; 8],
                            iv: [0u8; 16],
                            hash_h0: self.hash_chain[0],
                            filler: [0u8; 2],
                            sig_length: 0,
                            flags: 0,
                            exp_time: 0,
                        };

                        // Encrypt and HMAC if keys are available
                        if let Some(ref keys) = self.derived_keys {
                            use rand_core::{RngCore, OsRng};
                            OsRng.fill_bytes(&mut conf1.iv);
                            
                            // Data to encrypt (40 bytes)
                            let mut plain = Vec::new();
                            plain.extend_from_slice(&conf1.hash_h0);
                            plain.extend_from_slice(&conf1.filler);
                            plain.push(conf1.sig_length);
                            plain.push(conf1.flags);
                            plain.extend_from_slice(&conf1.exp_time.to_be_bytes());

                            if let Ok(encrypted) = self.cipher_provider.encrypt(&keys.confirm_key_r, &conf1.iv, &plain) {
                                // Put encrypted data back (hash_h0 is first 32 bytes)
                                conf1.hash_h0.copy_from_slice(&encrypted[0..32]);
                                conf1.filler.copy_from_slice(&encrypted[32..34]);
                                conf1.sig_length = encrypted[34];
                                conf1.flags = encrypted[35];
                                conf1.exp_time = u32::from_be_bytes(encrypted[36..40].try_into().unwrap());

                                // Compute HMAC over encrypted part (40 bytes)
                                let mac = self.hash_provider.hmac(&keys.confirm_key_r, &encrypted);
                                conf1.hmac.copy_from_slice(&mac[0..8]);
                            }
                        }
                        
                        self.send_packet(conf1.to_bytes());
                        self.state = ZrtpState::WaitConfirm2;
                    }
                }
            }
            (ZrtpState::WaitConfirm1, ZrtpEvent::Confirm1Received) => {
                if let (Some(data), Some(ref keys)) = (packet_data, self.derived_keys.as_ref()) {
                    if let Ok((_, conf1)) = ConfirmPacket::parse(data) {
                        // Decrypt Confirm1
                        let mut encrypted = Vec::new();
                        encrypted.extend_from_slice(&conf1.hash_h0);
                        encrypted.extend_from_slice(&conf1.filler);
                        encrypted.push(conf1.sig_length);
                        encrypted.push(conf1.flags);
                        encrypted.extend_from_slice(&conf1.exp_time.to_be_bytes());

                        // Verify HMAC first
                        let mac = self.hash_provider.hmac(&keys.confirm_key_r, &encrypted);
                        if mac[..8] != conf1.hmac {
                            log::error!("Confirm1 HMAC verification failed!");
                            self.state = ZrtpState::Error;
                            return;
                        }

                        if let Ok(plain) = self.cipher_provider.decrypt(&keys.confirm_key_r, &conf1.iv, &encrypted) {
                            let h0: [u8; 32] = plain[0..32].try_into().unwrap();
                            
                            // Verify H0 -> H1
                            if let Some(h1_expected) = self.peer_h1 {
                                let h1_computed = self.hash_provider.digest(&h0);
                                if h1_computed != h1_expected {
                                    log::error!("Hash chain verification (H0->H1) failed!");
                                    self.state = ZrtpState::Error;
                                    return;
                                }
                            }

                            // Verify DHPart HMAC using H0
                            if let Some(ref dh_data) = self.peer_dh_data {
                                let mac_len = dh_data.len() - 8;
                                let mac = self.hash_provider.hmac(&h0, &dh_data[..mac_len]);
                                if mac[..8] != dh_data[mac_len..] {
                                    log::error!("DHPart HMAC verification failed!");
                                    self.state = ZrtpState::Error;
                                    return;
                                }
                            }
                        }
                    }
                }

                // Send Confirm2
                let mut conf2 = ConfirmPacket {
                    header: ZrtpPacketHeader {
                        zrtp_id: ZRTP_ID,
                        length: 19,
                        message_type: ConfirmPacket::MESSAGE_TYPE_CONF2,
                    },
                    hmac: [0u8; 8],
                    iv: [0u8; 16],
                    hash_h0: self.hash_chain[0],
                    filler: [0u8; 2],
                    sig_length: 0,
                    flags: 0,
                    exp_time: 0,
                };

                // Encrypt and HMAC if keys are available
                if let Some(ref keys) = self.derived_keys {
                    use rand_core::{RngCore, OsRng};
                    OsRng.fill_bytes(&mut conf2.iv);
                    
                    let mut plain = Vec::new();
                    plain.extend_from_slice(&conf2.hash_h0);
                    plain.extend_from_slice(&conf2.filler);
                    plain.push(conf2.sig_length);
                    plain.push(conf2.flags);
                    plain.extend_from_slice(&conf2.exp_time.to_be_bytes());

                    if let Ok(encrypted) = self.cipher_provider.encrypt(&keys.confirm_key_i, &conf2.iv, &plain) {
                        conf2.hash_h0.copy_from_slice(&encrypted[0..32]);
                        conf2.filler.copy_from_slice(&encrypted[32..34]);
                        conf2.sig_length = encrypted[34];
                        conf2.flags = encrypted[35];
                        conf2.exp_time = u32::from_be_bytes(encrypted[36..40].try_into().unwrap());

                        let mac = self.hash_provider.hmac(&keys.confirm_key_i, &encrypted);
                        conf2.hmac.copy_from_slice(&mac[0..8]);
                    }
                }

                self.send_packet(conf2.to_bytes());
                self.state = ZrtpState::Secure;
            }
            (ZrtpState::WaitConfirm2, ZrtpEvent::Confirm2Received) => {
                if let (Some(data), Some(ref keys)) = (packet_data, self.derived_keys.as_ref()) {
                    if let Ok((_, conf2)) = ConfirmPacket::parse(data) {
                        // Decrypt Confirm2
                        let mut encrypted = Vec::new();
                        encrypted.extend_from_slice(&conf2.hash_h0);
                        encrypted.extend_from_slice(&conf2.filler);
                        encrypted.push(conf2.sig_length);
                        encrypted.push(conf2.flags);
                        encrypted.extend_from_slice(&conf2.exp_time.to_be_bytes());

                        // Verify HMAC first
                        let mac = self.hash_provider.hmac(&keys.confirm_key_i, &encrypted);
                        if mac[..8] != conf2.hmac {
                            log::error!("Confirm2 HMAC verification failed!");
                            self.state = ZrtpState::Error;
                            return;
                        }

                        if let Ok(plain) = self.cipher_provider.decrypt(&keys.confirm_key_i, &conf2.iv, &encrypted) {
                            let h0: [u8; 32] = plain[0..32].try_into().unwrap();
                            
                            // Verify H0 -> H1
                            if let Some(h1_expected) = self.peer_h1 {
                                let h1_computed = self.hash_provider.digest(&h0);
                                if h1_computed != h1_expected {
                                    log::error!("Hash chain verification (H0->H1) failed!");
                                    self.state = ZrtpState::Error;
                                    return;
                                }
                            }

                            // Verify DHPart HMAC using H0
                            if let Some(ref dh_data) = self.peer_dh_data {
                                let mac_len = dh_data.len() - 8;
                                let mac = self.hash_provider.hmac(&h0, &dh_data[..mac_len]);
                                if mac[..8] != dh_data[mac_len..] {
                                    log::error!("DHPart HMAC verification failed!");
                                    self.state = ZrtpState::Error;
                                    return;
                                }
                            }
                        }
                    }
                }
                self.state = ZrtpState::Secure;
            }
            (ZrtpState::Discovery, ZrtpEvent::Timeout) | (ZrtpState::AckSent, ZrtpEvent::Timeout) => {
                if self.retry_count < 10 {
                    if let Some(ref pkt) = self.sent_packet {
                        self.message_queue.push_back(pkt.clone());
                    }
                    self.retry_count += 1;
                } else {
                    self.state = ZrtpState::Error;
                }
            }
            _ => {
                log::warn!("Unhandled event {:?} in state {:?}", event, self.state);
            }
        }

        if self.state != old_state {
            if let Some(ref observer) = self.observer {
                observer.on_state_change(self.state);
            }
        }
    }
}
