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
use crate::options::ZrtpOptions;
use zrtp_proto::packets::*;
use zrtp_proto::packets::fragment::FragmentHeader;
use zrtp_crypto::utils::constant_time_eq;
use zrtp_crypto::traits::*;
use zrtp_crypto::ratchet::ZrtpRatchet;
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
    /// Options and feature toggles.
    pub options: ZrtpOptions,

    /// Optional PQC Key Encapsulation provider.
    pub kem_provider: Option<Box<dyn KeyEncapsulation>>,
    /// Optional PQC Signature provider.
    pub sig_provider: Option<Box<dyn Signature>>,

    /// Symmetric ratchet for initiator audio stream.
    pub initiator_ratchet: Option<ZrtpRatchet>,
    /// Symmetric ratchet for responder audio stream.
    pub responder_ratchet: Option<ZrtpRatchet>,
    
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

    /// Buffer for reassembling fragmented incoming packets.
    pub reassembly_buffer: Option<FragmentBuffer>,
    
    /// Measured Round-Trip Time (RTT).
    pub rtt: std::time::Duration,
    /// Current retransmission timer (T1).
    pub t1: std::time::Duration,
    /// Time when the last packet was sent.
    pub last_send_time: Option<std::time::Instant>,
}

/// Buffer for reassembling fragmented ZRTP packets.
pub struct FragmentBuffer {
    pub fragments: Vec<Option<Vec<u8>>>,
    pub frag_count: u8,
    pub last_updated: std::time::Instant,
}

impl ZrtpContext {
    /// Creates a new ZRTP context with the given ZID and crypto providers.
    pub fn new(
        zid: [u8; 12],
        hash: Box<dyn Hash>,
        dh: Box<dyn DiffieHellman>,
        cipher: Box<dyn Cipher>,
        cache: Box<dyn zrtp_cache::ZidCache>,
        options: ZrtpOptions,
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
            reassembly_buffer: None,
            rtt: std::time::Duration::from_millis(500), // Default RTT
            t1: std::time::Duration::from_millis(500),  // Default T1
            last_send_time: None,
            options,
            kem_provider: None,
            sig_provider: None,
            initiator_ratchet: None,
            responder_ratchet: None,
        }
    }

    /// Sets the PQC providers for hybrid exchange.
    pub fn set_pqc_providers(
        &mut self,
        kem: Option<Box<dyn KeyEncapsulation>>,
        sig: Option<Box<dyn Signature>>
    ) {
        self.kem_provider = kem;
        self.sig_provider = sig;
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

        // Add enhancement identifiers if enabled
        if self.options.enable_pqc_kem {
            hello.algs.extend_from_slice(&HelloPacket::ALGO_KEM_KYBER768);
            hello.num_key_agreement += 1;
        }
        if self.options.enable_pqc_sig {
            // Note: Standard ZRTP doesn't have a Signature category. 
            // We append it and increment a reserved count or handle via extensions.
            // For now, we append to algs to signal capability.
            hello.algs.extend_from_slice(&HelloPacket::ALGO_SIG_FALCON512);
        }
        if self.options.enable_ratchet {
            hello.algs.extend_from_slice(&HelloPacket::ALGO_RATCHET_HMAC256);
        }

        // Adjust packet length based on added algorithms (4 bytes each = 1 word)
        let added_algs = (hello.algs.len() / 4) - 5; // 5 is the standard count
        hello.header.length += added_algs as u16;

        // Hello HMAC: Keyed by H2 (Self)
        let bytes = hello.to_bytes();
        let mac_len = bytes.len() - 8;
        let h2 = self.hash_chain[2];
        let mac = self.hash_provider.hmac(&h2, &bytes[..mac_len]);
        hello.hmac.copy_from_slice(&mac[..8]);

        hello
    }

    /// Prepares a Confirm1 packet.
    pub fn prepare_confirm1(&mut self) -> ConfirmPacket {
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

        if let Some(keys) = &self.derived_keys {
            use rand_core::{RngCore, OsRng};
            OsRng.fill_bytes(&mut conf1.iv);
            
            let mut plain = Vec::new();
            plain.extend_from_slice(&conf1.hash_h0);
            plain.extend_from_slice(&conf1.filler);
            plain.push(conf1.sig_length);
            plain.push(conf1.flags);
            plain.extend_from_slice(&conf1.exp_time.to_be_bytes());

            if let Ok(encrypted) = self.cipher_provider.encrypt(&keys.confirm_key_r, &conf1.iv, &plain) {
                conf1.hash_h0.copy_from_slice(&encrypted[0..32]);
                conf1.filler.copy_from_slice(&encrypted[32..34]);
                conf1.sig_length = encrypted[34];
                conf1.flags = encrypted[35];
                conf1.exp_time = u32::from_be_bytes(encrypted[36..40].try_into().unwrap());

                let mac = self.hash_provider.hmac(&keys.confirm_key_r, &encrypted);
                conf1.hmac.copy_from_slice(&mac[0..8]);
            }
        }
        conf1
    }

    /// Prepares a Confirm2 packet.
    pub fn prepare_confirm2(&mut self) -> ConfirmPacket {
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

        if let Some(keys) = &self.derived_keys {
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
        conf2
    }

    /// Queues a packet for sending and stores it for potential retransmission.
    pub fn send_packet(&mut self, packet_data: Vec<u8>) {
        self.last_send_time = Some(std::time::Instant::now());

        if self.options.enable_fragmentation && packet_data.len() > self.options.fragmentation_threshold as usize {
            if let Ok((_, header)) = ZrtpPacketHeader::parse(&packet_data) {
                let payload = &packet_data[12..];
                let max_chunk = self.options.fragmentation_threshold as usize - 12 - FragmentHeader::SIZE;
                let frag_count = payload.len().div_ceil(max_chunk);
                
                log::debug!("Fragmenting ZRTP packet into {} fragments", frag_count);

                for i in 0..frag_count {
                    let start = i * max_chunk;
                    let end = std::cmp::min(start + max_chunk, payload.len());
                    let chunk = &payload[start..end];
                    
                    let mut frag_bytes = Vec::new();
                    let mut frag_hdr = header.clone();
                    // Length in words: (12 hdr + 2 frag_hdr + chunk) / 4
                    frag_hdr.length = ((12 + FragmentHeader::SIZE + chunk.len()).div_ceil(4)) as u16;
                    
                    frag_bytes.extend_from_slice(&frag_hdr.to_bytes());
                    frag_bytes.extend_from_slice(&FragmentHeader {
                        frag_count: frag_count as u8,
                        frag_seq: i as u8,
                    }.to_bytes());
                    frag_bytes.extend_from_slice(chunk);
                    
                    while frag_bytes.len() % 4 != 0 {
                        frag_bytes.push(0);
                    }
                    self.message_queue.push_back(frag_bytes);
                }
                self.sent_packet = Some(packet_data); 
                return;
            }
        }
        
        self.sent_packet = Some(packet_data.clone());
        self.message_queue.push_back(packet_data);
    }

    /// Processes a raw packet from the network, handling reassembly if needed.
    pub fn receive_packet(&mut self, raw_data: &[u8]) {
        if raw_data.len() < 12 {
            return;
        }

        // Measure RTT if we were waiting for a response
        if let Some(sent_time) = self.last_send_time {
            let rtt = sent_time.elapsed();
            self.rtt = (self.rtt * 7 + rtt) / 8; // Moving average
            self.t1 = std::cmp::max(std::time::Duration::from_millis(50), self.rtt * 2);
            self.last_send_time = None;
        }

        if let Ok((rem, header)) = ZrtpPacketHeader::parse(raw_data) {
            // Check if it's a fragment
            if let Ok((payload, frag_header)) = FragmentHeader::parse(rem) {
                if frag_header.frag_count > 1 {
                    // It is a fragment, handle it
                    // The payload might contain padding which we should strip based on header.length?
                    // Actually let's assume the payload is what's left after parsing FragmentHeader
                    self.handle_fragment(header, frag_header, payload);
                    return;
                }
            }

            // Not a fragment, dispatch normally
            let event = self.map_packet_to_event(&header);
            self.handle_event(event, Some(raw_data));
        }
    }

    fn handle_fragment(&mut self, header: ZrtpPacketHeader, frag: FragmentHeader, payload: &[u8]) {
        // Advanced Senior-Level Security: Protection against confused reassembly and DoS
        let now = std::time::Instant::now();
        
        // 1. Check TTL (30s) and Consistency
        if let Some(ref buffer) = self.reassembly_buffer {
            let is_stale = now.duration_since(buffer.last_updated).as_secs() > 30;
            let is_inconsistent = buffer.frag_count != frag.frag_count;
            
            if is_stale || is_inconsistent {
                log::warn!("Clearing stale or inconsistent fragment buffer (Stale: {}, Inconsistent: {})", is_stale, is_inconsistent);
                self.reassembly_buffer = None;
            }
        }

        let buffer = self.reassembly_buffer.get_or_insert_with(|| FragmentBuffer {
            fragments: vec![None; frag.frag_count as usize],
            frag_count: frag.frag_count,
            last_updated: now,
        });

        buffer.last_updated = now;

        if frag.frag_seq >= buffer.frag_count {
            return;
        }

        buffer.fragments[frag.frag_seq as usize] = Some(payload.to_vec());

        // Check completeness
        if buffer.fragments.iter().all(|f| f.is_some()) {
            let mut payloads = Vec::new();
            for f in buffer.fragments.drain(..) {
                payloads.extend_from_slice(&f.unwrap());
            }
            
            let mut complete_data = Vec::new();
            let mut final_header = header.clone();
            // Total length in words
            final_header.length = ((12 + payloads.len()).div_ceil(4)) as u16;
            
            complete_data.extend_from_slice(&final_header.to_bytes());
            complete_data.extend_from_slice(&payloads);
            
            self.reassembly_buffer = None; // Clear buffer
            let event = self.map_packet_to_event(&final_header);
            self.handle_event(event, Some(&complete_data));
        }
    }

    fn map_packet_to_event(&self, header: &ZrtpPacketHeader) -> ZrtpEvent {
        match header.message_type {
            HelloPacket::MESSAGE_TYPE => ZrtpEvent::HelloReceived,
            GenericAckPacket::MESSAGE_TYPE_HELLO_ACK => ZrtpEvent::HelloAckReceived,
            CommitPacket::MESSAGE_TYPE => ZrtpEvent::CommitReceived,
            DHPartPacket::MESSAGE_TYPE_DH1 => ZrtpEvent::DHPart1Received,
            DHPartPacket::MESSAGE_TYPE_DH2 => ZrtpEvent::DHPart2Received,
            ConfirmPacket::MESSAGE_TYPE_CONF1 => ZrtpEvent::Confirm1Received,
            ConfirmPacket::MESSAGE_TYPE_CONF2 => ZrtpEvent::Confirm2Received,
            GenericAckPacket::MESSAGE_TYPE_CONF2_ACK => ZrtpEvent::Conf2AckReceived,
            GoClearPacket::MESSAGE_TYPE => ZrtpEvent::GoClearReceived,
            ErrorPacket::MESSAGE_TYPE => {
                // Default to a generic error if we can't parse it here easily
                ZrtpEvent::Error(0) 
            }
            _ => ZrtpEvent::Error(0x01), // Unsupported
        }
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

        let mut key_agreement_alg = *b"X255";
        let zid_i = self.peer_zid.as_ref().unwrap();
        
        // Fast Resumption check: If we have RS1, try "Prsh"
        if self.cache.get_secret(zid_i, "rs1").is_some() {
            log::info!("Retained secret found, requesting Fast Session Resumption");
            key_agreement_alg = *b"Prsh";
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
            key_agreement_alg,
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
        if let (Some(own_hello), Some(peer_hello_bytes)) = (self.own_hello_data.as_ref(), self.peer_hello_data.as_ref()) {
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
                    let is_resumption = commit.key_agreement_alg == *b"Prsh";
                    self.send_packet(commit.to_bytes());
                    
                    if is_resumption {
                        log::info!("Initiator: Deriving keys for Fast Session Resumption");
                        let zid_r = self.peer_zid.as_ref().unwrap(); // Peer is Responder
                        if let Some(rs1) = self.cache.get_secret(zid_r, "rs1") {
                            let null_dh = vec![0u8; 32];
                            let s0 = zrtp_crypto::kdf::derive_s0(
                                &*self.hash_provider,
                                &null_dh,
                                b"ZRTP-HMAC-KDF",
                                &self.zid,      // ZIDi (ours)
                                zid_r,          // ZIDr (peer's)
                                &self.total_hash,
                                Some(&rs1), None, None,
                                None
                            );
                            self.derived_keys = zrtp_crypto::kdf::derive_session_keys(
                                &*self.hash_provider,
                                &s0,
                                &self.zid,
                                zid_r,
                                &self.total_hash,
                                16
                            ).ok();
                        }
                    }
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
                        if let (Some(peer_hello_data), Some(own_hello)) = (self.peer_hello_data.as_ref(), self.own_hello_data.as_ref()) {
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

                        if received_commit.key_agreement_alg == *b"Prsh" {
                            log::info!("Handling Fast Session Resumption (Prsh)");
                            // In Resumption mode, we skip DH and go straight to WaitConfirm1
                            // We need to derive keys NOW using the retained secret
                            let zid_i = self.peer_zid.as_ref().unwrap();
                            if let Some(rs1) = self.cache.get_secret(zid_i, "rs1") {
                                // S0 derivation for resumption uses null DH result
                                let null_dh = vec![0u8; 32];
                                let s0 = zrtp_crypto::kdf::derive_s0(
                                    &*self.hash_provider,
                                    &null_dh,
                                    b"ZRTP-HMAC-KDF",
                                    zid_i,
                                    &self.zid,
                                    &self.total_hash,
                                    Some(&rs1), None, None,
                                    None
                                );
                                self.derived_keys = zrtp_crypto::kdf::derive_session_keys(
                                    &*self.hash_provider,
                                    &s0,
                                    zid_i,
                                    &self.zid,
                                    &self.total_hash,
                                    16
                                ).ok();
                                
                                // Send Confirm1 directly
                                let conf1 = self.prepare_confirm1();
                                self.send_packet(conf1.to_bytes());
                                self.state = ZrtpState::WaitConfirm2;
                                return;
                            } else {
                                log::warn!("Prsh requested but no RS1 found, falling back (not implemented ideally here)");
                            }
                        }

                        // Send DHPart1 (Normal flow)
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
                            if !constant_time_eq(&h3, &peer_hello.hash_h3) {
                                log::error!("Hash chain verification (H1->H2->H3) failed!");
                                if self.options.enable_survival_mode {
                                    self.state = ZrtpState::SecurityWarning;
                                } else {
                                    self.state = ZrtpState::Error;
                                }
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
                                if !constant_time_eq(&mac[..8], &hello_data[mac_len..]) {
                                    log::error!("Hello HMAC verification failed!");
                                    if self.options.enable_survival_mode {
                                        self.state = ZrtpState::SecurityWarning;
                                    } else {
                                        self.state = ZrtpState::Error;
                                    }
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
                            if let Some(peer_pub) = &self.peer_public_key {
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
                                        rs1.as_deref(), rs2.as_deref(), None,
                                        None // Hybrid secret placeholder
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
                                    if let Some(k) = &self.derived_keys {
                                        self.cache.store_secret(zid_r, "rs1", &k.new_rs1);
                                    }
                                }
                            }
                            self.state = ZrtpState::WaitConfirm1;
                        }
                }
            }
            (ZrtpState::CommitSent, ZrtpEvent::Confirm1Received) => {
                log::info!("Initiator: Received Confirm1 during Resumption");
                self.state = ZrtpState::WaitConfirm1;
                self.handle_event(ZrtpEvent::Confirm1Received, packet_data);
            }
            (ZrtpState::WaitDHPart2, ZrtpEvent::DHPart2Received) => {
                if let Some(data) = packet_data {
                    if let Ok((_, dh2)) = DHPartPacket::parse(data) {
                        self.peer_dh_data = Some(data.to_vec());
                        self.peer_h1 = Some(dh2.hash_h1);

                        // Responder verification: H1 -> H2
                        if let Some(h2_expected) = self.peer_h2 {
                            let h2_computed = self.hash_provider.digest(&dh2.hash_h1);
                            if !constant_time_eq(&h2_computed, &h2_expected) {
                                log::error!("Hash chain verification (H1->H2) failed!");
                                self.state = ZrtpState::Error;
                                return;
                            }

                            // Verify Commit HMAC using peer_h1
                            if let Some(commit_data) = &self.peer_commit_data {
                                let mac_len = commit_data.len() - 8;
                                let mac = self.hash_provider.hmac(&dh2.hash_h1, &commit_data[..mac_len]);
                                if !constant_time_eq(&mac[..8], &commit_data[mac_len..]) {
                                    log::error!("Commit HMAC verification failed!");
                                    self.state = ZrtpState::Error;
                                    return;
                                }
                            }
                        }

                        self.peer_public_key = Some(dh2.public_value);
                        
                        if let (Some(peer_hvi), Some(peer_dh_bytes), Some(own_hello)) = (self.peer_hvi, self.peer_dh_data.as_ref(), self.own_hello_data.as_ref()) {
                            let mut data = peer_dh_bytes.to_vec();
                            data.extend_from_slice(own_hello); // My Hello (Responder)
                            let hash = self.hash_provider.digest(&data);
                            if !constant_time_eq(&hash, &peer_hvi) {
                                log::error!("HVI verification failed!");
                                self.state = ZrtpState::Error;
                                return;
                            }
                        }

                        // Compute shared secret
                        if let Some(peer_pub) = &self.peer_public_key {
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
                                    rs1.as_deref(), rs2.as_deref(), None,
                                    None // Hybrid secret placeholder
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
                                if let Some(k) = &self.derived_keys {
                                    self.cache.store_secret(zid_i, "rs1", &k.new_rs1);
                                }
                            }
                        }
                        
                        // Send Confirm1
                        let conf1 = self.prepare_confirm1();
                        self.send_packet(conf1.to_bytes());
                        self.state = ZrtpState::WaitConfirm2;
                    }
                }
            }
            (ZrtpState::WaitConfirm1, ZrtpEvent::Confirm1Received) => {
                if let (Some(data), Some(keys)) = (packet_data, self.derived_keys.as_ref()) {
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
                        if !constant_time_eq(&mac[..8], &conf1.hmac) {
                            log::error!("Confirm1 HMAC verification failed!");
                            self.state = ZrtpState::Error;
                            return;
                        }

                        if let Ok(plain) = self.cipher_provider.decrypt(&keys.confirm_key_r, &conf1.iv, &encrypted) {
                            let h0: [u8; 32] = plain[0..32].try_into().unwrap();
                            
                            // Verify H0 -> H1
                            if let Some(h1_expected) = self.peer_h1 {
                                let h1_computed = self.hash_provider.digest(&h0);
                                if !constant_time_eq(&h1_computed, &h1_expected) {
                                    log::error!("Hash chain verification (H0->H1) failed!");
                                    self.state = ZrtpState::Error;
                                    return;
                                }
                            }

                            // Verify DHPart HMAC using H0
                            if let Some(dh_data) = &self.peer_dh_data {
                                let mac_len = dh_data.len() - 8;
                                let mac = self.hash_provider.hmac(&h0, &dh_data[..mac_len]);
                                if !constant_time_eq(&mac[..8], &dh_data[mac_len..]) {
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
                if let Some(keys) = &self.derived_keys {
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
                
                // Initialize Initiator Ratchet if enabled
                if self.options.enable_ratchet {
                    if let Some(keys) = &self.derived_keys {
                        self.initiator_ratchet = Some(ZrtpRatchet::new(keys.srtp_key_i.clone()));
                        self.responder_ratchet = Some(ZrtpRatchet::new(keys.srtp_key_r.clone()));
                        log::info!("Symmetric Ratchet initialized for both directions.");
                    }
                }

                self.state = ZrtpState::Secure;
            }
            (ZrtpState::WaitConfirm2, ZrtpEvent::Confirm2Received) => {
                if let (Some(data), Some(keys)) = (packet_data, self.derived_keys.as_ref()) {
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
                        if !constant_time_eq(&mac[..8], &conf2.hmac) {
                            log::error!("Confirm2 HMAC verification failed!");
                            if self.options.enable_survival_mode {
                                self.state = ZrtpState::SecurityWarning;
                            } else {
                                self.state = ZrtpState::Error;
                            }
                            return;
                        }

                        if let Ok(plain) = self.cipher_provider.decrypt(&keys.confirm_key_i, &conf2.iv, &encrypted) {
                            let h0: [u8; 32] = plain[0..32].try_into().unwrap();
                            
                            // Verify H0 -> H1
                            if let Some(h1_expected) = self.peer_h1 {
                                let h1_computed = self.hash_provider.digest(&h0);
                                if !constant_time_eq(&h1_computed, &h1_expected) {
                                    log::error!("Hash chain verification (H0->H1) failed!");
                                    if self.options.enable_survival_mode {
                                        self.state = ZrtpState::SecurityWarning;
                                    } else {
                                        self.state = ZrtpState::Error;
                                    }
                                    return;
                                }
                            }

                            // Verify DHPart HMAC using H0
                            if let Some(dh_data) = &self.peer_dh_data {
                                let mac_len = dh_data.len() - 8;
                                let mac = self.hash_provider.hmac(&h0, &dh_data[..mac_len]);
                                if !constant_time_eq(&mac[..8], &dh_data[mac_len..]) {
                                    log::error!("DHPart HMAC verification failed!");
                                    if self.options.enable_survival_mode {
                                        self.state = ZrtpState::SecurityWarning;
                                    } else {
                                        self.state = ZrtpState::Error;
                                    }
                                    return;
                                }
                            }
                        }
                    }
                }

                // Initialize Responder Ratchet if enabled
                if self.options.enable_ratchet {
                    if let Some(keys) = &self.derived_keys {
                        self.initiator_ratchet = Some(ZrtpRatchet::new(keys.srtp_key_i.clone()));
                        self.responder_ratchet = Some(ZrtpRatchet::new(keys.srtp_key_r.clone()));
                        log::info!("Symmetric Ratchet initialized for both directions.");
                    }
                }

                self.state = ZrtpState::Secure;
            }
            (ZrtpState::Discovery, ZrtpEvent::Timeout) | (ZrtpState::AckSent, ZrtpEvent::Timeout) => {
                if self.retry_count < 10 {
                    if let Some(pkt) = &self.sent_packet {
                        self.message_queue.push_back(pkt.clone());
                    }
                    self.retry_count += 1;
                } else {
                    self.state = ZrtpState::Error;
                }
            }
            (_, ZrtpEvent::GoClearReceived) => {
                log::warn!("GoClear received but ignored in current implementation (Manual confirmation required)");
                if self.options.enable_survival_mode {
                     self.state = ZrtpState::SecurityWarning;
                }
            }
            (_, ZrtpEvent::Error(code)) => {
                log::error!("Received ZRTP Error packet: code {}", code);
                if !self.options.enable_survival_mode {
                    self.state = ZrtpState::Error;
                } else {
                    self.state = ZrtpState::SecurityWarning;
                }
            }
            _ => {
                log::warn!("Unhandled event {:?} in state {:?}", event, self.state);
                // Security: If we get a protocol packet in an illegal state, it might be an attack
                match event {
                    ZrtpEvent::CommitReceived | ZrtpEvent::DHPart1Received | ZrtpEvent::DHPart2Received | 
                    ZrtpEvent::Confirm1Received | ZrtpEvent::Confirm2Received => {
                        log::error!("Received protocol packet {:?} in illegal state {:?}", event, self.state);
                        if !self.options.enable_survival_mode {
                            self.state = ZrtpState::Error;
                        } else {
                            self.state = ZrtpState::SecurityWarning;
                        }
                    }
                    _ => {}
                }
            }
        }

        if self.state != old_state {
            if let Some(observer) = &self.observer {
                observer.on_state_change(self.state);
            }
        }
    }
}
