/*
 * Copyright 2026 - Francisco F. Pinochet
 */

use zrtp_core::{ZrtpContext, ZrtpEvent, ZrtpState, ZrtpOptions};
use zrtp_crypto::backends::Sha256;
use zrtp_proto::packets::*;

#[test]
fn test_fragmentation_and_reassembly() {
    let _ = env_logger::builder().is_test(true).try_init();
    
    let mut options = ZrtpOptions::default();
    options.enable_fragmentation = true;
    options.fragmentation_threshold = 100; // Very low threshold for testing

    let mut alice = ZrtpContext::new(
        [0x11; 12],
        Box::new(Sha256),
        Box::new(zrtp_crypto::backends::X25519::default()),
        Box::new(zrtp_crypto::backends::AesCfb128),
        Box::new(zrtp_cache::InMemoryCache::new()),
        options
    );

    // Create a large Hello packet (padded with many algs to exceed 100 bytes)
    let mut hello = HelloPacket {
        header: ZrtpPacketHeader {
            zrtp_id: zrtp_proto::packets::header::ZRTP_ID,
            length: 22, // Standard is 22 words (88 bytes), but we will add more
            message_type: HelloPacket::MESSAGE_TYPE,
        },
        version: *b"1.10",
        client_id: *b"TestClient      ",
        hash_h3: [0u8; 32],
        zid: [0u8; 12],
        flags: 0,
        num_hash: 1,
        num_cipher: 1,
        num_auth: 1,
        num_key_agreement: 1,
        num_sas: 1,
        algs: Vec::new(),
        hmac: [0u8; 8],
    };
    
    // Add 15 dummy algorithms
    for _ in 0..15 {
        hello.algs.extend_from_slice(b"DUMY");
    }
    hello.num_hash = 10;
    hello.num_cipher = 5;
    hello.num_auth = 0;
    hello.num_key_agreement = 0;
    hello.num_sas = 0;
    // Total 15 * 4 = 60 bytes.
    hello.header.length = (80 + 60 + 8) / 4; // 148 bytes = 37 words

    let large_packet = hello.to_bytes();
    assert!(large_packet.len() > 100);

    // Send the large packet through Alice
    alice.send_packet(large_packet.clone());

    // Alice should have produced multiple fragments in the queue
    assert!(alice.message_queue.len() > 1);
    
    // Now Bob receives these fragments
    let mut bob = ZrtpContext::new(
        [0x22; 12],
        Box::new(Sha256),
        Box::new(zrtp_crypto::backends::X25519::default()),
        Box::new(zrtp_crypto::backends::AesCfb128),
        Box::new(zrtp_cache::InMemoryCache::new()),
        ZrtpOptions::default()
    );

    // Bobs needs to start as well
    bob.handle_event(ZrtpEvent::Start, None);
    println!("Initial Bob state: {:?}", bob.state);

    // Collect fragments from Alice and give them to Bob
    while let Some(frag) = alice.message_queue.pop_front() {
        println!("Bob receiving fragment of size {}", frag.len());
        bob.receive_packet(&frag);
    }

    println!("Final Bob state: {:?}", bob.state);
    // Bob should have reassembled the packet and transitioned to Discovery state
    // (Wait, HelloReceived triggers Discovery -> AckSent if in Initial or Discovery)
    assert_eq!(bob.state, ZrtpState::AckSent);
    assert!(bob.peer_hello.is_some());
}
