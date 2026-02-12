/*
 * Copyright 2026 - Francisco F. Pinochet
 */

use zrtp_core::{ZrtpContext, ZrtpEvent, ZrtpState, ZrtpOptions};
use zrtp_crypto::backends::Sha256;
use zrtp_proto::packets::*;

#[test]
fn test_fast_session_resumption() {
    let _ = env_logger::builder().is_test(true).try_init();
    
    let db_path = "test_resumption.db";
    let _ = std::fs::remove_file(db_path);
    
    // Alice and Bob share the SAME DB file via separate connection objects
    // This simulates real-world persistence.
    
    // 1. First handshake to establish a retained secret
    {
        let mut alice = ZrtpContext::new(
            [0x11; 12],
            Box::new(Sha256),
            Box::new(zrtp_crypto::backends::X25519::default()),
            Box::new(zrtp_crypto::backends::AesCfb128),
            Box::new(zrtp_cache::SqliteCache::new(db_path).unwrap()),
            ZrtpOptions::default()
        );
        let mut bob = ZrtpContext::new(
            [0x22; 12],
            Box::new(Sha256),
            Box::new(zrtp_crypto::backends::X25519::default()),
            Box::new(zrtp_crypto::backends::AesCfb128),
            Box::new(zrtp_cache::SqliteCache::new(db_path).unwrap()), // Same DB for shared storage
            ZrtpOptions::default()
        );

        // Perform full handshake
        alice.receive_packet(&[]); // Trigger start? No, use handle_event
        alice.handle_event(ZrtpEvent::Start, None);
        bob.handle_event(ZrtpEvent::Start, None);
        println!("Alice initial state: {:?}", alice.state);
        println!("Bob initial state: {:?}", bob.state);
        
        let a_hello = alice.message_queue.pop_front().expect("Alice Hello missing");
        let b_hello = bob.message_queue.pop_front().expect("Bob Hello missing");
        
        println!("Alice receiving Bob's Hello...");
        alice.receive_packet(&b_hello);
        println!("Alice state after receiving Hello: {:?}", alice.state);
        
        let _a_ack = alice.message_queue.pop_front().expect("Alice Ack missing");
        
        println!("Bob receiving Alice's Hello...");
        bob.receive_packet(&a_hello);
        let b_ack = bob.message_queue.pop_front().unwrap();
        
        alice.receive_packet(&b_ack);
        let a_commit = alice.message_queue.pop_front().unwrap();
        bob.receive_packet(&a_commit);
        let b_dh1 = bob.message_queue.pop_front().unwrap();
        alice.receive_packet(&b_dh1);
        let a_dh2 = alice.message_queue.pop_front().unwrap();
        bob.receive_packet(&a_dh2);
        let b_conf1 = bob.message_queue.pop_front().unwrap();
        alice.receive_packet(&b_conf1);
        let a_conf2 = alice.message_queue.pop_front().unwrap();
        bob.receive_packet(&a_conf2);
        
        assert_eq!(alice.state, ZrtpState::Secure);
        assert_eq!(bob.state, ZrtpState::Secure);
    }

    // 2. Second handshake - should use Resumption
    {
        let mut alice = ZrtpContext::new(
            [0x11; 12],
            Box::new(Sha256),
            Box::new(zrtp_crypto::backends::X25519::default()),
            Box::new(zrtp_crypto::backends::AesCfb128),
            Box::new(zrtp_cache::SqliteCache::new(db_path).unwrap()),
            ZrtpOptions::default()
        );
        let mut bob = ZrtpContext::new(
            [0x22; 12],
            Box::new(Sha256),
            Box::new(zrtp_crypto::backends::X25519::default()),
            Box::new(zrtp_crypto::backends::AesCfb128),
            Box::new(zrtp_cache::SqliteCache::new(db_path).unwrap()),
            ZrtpOptions::default()
        );

        alice.handle_event(ZrtpEvent::Start, None);
        bob.handle_event(ZrtpEvent::Start, None);
        
        let a_hello = alice.message_queue.pop_front().unwrap();
        let b_hello = bob.message_queue.pop_front().unwrap();
        
        alice.receive_packet(&b_hello);
        let _a_ack = alice.message_queue.pop_front().unwrap();
        bob.receive_packet(&a_hello);
        let b_ack = bob.message_queue.pop_front().unwrap();
        
        // Alice receives Bob's Ack and should send a Prsh Commit
        alice.receive_packet(&b_ack);
        let a_commit = alice.message_queue.pop_front().unwrap();
        
        // Verify it's a Prsh commit
        if let Ok((_, commit)) = CommitPacket::parse(&a_commit) {
            assert_eq!(commit.key_agreement_alg, *b"Prsh");
        } else {
            panic!("Failed to parse resumption commit");
        }

        // Bob receives Prsh Commit and should send Confirm1 immediately
        bob.receive_packet(&a_commit);
        assert_eq!(bob.state, ZrtpState::WaitConfirm2);
        let b_conf1 = bob.message_queue.pop_front().unwrap();
        
        // Alice receives Confirm1 and should go Secure
        alice.receive_packet(&b_conf1);
        assert_eq!(alice.state, ZrtpState::Secure);
        let a_conf2 = alice.message_queue.pop_front().unwrap();
        
        // Bob receives Confirm2 and should go Secure
        bob.receive_packet(&a_conf2);
        assert_eq!(bob.state, ZrtpState::Secure);
        
        println!("Fast Resumption Handshake SECURE!");
    }
}
