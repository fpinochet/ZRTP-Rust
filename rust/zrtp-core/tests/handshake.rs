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

use zrtp_core::{ZrtpContext, ZrtpState, ZrtpEvent};
use zrtp_crypto::backends::{Sha256, X25519};

#[test]
fn test_full_zrtp_handshake() {
    let mut alice = ZrtpContext::new(
        [0x11; 12],
        Box::new(Sha256),
        Box::new(X25519::default()),
        Box::new(zrtp_crypto::backends::AesCfb128)
    );
    let mut bob = ZrtpContext::new(
        [0x22; 12],
        Box::new(Sha256),
        Box::new(X25519::default()),
        Box::new(zrtp_crypto::backends::AesCfb128)
    );

    // 1. Initial Start
    alice.handle_event(ZrtpEvent::Start, None);
    bob.handle_event(ZrtpEvent::Start, None);
    
    // Capture Hellos
    let alice_hello_raw = alice.message_queue.pop_front().unwrap();
    let bob_hello_raw = bob.message_queue.pop_front().unwrap();

    // 2. Discovery
    alice.handle_event(ZrtpEvent::HelloReceived, Some(&bob_hello_raw));
    let _alice_ack = alice.message_queue.pop_front().unwrap();
    
    bob.handle_event(ZrtpEvent::HelloReceived, Some(&alice_hello_raw));
    let bob_ack = bob.message_queue.pop_front().unwrap();

    // 3. Alice becomes Initiator
    alice.handle_event(ZrtpEvent::HelloAckReceived, Some(&bob_ack));
    assert_eq!(alice.state, ZrtpState::CommitSent);
    let alice_commit_raw = alice.message_queue.pop_front().unwrap();

    // 4. Bob receives Commit, becomes Responder
    bob.handle_event(ZrtpEvent::CommitReceived, Some(&alice_commit_raw));
    assert_eq!(bob.state, ZrtpState::WaitDHPart2);
    let bob_dh1_raw = bob.message_queue.pop_front().unwrap();

    // 5. Alice receives DHPart1, sends DHPart2
    alice.handle_event(ZrtpEvent::DHPart1Received, Some(&bob_dh1_raw));
    assert_eq!(alice.state, ZrtpState::WaitConfirm1);
    let alice_dh2_raw = alice.message_queue.pop_front().unwrap();

    // 6. Bob receives DHPart2, sends Confirm1
    bob.handle_event(ZrtpEvent::DHPart2Received, Some(&alice_dh2_raw));
    assert_eq!(bob.state, ZrtpState::WaitConfirm2);
    let bob_conf1_raw = bob.message_queue.pop_front().unwrap();

    // 7. Alice receives Confirm1, sends Confirm2
    alice.handle_event(ZrtpEvent::Confirm1Received, Some(&bob_conf1_raw));
    assert_eq!(alice.state, ZrtpState::Secure);
    let alice_conf2_raw = alice.message_queue.pop_front().unwrap();

    // 8. Bob receives Confirm2
    bob.handle_event(ZrtpEvent::Confirm2Received, Some(&alice_conf2_raw));
    assert_eq!(bob.state, ZrtpState::Secure);

    // 9. Verify SAS Agreement
    let alice_sas = alice.derived_keys.as_ref().unwrap().sas_hash.clone();
    let bob_sas = bob.derived_keys.as_ref().unwrap().sas_hash.clone();
    assert_eq!(alice_sas, bob_sas);
    println!("Handshake SECURE! SAS: {}", zrtp_crypto::sas::render_sas_base32(&alice_sas));
}
