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

/// Represents the various states of the ZRTP protocol state machine.
/// 
/// These states follow the logic defined in RFC 6189.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ZrtpState {
    /// Initial state before any protocol interaction.
    Initial,
    /// Discovery phase (sending Hello packets).
    Discovery,
    /// We sent a HelloAck and are waiting for the peer's reaction.
    AckSent,
    /// We detected the peer's HelloAck.
    AckDetected,
    /// Waiting for a Commit packet from the initiator.
    WaitCommit,
    /// Commit packet sent, waiting for DHPart1/2.
    CommitSent,
    /// Waiting for DHPart2 from the responder.
    WaitDHPart2,
    /// Waiting for Confirm1 packet.
    WaitConfirm1,
    /// Waiting for Confirm2 packet.
    WaitConfirm2,
    /// Waiting for Conf2Ack packet.
    WaitConf2Ack,
    /// Secure state (handshake completed).
    Secure,
    /// Security Warning state (e.g., MitM detected but Survivability is on).
    SecurityWarning,
    /// Error state.
    Error,
}

/// Represents the events that can trigger state transitions in the ZRTP engine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ZrtpEvent {
    /// Start the protocol engine.
    Start,
    /// Received a Hello packet.
    HelloReceived,
    /// Received a HelloAck packet.
    HelloAckReceived,
    /// Received a Commit packet.
    CommitReceived,
    /// Received a DHPart1 packet.
    DHPart1Received,
    /// Received a DHPart2 packet.
    DHPart2Received,
    /// Received a Confirm1 packet.
    Confirm1Received,
    /// Received a Confirm2 packet.
    Confirm2Received,
    /// Received a Conf2Ack packet.
    Conf2AckReceived,
    /// Received a GoClear packet.
    GoClearReceived,
    /// Retransmission timeout.
    Timeout,
    /// Protocol error occurred.
    Error(u32),
    /// Security warning (MitM detected).
    SecurityWarning(u32),
}
/// Protocol observer for state changes and events.
pub trait ZrtpObserver: Send + Sync {
    /// Called when the protocol changes state.
    fn on_state_change(&self, state: ZrtpState);
}
