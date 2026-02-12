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

//! ZRTP Packet types and their implementations.

pub mod header;
pub mod hello;
pub mod commit;
pub mod dh_part;
pub mod confirm;
pub mod fragment;
pub mod other;

pub use header::{ZrtpPacketHeader, ZRTP_MAGIC, ZRTP_ID};
pub use hello::HelloPacket;
pub use commit::CommitPacket;
/// The DHPart packet is used to exchange Diffie-Hellman public values.
///
/// Defined in RFC 6189 Section 5.5 and 5.6 (DHPart1 and DHPart2).
pub use dh_part::DHPartPacket;
/// The Confirm packet is used to confirm the Diffie-Hellman key exchange.
///
/// Defined in RFC 6189 Section 5.7 (Confirm1 and Confirm2).
pub use confirm::ConfirmPacket;
pub use other::{GoClearPacket, ErrorPacket, GenericAckPacket};
