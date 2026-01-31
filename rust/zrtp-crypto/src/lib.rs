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

//! ZRTP Cryptographic Primitives.
//! 
//! This crate defines traits for hashing, Diffie-Hellman, and symmetric 
//! encryption, along with their implementations and ZRTP-specific key 
//! derivation functions.

pub mod traits;
pub mod backends;
pub mod kdf;
pub mod sas;

pub use traits::*;
pub use kdf::*;
pub use sas::*;
