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

//! FFI bindings for the ZRTP Rust engine.
//! 
//! This crate provides a C-compatible interface to the `zrtp-core` engine,
//! allowing it to be integrated into C and C++ projects.

use zrtp_core::{ZrtpContext, ZrtpEvent};
use zrtp_crypto::backends::{Sha256, X25519};
use libc::size_t;
use std::ptr;

/// Creates a new ZRTP context for a given ZID.
/// 
/// # Safety
/// The `zid` pointer must point to at least 12 bytes of valid memory.
#[no_mangle]
pub extern "C" fn zrtp_context_new(zid: *const u8) -> *mut ZrtpContext {
    if zid.is_null() {
        return ptr::null_mut();
    }
    let mut zid_arr = [0u8; 12];
    unsafe {
        ptr::copy_nonoverlapping(zid, zid_arr.as_mut_ptr(), 12);
    }
    
    let context = ZrtpContext::new(
        zid_arr,
        Box::new(Sha256),
        Box::new(X25519::default()),
        Box::new(zrtp_crypto::backends::AesCfb128)
    );
    Box::into_raw(Box::new(context))
}

/// Frees a ZRTP context previously created by `zrtp_context_new`.
/// 
/// # Safety
/// The `ctx` pointer must be a valid pointer to a `ZrtpContext` or null.
#[no_mangle]
pub extern "C" fn zrtp_context_free(ctx: *mut ZrtpContext) {
    if !ctx.is_null() {
        unsafe {
            let _ = Box::from_raw(ctx);
        }
    }
}

/// Handles a protocol event and optional packet data.
/// 
/// # Safety
/// The `ctx` pointer must be valid. If `data` is not null, it must point to at 
/// least `len` bytes of valid memory.
#[no_mangle]
pub extern "C" fn zrtp_handle_event(
    ctx: *mut ZrtpContext,
    event: i32,
    data: *const u8,
    len: size_t
) {
    let context = unsafe {
        match ctx.as_mut() {
            Some(c) => c,
            None => return,
        }
    };

    let z_event = match event {
        0 => ZrtpEvent::Start,
        1 => ZrtpEvent::HelloReceived,
        2 => ZrtpEvent::HelloAckReceived,
        3 => ZrtpEvent::CommitReceived,
        // ... add more mapping
        _ => return,
    };

    let packet_data = if data.is_null() || len == 0 {
        None
    } else {
        Some(unsafe { std::slice::from_raw_parts(data, len) })
    };

    context.handle_event(z_event, packet_data);
}

/// Retrieves the next message from the engine's output queue.
/// 
/// Returns the number of bytes copied into `buf`. If the buffer is too small, 
/// the message is truncated. Returns 0 if no message is available.
/// 
/// # Safety
/// The `ctx` pointer must be valid. `buf` must point to at least `max_len` bytes 
/// of valid memory.
#[no_mangle]
pub extern "C" fn zrtp_get_message(
    ctx: *mut ZrtpContext,
    buf: *mut u8,
    max_len: size_t
) -> size_t {
    let context = unsafe {
        match ctx.as_mut() {
            Some(c) => c,
            None => return 0,
        }
    };

    if let Some(msg) = context.message_queue.pop_front() {
        let len = std::cmp::min(msg.len(), max_len);
        unsafe {
            ptr::copy_nonoverlapping(msg.as_ptr(), buf, len);
        }
        len
    } else {
        0
    }
}

/// Returns the current numeric state of the protocol engine.
/// 
/// # Safety
/// The `ctx` pointer must be valid.
#[no_mangle]
pub extern "C" fn zrtp_get_state(ctx: *mut ZrtpContext) -> i32 {
    let context = unsafe {
        match ctx.as_ref() {
            Some(c) => c,
            None => return -1,
        }
    };
    context.state as i32
}
