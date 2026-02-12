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

use zrtp_core::{ZrtpContext, ZrtpEvent, ZrtpOptions};
use zrtp_crypto::backends::{Sha256, X25519};
use libc::size_t;
use std::ptr;
use zrtp_crypto::sas::render_sas_base32;

/// Callback for state changes.
pub type ZrtpStatusCallback = extern "C" fn(ctx: *mut ZrtpContext, state: i32, user_data: *mut libc::c_void);

/// Creates a new ZRTP context for a given ZID.
/// 
/// This is the base function for creating a context without persistent storage.
/// In-memory caching will be used.
/// 
/// # Arguments
/// * `zid` - Pointer to a 12-byte array containing the own ZID.
/// 
/// # Returns
/// A pointer to the newly created `ZrtpContext`. Must be freed using `zrtp_context_free`.
/// 
/// # Safety
/// The `zid` pointer must point to at least 12 bytes of valid memory.
#[no_mangle]
pub unsafe extern "C" fn zrtp_context_new(zid: *const u8) -> *mut ZrtpContext {
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
        Box::new(zrtp_crypto::backends::AesCfb128),
        Box::new(zrtp_cache::InMemoryCache::new()),
        ZrtpOptions::default()
    );
    Box::into_raw(Box::new(context))
}

/// Creates a new ZRTP context with a persistent SQLite cache.
/// 
/// Use this if you want to store retained secrets in a modern, atomic database.
/// 
/// # Arguments
/// * `zid` - Pointer to a 12-byte array containing the own ZID.
/// * `db_path` - Null-terminated string containing the path to the SQLite file.
/// 
/// # Returns
/// A pointer to the `ZrtpContext`, or NULL if the database could not be opened.
/// 
/// # Safety
/// The `zid` pointer must point to at least 12 bytes. `db_path` must be a null-terminated string.
#[no_mangle]
pub unsafe extern "C" fn zrtp_context_new_with_db(zid: *const u8, db_path: *const libc::c_char) -> *mut ZrtpContext {
    let zid_arr = unsafe {
        let mut arr = [0u8; 12];
        if !zid.is_null() {
            ptr::copy_nonoverlapping(zid, arr.as_mut_ptr(), 12);
        }
        arr
    };

    let path = unsafe {
        if db_path.is_null() {
            return ptr::null_mut();
        }
        std::ffi::CStr::from_ptr(db_path).to_string_lossy().into_owned()
    };

    let cache = match zrtp_cache::SqliteCache::new(path) {
        Ok(c) => Box::new(c),
        Err(_) => return ptr::null_mut(),
    };

    let context = ZrtpContext::new(
        zid_arr,
        Box::new(Sha256),
        Box::new(X25519::default()),
        Box::new(zrtp_crypto::backends::AesCfb128),
        cache,
        ZrtpOptions::default()
    );
    Box::into_raw(Box::new(context))
}

/// Creates a new ZRTP context with a legacy binary file cache.
/// 
/// Use this for strict bit-compatible interoperability with the legacy C++ `names.zrid` format.
/// 
/// # Arguments
/// * `zid` - Pointer to a 12-byte array containing the own ZID.
/// * `file_path` - Null-terminated string containing the path to the binary cache file.
/// 
/// # Returns
/// A pointer to the `ZrtpContext`, or NULL if the file could not be opened.
/// 
/// # Safety
/// The `zid` pointer must point to at least 12 bytes. `file_path` must be a null-terminated string.
#[no_mangle]
pub unsafe extern "C" fn zrtp_context_new_with_file(zid: *const u8, file_path: *const libc::c_char) -> *mut ZrtpContext {
    let zid_arr = unsafe {
        let mut arr = [0u8; 12];
        if !zid.is_null() {
            ptr::copy_nonoverlapping(zid, arr.as_mut_ptr(), 12);
        }
        arr
    };

    let path = unsafe {
        if file_path.is_null() {
            return ptr::null_mut();
        }
        std::ffi::CStr::from_ptr(file_path).to_string_lossy().into_owned()
    };

    let cache = match zrtp_cache::BinaryFileCache::new(path, Some(zid_arr)) {
        Ok(c) => Box::new(c),
        Err(_) => return ptr::null_mut(),
    };

    let context = ZrtpContext::new(
        zid_arr,
        Box::new(Sha256),
        Box::new(X25519::default()),
        Box::new(zrtp_crypto::backends::AesCfb128),
        cache,
        ZrtpOptions::default()
    );
    Box::into_raw(Box::new(context))
}

/// Frees a ZRTP context previously created by `zrtp_context_new`.
/// 
/// # Safety
/// The `ctx` pointer must be a valid pointer to a `ZrtpContext` or null.
#[no_mangle]
pub unsafe extern "C" fn zrtp_context_free(ctx: *mut ZrtpContext) {
    if !ctx.is_null() {
        unsafe {
            let _ = Box::from_raw(ctx);
        }
    }
}

/// Handles a protocol event and optional packet data.
/// 
/// This is the main entry point for processing incoming packets and timer events.
/// 
/// # Arguments
/// * `ctx` - Pointer to the `ZrtpContext`.
/// * `event` - The event ID (e.g., 0=Start, 1=HelloReceived).
/// * `data` - Pointer to the raw packet buffer (can be NULL for events without packets).
/// * `len` - Length of the data buffer.
/// 
/// # Safety
/// The `ctx` pointer must be valid. If `data` is not null, it must point to at 
/// least `len` bytes of valid memory.
#[no_mangle]
pub unsafe extern "C" fn zrtp_handle_event(
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
        4 => ZrtpEvent::DHPart1Received,
        5 => ZrtpEvent::DHPart2Received,
        6 => ZrtpEvent::Confirm1Received,
        7 => ZrtpEvent::Confirm2Received,
        8 => ZrtpEvent::Timeout,
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
pub unsafe extern "C" fn zrtp_get_message(
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
pub unsafe extern "C" fn zrtp_get_state(ctx: *mut ZrtpContext) -> i32 {
    let context = unsafe {
        match ctx.as_ref() {
            Some(c) => c,
            None => return -1,
        }
    };
    context.state as i32
}

struct FfiObserver {
    ctx_ptr: *mut ZrtpContext,
    callback: ZrtpStatusCallback,
    user_data: *mut libc::c_void,
}

unsafe impl Send for FfiObserver {}
unsafe impl Sync for FfiObserver {}

impl zrtp_core::state::ZrtpObserver for FfiObserver {
    fn on_state_change(&self, state: zrtp_core::state::ZrtpState) {
        (self.callback)(self.ctx_ptr, state as i32, self.user_data);
    }
}

/// Sets a callback to be notified of protocol state changes.
/// 
/// # Safety
/// The `ctx` pointer must be valid.
#[no_mangle]
pub unsafe extern "C" fn zrtp_set_status_callback(
    ctx: *mut ZrtpContext,
    callback: ZrtpStatusCallback,
    user_data: *mut libc::c_void
) {
    let context = unsafe {
        match ctx.as_mut() {
            Some(c) => c,
            None => return,
        }
    };
    
    context.observer = Some(Box::new(FfiObserver {
        ctx_ptr: ctx,
        callback,
        user_data,
    }));
}
/// Retrieves the SAS as a 4-character Base32 string.
/// 
/// Returns 4 if SAS is available, 0 otherwise.
/// 
/// # Safety
/// The `ctx` pointer must be valid. `buf` must point to at least 4 bytes.
#[no_mangle]
pub unsafe extern "C" fn zrtp_get_sas_string(ctx: *mut ZrtpContext, buf: *mut u8) -> size_t {
    let context = unsafe {
        match ctx.as_ref() {
            Some(c) => c,
            None => return 0,
        }
    };

    if let Some(ref keys) = context.derived_keys {
        let sas = render_sas_base32(&keys.sas_hash);
        let len = std::cmp::min(sas.len(), 4);
        unsafe {
            ptr::copy_nonoverlapping(sas.as_ptr(), buf, len);
        }
        len
    } else {
        0
    }
}

/// Retrieves the SAS hash (32 bytes).
/// 
/// Returns 32 if keys are available, 0 otherwise.
/// 
/// # Safety
/// The `ctx` pointer must be valid. `sas` must point to at least 32 bytes of 
/// valid memory.
#[no_mangle]
pub unsafe extern "C" fn zrtp_get_sas(ctx: *mut ZrtpContext, sas: *mut u8) -> size_t {
    let context = unsafe {
        match ctx.as_ref() {
            Some(c) => c,
            None => return 0,
        }
    };

    if let Some(ref keys) = context.derived_keys {
        unsafe {
            ptr::copy_nonoverlapping(keys.sas_hash.as_ptr(), sas, 32);
        }
        32
    } else {
        0
    }
}

/// Retrieves the SRTP master key for the given role (Initiator or Responder).
/// 
/// # Safety
/// The `ctx` pointer must be valid. `key` must point to at least `key_len` bytes.
#[no_mangle]
pub unsafe extern "C" fn zrtp_get_srtp_key(
    ctx: *mut ZrtpContext,
    is_initiator: bool,
    key: *mut u8,
    key_len: size_t
) -> size_t {
    let context = unsafe {
        match ctx.as_ref() {
            Some(c) => c,
            None => return 0,
        }
    };

    if let Some(ref keys) = context.derived_keys {
        let src = if is_initiator { &keys.srtp_key_i } else { &keys.srtp_key_r };
        let len = std::cmp::min(src.len(), key_len);
        unsafe {
            ptr::copy_nonoverlapping(src.as_ptr(), key, len);
        }
        len
    } else {
        0
    }
}

/// Retrieves the SRTP master salt for the given role (Initiator or Responder).
/// 
/// # Safety
/// The `ctx` pointer must be valid. `salt` must point to at least 14 bytes.
#[no_mangle]
pub unsafe extern "C" fn zrtp_get_srtp_salt(
    ctx: *mut ZrtpContext,
    is_initiator: bool,
    salt: *mut u8
) -> size_t {
    let context = unsafe {
        match ctx.as_ref() {
            Some(c) => c,
            None => return 0,
        }
    };

    if let Some(ref keys) = context.derived_keys {
        let src = if is_initiator { &keys.srtp_salt_i } else { &keys.srtp_salt_r };
        let len = std::cmp::min(src.len(), 14);
        unsafe {
            ptr::copy_nonoverlapping(src.as_ptr(), salt, len);
        }
        len
    } else {
        0
    }
}

/// C-compatible options for ZRTP enhancements.
#[repr(C)]
pub struct ZrtpOptionsFFI {
    pub enable_ratchet: bool,
    pub ratchet_interval: u32,
    pub enable_pqc_kem: bool,
    pub enable_pqc_sig: bool,
    pub enable_fragmentation: bool,
    pub fragmentation_threshold: u16,
    pub enable_adaptive_timer: bool,
    pub enable_survival_mode: bool,
}

/// Configures the ZRTP context with modern enhancements.
/// 
/// # Safety
/// The `ctx` pointer must be valid. `options` must be a valid pointer.
#[no_mangle]
pub unsafe extern "C" fn zrtp_context_configure(ctx: *mut ZrtpContext, options: *const ZrtpOptionsFFI) {
    let context = unsafe {
        match ctx.as_mut() {
            Some(c) => c,
            None => return,
        }
    };
    let opts = unsafe { 
        match options.as_ref() {
            Some(o) => o,
            None => return,
        }
    };
    context.options = ZrtpOptions {
        enable_ratchet: opts.enable_ratchet,
        ratchet_interval: opts.ratchet_interval,
        enable_pqc_kem: opts.enable_pqc_kem,
        enable_pqc_sig: opts.enable_pqc_sig,
        enable_fragmentation: opts.enable_fragmentation,
        fragmentation_threshold: opts.fragmentation_threshold,
        enable_adaptive_timer: opts.enable_adaptive_timer,
        enable_survival_mode: opts.enable_survival_mode,
    };
}

/// Advances the symmetric ratchet and retrieves the next SRTP master key.
/// 
/// Use this if the ratchet is enabled to update the session key periodically.
/// 
/// # Safety
/// The `ctx` pointer must be valid. `key_buf` must point to at least 32 bytes.
#[no_mangle]
pub unsafe extern "C" fn zrtp_ratchet_next_key(
    ctx: *mut ZrtpContext,
    is_initiator: bool,
    key_buf: *mut u8
) -> size_t {
    let context = unsafe {
        match ctx.as_mut() {
            Some(c) => c,
            None => return 0,
        }
    };

    let ratchet = if is_initiator {
        &mut context.initiator_ratchet
    } else {
        &mut context.responder_ratchet
    };

    if let Some(ref mut r) = ratchet {
        let key = r.next_key(&*context.hash_provider);
        unsafe {
            ptr::copy_nonoverlapping(key.as_ptr(), key_buf, key.len());
        }
        key.len()
    } else {
        0
    }
}
