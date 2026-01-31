#include <cstdarg>
#include <cstdint>
#include <cstdlib>
#include <ostream>
#include <new>

extern "C" {

/// Creates a new ZRTP context for a given ZID.
///
/// # Safety
/// The `zid` pointer must point to at least 12 bytes of valid memory.
ZrtpContext *zrtp_context_new(const uint8_t *zid);

/// Frees a ZRTP context previously created by `zrtp_context_new`.
///
/// # Safety
/// The `ctx` pointer must be a valid pointer to a `ZrtpContext` or null.
void zrtp_context_free(ZrtpContext *ctx);

/// Handles a protocol event and optional packet data.
///
/// # Safety
/// The `ctx` pointer must be valid. If `data` is not null, it must point to at
/// least `len` bytes of valid memory.
void zrtp_handle_event(ZrtpContext *ctx, int32_t event, const uint8_t *data, size_t len);

/// Retrieves the next message from the engine's output queue.
///
/// Returns the number of bytes copied into `buf`. If the buffer is too small,
/// the message is truncated. Returns 0 if no message is available.
///
/// # Safety
/// The `ctx` pointer must be valid. `buf` must point to at least `max_len` bytes
/// of valid memory.
size_t zrtp_get_message(ZrtpContext *ctx, uint8_t *buf, size_t max_len);

/// Returns the current numeric state of the protocol engine.
///
/// # Safety
/// The `ctx` pointer must be valid.
int32_t zrtp_get_state(ZrtpContext *ctx);

} // extern "C"
