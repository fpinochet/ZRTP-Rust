#include "../rust/zrtp-ffi/zrtp-ffi.h"
#include <cstring>
#include <iomanip>
#include <iostream>
#include <vector>

void print_bytes(const std::string &label, const uint8_t *data, size_t len) {
  std::cout << label << ": ";
  for (size_t i = 0; i < len; ++i) {
    std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)data[i];
  }
  std::cout << std::dec << std::endl;
}

void on_zrtp_state_change(zrtp::ZrtpContext *ctx, int32_t state,
                          void *user_data) {
  const char *person = (const char *)user_data;
  std::cout << "[CALLBACK] " << person << " transitioned to state " << state
            << std::endl;
}

void perform_handshake(zrtp::ZrtpContext *alice, zrtp::ZrtpContext *bob) {
  if (!alice || !bob) {
    std::cerr << "Invalid ZRTP contexts" << std::endl;
    return;
  }

  zrtp::zrtp_set_status_callback(alice, on_zrtp_state_change, (void *)"Alice");
  zrtp::zrtp_set_status_callback(bob, on_zrtp_state_change, (void *)"Bob");

  zrtp::zrtp_handle_event(alice, 0, nullptr, 0); // Start
  zrtp::zrtp_handle_event(bob, 0, nullptr, 0);   // Start

  uint8_t buf[2048];
  size_t len;

  // Discovery
  len = zrtp::zrtp_get_message(alice, buf, sizeof(buf));
  zrtp::zrtp_handle_event(bob, 1, buf, len);

  len = zrtp::zrtp_get_message(bob, buf, sizeof(buf));
  zrtp::zrtp_handle_event(alice, 1, buf, len);

  len = zrtp::zrtp_get_message(alice, buf, sizeof(buf));
  len = zrtp::zrtp_get_message(bob, buf, sizeof(buf));
  zrtp::zrtp_handle_event(alice, 2, buf, len);

  len = zrtp::zrtp_get_message(alice, buf, sizeof(buf));
  zrtp::zrtp_handle_event(bob, 3, buf, len);

  len = zrtp::zrtp_get_message(bob, buf, sizeof(buf));
  zrtp::zrtp_handle_event(alice, 4, buf, len);

  len = zrtp::zrtp_get_message(alice, buf, sizeof(buf));
  zrtp::zrtp_handle_event(bob, 5, buf, len);

  len = zrtp::zrtp_get_message(bob, buf, sizeof(buf));
  zrtp::zrtp_handle_event(alice, 6, buf, len);

  len = zrtp::zrtp_get_message(alice, buf, sizeof(buf));
  zrtp::zrtp_handle_event(bob, 7, buf, len);

  if (zrtp::zrtp_get_state(alice) == 10) { // Secure
    char sas_str[5] = {0};
    zrtp::zrtp_get_sas_string(alice, (uint8_t *)sas_str);
    std::cout << "Handshake SECURE! SAS: " << sas_str << std::endl;

    uint8_t srtp_key[16];
    zrtp::zrtp_get_srtp_key(alice, true, srtp_key, 16);
    print_bytes("Alice SRTP Key", srtp_key, 16);
  }
}

int main() {
  uint8_t zid_alice[12] = {0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
                           0x11, 0x11, 0x11, 0x11, 0x11, 0x11};
  uint8_t zid_bob[12] = {0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
                         0x22, 0x22, 0x22, 0x22, 0x22, 0x22};

  std::cout << "--- SQLite Persistence Test ---" << std::endl;
  {
    zrtp::ZrtpContext *alice =
        zrtp::zrtp_context_new_with_db(zid_alice, "alice.db");
    zrtp::ZrtpContext *bob = zrtp::zrtp_context_new_with_db(zid_bob, "bob.db");
    perform_handshake(alice, bob);
    zrtp::zrtp_context_free(alice);
    zrtp::zrtp_context_free(bob);
  }
  {
    std::cout << "\n(Second Handshake with SQLite)" << std::endl;
    zrtp::ZrtpContext *alice =
        zrtp::zrtp_context_new_with_db(zid_alice, "alice.db");
    zrtp::ZrtpContext *bob = zrtp::zrtp_context_new_with_db(zid_bob, "bob.db");
    perform_handshake(alice, bob);
    zrtp::zrtp_context_free(alice);
    zrtp::zrtp_context_free(bob);
  }

  std::cout << "\n--- Legacy Binary File Persistence Test (names.zrid) ---"
            << std::endl;
  {
    zrtp::ZrtpContext *alice =
        zrtp::zrtp_context_new_with_file(zid_alice, "alice.zrid");
    zrtp::ZrtpContext *bob =
        zrtp::zrtp_context_new_with_file(zid_bob, "bob.zrid");
    perform_handshake(alice, bob);
    zrtp::zrtp_context_free(alice);
    zrtp::zrtp_context_free(bob);
  }
  {
    std::cout << "\n(Second Handshake with Binary File)" << std::endl;
    zrtp::ZrtpContext *alice =
        zrtp::zrtp_context_new_with_file(zid_alice, "alice.zrid");
    zrtp::ZrtpContext *bob =
        zrtp::zrtp_context_new_with_file(zid_bob, "bob.zrid");
    perform_handshake(alice, bob);
    zrtp::zrtp_context_free(alice);
    zrtp::zrtp_context_free(bob);
  }

  return 0;
}
