# ZRTP Enhancements: Technical Design Reference

This document provides a detailed overview of the enhancements designed for the ZRTP Rust implementation. These features are modular, toggleable, and maintain full backward compatibility with RFC 6189.

## 1. Core Security Principles

- **Forward Secrecy**: Compromise of a long-term key (like a retained secret) or a single session key must not reveal past session data.
- **Post-Compromise Security**: Continuous or periodic Diffie-Hellman renewal ensures that if an endpoint is compromised, session security can be recovered once the compromise is cleared.
- **Zero Trust**: Assume endpoint vulnerability and continuously verify trust throughout the session duration.
- **Human-in-the-Loop**: Verbal SAS (Short Authentication String) remains the ultimate root of trust for identity verification.

---

## 2. Feature: Symmetric Ratchet

Designed for lightweight, continuous forward secrecy within a single ZRTP session.

### Mechanism
The session key is ratcheted periodically (e.g., every 100 audio packets or every 5 seconds).

- **Chain Key (CK)**: Initially derived from the ZRTP master secret (`s0`).
- **Logic**:
  ```
  new_chain_key = HMAC-SHA256(chain_key, "ratchet chain")
  msg_key       = HMAC-SHA256(new_chain_key, "ratchet msg")
  chain_key     = new_chain_key
  ```
- **Implementation Note**: Synchronize ratchet steps using the SRTP sequence number or a dedicated ZRTP signaling packet to avoid key desynchronization during packet loss.

---

## 3. Feature: Post-Quantum Hybrid (PQH)

Protects against "Harvest Now, Decrypt Later" attacks by quantum computers.

### Components
- **Key Encapsulation (KEM)**: ML-KEM-768 (Kyber) for confidentiality.
- **PQC Signatures**: Falcon-512 for ephemeral key authentication.

### Master Key Derivation
The master secret (`s_hybrid`) is a combination of the classical DH secret and the PQ secret:
```
s_hybrid = HKDF(s_classical || k_PQ, "hybrid master")
```

### Toggleable Modes
1. **Classic**: Standard X25519 (RFC 6189).
2. **PQ-Transition**: Classical DH + Kyber (Confidentiality focus).
3. **Full Hybrid**: Classical DH + Kyber + Falcon (Confidentiality + Authenticity).

---

## 4. Feature: Automated Signed Ephemerals

Enhances the SAS verification by allowing clients to verify pre-signed ephemeral keys.

- **Mechanism**: Endpoints exchange public identity keys out-of-band or via a PKI. Ephemeral DH keys are signed using these identity keys.
- **Impact**: Automates trust verification for frequent callers while preserving the verbal SAS check for initial or high-security sessions.

---

## 5. Backward Compatibility & Interoperability

- **Signaling**: Use new algorithm identifiers in the `Hello` packet:
  - `KYB1`: Kyber-768
  - `FAL5`: Falcon-512
  - `RTCH`: Symmetric Ratchet support
- **Fallback**: If a peer does not acknowledge these identifiers in their `Commit` or `Hello` packets, the engine **must** drop back to standard RFC 6189 behavior.

---

## 6. Performance & Optimization

- **Precomputation**: Generate ephemeral X25519 and Kyber keypairs during idle time to minimize handshake latency.
- **Packet Handling**: Falcon signatures (~666 bytes) exceed standard MTUs when combined with other ZRTP data. Use fragmented ZRTP messages or dedicated extension packets.
- **Ratchet Frequency**: Configurable. High frequency (per-packet) is safer but CPU-intensive; grouping (per-sec) is recommended for mobile devices.
