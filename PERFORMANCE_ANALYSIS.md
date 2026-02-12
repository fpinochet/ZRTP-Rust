# ZRTP Enhancements: Performance & VoIP Impact Analysis

This analysis evaluates the impact of the proposed security enhancements (Symmetric Ratchet, PQ Hybrid, Signed Ephemerals) on VoIP performance and connection reliability.

## 1. Handshake Latency (Time-to-Secure)

### Classical vs. Hybrid Overhead
- **Standard (X25519)**: ~0.5ms computation.
- **Hybrid (X25519 + Kyber-768)**:
  - Kyber-768 Encapsulation/Decapsulation: ~0.1 - 0.2ms.
  - Total computational overhead is negligible (< 1ms).
- **Bottleneck**: The primary delay is **network-bound**. Kyber ciphertexts (~1kB) and Falcon signatures (~666b) increase the data transferred during the discovery and DH phases.

### Mitigation: Precomputation
To eliminate "Initial Silence" (the delay between call pickup and secure audio):
- **Strategy**: The engine should pre-generate X25519 and Kyber keypairs during the "Ringing" phase or while the app is idle.
- **Impact**: Reduces handshake computational time to almost zero at the moment of connection.

---

## 2. Network Overhead & Fragmentation

### Packet Sizes
| Feature | Packet Type | Delta Size | Total Size (Est.) |
| :--- | :--- | :--- | :--- |
| Standard | Hello / Commit | - | ~100 - 150 bytes |
| PQ Hybrid | Hello / Commit | +1024 bytes (Kyber) | ~1.2 KB |
| Signed Ephem | DHPart | +666 bytes (Falcon) | ~1.1 KB |

### The Fragmentation Risk
Most VoIP (UDP) packets are handled best under the standard MTU of **1500 bytes**.
- **Observation**: Even with Kyber and Falcon, the total packet size remains under 1500 bytes.
- **Risk**: Over certain VPNs or LTE/Satellite links, the MTU might be as low as **1280 bytes**. 
- **Recommendation**: Implement **ZRTP Message Fragmentation** (as per RFC 6189 Section 5.11) if packet sizes exceed 1200 bytes to ensure reliability over restrictive networks.

---

## 3. Real-time Audio Impact (Symmetric Ratchet)

### Computational Cost (Per Ratchet)
- **HMAC-SHA256**: Extremely fast (micro-benchmarks show > 500 MB/s on modern ARM/x86).
- **Per Packet Ratchet**: Adds ~1-2µs per packet.
- **Grouped Ratchet (Recommended)**: Adds zero noticeable latency to the audio path.

### Jitter Buffer & Packet Loss
- **The Sync Problem**: If the initiator ratchets at packet #100 but packet #100 is lost, the responder will fail to decrypt packet #101.
- **Solution**: The ratchet should be keyed to the **SRTP Master Key change mechanism** or signaled via a low-bitrate in-band metadata field to maintain sync during jitter.

---

## 4. Hardware Resources (Mobile/IoT)

### Battery Life
- **PQC Algorithms**: Kyber is specifically designed to be efficient. On mobile devices (iOS/Android), the energy impact of a single handshake is less than 0.01% of a typical call's total energy consumption.
- **Continuous Ratchet**: While low-cost, a per-packet ratchet increases the "always-on" CPU cycles. 
- **Optimized Frequency**: 1 ratchet per 1 second of audio provides excellent post-compromise security with zero meaningful battery impact.

---

## 5. Security vs. Performance Matrix

| Feature | Security Gain | Performance Cost | Recommendation |
| :--- | :--- | :--- | :--- |
| **Ratchet** | High (Post-Compromise) | Low | Enable by default (1s interval) |
| **Kyber (PQ)** | Critical (Future-proof) | Medium (Bandwidth) | Enable for high-security profiles |
| **Falcon (Sig)** | High (Identity) | Medium (Latency) | Use with pre-existing Identity Keys |

**Conclusion**: The enhancements are viable for modern VoIP applications. The primary focus for dev should be **robust packet fragmentation** and **key precomputation** to maintain the "instant-on" feel of traditional telephony.
