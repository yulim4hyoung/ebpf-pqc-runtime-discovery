# Real TLS 1.3 handshake: PQC hybrid group vs classical group

| Case | Crypto ev | RNG ev | PQC ev | Anchored PQC | Max conf | APIs |
|---|---:|---:|---:|---:|---:|---|
| pqc_kem | 8 | 27 | 3 | 3 | 1.0 | EVP_PKEY_decapsulate×3, EVP_PKEY_encapsulate×3, EVP_PKEY_keygen×2 |
| classical_x25519 | 2 | 26 | 0 | 0 | 1.0 | EVP_PKEY_keygen×2 |

- **pqc_kem** algorithms attributed: {'X25519MLKEM768': 3, 'X25519': 1}
- **classical_x25519** algorithms attributed: {'X25519': 1}

> Server and client both run as "openssl" and are aggregated together within each case; the two cases (pqc_kem vs classical_x25519) are separate monitored sessions, so there is no cross-contamination between them.
