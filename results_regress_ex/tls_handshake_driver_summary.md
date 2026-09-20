# Real TLS 1.3 handshake: PQC hybrid group vs classical group

| Case | Crypto ev | RNG ev | PQC ev | Anchored PQC | Max conf | APIs |
|---|---:|---:|---:|---:|---:|---|
| pqc_kem | 11 | 27 | 7 | 7 | 1.0 | EVP_DigestSignInit_ex×2, EVP_DigestVerifyInit_ex×1, EVP_PKEY_decapsulate×3, EVP_PKEY_encapsulate×3, EVP_PKEY_keygen×2 |
| classical_x25519 | 5 | 26 | 0 | 0 | 1.0 | EVP_DigestSignInit_ex×2, EVP_DigestVerifyInit_ex×1, EVP_PKEY_keygen×2 |

- **pqc_kem** algorithms attributed: {'X25519MLKEM768': 5, 'ML-KEM-768': 2, 'X25519': 1}
- **classical_x25519** algorithms attributed: {'X25519': 2}

> Server and client both run as "openssl" and are aggregated together within each case; the two cases (pqc_kem vs classical_x25519) are separate monitored sessions, so there is no cross-contamination between them.
