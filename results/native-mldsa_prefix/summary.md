# Native OpenSSL 3.5 ML-DSA vs liboqs detection

| Case | Crypto ev | RNG ev | PQC ev | Anchored PQC | Max conf | APIs |
|---|---:|---:|---:|---:|---:|---|
| native_evp | 1 | 3 | 0 | 0 | 0.5 | EVP_PKEY_keygen×1 |
| native_cli | 1 | 5 | 1 | 1 | 1.0 | EVP_PKEY_keygen×1 |
| liboqs | 3 | 6 | 3 | 3 | 1.0 | OQS_SIG_keypair×1, OQS_SIG_sign×1, OQS_SIG_verify×1 |

- **native_evp** algorithms attributed: none
- **native_cli** algorithms attributed: {'ML-DSA-65': 1}
- **liboqs** algorithms attributed: {'ML-DSA-65': 3}

> Note: sign/verify events are expected to carry no algorithm name (same EVP_PKEY_CTX_new_from_pkey gap as ML-KEM encaps/decaps, Sect. 4.6) until task ④ closes it. Only the keygen event should show a non-empty algorithm and confidence 1.0.
