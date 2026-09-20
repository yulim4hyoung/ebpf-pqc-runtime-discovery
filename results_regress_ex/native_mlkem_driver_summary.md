# Native OpenSSL 3.5 ML-KEM vs liboqs detection

| Case | Crypto ev | RNG ev | PQC ev | Anchored PQC | Max conf | APIs |
|---|---:|---:|---:|---:|---:|---|
| native_evp | 15 | 8 | 15 | 15 | 1.0 | EVP_PKEY_decapsulate×6, EVP_PKEY_encapsulate×6, EVP_PKEY_keygen×3 |
| native_cli | 1 | 3 | 1 | 1 | 1.0 | EVP_PKEY_keygen×1 |
| liboqs | 3 | 6 | 3 | 3 | 1.0 | OQS_KEM_decaps×1, OQS_KEM_encaps×1, OQS_KEM_keypair×1 |

- **native_evp** algorithms attributed: {'ML-KEM-512': 5, 'ML-KEM-768': 5, 'ML-KEM-1024': 5}
- **native_cli** algorithms attributed: {'ML-KEM-768': 1}
- **liboqs** algorithms attributed: {'ML-KEM-768': 3}
