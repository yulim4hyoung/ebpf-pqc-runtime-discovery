# Native OpenSSL 3.5 ML-DSA vs liboqs detection

| Case | Crypto ev | RNG ev | PQC ev | Anchored PQC | Max conf | APIs |
|---|---:|---:|---:|---:|---:|---|
| native_evp | 12 | 8 | 12 | 12 | 1.0 | EVP_PKEY_keygen×3, EVP_PKEY_sign×6, EVP_PKEY_verify×3 |
| native_cli | 3 | 7 | 1 | 1 | 1.0 | EVP_DigestSignInit_ex×1, EVP_DigestVerifyInit_ex×1, EVP_PKEY_keygen×1 |
| liboqs | 3 | 6 | 3 | 3 | 1.0 | OQS_SIG_keypair×1, OQS_SIG_sign×1, OQS_SIG_verify×1 |

- **native_evp** algorithms attributed: {'ML-DSA-44': 4, 'ML-DSA-65': 4, 'ML-DSA-87': 4}
- **native_cli** algorithms attributed: {'ML-DSA-65': 1}
- **liboqs** algorithms attributed: {'ML-DSA-65': 3}

> Expected (2026-09-20): every case shows keygen, sign and verify. native_evp signs through EVP_PKEY_sign_message_init + EVP_PKEY_sign (the size query and the signature are two EVP_PKEY_sign calls, so sign counts twice per parameter set, as encapsulation does in the ML-KEM experiment); its sign/verify contexts inherit the generated key's name (A10), so all events are named and anchored at confidence 1.0. native_cli signs through the OpenSSL 3.5 openssl app (one-shot EVP_DigestSignInit_ex / EVP_DigestVerifyInit_ex): those two events are detected but carry no name, because pkeyutl decodes its key from the PEM file written by a separate genpkey process, and keys decoded from encodings are outside the name producers (the open gap named in the paper's future work).
