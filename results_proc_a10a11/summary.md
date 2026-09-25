# A10/A11 validation (2026-09-20 monitor) vs paper baseline

Baseline = the logs under `results/` that the paper's numbers come from (unchanged).

| Case | Crypto ev (new/base) | Named (new/base) | Anchored (new/base) | Family new | Family base | Conf new | Conf base |
|---|---:|---:|---:|---|---|---|---|
| native_evp | 15/0 | 15/0 | 15/0 | {'PQC': 15} | {} | {'1.0': 15} | {} |
| native_cli | 1/0 | 1/0 | 1/0 | {'PQC': 1} | {} | {'1.0': 1} | {} |
| native_mldsa | 12/0 | 12/0 | 12/0 | {'PQC': 12} | {} | {'1.0': 12} | {} |
| liboqs_mlkem | 3/0 | 3/0 | 3/0 | {'PQC': 3} | {} | {'1.0': 3} | {} |
| liboqs_mldsa | 3/0 | 3/0 | 3/0 | {'PQC': 3} | {} | {'1.0': 3} | {} |
| curl_https | 9/0 | 5/0 | 9/0 | {'PQC': 4, 'classical': 1, 'unknown': 4} | {} | {'1.0': 5, '0.5': 4} | {} |
| tls_pqc_kem | 11/0 | 8/0 | 11/0 | {'PQC': 7, 'unknown': 3, 'classical': 1} | {} | {'1.0': 8, '0.5': 3} | {} |
| tls_classical_x25519 | 5/0 | 2/0 | 5/0 | {'classical': 2, 'unknown': 3} | {} | {'1.0': 2, '0.5': 3} | {} |

## native_evp

process filter: `['mlkem-native']`

### new
| # | API | algorithm | family | anchored | Δt (μs) | conf |
|---:|---|---|---|:-:|---:|---:|
| 1 | EVP_PKEY_keygen | ML-KEM-512 | PQC | yes | 677 | 1.0 |
| 2 | EVP_PKEY_encapsulate | ML-KEM-512 | PQC | yes | 971 | 1.0 |
| 3 | EVP_PKEY_encapsulate | ML-KEM-512 | PQC | yes | 997 | 1.0 |
| 4 | EVP_PKEY_decapsulate | ML-KEM-512 | PQC | yes | 81 | 1.0 |
| 5 | EVP_PKEY_decapsulate | ML-KEM-512 | PQC | yes | 108 | 1.0 |
| 6 | EVP_PKEY_keygen | ML-KEM-768 | PQC | yes | 66 | 1.0 |
| 7 | EVP_PKEY_encapsulate | ML-KEM-768 | PQC | yes | 99 | 1.0 |
| 8 | EVP_PKEY_encapsulate | ML-KEM-768 | PQC | yes | 124 | 1.0 |
| 9 | EVP_PKEY_decapsulate | ML-KEM-768 | PQC | yes | 29 | 1.0 |
| 10 | EVP_PKEY_decapsulate | ML-KEM-768 | PQC | yes | 54 | 1.0 |
| 11 | EVP_PKEY_keygen | ML-KEM-1024 | PQC | yes | 79 | 1.0 |
| 12 | EVP_PKEY_encapsulate | ML-KEM-1024 | PQC | yes | 112 | 1.0 |
| 13 | EVP_PKEY_encapsulate | ML-KEM-1024 | PQC | yes | 114 | 1.0 |
| 14 | EVP_PKEY_decapsulate | ML-KEM-1024 | PQC | yes | 32 | 1.0 |
| 15 | EVP_PKEY_decapsulate | ML-KEM-1024 | PQC | yes | 57 | 1.0 |

### baseline
(no baseline log)

## native_cli

process filter: `['openssl']`

### new
| # | API | algorithm | family | anchored | Δt (μs) | conf |
|---:|---|---|---|:-:|---:|---:|
| 1 | EVP_PKEY_keygen | ML-KEM-768 | PQC | yes | 101 | 1.0 |

### baseline
(no baseline log)

## native_mldsa

process filter: `['mldsa-native']`

### new
| # | API | algorithm | family | anchored | Δt (μs) | conf |
|---:|---|---|---|:-:|---:|---:|
| 1 | EVP_PKEY_keygen | ML-DSA-44 | PQC | yes | 246 | 1.0 |
| 2 | EVP_PKEY_sign | ML-DSA-44 | PQC | yes | 371 | 1.0 |
| 3 | EVP_PKEY_sign | ML-DSA-44 | PQC | yes | 405 | 1.0 |
| 4 | EVP_PKEY_verify | ML-DSA-44 | PQC | yes | 265 | 1.0 |
| 5 | EVP_PKEY_keygen | ML-DSA-65 | PQC | yes | 166 | 1.0 |
| 6 | EVP_PKEY_sign | ML-DSA-65 | PQC | yes | 209 | 1.0 |
| 7 | EVP_PKEY_sign | ML-DSA-65 | PQC | yes | 237 | 1.0 |
| 8 | EVP_PKEY_verify | ML-DSA-65 | PQC | yes | 639 | 1.0 |
| 9 | EVP_PKEY_keygen | ML-DSA-87 | PQC | yes | 262 | 1.0 |
| 10 | EVP_PKEY_sign | ML-DSA-87 | PQC | yes | 309 | 1.0 |
| 11 | EVP_PKEY_sign | ML-DSA-87 | PQC | yes | 311 | 1.0 |
| 12 | EVP_PKEY_verify | ML-DSA-87 | PQC | yes | 662 | 1.0 |

### baseline
(no baseline log)

## liboqs_mlkem

process filter: `['mlkem_workload']`

### new
| # | API | algorithm | family | anchored | Δt (μs) | conf |
|---:|---|---|---|:-:|---:|---:|
| 1 | OQS_KEM_keypair | ML-KEM-768 | PQC | yes | 82 | 1.0 |
| 2 | OQS_KEM_encaps | ML-KEM-768 | PQC | yes | 108 | 1.0 |
| 3 | OQS_KEM_decaps | ML-KEM-768 | PQC | yes | 17 | 1.0 |

### baseline
(no baseline log)

## liboqs_mldsa

process filter: `['mldsa_workload']`

### new
| # | API | algorithm | family | anchored | Δt (μs) | conf |
|---:|---|---|---|:-:|---:|---:|
| 1 | OQS_SIG_keypair | ML-DSA-65 | PQC | yes | 141 | 1.0 |
| 2 | OQS_SIG_sign | ML-DSA-65 | PQC | yes | 170 | 1.0 |
| 3 | OQS_SIG_verify | ML-DSA-65 | PQC | yes | 49 | 1.0 |

### baseline
(no baseline log)

## curl_https

process filter: `['curl']`

### new
| # | API | algorithm | family | anchored | Δt (μs) | conf |
|---:|---|---|---|:-:|---:|---:|
| 1 | EVP_PKEY_keygen | X25519MLKEM768 | PQC | yes | 113 | 1.0 |
| 2 | EVP_PKEY_keygen | X25519 | classical | yes | 55 | 1.0 |
| 3 | EVP_PKEY_decapsulate | X25519MLKEM768 | PQC | yes | 35179 | 1.0 |
| 4 | EVP_PKEY_decapsulate | X25519MLKEM768 | PQC | yes | 35209 | 1.0 |
| 5 | EVP_PKEY_decapsulate | ML-KEM-768 | PQC | yes | 35226 | 1.0 |
| 6 | EVP_DigestVerifyInit | (none) | unknown | yes | 36739 | 0.5 |
| 7 | EVP_DigestVerifyInit | (none) | unknown | yes | 37201 | 0.5 |
| 8 | EVP_DigestVerifyInit | (none) | unknown | yes | 37676 | 0.5 |
| 9 | EVP_DigestVerifyInit_ex | (none) | unknown | yes | 38058 | 0.5 |

### baseline
(no baseline log)

## tls_pqc_kem

process filter: `['openssl']`

### new
| # | API | algorithm | family | anchored | Δt (μs) | conf |
|---:|---|---|---|:-:|---:|---:|
| 1 | EVP_PKEY_keygen | X25519MLKEM768 | PQC | yes | 62 | 1.0 |
| 2 | EVP_DigestSignInit_ex | (none) | unknown | yes | 57 | 0.5 |
| 3 | EVP_PKEY_encapsulate | X25519MLKEM768 | PQC | yes | 116 | 1.0 |
| 4 | EVP_PKEY_encapsulate | X25519MLKEM768 | PQC | yes | 148 | 1.0 |
| 5 | EVP_PKEY_encapsulate | ML-KEM-768 | PQC | yes | 159 | 1.0 |
| 6 | EVP_PKEY_keygen | X25519 | classical | yes | 56 | 1.0 |
| 7 | EVP_DigestSignInit_ex | (none) | unknown | yes | 428 | 0.5 |
| 8 | EVP_PKEY_decapsulate | X25519MLKEM768 | PQC | yes | 1578 | 1.0 |
| 9 | EVP_PKEY_decapsulate | X25519MLKEM768 | PQC | yes | 1609 | 1.0 |
| 10 | EVP_PKEY_decapsulate | ML-KEM-768 | PQC | yes | 1620 | 1.0 |
| 11 | EVP_DigestVerifyInit_ex | (none) | unknown | yes | 2081 | 0.5 |

### baseline
(no baseline log)

## tls_classical_x25519

process filter: `['openssl']`

### new
| # | API | algorithm | family | anchored | Δt (μs) | conf |
|---:|---|---|---|:-:|---:|---:|
| 1 | EVP_PKEY_keygen | X25519 | classical | yes | 59 | 1.0 |
| 2 | EVP_DigestSignInit_ex | (none) | unknown | yes | 43 | 0.5 |
| 3 | EVP_PKEY_keygen | X25519 | classical | yes | 30 | 1.0 |
| 4 | EVP_DigestSignInit_ex | (none) | unknown | yes | 367 | 0.5 |
| 5 | EVP_DigestVerifyInit_ex | (none) | unknown | yes | 1601 | 0.5 |

### baseline
(no baseline log)

