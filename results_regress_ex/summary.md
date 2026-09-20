# A10/A11 validation (2026-09-20 monitor) vs paper baseline

Baseline = the logs under `results/` that the paper's numbers come from (unchanged).

| Case | Crypto ev (new/base) | Named (new/base) | Anchored (new/base) | Family new | Family base | Conf new | Conf base |
|---|---:|---:|---:|---|---|---|---|
| native_evp | 15/15 | 15/15 | 15/15 | {'PQC': 15} | {'PQC': 15} | {'1.0': 15} | {'1.0': 15} |
| native_cli | 1/1 | 1/1 | 1/1 | {'PQC': 1} | {'PQC': 1} | {'1.0': 1} | {'1.0': 1} |
| native_mldsa | 12/12 | 12/12 | 12/12 | {'PQC': 12} | {'PQC': 12} | {'1.0': 12} | {'1.0': 12} |
| liboqs_mlkem | 3/3 | 3/3 | 3/3 | {'PQC': 3} | {'PQC': 3} | {'1.0': 3} | {'1.0': 3} |
| liboqs_mldsa | 3/3 | 3/3 | 3/3 | {'PQC': 3} | {'PQC': 3} | {'1.0': 3} | {'1.0': 3} |
| curl_https | 9/0 | 5/0 | 9/0 | {'PQC': 4, 'classical': 1, 'unknown': 4} | {} | {'1.0': 5, '0.5': 4} | {} |
| tls_pqc_kem | 11/11 | 8/8 | 11/11 | {'PQC': 7, 'unknown': 3, 'classical': 1} | {'PQC': 7, 'unknown': 3, 'classical': 1} | {'1.0': 8, '0.5': 3} | {'1.0': 8, '0.5': 3} |
| tls_classical_x25519 | 5/5 | 2/2 | 5/5 | {'classical': 2, 'unknown': 3} | {'classical': 2, 'unknown': 3} | {'1.0': 2, '0.5': 3} | {'1.0': 2, '0.5': 3} |

## native_evp

process filter: `['mlkem-native']`

### new
| # | API | algorithm | family | anchored | Δt (μs) | conf |
|---:|---|---|---|:-:|---:|---:|
| 1 | EVP_PKEY_keygen | ML-KEM-512 | PQC | yes | 87 | 1.0 |
| 2 | EVP_PKEY_encapsulate | ML-KEM-512 | PQC | yes | 139 | 1.0 |
| 3 | EVP_PKEY_encapsulate | ML-KEM-512 | PQC | yes | 165 | 1.0 |
| 4 | EVP_PKEY_decapsulate | ML-KEM-512 | PQC | yes | 54 | 1.0 |
| 5 | EVP_PKEY_decapsulate | ML-KEM-512 | PQC | yes | 80 | 1.0 |
| 6 | EVP_PKEY_keygen | ML-KEM-768 | PQC | yes | 65 | 1.0 |
| 7 | EVP_PKEY_encapsulate | ML-KEM-768 | PQC | yes | 97 | 1.0 |
| 8 | EVP_PKEY_encapsulate | ML-KEM-768 | PQC | yes | 123 | 1.0 |
| 9 | EVP_PKEY_decapsulate | ML-KEM-768 | PQC | yes | 28 | 1.0 |
| 10 | EVP_PKEY_decapsulate | ML-KEM-768 | PQC | yes | 54 | 1.0 |
| 11 | EVP_PKEY_keygen | ML-KEM-1024 | PQC | yes | 82 | 1.0 |
| 12 | EVP_PKEY_encapsulate | ML-KEM-1024 | PQC | yes | 115 | 1.0 |
| 13 | EVP_PKEY_encapsulate | ML-KEM-1024 | PQC | yes | 116 | 1.0 |
| 14 | EVP_PKEY_decapsulate | ML-KEM-1024 | PQC | yes | 32 | 1.0 |
| 15 | EVP_PKEY_decapsulate | ML-KEM-1024 | PQC | yes | 57 | 1.0 |

### baseline
| # | API | algorithm | family | anchored | Δt (μs) | conf |
|---:|---|---|---|:-:|---:|---:|
| 1 | EVP_PKEY_keygen | ML-KEM-512 | PQC | yes | 101 | 1.0 |
| 2 | EVP_PKEY_encapsulate | ML-KEM-512 | PQC | yes | 9345 | 1.0 |
| 3 | EVP_PKEY_encapsulate | ML-KEM-512 | PQC | yes | 9375 | 1.0 |
| 4 | EVP_PKEY_decapsulate | ML-KEM-512 | PQC | yes | 51 | 1.0 |
| 5 | EVP_PKEY_decapsulate | ML-KEM-512 | PQC | yes | 80 | 1.0 |
| 6 | EVP_PKEY_keygen | ML-KEM-768 | PQC | yes | 73 | 1.0 |
| 7 | EVP_PKEY_encapsulate | ML-KEM-768 | PQC | yes | 109 | 1.0 |
| 8 | EVP_PKEY_encapsulate | ML-KEM-768 | PQC | yes | 111 | 1.0 |
| 9 | EVP_PKEY_decapsulate | ML-KEM-768 | PQC | yes | 56 | 1.0 |
| 10 | EVP_PKEY_decapsulate | ML-KEM-768 | PQC | yes | 83 | 1.0 |
| 11 | EVP_PKEY_keygen | ML-KEM-1024 | PQC | yes | 90 | 1.0 |
| 12 | EVP_PKEY_encapsulate | ML-KEM-1024 | PQC | yes | 126 | 1.0 |
| 13 | EVP_PKEY_encapsulate | ML-KEM-1024 | PQC | yes | 153 | 1.0 |
| 14 | EVP_PKEY_decapsulate | ML-KEM-1024 | PQC | yes | 38 | 1.0 |
| 15 | EVP_PKEY_decapsulate | ML-KEM-1024 | PQC | yes | 66 | 1.0 |

## native_cli

process filter: `['openssl']`

### new
| # | API | algorithm | family | anchored | Δt (μs) | conf |
|---:|---|---|---|:-:|---:|---:|
| 1 | EVP_PKEY_keygen | ML-KEM-768 | PQC | yes | 101 | 1.0 |

### baseline
| # | API | algorithm | family | anchored | Δt (μs) | conf |
|---:|---|---|---|:-:|---:|---:|
| 1 | EVP_PKEY_keygen | ML-KEM-768 | PQC | yes | 102 | 1.0 |

## native_mldsa

process filter: `['mldsa-native']`

### new
| # | API | algorithm | family | anchored | Δt (μs) | conf |
|---:|---|---|---|:-:|---:|---:|
| 1 | EVP_PKEY_keygen | ML-DSA-44 | PQC | yes | 221 | 1.0 |
| 2 | EVP_PKEY_sign | ML-DSA-44 | PQC | yes | 396 | 1.0 |
| 3 | EVP_PKEY_sign | ML-DSA-44 | PQC | yes | 436 | 1.0 |
| 4 | EVP_PKEY_verify | ML-DSA-44 | PQC | yes | 336 | 1.0 |
| 5 | EVP_PKEY_keygen | ML-DSA-65 | PQC | yes | 200 | 1.0 |
| 6 | EVP_PKEY_sign | ML-DSA-65 | PQC | yes | 244 | 1.0 |
| 7 | EVP_PKEY_sign | ML-DSA-65 | PQC | yes | 277 | 1.0 |
| 8 | EVP_PKEY_verify | ML-DSA-65 | PQC | yes | 1368 | 1.0 |
| 9 | EVP_PKEY_keygen | ML-DSA-87 | PQC | yes | 267 | 1.0 |
| 10 | EVP_PKEY_sign | ML-DSA-87 | PQC | yes | 310 | 1.0 |
| 11 | EVP_PKEY_sign | ML-DSA-87 | PQC | yes | 342 | 1.0 |
| 12 | EVP_PKEY_verify | ML-DSA-87 | PQC | yes | 516 | 1.0 |

### baseline
| # | API | algorithm | family | anchored | Δt (μs) | conf |
|---:|---|---|---|:-:|---:|---:|
| 1 | EVP_PKEY_keygen | ML-DSA-44 | PQC | yes | 268 | 1.0 |
| 2 | EVP_PKEY_sign | ML-DSA-44 | PQC | yes | 391 | 1.0 |
| 3 | EVP_PKEY_sign | ML-DSA-44 | PQC | yes | 423 | 1.0 |
| 4 | EVP_PKEY_verify | ML-DSA-44 | PQC | yes | 399 | 1.0 |
| 5 | EVP_PKEY_keygen | ML-DSA-65 | PQC | yes | 149 | 1.0 |
| 6 | EVP_PKEY_sign | ML-DSA-65 | PQC | yes | 183 | 1.0 |
| 7 | EVP_PKEY_sign | ML-DSA-65 | PQC | yes | 209 | 1.0 |
| 8 | EVP_PKEY_verify | ML-DSA-65 | PQC | yes | 685 | 1.0 |
| 9 | EVP_PKEY_keygen | ML-DSA-87 | PQC | yes | 187 | 1.0 |
| 10 | EVP_PKEY_sign | ML-DSA-87 | PQC | yes | 220 | 1.0 |
| 11 | EVP_PKEY_sign | ML-DSA-87 | PQC | yes | 246 | 1.0 |
| 12 | EVP_PKEY_verify | ML-DSA-87 | PQC | yes | 872 | 1.0 |

## liboqs_mlkem

process filter: `['mlkem_workload']`

### new
| # | API | algorithm | family | anchored | Δt (μs) | conf |
|---:|---|---|---|:-:|---:|---:|
| 1 | OQS_KEM_keypair | ML-KEM-768 | PQC | yes | 76 | 1.0 |
| 2 | OQS_KEM_encaps | ML-KEM-768 | PQC | yes | 101 | 1.0 |
| 3 | OQS_KEM_decaps | ML-KEM-768 | PQC | yes | 16 | 1.0 |

### baseline
| # | API | algorithm | family | anchored | Δt (μs) | conf |
|---:|---|---|---|:-:|---:|---:|
| 1 | OQS_KEM_keypair | ML-KEM-768 | PQC | yes | 989 | 1.0 |
| 2 | OQS_KEM_encaps | ML-KEM-768 | PQC | yes | 1017 | 1.0 |
| 3 | OQS_KEM_decaps | ML-KEM-768 | PQC | yes | 20 | 1.0 |

## liboqs_mldsa

process filter: `['mldsa_workload']`

### new
| # | API | algorithm | family | anchored | Δt (μs) | conf |
|---:|---|---|---|:-:|---:|---:|
| 1 | OQS_SIG_keypair | ML-DSA-65 | PQC | yes | 109 | 1.0 |
| 2 | OQS_SIG_sign | ML-DSA-65 | PQC | yes | 135 | 1.0 |
| 3 | OQS_SIG_verify | ML-DSA-65 | PQC | yes | 44 | 1.0 |

### baseline
| # | API | algorithm | family | anchored | Δt (μs) | conf |
|---:|---|---|---|:-:|---:|---:|
| 1 | OQS_SIG_keypair | ML-DSA-65 | PQC | yes | 1100 | 1.0 |
| 2 | OQS_SIG_sign | ML-DSA-65 | PQC | yes | 1129 | 1.0 |
| 3 | OQS_SIG_verify | ML-DSA-65 | PQC | yes | 152 | 1.0 |

## curl_https

process filter: `['curl']`

### new
| # | API | algorithm | family | anchored | Δt (μs) | conf |
|---:|---|---|---|:-:|---:|---:|
| 1 | EVP_PKEY_keygen | X25519MLKEM768 | PQC | yes | 56 | 1.0 |
| 2 | EVP_PKEY_keygen | X25519 | classical | yes | 48 | 1.0 |
| 3 | EVP_PKEY_decapsulate | X25519MLKEM768 | PQC | yes | 38967 | 1.0 |
| 4 | EVP_PKEY_decapsulate | X25519MLKEM768 | PQC | yes | 38996 | 1.0 |
| 5 | EVP_PKEY_decapsulate | ML-KEM-768 | PQC | yes | 39009 | 1.0 |
| 6 | EVP_DigestVerifyInit | (none) | unknown | yes | 39500 | 0.5 |
| 7 | EVP_DigestVerifyInit | (none) | unknown | yes | 39867 | 0.5 |
| 8 | EVP_DigestVerifyInit | (none) | unknown | yes | 40219 | 0.5 |
| 9 | EVP_DigestVerifyInit_ex | (none) | unknown | yes | 40331 | 0.5 |

### baseline
(no baseline log)

## tls_pqc_kem

process filter: `['openssl']`

### new
| # | API | algorithm | family | anchored | Δt (μs) | conf |
|---:|---|---|---|:-:|---:|---:|
| 1 | EVP_PKEY_keygen | X25519MLKEM768 | PQC | yes | 56 | 1.0 |
| 2 | EVP_DigestSignInit_ex | (none) | unknown | yes | 41 | 0.5 |
| 3 | EVP_PKEY_encapsulate | X25519MLKEM768 | PQC | yes | 92 | 1.0 |
| 4 | EVP_PKEY_encapsulate | X25519MLKEM768 | PQC | yes | 122 | 1.0 |
| 5 | EVP_PKEY_encapsulate | ML-KEM-768 | PQC | yes | 132 | 1.0 |
| 6 | EVP_PKEY_keygen | X25519 | classical | yes | 49 | 1.0 |
| 7 | EVP_DigestSignInit_ex | (none) | unknown | yes | 392 | 0.5 |
| 8 | EVP_PKEY_decapsulate | X25519MLKEM768 | PQC | yes | 1462 | 1.0 |
| 9 | EVP_PKEY_decapsulate | X25519MLKEM768 | PQC | yes | 1490 | 1.0 |
| 10 | EVP_PKEY_decapsulate | ML-KEM-768 | PQC | yes | 1500 | 1.0 |
| 11 | EVP_DigestVerifyInit_ex | (none) | unknown | yes | 1855 | 0.5 |

### baseline
| # | API | algorithm | family | anchored | Δt (μs) | conf |
|---:|---|---|---|:-:|---:|---:|
| 1 | EVP_PKEY_keygen | X25519MLKEM768 | PQC | yes | 56 | 1.0 |
| 2 | EVP_DigestSignInit_ex | (none) | unknown | yes | 42 | 0.5 |
| 3 | EVP_PKEY_encapsulate | X25519MLKEM768 | PQC | yes | 128 | 1.0 |
| 4 | EVP_PKEY_encapsulate | X25519MLKEM768 | PQC | yes | 158 | 1.0 |
| 5 | EVP_PKEY_encapsulate | ML-KEM-768 | PQC | yes | 191 | 1.0 |
| 6 | EVP_PKEY_keygen | X25519 | classical | yes | 49 | 1.0 |
| 7 | EVP_DigestSignInit_ex | (none) | unknown | yes | 1242 | 0.5 |
| 8 | EVP_PKEY_decapsulate | X25519MLKEM768 | PQC | yes | 2343 | 1.0 |
| 9 | EVP_PKEY_decapsulate | X25519MLKEM768 | PQC | yes | 2371 | 1.0 |
| 10 | EVP_PKEY_decapsulate | ML-KEM-768 | PQC | yes | 2388 | 1.0 |
| 11 | EVP_DigestVerifyInit_ex | (none) | unknown | yes | 3308 | 0.5 |

## tls_classical_x25519

process filter: `['openssl']`

### new
| # | API | algorithm | family | anchored | Δt (μs) | conf |
|---:|---|---|---|:-:|---:|---:|
| 1 | EVP_PKEY_keygen | X25519 | classical | yes | 60 | 1.0 |
| 2 | EVP_DigestSignInit_ex | (none) | unknown | yes | 45 | 0.5 |
| 3 | EVP_PKEY_keygen | X25519 | classical | yes | 30 | 1.0 |
| 4 | EVP_DigestSignInit_ex | (none) | unknown | yes | 410 | 0.5 |
| 5 | EVP_DigestVerifyInit_ex | (none) | unknown | yes | 1657 | 0.5 |

### baseline
| # | API | algorithm | family | anchored | Δt (μs) | conf |
|---:|---|---|---|:-:|---:|---:|
| 1 | EVP_PKEY_keygen | X25519 | classical | yes | 38 | 1.0 |
| 2 | EVP_DigestSignInit_ex | (none) | unknown | yes | 45 | 0.5 |
| 3 | EVP_PKEY_keygen | X25519 | classical | yes | 56 | 1.0 |
| 4 | EVP_DigestSignInit_ex | (none) | unknown | yes | 425 | 0.5 |
| 5 | EVP_DigestVerifyInit_ex | (none) | unknown | yes | 1709 | 0.5 |

