# A10/A11 validation (2026-09-20 monitor) vs paper baseline

Baseline = the logs under `results/` that the paper's numbers come from (unchanged).

| Case | Crypto ev (new/base) | Named (new/base) | Anchored (new/base) | Family new | Family base | Conf new | Conf base |
|---|---:|---:|---:|---|---|---|---|
| native_evp | 15/15 | 15/4 | 15/15 | {'PQC': 15} | {'classical': 11, 'PQC': 4} | {'1.0': 15} | {'0.5': 11, '1.0': 4} |
| native_cli | 1/1 | 1/1 | 1/1 | {'PQC': 1} | {'PQC': 1} | {'1.0': 1} | {'1.0': 1} |
| native_mldsa | 1/1 | 1/0 | 1/1 | {'PQC': 1} | {'classical': 1} | {'1.0': 1} | {'0.5': 1} |
| liboqs_mlkem | 3/3 | 3/3 | 3/2 | {'PQC': 3} | {'PQC': 3} | {'1.0': 3} | {'0.9': 1, '1.0': 2} |
| liboqs_mldsa | 3/3 | 3/3 | 3/3 | {'PQC': 3} | {'PQC': 3} | {'1.0': 3} | {'1.0': 3} |
| curl_https | 8/4 | 5/1 | 8/4 | {'PQC': 4, 'classical': 1, 'unknown': 3} | {'classical': 4} | {'1.0': 5, '0.5': 3} | {'1.0': 1, '0.5': 3} |
| tls_pqc_kem | 8/8 | 8/4 | 8/8 | {'PQC': 7, 'classical': 1} | {'PQC': 3, 'classical': 5} | {'1.0': 8} | {'1.0': 4, '0.5': 4} |
| tls_classical_x25519 | 2/2 | 2/1 | 2/2 | {'classical': 2} | {'classical': 2} | {'1.0': 2} | {'1.0': 1, '0.5': 1} |

## native_evp

process filter: `['mlkem-native']`

### new
| # | API | algorithm | family | anchored | Δt (μs) | conf |
|---:|---|---|---|:-:|---:|---:|
| 1 | EVP_PKEY_keygen | ML-KEM-512 | PQC | yes | 621 | 1.0 |
| 2 | EVP_PKEY_encapsulate | ML-KEM-512 | PQC | yes | 923 | 1.0 |
| 3 | EVP_PKEY_encapsulate | ML-KEM-512 | PQC | yes | 950 | 1.0 |
| 4 | EVP_PKEY_decapsulate | ML-KEM-512 | PQC | yes | 41 | 1.0 |
| 5 | EVP_PKEY_decapsulate | ML-KEM-512 | PQC | yes | 67 | 1.0 |
| 6 | EVP_PKEY_keygen | ML-KEM-768 | PQC | yes | 138 | 1.0 |
| 7 | EVP_PKEY_encapsulate | ML-KEM-768 | PQC | yes | 201 | 1.0 |
| 8 | EVP_PKEY_encapsulate | ML-KEM-768 | PQC | yes | 250 | 1.0 |
| 9 | EVP_PKEY_decapsulate | ML-KEM-768 | PQC | yes | 106 | 1.0 |
| 10 | EVP_PKEY_decapsulate | ML-KEM-768 | PQC | yes | 155 | 1.0 |
| 11 | EVP_PKEY_keygen | ML-KEM-1024 | PQC | yes | 157 | 1.0 |
| 12 | EVP_PKEY_encapsulate | ML-KEM-1024 | PQC | yes | 220 | 1.0 |
| 13 | EVP_PKEY_encapsulate | ML-KEM-1024 | PQC | yes | 223 | 1.0 |
| 14 | EVP_PKEY_decapsulate | ML-KEM-1024 | PQC | yes | 44 | 1.0 |
| 15 | EVP_PKEY_decapsulate | ML-KEM-1024 | PQC | yes | 45 | 1.0 |

### baseline
| # | API | algorithm | family | anchored | Δt (μs) | conf |
|---:|---|---|---|:-:|---:|---:|
| 1 | EVP_PKEY_keygen | (none) | classical | yes | 915 | 0.5 |
| 2 | EVP_PKEY_encapsulate | (none) | classical | yes | 1235 | 0.5 |
| 3 | EVP_PKEY_encapsulate | (none) | classical | yes | 1265 | 0.5 |
| 4 | EVP_PKEY_decapsulate | (none) | classical | yes | 40 | 0.5 |
| 5 | EVP_PKEY_decapsulate | (none) | classical | yes | 69 | 0.5 |
| 6 | EVP_PKEY_keygen | ML-KEM-768 | PQC | yes | 69 | 1.0 |
| 7 | EVP_PKEY_encapsulate | (none) | classical | yes | 101 | 0.5 |
| 8 | EVP_PKEY_encapsulate | (none) | classical | yes | 105 | 0.5 |
| 9 | EVP_PKEY_decapsulate | (none) | classical | yes | 25 | 0.5 |
| 10 | EVP_PKEY_decapsulate | (none) | classical | yes | 27 | 0.5 |
| 11 | EVP_PKEY_keygen | ML-KEM-1024 | PQC | yes | 85 | 1.0 |
| 12 | EVP_PKEY_encapsulate | (none) | classical | yes | 116 | 0.5 |
| 13 | EVP_PKEY_encapsulate | (none) | classical | yes | 120 | 0.5 |
| 14 | EVP_PKEY_decapsulate | ML-KEM-768 | PQC | yes | 37 | 1.0 |
| 15 | EVP_PKEY_decapsulate | ML-KEM-768 | PQC | yes | 63 | 1.0 |

## native_cli

process filter: `['openssl']`

### new
| # | API | algorithm | family | anchored | Δt (μs) | conf |
|---:|---|---|---|:-:|---:|---:|
| 1 | EVP_PKEY_keygen | ML-KEM-768 | PQC | yes | 92 | 1.0 |

### baseline
| # | API | algorithm | family | anchored | Δt (μs) | conf |
|---:|---|---|---|:-:|---:|---:|
| 1 | EVP_PKEY_keygen | ML-KEM-768 | PQC | yes | 108 | 1.0 |

## native_mldsa

process filter: `['mldsa-native']`

### new
| # | API | algorithm | family | anchored | Δt (μs) | conf |
|---:|---|---|---|:-:|---:|---:|
| 1 | EVP_PKEY_keygen | ML-DSA-44 | PQC | yes | 155 | 1.0 |

### baseline
| # | API | algorithm | family | anchored | Δt (μs) | conf |
|---:|---|---|---|:-:|---:|---:|
| 1 | EVP_PKEY_keygen | (none) | classical | yes | 805 | 0.5 |

## liboqs_mlkem

process filter: `['mlkem_workload']`

### new
| # | API | algorithm | family | anchored | Δt (μs) | conf |
|---:|---|---|---|:-:|---:|---:|
| 1 | OQS_KEM_keypair | ML-KEM-768 | PQC | yes | 903 | 1.0 |
| 2 | OQS_KEM_encaps | ML-KEM-768 | PQC | yes | 933 | 1.0 |
| 3 | OQS_KEM_decaps | ML-KEM-768 | PQC | yes | 15 | 1.0 |

### baseline
| # | API | algorithm | family | anchored | Δt (μs) | conf |
|---:|---|---|---|:-:|---:|---:|
| 1 | OQS_KEM_keypair | ML-KEM-768 | PQC | no |  | 0.9 |
| 2 | OQS_KEM_encaps | ML-KEM-768 | PQC | yes | 58 | 1.0 |
| 3 | OQS_KEM_decaps | ML-KEM-768 | PQC | yes | 18 | 1.0 |

## liboqs_mldsa

process filter: `['mldsa_workload']`

### new
| # | API | algorithm | family | anchored | Δt (μs) | conf |
|---:|---|---|---|:-:|---:|---:|
| 1 | OQS_SIG_keypair | ML-DSA-65 | PQC | yes | 111 | 1.0 |
| 2 | OQS_SIG_sign | ML-DSA-65 | PQC | yes | 136 | 1.0 |
| 3 | OQS_SIG_verify | ML-DSA-65 | PQC | yes | 75 | 1.0 |

### baseline
| # | API | algorithm | family | anchored | Δt (μs) | conf |
|---:|---|---|---|:-:|---:|---:|
| 1 | OQS_SIG_keypair | ML-DSA-65 | PQC | yes | 53 | 1.0 |
| 2 | OQS_SIG_sign | ML-DSA-65 | PQC | yes | 936 | 1.0 |
| 3 | OQS_SIG_verify | ML-DSA-65 | PQC | yes | 43 | 1.0 |

## curl_https

process filter: `['curl']`

### new
| # | API | algorithm | family | anchored | Δt (μs) | conf |
|---:|---|---|---|:-:|---:|---:|
| 1 | EVP_PKEY_keygen | X25519MLKEM768 | PQC | yes | 92 | 1.0 |
| 2 | EVP_PKEY_keygen | X25519 | classical | yes | 54 | 1.0 |
| 3 | EVP_PKEY_decapsulate | X25519MLKEM768 | PQC | yes | 32170 | 1.0 |
| 4 | EVP_PKEY_decapsulate | X25519MLKEM768 | PQC | yes | 32199 | 1.0 |
| 5 | EVP_PKEY_decapsulate | ML-KEM-768 | PQC | yes | 32214 | 1.0 |
| 6 | EVP_DigestVerifyInit | (none) | unknown | yes | 33612 | 0.5 |
| 7 | EVP_DigestVerifyInit | (none) | unknown | yes | 33991 | 0.5 |
| 8 | EVP_DigestVerifyInit | (none) | unknown | yes | 34343 | 0.5 |

### baseline
| # | API | algorithm | family | anchored | Δt (μs) | conf |
|---:|---|---|---|:-:|---:|---:|
| 1 | EVP_PKEY_keygen | X25519 | classical | yes | 55 | 1.0 |
| 2 | EVP_DigestVerifyInit | (none) | classical | yes | 39803 | 0.5 |
| 3 | EVP_DigestVerifyInit | (none) | classical | yes | 338 | 0.5 |
| 4 | EVP_DigestVerifyInit | (none) | classical | yes | 331 | 0.5 |

## tls_pqc_kem

process filter: `['openssl']`

### new
| # | API | algorithm | family | anchored | Δt (μs) | conf |
|---:|---|---|---|:-:|---:|---:|
| 1 | EVP_PKEY_keygen | X25519MLKEM768 | PQC | yes | 57 | 1.0 |
| 2 | EVP_PKEY_encapsulate | X25519MLKEM768 | PQC | yes | 89 | 1.0 |
| 3 | EVP_PKEY_encapsulate | X25519MLKEM768 | PQC | yes | 95 | 1.0 |
| 4 | EVP_PKEY_encapsulate | ML-KEM-768 | PQC | yes | 101 | 1.0 |
| 5 | EVP_PKEY_keygen | X25519 | classical | yes | 24 | 1.0 |
| 6 | EVP_PKEY_decapsulate | X25519MLKEM768 | PQC | yes | 1459 | 1.0 |
| 7 | EVP_PKEY_decapsulate | X25519MLKEM768 | PQC | yes | 1488 | 1.0 |
| 8 | EVP_PKEY_decapsulate | ML-KEM-768 | PQC | yes | 1498 | 1.0 |

### baseline
| # | API | algorithm | family | anchored | Δt (μs) | conf |
|---:|---|---|---|:-:|---:|---:|
| 1 | EVP_PKEY_keygen | X25519MLKEM768 | PQC | yes | 99 | 1.0 |
| 2 | EVP_PKEY_encapsulate | (none) | classical | yes | 77 | 0.5 |
| 3 | EVP_PKEY_encapsulate | (none) | classical | yes | 110 | 0.5 |
| 4 | EVP_PKEY_encapsulate | (none) | classical | yes | 117 | 0.5 |
| 5 | EVP_PKEY_keygen | (none) | classical | yes | 54 | 0.5 |
| 6 | EVP_PKEY_decapsulate | X25519MLKEM768 | PQC | yes | 2168 | 1.0 |
| 7 | EVP_PKEY_decapsulate | X25519MLKEM768 | PQC | yes | 2200 | 1.0 |
| 8 | EVP_PKEY_decapsulate | X25519 | classical | yes | 2207 | 1.0 |

## tls_classical_x25519

process filter: `['openssl']`

### new
| # | API | algorithm | family | anchored | Δt (μs) | conf |
|---:|---|---|---|:-:|---:|---:|
| 1 | EVP_PKEY_keygen | X25519 | classical | yes | 103 | 1.0 |
| 2 | EVP_PKEY_keygen | X25519 | classical | yes | 51 | 1.0 |

### baseline
| # | API | algorithm | family | anchored | Δt (μs) | conf |
|---:|---|---|---|:-:|---:|---:|
| 1 | EVP_PKEY_keygen | X25519 | classical | yes | 58 | 1.0 |
| 2 | EVP_PKEY_keygen | (none) | classical | yes | 55 | 0.5 |

