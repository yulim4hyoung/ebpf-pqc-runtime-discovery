# Randomness detector evaluation

| Detector | Precision | Recall | F1 | FP | FN |
|---|---:|---:|---:|---:|---:|
| D_random (random alone) | 1.00 | 1.00 | 1.00 | 0 | 0 |
| D_api (crypto API) | 1.00 | 1.00 | 1.00 | 0 | 0 |
| D_corr (API + random correlation) | 1.00 | 1.00 | 1.00 | 0 | 0 |

## Per-case

| Case | Label | D_random | D_api | D_corr | APIs |
|---|---|---|---|---|---|
| pos_rsa | crypto | True | True | True | EVP_PKEY_keygen, RAND_priv_bytes_ex |
| pos_mlkem | crypto | True | True | True | OQS_KEM_decaps, OQS_KEM_encaps, OQS_KEM_keypair, RAND_bytes, RAND_bytes_ex |
| neg_getrandom | random_only | False | False | False |  |
| neg_urandom | random_only | False | False | False |  |
| neg_uuid | random_only | False | False | False |  |

## Interpretation
- **D_random alone is NOT a valid crypto detector** — negatives that call getrandom become FPs.
- **D_api** is the primary detector.
- **D_corr** raises confidence when randomness precedes a crypto API; it does not invent detections.
