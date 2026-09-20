# Randomness detection — how to read this

## What we do NOT claim
`RAND_bytes` / `getrandom` alone ≠ cryptographic operation.

## What we claim
1. **Crypto API probe** (`EVP_*`, `OQS_*`, `Esys_CreatePrimary`, …) = primary detector
2. **Randomness** = behavioral *indicator*
3. **Correlation** = crypto event with `randomness_recently_observed=true` (same PID, window ≤1s)

## Columns
- **Crypto API**: process-matched event_type=1 only
- **Random**: process-matched RAND_bytes / getrandom / Esys_GetRandom
- **Correlated**: crypto event that saw a prior random call from same process
- **Contam**: events from other processes (ignored for verdict)
