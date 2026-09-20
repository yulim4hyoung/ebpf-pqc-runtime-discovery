| App | Filter | Crypto API | Random | Correlated | Contam | Verdict |
|---|---|---:|---:|---|---:|---|
| curl-https | `curl` | 4 | 12 | True | 0 | **PASS** |
| wget-https | `wget` | 11 | 9 | True | 0 | **PASS** |
| ssh-version | `ssh` | 0 | 3 | False | 0 | **PASS** |
| md5sum | `md5sum` | 0 | 1 | False | 2 | **FAIL** |
| tpm2-getrandom | `tpm2_getrandom` | 0 | 4 | False | 0 | **PASS** |
| tpm2-createprimary-rsa | `tpm2_createprim` | 4 | 6 | True | 0 | **PASS** |
| qed-tpm2-getrandom | `tpm2_getrandom` | 0 | 3 | False | 0 | **PASS** |
| qed-tpm2-createprimary | `tpm2_createprim` | 4 | 5 | True | 0 | **PASS** |
| qed-synthetic-rsa | `openssl3.3-rsa` | 3 | 6 | True | 2 | **PASS** |
