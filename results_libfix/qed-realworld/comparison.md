| App | Filter | Crypto API | Random | Correlated | Contam | Verdict |
|---|---|---:|---:|---|---:|---|
| curl-https | `curl` | 5 | 9 | True | 0 | **PASS** |
| wget-https | `wget` | 11 | 7 | True | 0 | **PASS** |
| ssh-version | `ssh` | 0 | 1 | False | 0 | **PASS** |
| md5sum | `md5sum` | 0 | 0 | False | 0 | **PASS** |
| tpm2-getrandom | `tpm2_getrandom` | 0 | 2 | False | 0 | **PASS** |
| tpm2-createprimary-rsa | `tpm2_createprim` | 4 | 2 | True | 0 | **PASS** |
| qed-tpm2-getrandom | `tpm2_getrandom` | 0 | 2 | False | 0 | **PASS** |
| qed-tpm2-createprimary | `tpm2_createprim` | 4 | 2 | True | 0 | **PASS** |
| qed-synthetic-rsa | `openssl3.3-rsa` | 3 | 2 | True | 0 | **PASS** |
