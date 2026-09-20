/* OpenSSL 3.5+ native ML-DSA workload (no liboqs).
 * Mirrors workloads/openssl_native/mlkem_native_workload.c for the
 * signature family instead of the KEM family (TODO ① ML-DSA task).
 *
 * Exercises the call sequence the monitor's EVP probes hook:
 *   EVP_PKEY_CTX_new_from_name(NULL, "ML-DSA-65", NULL)  -> name correlation
 *   EVP_PKEY_keygen                                      -> OP_KEYGEN
 *   EVP_PKEY_sign / EVP_PKEY_verify                      -> OP_SIGN/OP_VERIFY
 *
 * 2026-09-20: ML-DSA signs whole messages, and the OpenSSL 3.5 ML-DSA
 * provider does not implement the pre-hash initialisers
 * EVP_PKEY_sign_init() / EVP_PKEY_verify_init() that RSA and ECDSA use
 * (they fail with "provider signature not supported", see
 * results/logs/native_mldsa_prefix_error.log). The contexts are therefore
 * initialised with the 3.5 message-signing API,
 * EVP_PKEY_sign_message_init() / EVP_PKEY_verify_message_init(), after
 * which the same EVP_PKEY_sign() / EVP_PKEY_verify() entry points run the
 * operation, so the monitor's existing uprobes on those two symbols fire.
 * Building this file needs OpenSSL >= 3.5 headers.
 *
 * The sign/verify contexts come from EVP_PKEY_CTX_new_from_pkey(); with the
 * key-to-context name propagation (TODO A10) they inherit the key's
 * algorithm name, so all three events are expected to be named.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/err.h>

static const unsigned char MSG[] = "runtime-pqc-discovery ML-DSA test message";
static const size_t MSGLEN = sizeof(MSG) - 1;

static int run(const char *alg)
{
	EVP_PKEY_CTX *gctx = NULL, *sctx = NULL, *vctx = NULL;
	EVP_SIGNATURE *sa = NULL;
	EVP_PKEY *key = NULL;
	unsigned char *sig = NULL;
	size_t siglen = 0;
	int rc = 1;

	gctx = EVP_PKEY_CTX_new_from_name(NULL, alg, NULL);
	if (!gctx) {
		fprintf(stderr, "[SKIP] %s not available in this OpenSSL\n", alg);
		return 0;
	}
	if (EVP_PKEY_keygen_init(gctx) <= 0)
		goto out;
	if (EVP_PKEY_keygen(gctx, &key) <= 0)
		goto out;

	/* Message-signing initialisation (OpenSSL >= 3.5); the pre-hash
	 * EVP_PKEY_sign_init() is not provided for ML-DSA. */
	sa = EVP_SIGNATURE_fetch(NULL, alg, NULL);
	if (!sa)
		goto out;

	sctx = EVP_PKEY_CTX_new_from_pkey(NULL, key, NULL);
	if (!sctx || EVP_PKEY_sign_message_init(sctx, sa, NULL) <= 0)
		goto out;
	if (EVP_PKEY_sign(sctx, NULL, &siglen, MSG, MSGLEN) <= 0)
		goto out;
	sig = malloc(siglen);
	if (!sig)
		goto out;
	if (EVP_PKEY_sign(sctx, sig, &siglen, MSG, MSGLEN) <= 0)
		goto out;

	vctx = EVP_PKEY_CTX_new_from_pkey(NULL, key, NULL);
	if (!vctx || EVP_PKEY_verify_message_init(vctx, sa, NULL) <= 0)
		goto out;
	if (EVP_PKEY_verify(vctx, sig, siglen, MSG, MSGLEN) <= 0) {
		fprintf(stderr, "signature verification failed for %s\n", alg);
		goto out;
	}

	printf("[workload] native %s keygen+sign+verify OK (siglen=%zu)\n",
	       alg, siglen);
	rc = 0;

out:
	if (rc) {
		/* Never fail silently: the harness log must show which step
		 * of the OpenSSL call sequence rejected the operation. */
		fprintf(stderr, "[workload] native %s FAILED\n", alg);
		ERR_print_errors_fp(stderr);
	}
	free(sig);
	EVP_SIGNATURE_free(sa);
	EVP_PKEY_CTX_free(gctx);
	EVP_PKEY_CTX_free(sctx);
	EVP_PKEY_CTX_free(vctx);
	EVP_PKEY_free(key);
	return rc;
}

int main(int argc, char **argv)
{
	if (argc > 1)
		return run(argv[1]);
	if (run("ML-DSA-44"))
		return 1;
	if (run("ML-DSA-65"))
		return 1;
	if (run("ML-DSA-87"))
		return 1;
	return 0;
}
