/* OpenSSL 3.5+ native ML-DSA workload (no liboqs).
 * Mirrors workloads/openssl_native/mlkem_native_workload.c for the
 * signature family instead of the KEM family (TODO ① ML-DSA task).
 *
 * Exercises the exact call sequence the monitor's existing EVP probes hook:
 *   EVP_PKEY_CTX_new_from_name(NULL, "ML-DSA-65", NULL)  -> name correlation
 *   EVP_PKEY_keygen                                      -> OP_KEYGEN
 *   EVP_PKEY_sign / EVP_PKEY_verify                      -> OP_SIGN/OP_VERIFY
 *
 * Note: same limitation as the ML-KEM encaps/decaps case (Sect. 4.6) — the
 * sign/verify contexts come from EVP_PKEY_CTX_new_from_pkey (required by
 * the API to bind the context to a specific key), which the monitor does
 * not hook, so those events carry no algorithm name; only the keygen event
 * is name-attributed via the from_name uretprobe. This is the same probe
 * gap task ④ (paired with 형유림) is meant to close.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>

static const unsigned char MSG[] = "runtime-pqc-discovery ML-DSA test message";
static const size_t MSGLEN = sizeof(MSG) - 1;

static int run(const char *alg)
{
	EVP_PKEY_CTX *gctx = NULL, *sctx = NULL, *vctx = NULL;
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

	sctx = EVP_PKEY_CTX_new_from_pkey(NULL, key, NULL);
	if (!sctx || EVP_PKEY_sign_init(sctx) <= 0)
		goto out;
	if (EVP_PKEY_sign(sctx, NULL, &siglen, MSG, MSGLEN) <= 0)
		goto out;
	sig = malloc(siglen);
	if (!sig)
		goto out;
	if (EVP_PKEY_sign(sctx, sig, &siglen, MSG, MSGLEN) <= 0)
		goto out;

	vctx = EVP_PKEY_CTX_new_from_pkey(NULL, key, NULL);
	if (!vctx || EVP_PKEY_verify_init(vctx) <= 0)
		goto out;
	if (EVP_PKEY_verify(vctx, sig, siglen, MSG, MSGLEN) <= 0) {
		fprintf(stderr, "signature verification failed for %s\n", alg);
		goto out;
	}

	printf("[workload] native %s keygen+sign+verify OK (siglen=%zu)\n",
	       alg, siglen);
	rc = 0;

out:
	free(sig);
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
