/* OpenSSL 3.5+ native ML-KEM workload (no liboqs).
 *
 * Exercises the exact call sequence the monitor's existing EVP probes hook:
 *   EVP_PKEY_CTX_new_from_name(NULL, "ML-KEM-768", NULL)  -> name correlation
 *   EVP_PKEY_keygen                                       -> OP_KEYGEN
 *   EVP_PKEY_encapsulate / EVP_PKEY_decapsulate           -> OP_ENCAPS/OP_DECAPS
 *
 * Note: the encapsulate/decapsulate contexts come from
 * EVP_PKEY_CTX_new_from_pkey (required by the API), which the monitor does
 * not hook, so those events carry no algorithm name; only the keygen event
 * is name-attributed via the from_name uretprobe.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>

static int run(const char *alg)
{
	EVP_PKEY_CTX *gctx = NULL, *ectx = NULL, *dctx = NULL;
	EVP_PKEY *key = NULL;
	unsigned char *ct = NULL, *ss_e = NULL, *ss_d = NULL;
	size_t ctlen = 0, sslen_e = 0, sslen_d = 0;
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

	ectx = EVP_PKEY_CTX_new_from_pkey(NULL, key, NULL);
	if (!ectx || EVP_PKEY_encapsulate_init(ectx, NULL) <= 0)
		goto out;
	if (EVP_PKEY_encapsulate(ectx, NULL, &ctlen, NULL, &sslen_e) <= 0)
		goto out;
	ct = malloc(ctlen);
	ss_e = malloc(sslen_e);
	if (!ct || !ss_e)
		goto out;
	if (EVP_PKEY_encapsulate(ectx, ct, &ctlen, ss_e, &sslen_e) <= 0)
		goto out;

	dctx = EVP_PKEY_CTX_new_from_pkey(NULL, key, NULL);
	if (!dctx || EVP_PKEY_decapsulate_init(dctx, NULL) <= 0)
		goto out;
	if (EVP_PKEY_decapsulate(dctx, NULL, &sslen_d, ct, ctlen) <= 0)
		goto out;
	ss_d = malloc(sslen_d);
	if (!ss_d)
		goto out;
	if (EVP_PKEY_decapsulate(dctx, ss_d, &sslen_d, ct, ctlen) <= 0)
		goto out;

	if (sslen_e != sslen_d || memcmp(ss_e, ss_d, sslen_e) != 0) {
		fprintf(stderr, "shared secret mismatch for %s\n", alg);
		goto out;
	}

	printf("[workload] native %s keygen+encaps+decaps OK (ct=%zu ss=%zu)\n",
	       alg, ctlen, sslen_e);
	rc = 0;

out:
	free(ct);
	free(ss_e);
	free(ss_d);
	EVP_PKEY_CTX_free(gctx);
	EVP_PKEY_CTX_free(ectx);
	EVP_PKEY_CTX_free(dctx);
	EVP_PKEY_free(key);
	return rc;
}

int main(int argc, char **argv)
{
	if (argc > 1)
		return run(argv[1]);
	if (run("ML-KEM-512"))
		return 1;
	if (run("ML-KEM-768"))
		return 1;
	if (run("ML-KEM-1024"))
		return 1;
	return 0;
}
