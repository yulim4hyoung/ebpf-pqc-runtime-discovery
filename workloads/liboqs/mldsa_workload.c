/* liboqs ML-DSA (OQS_SIG) workload.
 * Mirrors workloads/liboqs/mlkem_workload.c for the signature family.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <oqs/oqs.h>

static const unsigned char MSG[] = "runtime-pqc-discovery ML-DSA test message";
static const size_t MSGLEN = sizeof(MSG) - 1;

int main(int argc, char **argv)
{
	const char *alg = argc > 1 ? argv[1] : "ML-DSA-65";
	OQS_SIG *sig_obj = NULL;
	uint8_t *pk = NULL, *sk = NULL, *sig = NULL;
	size_t siglen = 0;
	int rc = 1;

	OQS_init();
	if (!OQS_SIG_alg_is_enabled(alg)) {
		fprintf(stderr, "[SKIP] %s not enabled in liboqs\n", alg);
		OQS_destroy();
		return 0;
	}

	sig_obj = OQS_SIG_new(alg);
	if (!sig_obj) {
		fprintf(stderr, "OQS_SIG_new failed\n");
		goto out;
	}

	pk = malloc(sig_obj->length_public_key);
	sk = malloc(sig_obj->length_secret_key);
	sig = malloc(sig_obj->length_signature);
	if (!pk || !sk || !sig)
		goto out;

	if (OQS_SIG_keypair(sig_obj, pk, sk) != OQS_SUCCESS)
		goto out;
	if (OQS_SIG_sign(sig_obj, sig, &siglen, MSG, MSGLEN, sk) != OQS_SUCCESS)
		goto out;
	if (OQS_SIG_verify(sig_obj, MSG, MSGLEN, sig, siglen, pk) != OQS_SUCCESS) {
		fprintf(stderr, "signature verification failed for %s\n", alg);
		goto out;
	}

	printf("[workload] liboqs %s keypair+sign+verify OK (siglen=%zu)\n",
	       alg, siglen);
	rc = 0;

out:
	free(pk);
	free(sk);
	free(sig);
	OQS_SIG_free(sig_obj);
	OQS_destroy();
	return rc;
}
