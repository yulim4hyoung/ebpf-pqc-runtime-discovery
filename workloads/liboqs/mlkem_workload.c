/* liboqs ML-KEM workload */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <oqs/oqs.h>

int main(int argc, char **argv)
{
	const char *alg = argc > 1 ? argv[1] : "ML-KEM-768";
	OQS_KEM *kem;
	uint8_t *pk = NULL, *sk = NULL, *ct = NULL, *ss_e = NULL, *ss_d = NULL;
	int rc = 1;

	OQS_init();
	if (!OQS_KEM_alg_is_enabled(alg)) {
		fprintf(stderr, "[SKIP] %s not enabled in liboqs\n", alg);
		OQS_destroy();
		return 0;
	}

	kem = OQS_KEM_new(alg);
	if (!kem) {
		fprintf(stderr, "OQS_KEM_new failed\n");
		goto out;
	}

	pk = malloc(kem->length_public_key);
	sk = malloc(kem->length_secret_key);
	ct = malloc(kem->length_ciphertext);
	ss_e = malloc(kem->length_shared_secret);
	ss_d = malloc(kem->length_shared_secret);
	if (!pk || !sk || !ct || !ss_e || !ss_d)
		goto out;

	if (OQS_KEM_keypair(kem, pk, sk) != OQS_SUCCESS)
		goto out;
	if (OQS_KEM_encaps(kem, ct, ss_e, pk) != OQS_SUCCESS)
		goto out;
	if (OQS_KEM_decaps(kem, ss_d, ct, sk) != OQS_SUCCESS)
		goto out;

	printf("[workload] liboqs %s keygen+encaps+decaps OK\n", alg);
	rc = 0;

out:
	free(pk);
	free(sk);
	free(ct);
	free(ss_e);
	free(ss_d);
	OQS_KEM_free(kem);
	OQS_destroy();
	return rc;
}
