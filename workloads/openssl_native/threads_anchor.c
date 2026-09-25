/*
 * Multi-thread anchor check for the per-process randomness correlation fix.
 *
 * Main thread: generate an EC P-256 key, draw RAND_bytes(32), then sign a
 * fixed digest (the signature is the object the worker will verify). All
 * randomness is consumed on the main thread.
 *
 * Worker thread (spawned within 1 s): only EVP_PKEY_verify — it never draws
 * randomness itself. With per-thread correlation the worker's verify event
 * has no anchor (the draw happened on a different thread id); with per-process
 * correlation it anchors to the main thread's draw.
 *
 * Build (OpenSSL 3): gcc -O2 threads_anchor.c -o threads_anchor -lcrypto -lpthread
 */
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/obj_mac.h>

static EVP_PKEY *key;
static unsigned char sig[256];
static size_t siglen;
static unsigned char digest[32];

static void *worker(void *arg)
{
	(void)arg;
	EVP_PKEY_CTX *c = EVP_PKEY_CTX_new(key, NULL);
	if (c && EVP_PKEY_verify_init(c) > 0) {
		int r = EVP_PKEY_verify(c, sig, siglen, digest, sizeof(digest));
		printf("[worker] EVP_PKEY_verify = %d\n", r);
	}
	EVP_PKEY_CTX_free(c);
	return NULL;
}

int main(void)
{
	/* EC P-256 key generation (main thread) */
	EVP_PKEY_CTX *g = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
	EVP_PKEY_keygen_init(g);
	EVP_PKEY_CTX_set_ec_paramgen_curve_nid(g, NID_X9_62_prime256v1);
	EVP_PKEY_keygen(g, &key);
	EVP_PKEY_CTX_free(g);

	/* Explicit randomness draw on the main thread (the anchor). */
	unsigned char rnd[32];
	RAND_bytes(rnd, sizeof(rnd));

	/* Sign a fixed digest on the main thread. */
	memset(digest, 0xab, sizeof(digest));
	EVP_PKEY_CTX *s = EVP_PKEY_CTX_new(key, NULL);
	EVP_PKEY_sign_init(s);
	siglen = sizeof(sig);
	EVP_PKEY_sign(s, sig, &siglen, digest, sizeof(digest));
	EVP_PKEY_CTX_free(s);
	printf("[main] EC keygen + RAND_bytes + sign done (siglen=%zu)\n", siglen);

	/* Spawn the worker well within the correlation window. */
	usleep(200 * 1000);
	pthread_t t;
	pthread_create(&t, NULL, worker, NULL);
	pthread_join(t, NULL);

	EVP_PKEY_free(key);
	return 0;
}
