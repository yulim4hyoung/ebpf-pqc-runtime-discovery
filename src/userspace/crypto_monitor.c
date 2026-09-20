/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <time.h>
#include <stdint.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "events.h"

static volatile sig_atomic_t exiting;

struct monitor_stats {
	uint64_t events_total;
	uint64_t events_crypto;
	uint64_t events_random;
	uint64_t latency_sum_us;
	uint64_t latency_min_us;
	uint64_t latency_max_us;
	uint64_t *latency_samples;
	size_t latency_cap;
	size_t latency_count;
};

struct monitor_config {
	const char *output_path;
	const char *stats_path;
	int duration_sec;
	int poll_timeout_ms;
	int minimal_json;
};

struct event_ctx {
	FILE *out;
	struct monitor_config cfg;
};

static struct monitor_stats g_stats;

static void on_signal(int sig)
{
	(void)sig;
	exiting = 1;
}

static int libbpf_print(enum libbpf_print_level level, const char *fmt, va_list ap)
{
	if (level == LIBBPF_DEBUG)
		return 0;
	return vfprintf(stderr, fmt, ap);
}

static uint64_t now_ns(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static void record_latency(uint64_t latency_us)
{
	if (g_stats.latency_min_us == 0 || latency_us < g_stats.latency_min_us)
		g_stats.latency_min_us = latency_us;
	if (latency_us > g_stats.latency_max_us)
		g_stats.latency_max_us = latency_us;
	g_stats.latency_sum_us += latency_us;

	if (g_stats.latency_count < g_stats.latency_cap) {
		g_stats.latency_samples[g_stats.latency_count++] = latency_us;
	}
}

static const char *op_name(__u8 op)
{
	switch (op) {
	case OP_KEYGEN: return "keygen";
	case OP_ENCAPS: return "encapsulation";
	case OP_DECAPS: return "decapsulation";
	case OP_SIGN: return "sign";
	case OP_VERIFY: return "verify";
	default: return "unknown";
	}
}

static const char *family_name(__u8 f)
{
	switch (f) {
	case FAMILY_CLASSICAL: return "classical";
	case FAMILY_PQC: return "PQC";
	default: return "unknown";
	}
}

static int handle_event(void *ctx, void *data, size_t len)
{
	const struct crypto_event *e = data;
	struct event_ctx *ectx = ctx;
	FILE *out = ectx->out;
	uint64_t recv_ns = now_ns();
	uint64_t latency_us = 0;
	struct timespec ts;
	char tsbuf[64];

	if (len < sizeof(*e))
		return 0;

	if (recv_ns > e->timestamp_ns)
		latency_us = (recv_ns - e->timestamp_ns) / 1000;

	record_latency(latency_us);
	g_stats.events_total++;
	if (e->event_type == EVENT_CRYPTO_API)
		g_stats.events_crypto++;
	else
		g_stats.events_random++;

	clock_gettime(CLOCK_REALTIME, &ts);
	snprintf(tsbuf, sizeof(tsbuf), "%ld.%09ld", ts.tv_sec, ts.tv_nsec);

	if (ectx->cfg.minimal_json) {
		fprintf(out,
			"{\"api\":\"%.32s\",\"alg\":\"%.32s\",\"lat_us\":%llu,\"etype\":%u}\n",
			e->api, e->algorithm, (unsigned long long)latency_us, e->event_type);
	} else {
		fprintf(out,
			"{\"timestamp\":\"%s\",\"event_ns\":%llu,\"receive_ns\":%llu,"
			"\"detection_latency_us\":%llu,\"hostname\":\"localhost\","
			"\"pid\":%u,\"tgid\":%u,\"uid\":%u,\"process\":\"%.16s\","
			"\"api\":\"%.64s\",\"library\":\"%.128s\",\"operation\":\"%s\","
			"\"algorithm\":\"%.64s\",\"crypto_family\":\"%s\",\"event_type\":%u,"
			"\"randomness_recently_observed\":%s,\"random_bytes\":%u,"
			"\"random_delta_us\":%llu,\"confidence\":%.2f}\n",
			tsbuf, (unsigned long long)e->timestamp_ns,
			(unsigned long long)recv_ns, (unsigned long long)latency_us,
			e->pid, e->tgid, e->uid, e->comm, e->api, e->library,
			op_name(e->operation), e->algorithm, family_name(e->crypto_family),
			e->event_type, e->random_recent ? "true" : "false",
			e->random_bytes, (unsigned long long)e->random_delta_us,
			e->confidence_pct / 100.0);
	}

	return 0;
}

static int handle_event_wrapper(void *ctx, void *data, size_t len)
{
	return handle_event(ctx, data, len);
}

static int cmp_u64(const void *a, const void *b)
{
	uint64_t va = *(const uint64_t *)a;
	uint64_t vb = *(const uint64_t *)b;

	if (va < vb) return -1;
	if (va > vb) return 1;
	return 0;
}

static uint64_t percentile(uint64_t *samples, size_t n, double p)
{
	if (!n)
		return 0;
	qsort(samples, n, sizeof(uint64_t), cmp_u64);
	size_t idx = (size_t)((n - 1) * p);
	return samples[idx];
}

static void write_stats(const struct monitor_config *cfg)
{
	FILE *sf;
	uint64_t mean = 0, med = 0, p95 = 0, p99 = 0;

	if (!cfg->stats_path)
		return;

	if (g_stats.latency_count)
		mean = g_stats.latency_sum_us / g_stats.latency_count;

	if (g_stats.latency_count) {
		uint64_t *tmp = malloc(g_stats.latency_count * sizeof(uint64_t));

		if (tmp) {
			memcpy(tmp, g_stats.latency_samples,
			       g_stats.latency_count * sizeof(uint64_t));
			med = percentile(tmp, g_stats.latency_count, 0.50);
			p95 = percentile(tmp, g_stats.latency_count, 0.95);
			p99 = percentile(tmp, g_stats.latency_count, 0.99);
			free(tmp);
		}
	}

	sf = fopen(cfg->stats_path, "w");
	if (!sf)
		return;

	fprintf(sf,
		"{\n"
		"  \"events_total\": %llu,\n"
		"  \"events_crypto\": %llu,\n"
		"  \"events_random\": %llu,\n"
		"  \"latency_us\": {\n"
		"    \"samples\": %zu,\n"
		"    \"mean\": %llu,\n"
		"    \"median\": %llu,\n"
		"    \"p95\": %llu,\n"
		"    \"p99\": %llu,\n"
		"    \"min\": %llu,\n"
		"    \"max\": %llu\n"
		"  },\n"
		"  \"poll_timeout_ms\": %d,\n"
		"  \"minimal_json\": %d\n"
		"}\n",
		(unsigned long long)g_stats.events_total,
		(unsigned long long)g_stats.events_crypto,
		(unsigned long long)g_stats.events_random,
		(size_t)g_stats.latency_count,
		(unsigned long long)mean,
		(unsigned long long)med,
		(unsigned long long)p95,
		(unsigned long long)p99,
		(unsigned long long)g_stats.latency_min_us,
		(unsigned long long)g_stats.latency_max_us,
		cfg->poll_timeout_ms, cfg->minimal_json);

	fclose(sf);
}

static int attach_uprobe(struct bpf_object *obj, const char *prog_name,
			 const char *lib, const char *sym, bool retprobe)
{
	struct bpf_program *prog;
	struct bpf_link *link;
	LIBBPF_OPTS(bpf_uprobe_opts, opts,
		    .func_name = sym,
		    .retprobe = retprobe,
	);

	prog = bpf_object__find_program_by_name(obj, prog_name);
	if (!prog) {
		fprintf(stderr, "attach: program %s not found\n", prog_name);
		return -ENOENT;
	}

	link = bpf_program__attach_uprobe_opts(prog, -1, lib, 0, &opts);
	if (!link) {
		/* Expected for symbols a library lacks (e.g. OpenSSL 1.1 has no
		 * EVP_PKEY_CTX_new_from_pkey); logged so probe coverage is visible. */
		fprintf(stderr, "attach: %s@%s skipped (%s)\n", sym, lib,
			strerror(errno));
		return -errno;
	}

	return 0;
}

static int attach_all(struct bpf_object *obj)
{
	const char *crypto_libs[] = {
		"/usr/lib/x86_64-linux-gnu/libcrypto.so.3",
		"/usr/lib/x86_64-linux-gnu/libcrypto.so.1.1",
		NULL,
	};
	const char *tss2_paths[] = {
		"/usr/lib/x86_64-linux-gnu/libtss2-esys.so.0",
		"/usr/lib/x86_64-linux-gnu/libtss2-esys.so.0.0.1",
		NULL,
	};
	const char *oqs_lib = "/usr/local/lib/liboqs.so";
	enum probe_type { P_CRYPTO, P_OQS, P_TSS2 };
	struct {
		const char *prog;
		const char *sym;
		bool ret;
		enum probe_type type;
	} probes[] = {
		{ "uprobe_evp_pkey_ctx_new_from_name", "EVP_PKEY_CTX_new_from_name", false, P_CRYPTO },
		{ "uretprobe_evp_pkey_ctx_new_from_name", "EVP_PKEY_CTX_new_from_name", true, P_CRYPTO },
		/* 2026-09-20 (A10): name propagation key -> ctx, key producers, cleanup.
		 * Symbols missing from a library (e.g. libcrypto 1.1) fail to attach
		 * silently, which is the intended behaviour. */
		{ "uprobe_evp_pkey_ctx_new_from_pkey", "EVP_PKEY_CTX_new_from_pkey", false, P_CRYPTO },
		{ "uretprobe_evp_pkey_ctx_new_from_pkey", "EVP_PKEY_CTX_new_from_pkey", true, P_CRYPTO },
		{ "uprobe_evp_pkey_ctx_new", "EVP_PKEY_CTX_new", false, P_CRYPTO },
		{ "uretprobe_evp_pkey_ctx_new", "EVP_PKEY_CTX_new", true, P_CRYPTO },
		{ "uprobe_evp_pkey_generate", "EVP_PKEY_generate", false, P_CRYPTO },
		{ "uretprobe_evp_pkey_generate", "EVP_PKEY_generate", true, P_CRYPTO },
		{ "uprobe_evp_pkey_fromdata", "EVP_PKEY_fromdata", false, P_CRYPTO },
		{ "uretprobe_evp_pkey_fromdata", "EVP_PKEY_fromdata", true, P_CRYPTO },
		{ "uprobe_evp_pkey_new_raw_public_key_ex", "EVP_PKEY_new_raw_public_key_ex", false, P_CRYPTO },
		{ "uretprobe_evp_pkey_new_raw_public_key_ex", "EVP_PKEY_new_raw_public_key_ex", true, P_CRYPTO },
		{ "uprobe_evp_pkey_new_raw_private_key_ex", "EVP_PKEY_new_raw_private_key_ex", false, P_CRYPTO },
		{ "uretprobe_evp_pkey_new_raw_private_key_ex", "EVP_PKEY_new_raw_private_key_ex", true, P_CRYPTO },
		{ "uprobe_evp_pkey_ctx_free", "EVP_PKEY_CTX_free", false, P_CRYPTO },
		{ "uprobe_evp_pkey_keygen", "EVP_PKEY_keygen", false, P_CRYPTO },
		{ "uretprobe_evp_pkey_keygen", "EVP_PKEY_keygen", true, P_CRYPTO },
		{ "uprobe_evp_pkey_encapsulate", "EVP_PKEY_encapsulate", false, P_CRYPTO },
		{ "uprobe_evp_pkey_decapsulate", "EVP_PKEY_decapsulate", false, P_CRYPTO },
		{ "uprobe_evp_pkey_sign", "EVP_PKEY_sign", false, P_CRYPTO },
		{ "uprobe_evp_pkey_verify", "EVP_PKEY_verify", false, P_CRYPTO },
		{ "uprobe_evp_digestsign_init", "EVP_DigestSignInit", false, P_CRYPTO },
		{ "uprobe_evp_digestverify_init", "EVP_DigestVerifyInit", false, P_CRYPTO },
		{ "uprobe_rand_bytes", "RAND_bytes", false, P_CRYPTO },
		{ "uprobe_rand_bytes_ex", "RAND_bytes_ex", false, P_CRYPTO },
		{ "uprobe_rand_priv_bytes", "RAND_priv_bytes", false, P_CRYPTO },
		{ "uprobe_rand_priv_bytes_ex", "RAND_priv_bytes_ex", false, P_CRYPTO },
		{ "uprobe_oqs_kem_new", "OQS_KEM_new", false, P_OQS },
		{ "uretprobe_oqs_kem_new", "OQS_KEM_new", true, P_OQS },
		/* 2026-09-20 (A11): keypair events are emitted on return so that the
		 * randomness drawn inside the call is already visible. */
		{ "uprobe_oqs_kem_keypair", "OQS_KEM_keypair", false, P_OQS },
		{ "uretprobe_oqs_kem_keypair", "OQS_KEM_keypair", true, P_OQS },
		{ "uprobe_oqs_kem_encaps", "OQS_KEM_encaps", false, P_OQS },
		{ "uprobe_oqs_kem_decaps", "OQS_KEM_decaps", false, P_OQS },
		{ "uprobe_oqs_kem_free", "OQS_KEM_free", false, P_OQS },
		{ "uprobe_oqs_sig_new", "OQS_SIG_new", false, P_OQS },
		{ "uretprobe_oqs_sig_new", "OQS_SIG_new", true, P_OQS },
		{ "uprobe_oqs_sig_keypair", "OQS_SIG_keypair", false, P_OQS },
		{ "uretprobe_oqs_sig_keypair", "OQS_SIG_keypair", true, P_OQS },
		{ "uprobe_oqs_sig_sign", "OQS_SIG_sign", false, P_OQS },
		{ "uprobe_oqs_sig_verify", "OQS_SIG_verify", false, P_OQS },
		{ "uprobe_oqs_sig_free", "OQS_SIG_free", false, P_OQS },
		{ "uprobe_esys_createprimary", "Esys_CreatePrimary", false, P_TSS2 },
		{ "uprobe_esys_getrandom", "Esys_GetRandom", false, P_TSS2 },
		{ "uprobe_esys_rsaencrypt", "Esys_RSA_Encrypt", false, P_TSS2 },
	};

	for (size_t i = 0; i < sizeof(probes) / sizeof(probes[0]); i++) {
		if (probes[i].type == P_CRYPTO) {
			for (size_t li = 0; crypto_libs[li]; li++) {
				if (access(crypto_libs[li], R_OK) == 0)
					attach_uprobe(obj, probes[i].prog, crypto_libs[li],
						      probes[i].sym, probes[i].ret);
			}
		} else if (probes[i].type == P_OQS) {
			if (access(oqs_lib, R_OK) == 0)
				attach_uprobe(obj, probes[i].prog, oqs_lib,
					      probes[i].sym, probes[i].ret);
		} else if (probes[i].type == P_TSS2) {
			for (size_t ti = 0; tss2_paths[ti]; ti++) {
				if (access(tss2_paths[ti], R_OK) == 0)
					attach_uprobe(obj, probes[i].prog, tss2_paths[ti],
						      probes[i].sym, probes[i].ret);
			}
		}
	}
	return 0;
}

int main(int argc, char **argv)
{
	struct bpf_object *obj;
	struct ring_buffer *rb;
	struct monitor_config cfg = {
		.output_path = NULL,
		.stats_path = NULL,
		.duration_sec = 0,
		.poll_timeout_ms = 100,
		.minimal_json = 0,
	};
	struct event_ctx ectx = { .out = stdout, .cfg = cfg };
	FILE *out = stdout;
	time_t start_time = 0;
	int err;

	g_stats.latency_cap = 1000000;
	g_stats.latency_samples = calloc(g_stats.latency_cap, sizeof(uint64_t));
	if (!g_stats.latency_samples)
		return 1;

	for (int i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "-o") && i + 1 < argc)
			cfg.output_path = argv[++i];
		else if (!strcmp(argv[i], "-S") && i + 1 < argc)
			cfg.stats_path = argv[++i];
		else if (!strcmp(argv[i], "-d") && i + 1 < argc)
			cfg.duration_sec = atoi(argv[++i]);
		else if (!strcmp(argv[i], "-p") && i + 1 < argc)
			cfg.poll_timeout_ms = atoi(argv[++i]);
		else if (!strcmp(argv[i], "-m"))
			cfg.minimal_json = 1;
	}

	ectx.cfg = cfg;

	libbpf_set_print(libbpf_print);
	signal(SIGINT, on_signal);
	signal(SIGTERM, on_signal);

	if (cfg.output_path) {
		out = fopen(cfg.output_path, "a");
		if (!out) {
			perror(cfg.output_path);
			return 1;
		}
	}
	ectx.out = out;

	obj = bpf_object__open_file("build/crypto_monitor.bpf.o", NULL);
	if (!obj)
		return 1;

	err = bpf_object__load(obj);
	if (err)
		return 1;

	attach_all(obj);

	/* Auto-attach remaining programs (e.g. getrandom tracepoint) */
	struct bpf_program *prog;
	bpf_object__for_each_program(prog, obj) {
		const char *sec = bpf_program__section_name(prog);
		if (sec && strstr(sec, "tracepoint")) {
			struct bpf_link *link = bpf_program__attach(prog);
			if (!link)
				fprintf(stderr, "warning: attach %s failed: %d\n",
					bpf_program__name(prog), -errno);
		}
	}

	rb = ring_buffer__new(bpf_object__find_map_fd_by_name(obj, "events"),
			      handle_event_wrapper, &ectx, NULL);
	if (!rb)
		return 1;

	/* Readiness marker: all probes are attached and the ring buffer is
	 * being consumed. Harnesses wait for this line (stderr) before
	 * launching workloads; uprobe attachment can take seconds on VMs. */
	fprintf(stderr, "monitor ready\n");
	fflush(stderr);

	start_time = time(NULL);
	while (!exiting) {
		err = ring_buffer__poll(rb, cfg.poll_timeout_ms);
		if (err == -EINTR)
			break;
		if (cfg.duration_sec > 0 && time(NULL) - start_time >= cfg.duration_sec)
			break;
	}

	write_stats(&cfg);
	ring_buffer__free(rb);
	bpf_object__close(obj);
	if (out != stdout)
		fclose(out);
	free(g_stats.latency_samples);

	return 0;
}
