/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "../../include/events.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";


/*
 * The libcrypto probes are attached to both OpenSSL 3 and OpenSSL 1.1
 * (crypto_monitor.c, attach_all()); the daemon passes the library index as
 * the uprobe's attach cookie so each event names the library it actually
 * fired in. Fixed 64-byte arrays keep the copy into e->library in bounds.
 */
#define LIBCRYPTO_COOKIE_11 1
static const char libcrypto3_path[64] = "/usr/lib/x86_64-linux-gnu/libcrypto.so.3";
static const char libcrypto11_path[64] = "/usr/lib/x86_64-linux-gnu/libcrypto.so.1.1";

static __always_inline const char *crypto_lib(void *ctx)
{
	return bpf_get_attach_cookie(ctx) == LIBCRYPTO_COOKIE_11 ?
		libcrypto11_path : libcrypto3_path;
}
#define LIBOQS_PATH    "/usr/local/lib/liboqs.so"
#define LIBTSS2_PATH   "/usr/lib/x86_64-linux-gnu/libtss2-esys.so.0"

/*
 * Algorithm-name attribution (2026-09-20, TODO A10).
 *
 * Two name maps, both keyed by (process id, pointer):
 *   ctx_alg_map  : EVP_PKEY_CTX* / OQS_KEM* / OQS_SIG*  -> algorithm name
 *   pkey_alg_map : EVP_PKEY*                            -> algorithm name
 *
 * Producers of names
 *   EVP_PKEY_CTX_new_from_name(libctx, name, propq)      -> ctx name
 *   OQS_KEM_new(name) / OQS_SIG_new(name)                -> ctx name
 *   EVP_PKEY_keygen(ctx, &pkey)        (on return)       -> pkey name := ctx name
 *   EVP_PKEY_fromdata(ctx, &pkey, ...) (on return)       -> pkey name := ctx name
 *   EVP_PKEY_new_raw_{public,private}_key_ex(.., keytype, ..) -> pkey name
 * Propagation
 *   EVP_PKEY_CTX_new_from_pkey(libctx, pkey, propq)      -> ctx name := pkey name
 *   EVP_PKEY_CTX_new(pkey, engine)                        -> ctx name := pkey name
 * Consumers
 *   EVP_PKEY_{keygen,encapsulate,decapsulate,sign,verify}(ctx, ...)  via ctx
 *   EVP_Digest{Sign,Verify}Init(mdctx, pctx, md, e, pkey)             via pkey
 *   EVP_Digest{Sign,Verify}Init_ex(mdctx, pctx, mdname, libctx, propq,
 *                                  pkey, params)                     via pkey (arg 6)
 * Cleanup (prevents a freed address from handing its stale name to a new
 * object at the same address)
 *   EVP_PKEY_CTX_free(ctx), OQS_KEM_free(kem), OQS_SIG_free(sig)
 * EVP_PKEY_free is deliberately not hooked: EVP_PKEY is reference counted
 * and EVP_PKEY_CTX_free drops a reference, so deleting on the first free
 * would strip names from keys the application still holds.
 */

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 16384);
	__type(key, __u64);
	__type(value, char[ALG_NAME_LEN]);
} ctx_alg_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 16384);
	__type(key, __u64);
	__type(value, char[ALG_NAME_LEN]);
} pkey_alg_map SEC(".maps");

/* Pointer to the algorithm-name string passed to a constructor. The string
 * itself is read on RETURN: on the first call in a process the literal may
 * live on a page that has not been faulted in yet, and bpf_probe_read_user
 * cannot take page faults, so an entry-time read silently fails (observed as
 * an unnamed first ML-KEM-512 run). By the time the constructor returns the
 * library has read the string, so the page is present. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, __u32);
	__type(value, __u64);
} pending_name_ptr SEC(".maps");

/* Entry-side stash for functions whose result is read on return. */
struct pending_call {
	__u64 ctx;    /* EVP_PKEY_CTX* / OQS_KEM* / OQS_SIG* (first argument) */
	__u64 ppkey;  /* EVP_PKEY** output argument, or 0 */
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, __u32);
	__type(value, struct pending_call);
} pending_keygen SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, __u32);
	__type(value, struct pending_call);
} pending_fromdata SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, __u32);
	__type(value, struct pending_call);
} pending_generate SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, __u32);
	__type(value, __u64);
} pending_pkey SEC(".maps");     /* EVP_PKEY* given to a ctx constructor */

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, __u32);
	__type(value, __u64);
} pending_oqs_ctx SEC(".maps");  /* OQS_KEM or OQS_SIG object of an in-flight keypair() */

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 16384);
	__type(key, __u32);
	__type(value, struct {
		__u64 ts_ns;
		__u32 bytes;
	});
} last_random SEC(".maps");	/* key: process id (pid_tgid >> 32) */

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 512 * 1024);
} events SEC(".maps");

static __always_inline __u32 cur_pid(void)
{
	return bpf_get_current_pid_tgid() >> 32;
}

static __always_inline __u64 ctx_key(__u32 pid, __u64 ptr)
{
	return ((__u64)pid << 32) | (ptr & 0xffffffff);
}

static __always_inline __u8 classify_family(const char *alg)
{
	if (alg[0] == 'M' && alg[1] == 'L' && alg[2] == '-')
		return FAMILY_PQC;
	if (alg[0] == 'S' && alg[1] == 'L' && alg[2] == 'H')
		return FAMILY_PQC;
	if (alg[0] == 'K' && alg[1] == 'y' && alg[2] == 'b')
		return FAMILY_PQC;
	if (alg[0] == 'D' && alg[1] == 'i' && alg[2] == 'l')
		return FAMILY_PQC;
	if (alg[0] == 'F' && alg[1] == 'r' && alg[2] == 'o')
		return FAMILY_PQC;
	if (alg[0] == 'H' && alg[1] == 'Q' && alg[2] == 'C')
		return FAMILY_PQC;
	if (alg[0] == 'B' && alg[1] == 'I' && alg[2] == 'K')
		return FAMILY_PQC;
	/* Real TLS group names embed the PQC token at a non-zero offset
	 * (e.g. X25519MLKEM768), which the fixed-prefix checks above miss.
	 * Scan for "MLKEM"/"MLDSA" anywhere in the name. */
	for (int i = 0; i + 5 <= ALG_NAME_LEN && alg[i] != '\0'; i++) {
		if (alg[i] == 'M' && alg[i + 1] == 'L' && alg[i + 2] == 'K' &&
		    alg[i + 3] == 'E' && alg[i + 4] == 'M')
			return FAMILY_PQC;
		if (alg[i] == 'M' && alg[i + 1] == 'L' && alg[i + 2] == 'D' &&
		    alg[i + 3] == 'S' && alg[i + 4] == 'A')
			return FAMILY_PQC;
	}
	return FAMILY_CLASSICAL;
}

static __always_inline void fill_process(struct crypto_event *e)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();

	e->timestamp_ns = bpf_ktime_get_ns();
	/* e->pid is the process id (the kernel's tgid); e->tgid carries the
	 * thread id despite its name. The JSON field names are kept as they
	 * are for compatibility with the recorded results. */
	e->pid = pid_tgid >> 32;
	e->tgid = (__u32)pid_tgid;
	e->uid = bpf_get_current_uid_gid() & 0xffffffff;
	bpf_get_current_comm(e->comm, sizeof(e->comm));
}

static __always_inline void apply_random_corr(struct crypto_event *e)
{
	/* Correlate per process, as the paper describes: a draw made by one
	 * thread anchors a cryptographic call made by another thread of the
	 * same process. (Earlier builds keyed by thread id.) */
	__u32 key = e->pid;
	struct {
		__u64 ts_ns;
		__u32 bytes;
	} *rnd = bpf_map_lookup_elem(&last_random, &key);

	if (!rnd)
		return;

	__u64 delta = e->timestamp_ns - rnd->ts_ns;
	if (delta <= 1000000000ULL) {
		e->random_recent = 1;
		e->random_bytes = rnd->bytes;
		e->random_delta_us = delta / 1000;
	}
}

/* Copy the name stored for (pid, ptr) in `map` into dst; dst untouched if none. */
static __always_inline int copy_name(void *map, __u32 pid, __u64 ptr, char *dst)
{
	__u64 key;
	char *alg;

	if (!ptr)
		return 0;
	key = ctx_key(pid, ptr);
	alg = bpf_map_lookup_elem(map, &key);
	if (!alg)
		return 0;
	__builtin_memcpy(dst, alg, ALG_NAME_LEN);
	return 1;
}

static __always_inline void store_name(void *map, __u32 pid, __u64 ptr,
				       const char *name)
{
	__u64 key;

	if (!ptr || !name[0])
		return;
	key = ctx_key(pid, ptr);
	bpf_map_update_elem(map, &key, name, BPF_ANY);
}

static __always_inline void forget_name(void *map, __u32 pid, __u64 ptr)
{
	__u64 key;

	if (!ptr)
		return;
	key = ctx_key(pid, ptr);
	bpf_map_delete_elem(map, &key);
}

/*
 * Emit one cryptographic event. The algorithm name is resolved from the
 * context pointer first and from the key pointer second; an event with no
 * resolvable name is reported with family "unknown" rather than
 * "classical", so that an unnamed post-quantum operation is never
 * mislabelled.
 */
static __always_inline int emit_crypto(const char *api, const char *lib,
				       __u8 op, __u64 ctx_ptr, __u64 pkey_ptr)
{
	struct crypto_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);

	if (!e)
		return 0;

	__builtin_memset(e, 0, sizeof(*e));
	fill_process(e);
	e->event_type = EVENT_CRYPTO_API;
	e->operation = op;
	__builtin_memcpy(e->api, api, 32);
	__builtin_memcpy(e->library, lib, 64);

	/* Producers key the name maps by the process id (pid_tgid >> 32),
	 * which fill_process() stores in e->pid; use the same key here. */
	if (!copy_name(&ctx_alg_map, e->pid, ctx_ptr, e->algorithm))
		copy_name(&pkey_alg_map, e->pid, pkey_ptr, e->algorithm);

	apply_random_corr(e);
	e->crypto_family = e->algorithm[0] ? classify_family(e->algorithm)
					   : FAMILY_UNKNOWN;
	e->confidence_pct = e->algorithm[0] ? 90 : 50;
	if (e->random_recent && e->algorithm[0])
		e->confidence_pct = 100;

	bpf_ringbuf_submit(e, 0);
	return 0;
}

/* ------------------------------------------------------------------ */
/* Name producers: constructor from a name string                      */
/* ------------------------------------------------------------------ */

static __always_inline int stash_name_arg(__u64 name_ptr)
{
	__u32 pid = cur_pid();

	if (!name_ptr)
		return 0;
	return bpf_map_update_elem(&pending_name_ptr, &pid, &name_ptr, BPF_ANY);
}

static __always_inline int bind_pending_name(void *map, __u64 ret)
{
	__u32 pid = cur_pid();
	__u64 *pp = bpf_map_lookup_elem(&pending_name_ptr, &pid);
	char name[ALG_NAME_LEN] = {};

	if (!pp)
		return 0;
	if (ret) {
		bpf_probe_read_user_str(name, sizeof(name), (const void *)*pp);
		if (name[0])
			store_name(map, pid, ret, name);
	}
	bpf_map_delete_elem(&pending_name_ptr, &pid);
	return 0;
}

SEC("uprobe")
int uprobe_evp_pkey_ctx_new_from_name(struct pt_regs *ctx)
{
	/* EVP_PKEY_CTX_new_from_name(libctx, name, propq) */
	return stash_name_arg(PT_REGS_PARM2(ctx));
}

SEC("uretprobe")
int uretprobe_evp_pkey_ctx_new_from_name(struct pt_regs *ctx)
{
	return bind_pending_name(&ctx_alg_map, PT_REGS_RC(ctx));
}

SEC("uprobe")
int uprobe_evp_pkey_new_raw_public_key_ex(struct pt_regs *ctx)
{
	/* EVP_PKEY_new_raw_public_key_ex(libctx, keytype, propq, key, keylen) */
	return stash_name_arg(PT_REGS_PARM2(ctx));
}

SEC("uretprobe")
int uretprobe_evp_pkey_new_raw_public_key_ex(struct pt_regs *ctx)
{
	return bind_pending_name(&pkey_alg_map, PT_REGS_RC(ctx));
}

SEC("uprobe")
int uprobe_evp_pkey_new_raw_private_key_ex(struct pt_regs *ctx)
{
	return stash_name_arg(PT_REGS_PARM2(ctx));
}

SEC("uretprobe")
int uretprobe_evp_pkey_new_raw_private_key_ex(struct pt_regs *ctx)
{
	return bind_pending_name(&pkey_alg_map, PT_REGS_RC(ctx));
}

/* ------------------------------------------------------------------ */
/* Name propagation: context constructed from an existing key          */
/* ------------------------------------------------------------------ */

static __always_inline int stash_pkey_arg(__u64 pkey)
{
	__u32 pid = cur_pid();

	if (!pkey)
		return 0;
	return bpf_map_update_elem(&pending_pkey, &pid, &pkey, BPF_ANY);
}

static __always_inline int bind_ctx_from_pkey(__u64 ret_ctx)
{
	__u32 pid = cur_pid();
	__u64 *pkey = bpf_map_lookup_elem(&pending_pkey, &pid);
	char name[ALG_NAME_LEN] = {};

	if (!pkey)
		return 0;
	if (ret_ctx && copy_name(&pkey_alg_map, pid, *pkey, name))
		store_name(&ctx_alg_map, pid, ret_ctx, name);
	bpf_map_delete_elem(&pending_pkey, &pid);
	return 0;
}

SEC("uprobe")
int uprobe_evp_pkey_ctx_new_from_pkey(struct pt_regs *ctx)
{
	/* EVP_PKEY_CTX_new_from_pkey(libctx, pkey, propq): the constructor
	 * used for encapsulation, decapsulation, sign and verify contexts. */
	return stash_pkey_arg(PT_REGS_PARM2(ctx));
}

SEC("uretprobe")
int uretprobe_evp_pkey_ctx_new_from_pkey(struct pt_regs *ctx)
{
	return bind_ctx_from_pkey(PT_REGS_RC(ctx));
}

SEC("uprobe")
int uprobe_evp_pkey_ctx_new(struct pt_regs *ctx)
{
	/* EVP_PKEY_CTX_new(pkey, engine): legacy constructor, still used by
	 * applications written against the OpenSSL 1.1 API. */
	return stash_pkey_arg(PT_REGS_PARM1(ctx));
}

SEC("uretprobe")
int uretprobe_evp_pkey_ctx_new(struct pt_regs *ctx)
{
	return bind_ctx_from_pkey(PT_REGS_RC(ctx));
}

/* ------------------------------------------------------------------ */
/* Key generation / key import: name flows from ctx to the new key     */
/* ------------------------------------------------------------------ */

static __always_inline int stash_call(void *map, __u64 fn_ctx, __u64 ppkey)
{
	__u32 pid = cur_pid();
	struct pending_call pc = { .ctx = fn_ctx, .ppkey = ppkey };

	return bpf_map_update_elem(map, &pid, &pc, BPF_ANY);
}

/* On return: if the call succeeded, read *ppkey and give the new key the
 * context's name. Returns the stashed ctx pointer (0 if none). */
static __always_inline __u64 finish_call(void *map, __u64 ret)
{
	__u32 pid = cur_pid();
	struct pending_call *pc = bpf_map_lookup_elem(map, &pid);
	__u64 fn_ctx = 0, ppkey = 0, pkey = 0;
	char name[ALG_NAME_LEN] = {};

	if (!pc)
		return 0;
	fn_ctx = pc->ctx;
	ppkey = pc->ppkey;
	bpf_map_delete_elem(map, &pid);

	if (ret == 1 && ppkey &&
	    bpf_probe_read_user(&pkey, sizeof(pkey), (const void *)ppkey) == 0 &&
	    pkey && copy_name(&ctx_alg_map, pid, fn_ctx, name))
		store_name(&pkey_alg_map, pid, pkey, name);

	return fn_ctx;
}

SEC("uprobe")
int uprobe_evp_pkey_keygen(struct pt_regs *ctx)
{
	/* EVP_PKEY_keygen(ctx, &pkey). Entry: stash both so the uretprobe can
	 * resolve the algorithm, correlate RNG and name the generated key. */
	return stash_call(&pending_keygen, PT_REGS_PARM1(ctx), PT_REGS_PARM2(ctx));
}

SEC("uretprobe")
int uretprobe_evp_pkey_keygen(struct pt_regs *ctx)
{
	/*
	 * Emit on RETURN: OpenSSL 3 RSA calls RAND_priv_bytes_ex *inside*
	 * keygen, so entry-time correlation always misses randomness.
	 */
	__u64 ctx_ptr = finish_call(&pending_keygen, PT_REGS_RC(ctx));

	return emit_crypto("EVP_PKEY_keygen", crypto_lib(ctx), OP_KEYGEN, ctx_ptr, 0);
}

SEC("uprobe")
int uprobe_evp_pkey_generate(struct pt_regs *ctx)
{
	/* EVP_PKEY_generate(ctx, &pkey) is the generic generator behind both
	 * EVP_PKEY_keygen and EVP_PKEY_paramgen (TLS creates its key-share
	 * template keys through paramgen), so hook it as a name producer only;
	 * the key-generation event itself still comes from EVP_PKEY_keygen. */
	return stash_call(&pending_generate, PT_REGS_PARM1(ctx), PT_REGS_PARM2(ctx));
}

SEC("uretprobe")
int uretprobe_evp_pkey_generate(struct pt_regs *ctx)
{
	finish_call(&pending_generate, PT_REGS_RC(ctx));
	return 0;
}

SEC("uprobe")
int uprobe_evp_pkey_fromdata(struct pt_regs *ctx)
{
	/* EVP_PKEY_fromdata(ctx, &pkey, selection, params): imports a key
	 * (e.g. a TLS peer's public key) through a name-constructed ctx. */
	return stash_call(&pending_fromdata, PT_REGS_PARM1(ctx), PT_REGS_PARM2(ctx));
}

SEC("uretprobe")
int uretprobe_evp_pkey_fromdata(struct pt_regs *ctx)
{
	finish_call(&pending_fromdata, PT_REGS_RC(ctx));
	return 0;
}

SEC("uprobe")
int uprobe_evp_pkey_ctx_free(struct pt_regs *ctx)
{
	forget_name(&ctx_alg_map, cur_pid(), PT_REGS_PARM1(ctx));
	return 0;
}

/* ------------------------------------------------------------------ */
/* Cryptographic operations (OpenSSL EVP)                              */
/* ------------------------------------------------------------------ */

SEC("uprobe")
int uprobe_evp_pkey_encapsulate(struct pt_regs *ctx)
{
	return emit_crypto("EVP_PKEY_encapsulate", crypto_lib(ctx), OP_ENCAPS,
			   PT_REGS_PARM1(ctx), 0);
}

SEC("uprobe")
int uprobe_evp_pkey_decapsulate(struct pt_regs *ctx)
{
	return emit_crypto("EVP_PKEY_decapsulate", crypto_lib(ctx), OP_DECAPS,
			   PT_REGS_PARM1(ctx), 0);
}

SEC("uprobe")
int uprobe_evp_pkey_sign(struct pt_regs *ctx)
{
	/* EVP_PKEY_sign(ctx, sig, siglen, tbs, tbslen) — ctx = arg1.
	 * Covers sign paths that never touch keygen (e.g. hard-coded keys),
	 * the coverage gap exposed by the qed-synthetic-rsa case. */
	return emit_crypto("EVP_PKEY_sign", crypto_lib(ctx), OP_SIGN,
			   PT_REGS_PARM1(ctx), 0);
}

SEC("uprobe")
int uprobe_evp_pkey_verify(struct pt_regs *ctx)
{
	return emit_crypto("EVP_PKEY_verify", crypto_lib(ctx), OP_VERIFY,
			   PT_REGS_PARM1(ctx), 0);
}

SEC("uprobe")
int uprobe_evp_digestsign_init(struct pt_regs *ctx)
{
	/* EVP_DigestSignInit(mdctx, pctx, md, engine, pkey): the EVP_MD_CTX
	 * carries no name, but the key (arg 5) may be known from pkey_alg_map. */
	return emit_crypto("EVP_DigestSignInit", crypto_lib(ctx), OP_SIGN, 0,
			   PT_REGS_PARM5(ctx));
}

SEC("uprobe")
int uprobe_evp_digestverify_init(struct pt_regs *ctx)
{
	return emit_crypto("EVP_DigestVerifyInit", crypto_lib(ctx), OP_VERIFY, 0,
			   PT_REGS_PARM5(ctx));
}

/* 2026-09-20: the _ex variants. OpenSSL 3 applications (the openssl command,
 * libssl) call EVP_DigestSignInit_ex / EVP_DigestVerifyInit_ex rather than
 * the five-argument forms; for ML-DSA, whose provider signs whole messages
 * in one shot, this init call is the only signature-side symbol that fires
 * (EVP_DigestSign() goes straight to the provider). The key is the sixth
 * argument. Both variants are siblings that call the internal
 * do_sigver_init(), so hooking both never fires twice for one call. */
SEC("uprobe")
int uprobe_evp_digestsign_init_ex(struct pt_regs *ctx)
{
	/* EVP_DigestSignInit_ex(mdctx, pctx, mdname, libctx, propq, pkey, params) */
	return emit_crypto("EVP_DigestSignInit_ex", crypto_lib(ctx), OP_SIGN, 0,
			   PT_REGS_PARM6(ctx));
}

SEC("uprobe")
int uprobe_evp_digestverify_init_ex(struct pt_regs *ctx)
{
	return emit_crypto("EVP_DigestVerifyInit_ex", crypto_lib(ctx), OP_VERIFY, 0,
			   PT_REGS_PARM6(ctx));
}

/* ------------------------------------------------------------------ */
/* Randomness observations                                             */
/* ------------------------------------------------------------------ */

/* OpenSSL 3 keygen uses RAND_priv_bytes_ex, not RAND_bytes. */
static __always_inline int emit_random_api(const char *api, const char *lib,
					   __u32 num)
{
	struct crypto_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	__u32 key;
	struct {
		__u64 ts_ns;
		__u32 bytes;
	} val;

	/* Always refresh correlation map even if ringbuf is full. */
	key = cur_pid();
	val.ts_ns = bpf_ktime_get_ns();
	val.bytes = num;
	bpf_map_update_elem(&last_random, &key, &val, BPF_ANY);

	if (!e)
		return 0;

	__builtin_memset(e, 0, sizeof(*e));
	fill_process(e);
	e->event_type = EVENT_RANDOM;
	e->timestamp_ns = val.ts_ns;
	__builtin_memcpy(e->api, api, 32);
	__builtin_memcpy(e->library, lib, 64);
	e->random_bytes = num;

	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("uprobe")
int uprobe_rand_bytes(struct pt_regs *ctx)
{
	/* RAND_bytes(buf, num) — num = arg2 */
	return emit_random_api("RAND_bytes", crypto_lib(ctx), (__u32)PT_REGS_PARM2(ctx));
}

SEC("uprobe")
int uprobe_rand_bytes_ex(struct pt_regs *ctx)
{
	/* RAND_bytes_ex(ctx, buf, num, strength) — num = arg3 */
	return emit_random_api("RAND_bytes_ex", crypto_lib(ctx), (__u32)PT_REGS_PARM3(ctx));
}

SEC("uprobe")
int uprobe_rand_priv_bytes(struct pt_regs *ctx)
{
	/* RAND_priv_bytes(buf, num) — num = arg2 */
	return emit_random_api("RAND_priv_bytes", crypto_lib(ctx), (__u32)PT_REGS_PARM2(ctx));
}

SEC("uprobe")
int uprobe_rand_priv_bytes_ex(struct pt_regs *ctx)
{
	/* RAND_priv_bytes_ex(ctx, buf, num, strength) — num = arg3 */
	return emit_random_api("RAND_priv_bytes_ex", crypto_lib(ctx), (__u32)PT_REGS_PARM3(ctx));
}

/* ------------------------------------------------------------------ */
/* liboqs                                                              */
/* ------------------------------------------------------------------ */

SEC("uprobe")
int uprobe_oqs_kem_new(struct pt_regs *ctx)
{
	/* OQS_KEM_new(method_name) */
	return stash_name_arg(PT_REGS_PARM1(ctx));
}

SEC("uretprobe")
int uretprobe_oqs_kem_new(struct pt_regs *ctx)
{
	return bind_pending_name(&ctx_alg_map, PT_REGS_RC(ctx));
}

static __always_inline int stash_oqs_ctx(__u64 obj)
{
	__u32 pid = cur_pid();

	return bpf_map_update_elem(&pending_oqs_ctx, &pid, &obj, BPF_ANY);
}

static __always_inline __u64 pop_oqs_ctx(void)
{
	__u32 pid = cur_pid();
	__u64 *p = bpf_map_lookup_elem(&pending_oqs_ctx, &pid);
	__u64 obj = p ? *p : 0;

	bpf_map_delete_elem(&pending_oqs_ctx, &pid);
	return obj;
}

SEC("uprobe")
int uprobe_oqs_kem_keypair(struct pt_regs *ctx)
{
	/* OQS_KEM_keypair(kem, pk, sk) draws its randomness inside the call,
	 * so the event is emitted on return (TODO A11), exactly as for
	 * EVP_PKEY_keygen; the entry probe only stashes the kem pointer. */
	return stash_oqs_ctx(PT_REGS_PARM1(ctx));
}

SEC("uretprobe")
int uretprobe_oqs_kem_keypair(struct pt_regs *ctx)
{
	return emit_crypto("OQS_KEM_keypair", LIBOQS_PATH, OP_KEYGEN,
			   pop_oqs_ctx(), 0);
}

SEC("uprobe")
int uprobe_oqs_kem_encaps(struct pt_regs *ctx)
{
	return emit_crypto("OQS_KEM_encaps", LIBOQS_PATH, OP_ENCAPS,
			   PT_REGS_PARM1(ctx), 0);
}

SEC("uprobe")
int uprobe_oqs_kem_decaps(struct pt_regs *ctx)
{
	return emit_crypto("OQS_KEM_decaps", LIBOQS_PATH, OP_DECAPS,
			   PT_REGS_PARM1(ctx), 0);
}

SEC("uprobe")
int uprobe_oqs_kem_free(struct pt_regs *ctx)
{
	forget_name(&ctx_alg_map, cur_pid(), PT_REGS_PARM1(ctx));
	return 0;
}

SEC("uprobe")
int uprobe_oqs_sig_new(struct pt_regs *ctx)
{
	return stash_name_arg(PT_REGS_PARM1(ctx));
}

SEC("uretprobe")
int uretprobe_oqs_sig_new(struct pt_regs *ctx)
{
	return bind_pending_name(&ctx_alg_map, PT_REGS_RC(ctx));
}

SEC("uprobe")
int uprobe_oqs_sig_keypair(struct pt_regs *ctx)
{
	return stash_oqs_ctx(PT_REGS_PARM1(ctx));
}

SEC("uretprobe")
int uretprobe_oqs_sig_keypair(struct pt_regs *ctx)
{
	return emit_crypto("OQS_SIG_keypair", LIBOQS_PATH, OP_KEYGEN,
			   pop_oqs_ctx(), 0);
}

SEC("uprobe")
int uprobe_oqs_sig_sign(struct pt_regs *ctx)
{
	return emit_crypto("OQS_SIG_sign", LIBOQS_PATH, OP_SIGN,
			   PT_REGS_PARM1(ctx), 0);
}

SEC("uprobe")
int uprobe_oqs_sig_verify(struct pt_regs *ctx)
{
	return emit_crypto("OQS_SIG_verify", LIBOQS_PATH, OP_VERIFY,
			   PT_REGS_PARM1(ctx), 0);
}

SEC("uprobe")
int uprobe_oqs_sig_free(struct pt_regs *ctx)
{
	forget_name(&ctx_alg_map, cur_pid(), PT_REGS_PARM1(ctx));
	return 0;
}

/* ------------------------------------------------------------------ */
/* TPM2-TSS                                                            */
/* ------------------------------------------------------------------ */

SEC("uprobe")
int uprobe_esys_createprimary(struct pt_regs *ctx)
{
	return emit_crypto("Esys_CreatePrimary", LIBTSS2_PATH, OP_KEYGEN, 0, 0);
}

SEC("uprobe")
int uprobe_esys_getrandom(struct pt_regs *ctx)
{
	return emit_crypto("Esys_GetRandom", LIBTSS2_PATH, OP_UNKNOWN, 0, 0);
}

SEC("uprobe")
int uprobe_esys_rsaencrypt(struct pt_regs *ctx)
{
	return emit_crypto("Esys_RSA_Encrypt", LIBTSS2_PATH, OP_ENCAPS, 0, 0);
}

/* ------------------------------------------------------------------ */
/* Kernel RNG                                                          */
/* ------------------------------------------------------------------ */

SEC("tracepoint/syscalls/sys_enter_getrandom")
int trace_getrandom(struct trace_event_raw_sys_enter *ctx)
{
	struct crypto_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	__u64 args = ctx->args[1];
	__u32 key;
	struct {
		__u64 ts_ns;
		__u32 bytes;
	} val;

	if (!e)
		return 0;

	__builtin_memset(e, 0, sizeof(*e));
	fill_process(e);
	e->event_type = EVENT_RANDOM;
	__builtin_memcpy(e->api, "getrandom", 16);
	e->random_bytes = (__u32)args;

	key = e->pid;
	val.ts_ns = e->timestamp_ns;
	val.bytes = e->random_bytes;
	bpf_map_update_elem(&last_random, &key, &val, BPF_ANY);

	bpf_ringbuf_submit(e, 0);
	return 0;
}
