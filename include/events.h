/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
#ifndef EVENTS_H
#define EVENTS_H

#define TASK_COMM_LEN 16
#define API_NAME_LEN 64
#define ALG_NAME_LEN 64
#define LIB_PATH_LEN 128

#define EVENT_CRYPTO_API 1
#define EVENT_RANDOM     2

#define FAMILY_UNKNOWN   0
#define FAMILY_CLASSICAL 1
#define FAMILY_PQC       2

#define OP_UNKNOWN       0
#define OP_KEYGEN        1
#define OP_ENCAPS        2
#define OP_DECAPS        3
#define OP_SIGN          4
#define OP_VERIFY        5
#define OP_DIGEST        6

struct crypto_event {
	__u64 timestamp_ns;
	__u32 pid;
	__u32 tgid;
	__u32 uid;
	char comm[TASK_COMM_LEN];
	char api[API_NAME_LEN];
	char algorithm[ALG_NAME_LEN];
	char library[LIB_PATH_LEN];
	__u8 event_type;
	__u8 crypto_family;
	__u8 operation;
	__u8 random_recent;
	__u32 random_bytes;
	__u64 random_delta_us;
	__u16 confidence_pct;
	__u16 _pad;
};

#endif /* EVENTS_H */
