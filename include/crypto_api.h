/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
#ifndef CRYPTO_API_H
#define CRYPTO_API_H

struct probe_target {
	const char *library;
	const char *symbol;
	const char *api_name;
	__u8 operation;
};

#define LIBCRYPTO_DEFAULT "/usr/lib/x86_64-linux-gnu/libcrypto.so.3"
#define LIBOQS_DEFAULT    "/usr/local/lib/liboqs.so"

#endif /* CRYPTO_API_H */
