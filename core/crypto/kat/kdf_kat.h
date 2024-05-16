// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef KDF_KAT_H_
#define KDF_KAT_H_

#include "crypto/kdf.h"


int kdf_kat_run_self_test_nist800_108_counter_mode_sha1 (struct hash_engine *hash);
int kdf_kat_run_self_test_nist800_108_counter_mode_sha256 (struct hash_engine *hash);
int kdf_kat_run_self_test_nist800_108_counter_mode_sha384 (struct hash_engine *hash);
int kdf_kat_run_self_test_nist800_108_counter_mode_sha512 (struct hash_engine *hash);

int kdf_kat_run_self_test_hkdf_expand_sha1 (struct hash_engine *hash);
int kdf_kat_run_self_test_hkdf_expand_sha256 (struct hash_engine *hash);
int kdf_kat_run_self_test_hkdf_expand_sha384 (struct hash_engine *hash);
int kdf_kat_run_self_test_hkdf_expand_sha512 (struct hash_engine *hash);


/* KDF self-tests use KDF error codes. */


#endif	/* KDF_KAT_H_ */
