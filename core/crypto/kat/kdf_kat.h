// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef KDF_KAT_H_
#define KDF_KAT_H_

#include "crypto/hkdf_interface.h"
#include "crypto/kdf.h"


int kdf_kat_run_self_test_nist800_108_counter_mode_sha1 (const struct hash_engine *hash);
int kdf_kat_run_self_test_nist800_108_counter_mode_sha256 (const struct hash_engine *hash);
int kdf_kat_run_self_test_nist800_108_counter_mode_sha384 (const struct hash_engine *hash);
int kdf_kat_run_self_test_nist800_108_counter_mode_sha512 (const struct hash_engine *hash);

int kdf_kat_run_self_test_hkdf_sha1 (const struct hkdf_interface *hkdf);
int kdf_kat_run_self_test_hkdf_sha256 (const struct hkdf_interface *hkdf);
int kdf_kat_run_self_test_hkdf_sha384 (const struct hkdf_interface *hkdf);
int kdf_kat_run_self_test_hkdf_sha512 (const struct hkdf_interface *hkdf);


/* KDF self-tests use KDF error codes. */


#endif	/* KDF_KAT_H_ */
