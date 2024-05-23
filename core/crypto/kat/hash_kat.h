// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef HASH_KAT_H_
#define HASH_KAT_H_

#include "crypto/hash.h"


int hash_kat_run_self_test_calculate_sha1 (struct hash_engine *hash);
int hash_kat_run_self_test_calculate_sha256 (struct hash_engine *hash);
int hash_kat_run_self_test_calculate_sha384 (struct hash_engine *hash);
int hash_kat_run_self_test_calculate_sha512 (struct hash_engine *hash);

int hash_kat_run_all_calculate_self_tests (struct hash_engine *hash);

int hash_kat_run_self_test_update_sha1 (struct hash_engine *hash);
int hash_kat_run_self_test_update_sha256 (struct hash_engine *hash);
int hash_kat_run_self_test_update_sha384 (struct hash_engine *hash);
int hash_kat_run_self_test_update_sha512 (struct hash_engine *hash);

int hash_kat_run_all_update_self_tests (struct hash_engine *hash);

int hash_kat_hmac_run_self_test_sha1 (struct hash_engine *hash);
int hash_kat_hmac_run_self_test_sha256 (struct hash_engine *hash);
int hash_kat_hmac_run_self_test_sha384 (struct hash_engine *hash);
int hash_kat_hmac_run_self_test_sha512 (struct hash_engine *hash);

int hash_kat_hmac_run_all_self_tests (struct hash_engine *hash);


/* Hash and HMAC self-tests leverage hash error codes. */


#endif	/* HASH_KAT_H_ */
