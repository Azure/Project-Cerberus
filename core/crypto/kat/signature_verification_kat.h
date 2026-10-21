// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef SIGNATURE_VERIFICATION_KAT_H_
#define SIGNATURE_VERIFICATION_KAT_H_

#include "crypto/signature_verification.h"


int signature_verification_kat_run_self_test_verify_ecdsa_p256_sha256 (
	const struct signature_verification *ecdsa, const struct hash_engine *hash);
int signature_verification_kat_run_self_test_verify_ecdsa_p384_sha384 (
	const struct signature_verification *ecdsa, const struct hash_engine *hash);
int signature_verification_kat_run_self_test_verify_ecdsa_p521_sha512 (
	const struct signature_verification *ecdsa, const struct hash_engine *hash);

int signature_verification_kat_run_self_test_verify_hash_ecdsa_p256_sha256 (
	const struct signature_verification *ecdsa, const struct hash_engine *hash);
int signature_verification_kat_run_self_test_verify_hash_ecdsa_p384_sha384 (
	const struct signature_verification *ecdsa, const struct hash_engine *hash);
int signature_verification_kat_run_self_test_verify_hash_ecdsa_p521_sha512 (
	const struct signature_verification *ecdsa, const struct hash_engine *hash);


int signature_verification_kat_run_self_test_verify_rsassa_2048_sha256 (
	const struct signature_verification *rsassa, const struct hash_engine *hash);
int signature_verification_kat_run_self_test_verify_rsassa_2048_sha384 (
	const struct signature_verification *rsassa, const struct hash_engine *hash);
int signature_verification_kat_run_self_test_verify_rsassa_2048_sha512 (
	const struct signature_verification *rsassa, const struct hash_engine *hash);
int signature_verification_kat_run_self_test_verify_rsassa_3072_sha384 (
	const struct signature_verification *rsassa, const struct hash_engine *hash);
int signature_verification_kat_run_self_test_verify_rsassa_4096_sha384 (
	const struct signature_verification *rsassa, const struct hash_engine *hash);

int signature_verification_kat_run_self_test_verify_hash_rsassa_2048_sha256 (
	const struct signature_verification *rsassa, const struct hash_engine *hash);
int signature_verification_kat_run_self_test_verify_hash_rsassa_2048_sha384 (
	const struct signature_verification *rsassa, const struct hash_engine *hash);
int signature_verification_kat_run_self_test_verify_hash_rsassa_2048_sha512 (
	const struct signature_verification *rsassa, const struct hash_engine *hash);
int signature_verification_kat_run_self_test_verify_hash_rsassa_3072_sha384 (
	const struct signature_verification *rsassa, const struct hash_engine *hash);
int signature_verification_kat_run_self_test_verify_hash_rsassa_4096_sha384 (
	const struct signature_verification *rsassa, const struct hash_engine *hash);


/* Signature verification self-tests leverage ECDSA and RSASSA error codes. */


#endif	/* SIGNATURE_VERIFICATION_KAT_H_ */
