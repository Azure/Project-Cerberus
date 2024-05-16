// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef KDF_TESTING_H_
#define KDF_TESTING_H_

#include <stddef.h>
#include <stdint.h>
#include "testing.h"
#include "testing/mock/crypto/hash_mock.h"


int kdf_testing_expect_nist800_108_counter_mode (struct hash_engine_mock *hash,
	enum hash_type hash_algo, const uint8_t *ki, size_t ki_length, uint32_t round,
	const uint8_t *label, size_t label_length, const uint8_t *context, size_t context_length,
	uint32_t bytes_out, const uint8_t *result, size_t result_length);

int kdf_testing_expect_hkdf_expand (struct hash_engine_mock *hash, enum hash_type hash_algo,
	const uint8_t *psk, size_t psk_length, const uint8_t *t, size_t t_length, const uint8_t *info,
	size_t info_length, uint8_t round, const uint8_t *result, size_t result_length);


#endif	/* KDF_TESTING_H_ */
