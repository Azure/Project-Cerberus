// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef DEVICE_UNLOCK_TOKEN_TESTING_H_
#define DEVICE_UNLOCK_TOKEN_TESTING_H_

#include <stdint.h>
#include <stddef.h>
#include "testing.h"


extern const uint8_t DEVICE_UNLOCK_TOKEN_TESTING_UUID[16];
extern const size_t DEVICE_UNLOCK_TOKEN_TESTING_UUID_LEN;

extern const uint8_t DEVICE_UNLOCK_TOKEN_TESTING_UUID_PADDED[16];
extern const size_t DEVICE_UNLOCK_TOKEN_TESTING_UUID_PADDED_LEN;

extern const uint8_t DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED[];
extern const uint8_t DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED_LOCKED[];
extern const uint8_t DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED_LOCKED_UNLOCKED[];
extern const size_t DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED_LEN;

extern const uint8_t DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_LOCKED[];
extern const uint8_t DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_LOCKED_UNLOCKED[];
extern const size_t DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_LOCKED_LEN;

extern const uint8_t DEVICE_UNLOCK_TOKEN_TESTING_NONCE[32];
extern const size_t DEVICE_UNLOCK_TOKEN_TESTING_NONCE_LEN;

extern const uint8_t DEVICE_UNLOCK_TOKEN_TESTING_UNLOCK_POLICY[];
extern const size_t DEVICE_UNLOCK_TOKEN_TESTING_UNLOCK_POLICY_LEN;


void device_unlock_token_testing_build_token (const uint8_t *oid, size_t oid_len,
	const uint8_t *uuid, const uint8_t *counter, size_t counter_len, const uint8_t *nonce,
	const uint8_t *signature, size_t sig_len, uint8_t *token);
size_t device_unlock_token_testing_build_authorized_data (const uint8_t *token, size_t token_len,
	const uint8_t *policy, size_t policy_len, const uint8_t *signature, size_t sig_len,
	uint8_t *auth_data);

void device_unlock_token_testing_allocate_token (CuTest *test, const uint8_t *counter,
	size_t counter_len, uint8_t **token, size_t *length, size_t *context_length);
void device_unlock_token_testing_allocate_authorized_data (CuTest *test, const uint8_t *counter,
	size_t counter_len, size_t extra_space, uint8_t **auth_data, size_t *length,
	size_t *token_offset, size_t *policy_offset);


#endif /* DEVICE_UNLOCK_TOKEN_TESTING_H_ */
