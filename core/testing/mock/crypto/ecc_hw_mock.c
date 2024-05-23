// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "ecc_hw_mock.h"


static int ecc_hw_mock_get_ecc_public_key (const struct ecc_hw *ecc_hw, const uint8_t *priv_key,
	size_t key_length, struct ecc_point_public_key *pub_key)
{
	struct ecc_hw_mock *mock = (struct ecc_hw_mock*) ecc_hw;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, ecc_hw_mock_get_ecc_public_key, ecc_hw, MOCK_ARG_PTR_CALL (priv_key),
		MOCK_ARG_CALL (key_length), MOCK_ARG_PTR_CALL (pub_key));
}

static int ecc_hw_mock_generate_ecc_key_pair (const struct ecc_hw *ecc_hw, size_t key_length,
	uint8_t *priv_key, struct ecc_point_public_key *pub_key)
{
	struct ecc_hw_mock *mock = (struct ecc_hw_mock*) ecc_hw;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, ecc_hw_mock_generate_ecc_key_pair, ecc_hw, MOCK_ARG_CALL (key_length),
		MOCK_ARG_PTR_CALL (priv_key), MOCK_ARG_PTR_CALL (pub_key));
}

static int ecc_hw_mock_ecdsa_sign (const struct ecc_hw *ecc_hw, const uint8_t *priv_key,
	size_t key_length, const uint8_t *digest, size_t digest_length, struct rng_engine *rng,
	struct ecc_ecdsa_signature *signature)
{
	struct ecc_hw_mock *mock = (struct ecc_hw_mock*) ecc_hw;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, ecc_hw_mock_ecdsa_sign, ecc_hw, MOCK_ARG_PTR_CALL (priv_key),
		MOCK_ARG_CALL (key_length), MOCK_ARG_PTR_CALL (digest), MOCK_ARG_CALL (digest_length),
		MOCK_ARG_PTR_CALL (rng), MOCK_ARG_PTR_CALL (signature));
}

static int ecc_hw_mock_ecdsa_verify (const struct ecc_hw *ecc_hw,
	const struct ecc_point_public_key *pub_key, const struct ecc_ecdsa_signature *signature,
	const uint8_t *digest, size_t digest_length)
{
	struct ecc_hw_mock *mock = (struct ecc_hw_mock*) ecc_hw;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, ecc_hw_mock_ecdsa_verify, ecc_hw, MOCK_ARG_PTR_CALL (pub_key),
		MOCK_ARG_PTR_CALL (signature), MOCK_ARG_PTR_CALL (digest), MOCK_ARG_CALL (digest_length));
}

static int ecc_hw_mock_ecdh_compute (const struct ecc_hw *ecc_hw, const uint8_t *priv_key,
	size_t key_length, const struct ecc_point_public_key *pub_key, uint8_t *secret, size_t length)
{
	struct ecc_hw_mock *mock = (struct ecc_hw_mock*) ecc_hw;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, ecc_hw_mock_ecdh_compute, ecc_hw, MOCK_ARG_PTR_CALL (priv_key),
		MOCK_ARG_CALL (key_length), MOCK_ARG_PTR_CALL (pub_key), MOCK_ARG_PTR_CALL (secret),
		MOCK_ARG_CALL (length));
}

static int ecc_hw_mock_is_free (const struct ecc_hw *ecc_hw)
{
	struct ecc_hw_mock *mock = (struct ecc_hw_mock*) ecc_hw;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN_NO_ARGS (&mock->mock, ecc_hw_mock_is_free, ecc_hw);
}

static int ecc_hw_mock_func_arg_count (void *func)
{
	if (func == ecc_hw_mock_ecdsa_sign) {
		return 6;
	}
	else if (func == ecc_hw_mock_ecdh_compute) {
		return 5;
	}
	else if (func == ecc_hw_mock_ecdsa_verify) {
		return 4;
	}
	else if ((func == ecc_hw_mock_get_ecc_public_key) ||
		(func == ecc_hw_mock_generate_ecc_key_pair)) {
		return 3;
	}
	else {
		return 0;
	}
}

static const char* ecc_hw_mock_func_name_map (void *func)
{
	if (func == ecc_hw_mock_get_ecc_public_key) {
		return "get_ecc_public_key";
	}
	else if (func == ecc_hw_mock_generate_ecc_key_pair) {
		return "generate_ecc_key_pair";
	}
	else if (func == ecc_hw_mock_ecdsa_sign) {
		return "ecdsa_sign";
	}
	else if (func == ecc_hw_mock_ecdsa_verify) {
		return "ecdsa_verify";
	}
	else if (func == ecc_hw_mock_ecdh_compute) {
		return "ecdh_compute";
	}
	else if (func == ecc_hw_mock_is_free) {
		return "is_free";
	}
	else {
		return "unknown";
	}
}

static const char* ecc_hw_mock_arg_name_map (void *func, int arg)
{
	if (func == ecc_hw_mock_get_ecc_public_key) {
		switch (arg) {
			case 0:
				return "priv_key";

			case 1:
				return "key_length";

			case 2:
				return "pub_key";
		}
	}
	else if (func == ecc_hw_mock_generate_ecc_key_pair) {
		switch (arg) {
			case 0:
				return "key_length";

			case 1:
				return "priv_key";

			case 2:
				return "pub_key";
		}
	}
	else if (func == ecc_hw_mock_ecdsa_sign) {
		switch (arg) {
			case 0:
				return "priv_key";

			case 1:
				return "key_length";

			case 2:
				return "digest";

			case 3:
				return "digest_length";

			case 4:
				return "rng";

			case 5:
				return "signature";
		}
	}
	else if (func == ecc_hw_mock_ecdsa_verify) {
		switch (arg) {
			case 0:
				return "pub_key";

			case 1:
				return "signature";

			case 2:
				return "digest";

			case 3:
				return "digest_length";
		}
	}
	else if (func == ecc_hw_mock_ecdh_compute) {
		switch (arg) {
			case 0:
				return "priv_key";

			case 1:
				return "key_length";

			case 2:
				return "pub_key";

			case 3:
				return "secret";

			case 4:
				return "length";
		}
	}

	return "unknown";
}

/**
 * Initialize a mock instance for an ECC HW accelerator.
 *
 * @param mock The mock to initialize.
 *
 * @return 0 if the mock was successfully initialized or an error code.
 */
int ecc_hw_mock_init (struct ecc_hw_mock *mock)
{
	int status;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	memset (mock, 0, sizeof (struct ecc_hw_mock));

	status = mock_init (&mock->mock);
	if (status != 0) {
		return status;
	}

	mock_set_name (&mock->mock, "ecc_hw");

	mock->base.get_ecc_public_key = ecc_hw_mock_get_ecc_public_key;
	mock->base.generate_ecc_key_pair = ecc_hw_mock_generate_ecc_key_pair;
	mock->base.ecdsa_sign = ecc_hw_mock_ecdsa_sign;
	mock->base.ecdsa_verify = ecc_hw_mock_ecdsa_verify;
	mock->base.ecdh_compute = ecc_hw_mock_ecdh_compute;
	mock->base.is_free = ecc_hw_mock_is_free;

	mock->mock.func_arg_count = ecc_hw_mock_func_arg_count;
	mock->mock.func_name_map = ecc_hw_mock_func_name_map;
	mock->mock.arg_name_map = ecc_hw_mock_arg_name_map;

	return 0;
}

/**
 * Release the resources used by the mock API.
 *
 * @param mock The mock to release.
 */
void ecc_hw_mock_release (struct ecc_hw_mock *mock)
{
	if (mock) {
		mock_release (&mock->mock);
	}
}

/**
 * Validate all mock expectations were called and release the mock instance.
 *
 * @param mock The mock to validate.
 *
 * @return 0 if the expectations were met or 1 if not.
 */
int ecc_hw_mock_validate_and_release (struct ecc_hw_mock *mock)
{
	int status = 1;

	if (mock != NULL) {
		status = mock_validate (&mock->mock);
		ecc_hw_mock_release (mock);
	}

	return status;
}
