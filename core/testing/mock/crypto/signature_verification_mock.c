// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "signature_verification_mock.h"


static int signature_verification_mock_verify_signature (
	const struct signature_verification *verification, const uint8_t *digest, size_t length,
	const uint8_t *signature, size_t sig_length)
{
	struct signature_verification_mock *mock = (struct signature_verification_mock*) verification;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, signature_verification_mock_verify_signature, verification,
		MOCK_ARG_PTR_CALL (digest), MOCK_ARG_CALL (length), MOCK_ARG_PTR_CALL (signature),
		MOCK_ARG_CALL (sig_length));
}

static int signature_verification_mock_get_max_signature_length (
	const struct signature_verification *verification, size_t *max_length)
{
	struct signature_verification_mock *mock = (struct signature_verification_mock*) verification;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, signature_verification_mock_get_max_signature_length, verification,
		MOCK_ARG_PTR_CALL (max_length));
}

static int signature_verification_mock_set_verification_key (
	const struct signature_verification *verification, const uint8_t *key, size_t length)
{
	struct signature_verification_mock *mock = (struct signature_verification_mock*) verification;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, signature_verification_mock_set_verification_key, verification,
		MOCK_ARG_PTR_CALL (key), MOCK_ARG_CALL (length));
}

static int signature_verification_mock_is_key_valid (
	const struct signature_verification *verification, const uint8_t *key, size_t length)
{
	struct signature_verification_mock *mock = (struct signature_verification_mock*) verification;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, signature_verification_mock_is_key_valid, verification,
		MOCK_ARG_PTR_CALL (key), MOCK_ARG_CALL (length));
}

static int signature_verification_mock_func_arg_count (void *func)
{
	if (func == signature_verification_mock_verify_signature) {
		return 4;
	}
	else if ((func == signature_verification_mock_set_verification_key) ||
		(func == signature_verification_mock_is_key_valid)) {
		return 2;
	}
	else if (func == signature_verification_mock_get_max_signature_length) {
		return 1;
	}
	else {
		return 0;
	}
}

static const char* signature_verification_mock_func_name_map (void *func)
{
	if (func == signature_verification_mock_verify_signature) {
		return "verify_signature";
	}
	else if (func == signature_verification_mock_get_max_signature_length) {
		return "get_max_signature_length";
	}
	else if (func == signature_verification_mock_set_verification_key) {
		return "set_verification_key";
	}
	else if (func == signature_verification_mock_is_key_valid) {
		return "is_key_valid";
	}
	else {
		return "unknown";
	}
}

static const char* signature_verification_mock_arg_name_map (void *func, int arg)
{
	if (func == signature_verification_mock_verify_signature) {
		switch (arg) {
			case 0:
				return "digest";

			case 1:
				return "length";

			case 2:
				return "signature";

			case 3:
				return "sig_length";
		}
	}
	else if (func == signature_verification_mock_get_max_signature_length) {
		switch (arg) {
			case 0:
				return "max_length";
		}
	}
	else if (func == signature_verification_mock_set_verification_key) {
		switch (arg) {
			case 0:
				return "key";

			case 1:
				return "length";
		}
	}
	else if (func == signature_verification_mock_is_key_valid) {
		switch (arg) {
			case 0:
				return "key";

			case 1:
				return "length";
		}
	}

	return "unknown";
}

/**
 * Initialize a mock for signature verification.
 *
 * @param mock The mock to initialize.
 *
 * @return 0 if the mock was successfully initialized or an error code.
 */
int signature_verification_mock_init (struct signature_verification_mock *mock)
{
	int status;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	memset (mock, 0, sizeof (struct signature_verification_mock));

	status = mock_init (&mock->mock);
	if (status != 0) {
		return status;
	}

	mock_set_name (&mock->mock, "signature_verification");

	mock->base.verify_signature = signature_verification_mock_verify_signature;
	mock->base.get_max_signature_length = signature_verification_mock_get_max_signature_length;
	mock->base.set_verification_key = signature_verification_mock_set_verification_key;
	mock->base.is_key_valid = signature_verification_mock_is_key_valid;

	mock->mock.func_arg_count = signature_verification_mock_func_arg_count;
	mock->mock.func_name_map = signature_verification_mock_func_name_map;
	mock->mock.arg_name_map = signature_verification_mock_arg_name_map;

	return 0;
}

/**
 * Release the resources used by a signature verification mock.
 *
 * @param mock The mock to release.
 */
void signature_verification_mock_release (struct signature_verification_mock *mock)
{
	if (mock) {
		mock_release (&mock->mock);
	}
}

/**
 * Validate the expectations on the mock and release the instance.
 *
 * @param mock The mock to validate.
 *
 * @return 0 if all expectations were met or 1 if not.
 */
int signature_verification_mock_validate_and_release (struct signature_verification_mock *mock)
{
	int status = 1;

	if (mock != NULL) {
		status = mock_validate (&mock->mock);
		signature_verification_mock_release (mock);
	}

	return status;
}
