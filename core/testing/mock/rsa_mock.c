// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include "rsa_mock.h"


static int rsa_mock_generate_key (struct rsa_engine *engine, struct rsa_private_key *key, int bits)
{
	struct rsa_engine_mock *mock = (struct rsa_engine_mock*) engine;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, rsa_mock_generate_key, engine, MOCK_ARG_CALL (key),
		MOCK_ARG_CALL (bits));
}

static int rsa_mock_init_private_key (struct rsa_engine *engine, struct rsa_private_key *key,
	const uint8_t *der, size_t length)
{
	struct rsa_engine_mock *mock = (struct rsa_engine_mock*) engine;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, rsa_mock_init_private_key, engine, MOCK_ARG_CALL (key),
		MOCK_ARG_CALL (der), MOCK_ARG_CALL (length));
}

static void rsa_mock_release_key (struct rsa_engine *engine, struct rsa_private_key *key)
{
	struct rsa_engine_mock *mock = (struct rsa_engine_mock*) engine;

	if (mock == NULL) {
		return;
	}

	MOCK_VOID_RETURN (&mock->mock, rsa_mock_release_key, engine, MOCK_ARG_CALL (key));
}

static int rsa_mock_get_private_key_der (struct rsa_engine *engine,
	const struct rsa_private_key *key, uint8_t **der, size_t *length)
{
	struct rsa_engine_mock *mock = (struct rsa_engine_mock*) engine;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, rsa_mock_get_private_key_der, engine, MOCK_ARG_CALL (key),
		MOCK_ARG_CALL (der), MOCK_ARG_CALL (length));
}

static int rsa_mock_decrypt (struct rsa_engine *engine, const struct rsa_private_key *key,
	const uint8_t *encrypted, size_t in_length, const uint8_t *label, size_t label_length,
	enum hash_type pad_hash, uint8_t *decrypted, size_t out_length)
{
	struct rsa_engine_mock *mock = (struct rsa_engine_mock*) engine;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, rsa_mock_decrypt, engine, MOCK_ARG_CALL (key),
		MOCK_ARG_CALL (encrypted), MOCK_ARG_CALL (in_length), MOCK_ARG_CALL (label),
		MOCK_ARG_CALL (label_length), MOCK_ARG_CALL (pad_hash), MOCK_ARG_CALL (decrypted),
		MOCK_ARG_CALL (out_length));
}

static int rsa_mock_init_public_key (struct rsa_engine *engine, struct rsa_public_key *key,
	const uint8_t *der, size_t length)
{
	struct rsa_engine_mock *mock = (struct rsa_engine_mock*) engine;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, rsa_mock_init_public_key, engine, MOCK_ARG_CALL (key),
		MOCK_ARG_CALL (der), MOCK_ARG_CALL (length));
}

static int rsa_mock_get_public_key_der (struct rsa_engine *engine,
	const struct rsa_private_key *key, uint8_t **der, size_t *length)
{
	struct rsa_engine_mock *mock = (struct rsa_engine_mock*) engine;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, rsa_mock_get_public_key_der, engine, MOCK_ARG_CALL (key),
		MOCK_ARG_CALL (der), MOCK_ARG_CALL (length));
}

static int rsa_mock_sig_verify (struct rsa_engine *engine, const struct rsa_public_key *key,
	const uint8_t *signature, size_t sig_length, const uint8_t *match, size_t match_length)
{
	struct rsa_engine_mock *mock = (struct rsa_engine_mock*) engine;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, rsa_mock_sig_verify, engine, MOCK_ARG_CALL (key),
		MOCK_ARG_CALL (signature), MOCK_ARG_CALL (sig_length), MOCK_ARG_CALL (match),
		MOCK_ARG_CALL (match_length));
}

static int rsa_mock_func_arg_count (void *func)
{
	if (func == rsa_mock_decrypt) {
		return 8;
	}
	else if (func == rsa_mock_sig_verify) {
		return 5;
	}
	else if ((func == rsa_mock_init_private_key) || (func == rsa_mock_get_private_key_der) ||
		(func == rsa_mock_init_public_key) || (func == rsa_mock_get_public_key_der)) {
		return 3;
	}
	else if (func == rsa_mock_generate_key) {
		return 2;
	}
	else if (func == rsa_mock_release_key) {
		return 1;
	}
	else {
		return 0;
	}
}

static const char* rsa_mock_func_name_map (void *func)
{
	if (func == rsa_mock_generate_key) {
		return "generate_key";
	}
	else if (func == rsa_mock_init_private_key) {
		return "init_private_key";
	}
	else if (func == rsa_mock_release_key) {
		return "release_key";
	}
	else if (func == rsa_mock_get_private_key_der) {
		return "get_private_key_der";
	}
	else if (func == rsa_mock_decrypt) {
		return "decrypt";
	}
	else if (func == rsa_mock_init_public_key) {
		return "init_public_key";
	}
	else if (func == rsa_mock_get_public_key_der) {
		return "get_public_key_der";
	}
	else if (func == rsa_mock_sig_verify) {
		return "sig_verify";
	}
	else {
		return "unknown";
	}
}

static const char* rsa_mock_arg_name_map (void *func, int arg)
{
	if (func == rsa_mock_generate_key) {
		switch (arg) {
			case 0:
				return "key";

			case 1:
				return "bits";
		}
	}
	else if (func == rsa_mock_init_private_key) {
		switch (arg) {
			case 0:
				return "key";

			case 1:
				return "der";

			case 2:
				return "length";
		}
	}
	else if (func == rsa_mock_release_key) {
		switch (arg) {
			case 0:
				return "key";
		}
	}
	else if (func == rsa_mock_get_private_key_der) {
		switch (arg) {
			case 0:
				return "key";

			case 1:
				return "der";

			case 2:
				return "length";
		}
	}
	else if (func == rsa_mock_decrypt) {
		switch (arg) {
			case 0:
				return "key";

			case 1:
				return "encrypted";

			case 2:
				return "in_length";

			case 3:
				return "label";

			case 4:
				return "label_length";

			case 5:
				return "pad_hash";

			case 6:
				return "decrypted";

			case 7:
				return "out_length";
		}
	}
	else if (func == rsa_mock_init_public_key) {
		switch (arg) {
			case 0:
				return "key";

			case 1:
				return "der";

			case 2:
				return "length";
		}
	}
	else if (func == rsa_mock_get_public_key_der) {
		switch (arg) {
			case 0:
				return "key";

			case 1:
				return "der";

			case 2:
				return "length";
		}
	}
	else if (func == rsa_mock_sig_verify) {
		switch (arg) {
			case 0:
				return "key";

			case 1:
				return "signature";

			case 2:
				return "sig_length";

			case 3:
				return "match";

			case 4:
				return "match_length";
		}
	}

	return "unknown";
}

/**
 * Initialize a mock for the RSA API.
 *
 * @param mock The mock to initialize.
 *
 * @return 0 if the mock was successfully initialized or an error code.
 */
int rsa_mock_init (struct rsa_engine_mock *mock)
{
	int status;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	memset (mock, 0, sizeof (struct rsa_engine_mock));

	status = mock_init (&mock->mock);
	if (status != 0) {
		return status;
	}

	mock_set_name (&mock->mock, "rsa");

	mock->base.generate_key = rsa_mock_generate_key;
	mock->base.init_private_key = rsa_mock_init_private_key;
	mock->base.release_key = rsa_mock_release_key;
	mock->base.get_private_key_der = rsa_mock_get_private_key_der;
	mock->base.decrypt = rsa_mock_decrypt;
	mock->base.init_public_key = rsa_mock_init_public_key;
	mock->base.get_public_key_der = rsa_mock_get_public_key_der;
	mock->base.sig_verify = rsa_mock_sig_verify;

	mock->mock.func_arg_count = rsa_mock_func_arg_count;
	mock->mock.func_name_map = rsa_mock_func_name_map;
	mock->mock.arg_name_map = rsa_mock_arg_name_map;

	return 0;
}

/**
 * Release a mock RSA API instance.
 *
 * @param mock The mock to release.
 */
void rsa_mock_release (struct rsa_engine_mock *mock)
{
	if (mock) {
		mock_release (&mock->mock);
	}
}

/**
 * Verify the mock was called as expected and release the instance.
 *
 * @param mock The mock to validate.
 *
 * @return 0 if all expectations were met or 1 if not.
 */
int rsa_mock_validate_and_release (struct rsa_engine_mock *mock)
{
	int status = 1;

	if (mock != NULL) {
		status = mock_validate (&mock->mock);
		rsa_mock_release (mock);
	}

	return status;
}
