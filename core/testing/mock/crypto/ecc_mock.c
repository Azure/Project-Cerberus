// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include "platform_io.h"
#include "ecc_mock.h"
#include "testing.h"


static int ecc_mock_init_key_pair (struct ecc_engine *engine, const uint8_t *key, size_t key_length,
	struct ecc_private_key *priv_key, struct ecc_public_key *pub_key)
{
	struct ecc_engine_mock *mock = (struct ecc_engine_mock*) engine;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, ecc_mock_init_key_pair, engine, MOCK_ARG_CALL (key),
		MOCK_ARG_CALL (key_length), MOCK_ARG_CALL (priv_key), MOCK_ARG_CALL (pub_key));
}

static int ecc_mock_init_public_key (struct ecc_engine *engine, const uint8_t *key,
	size_t key_length, struct ecc_public_key *pub_key)
{
	struct ecc_engine_mock *mock = (struct ecc_engine_mock*) engine;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, ecc_mock_init_public_key, engine, MOCK_ARG_CALL (key),
		MOCK_ARG_CALL (key_length), MOCK_ARG_CALL (pub_key));
}

static int ecc_mock_generate_derived_key_pair (struct ecc_engine *engine, const uint8_t *priv,
	size_t key_length, struct ecc_private_key *priv_key, struct ecc_public_key *pub_key)
{
	struct ecc_engine_mock *mock = (struct ecc_engine_mock*) engine;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, ecc_mock_generate_derived_key_pair, engine, MOCK_ARG_CALL (priv),
		MOCK_ARG_CALL (key_length), MOCK_ARG_CALL (priv_key), MOCK_ARG_CALL (pub_key));
}

static int ecc_mock_generate_key_pair (struct ecc_engine *engine, size_t key_length,
	struct ecc_private_key *priv_key, struct ecc_public_key *pub_key)
{
	struct ecc_engine_mock *mock = (struct ecc_engine_mock*) engine;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, ecc_mock_generate_key_pair, engine, MOCK_ARG_CALL (key_length),
		MOCK_ARG_CALL (priv_key), MOCK_ARG_CALL (pub_key));
}

static void ecc_mock_release_key_pair (struct ecc_engine *engine, struct ecc_private_key *priv_key,
	struct ecc_public_key *pub_key)
{
	struct ecc_engine_mock *mock = (struct ecc_engine_mock*) engine;

	if (mock == NULL) {
		return;
	}

	MOCK_VOID_RETURN (&mock->mock, ecc_mock_release_key_pair, engine, MOCK_ARG_CALL (priv_key),
		MOCK_ARG_CALL (pub_key));
}

static int ecc_mock_get_signature_max_length (struct ecc_engine *engine,
	struct ecc_private_key *key)
{
	struct ecc_engine_mock *mock = (struct ecc_engine_mock*) engine;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, ecc_mock_get_signature_max_length, engine, MOCK_ARG_CALL (key));
}

static int ecc_mock_get_private_key_der (struct ecc_engine *engine,
	const struct ecc_private_key *key, uint8_t **der, size_t *length)
{
	struct ecc_engine_mock *mock = (struct ecc_engine_mock*) engine;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, ecc_mock_get_private_key_der, engine, MOCK_ARG_CALL (key),
		MOCK_ARG_CALL (der), MOCK_ARG_CALL (length));
}

static int ecc_mock_get_public_key_der (struct ecc_engine *engine, const struct ecc_public_key *key,
	uint8_t **der, size_t *length)
{
	struct ecc_engine_mock *mock = (struct ecc_engine_mock*) engine;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, ecc_mock_get_public_key_der, engine, MOCK_ARG_CALL (key),
		MOCK_ARG_CALL (der), MOCK_ARG_CALL (length));
}

static int ecc_mock_sign (struct ecc_engine *engine, struct ecc_private_key *key,
	const uint8_t *digest, size_t length, uint8_t *signature, size_t sig_length)
{
	struct ecc_engine_mock *mock = (struct ecc_engine_mock*) engine;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, ecc_mock_sign, engine, MOCK_ARG_CALL (key), MOCK_ARG_CALL (digest),
		MOCK_ARG_CALL (length), MOCK_ARG_CALL (signature), MOCK_ARG_CALL (sig_length));
}

static int ecc_mock_verify (struct ecc_engine *engine, struct ecc_public_key *key,
	const uint8_t *digest, size_t length, const uint8_t *signature, size_t sig_length)
{
	struct ecc_engine_mock *mock = (struct ecc_engine_mock*) engine;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, ecc_mock_verify, engine, MOCK_ARG_CALL (key), MOCK_ARG_CALL (digest),
		MOCK_ARG_CALL (length), MOCK_ARG_CALL (signature), MOCK_ARG_CALL (sig_length));
}

static int ecc_mock_get_shared_secret_max_length (struct ecc_engine *engine,
	struct ecc_private_key *key)
{
	struct ecc_engine_mock *mock = (struct ecc_engine_mock*) engine;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, ecc_mock_get_shared_secret_max_length, engine, MOCK_ARG_CALL (key));
}

static int ecc_mock_compute_shared_secret (struct ecc_engine *engine,
	struct ecc_private_key *priv_key, struct ecc_public_key *pub_key, uint8_t *secret,
	size_t length)
{
	struct ecc_engine_mock *mock = (struct ecc_engine_mock*) engine;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, ecc_mock_compute_shared_secret, engine, MOCK_ARG_CALL (priv_key),
		MOCK_ARG_CALL (pub_key), MOCK_ARG_CALL (secret), MOCK_ARG_CALL (length));
}

static int ecc_mock_func_arg_count (void *func)
{
	if ((func == ecc_mock_sign) || (func == ecc_mock_verify)) {
		return 5;
	}
	else if ((func == ecc_mock_init_key_pair) || (func == ecc_mock_generate_derived_key_pair) ||
		(func == ecc_mock_compute_shared_secret)) {
		return 4;
	}
	else if ((func == ecc_mock_init_public_key) || (func == ecc_mock_generate_key_pair) ||
		(func == ecc_mock_get_private_key_der) || (func == ecc_mock_get_public_key_der)) {
		return 3;
	}
	else if (func == ecc_mock_release_key_pair) {
		return 2;
	}
	else if ((func == ecc_mock_get_signature_max_length) ||
		(func == ecc_mock_get_shared_secret_max_length)) {
		return 1;
	}
	else {
		return 0;
	}
}

static const char* ecc_mock_func_name_map (void *func)
{
	if (func == ecc_mock_init_key_pair) {
		return "init_key_pair";
	}
	else if (func == ecc_mock_init_public_key) {
		return "init_public_key";
	}
	else if (func == ecc_mock_generate_derived_key_pair) {
		return "generate_derived_key_pair";
	}
	else if (func == ecc_mock_generate_key_pair) {
		return "generat_key_pair";
	}
	else if (func == ecc_mock_release_key_pair) {
		return "release_key_pair";
	}
	else if (func == ecc_mock_get_signature_max_length) {
		return "get_signature_max_length";
	}
	else if (func == ecc_mock_get_private_key_der) {
		return "get_private_key_der";
	}
	else if (func == ecc_mock_get_public_key_der) {
		return "get_public_key_der";
	}
	else if (func == ecc_mock_sign) {
		return "sign";
	}
	else if (func == ecc_mock_verify) {
		return "verify";
	}
	else if (func == ecc_mock_get_shared_secret_max_length) {
		return "get_shared_secret_max_length";
	}
	else if (func == ecc_mock_compute_shared_secret) {
		return "compute_shared_secret";
	}
	else {
		return "unknown";
	}
}

static const char* ecc_mock_arg_name_map (void *func, int arg)
{
	if (func == ecc_mock_init_key_pair) {
		switch (arg) {
			case 0:
				return "key";

			case 1:
				return "key_length";

			case 2:
				return "priv_key";

			case 3:
				return "pub_key";
		}
	}
	else if (func == ecc_mock_init_public_key) {
		switch (arg) {
			case 0:
				return "key";

			case 1:
				return "key_length";

			case 2:
				return "pub_key";
		}
	}
	else if (func == ecc_mock_generate_derived_key_pair) {
		switch (arg) {
			case 0:
				return "priv";

			case 1:
				return "key_length";

			case 2:
				return "priv_key";

			case 3:
				return "pub_key";
		}
	}
	else if (func == ecc_mock_generate_key_pair) {
		switch (arg) {
			case 0:
				return "key_length";

			case 1:
				return "priv_key";

			case 2:
				return "pub_key";
		}
	}
	else if (func == ecc_mock_release_key_pair) {
		switch (arg) {
			case 0:
				return "priv_key";

			case 1:
				return "pub_key";
		}
	}
	else if (func == ecc_mock_get_signature_max_length) {
		switch (arg) {
			case 0:
				return "key";
		}
	}
	else if (func == ecc_mock_get_private_key_der) {
		switch (arg) {
			case 0:
				return "key";

			case 1:
				return "der";

			case 2:
				return "length";
		}
	}
	else if (func == ecc_mock_get_public_key_der) {
		switch (arg) {
			case 0:
				return "key";

			case 1:
				return "der";

			case 2:
				return "length";
		}
	}
	else if (func == ecc_mock_sign) {
		switch (arg) {
			case 0:
				return "key";

			case 1:
				return "digest";

			case 2:
				return "length";

			case 3:
				return "signature";

			case 4:
				return "sig_length";
		}
	}
	else if (func == ecc_mock_verify) {
		switch (arg) {
			case 0:
				return "key";

			case 1:
				return "digest";

			case 2:
				return "length";

			case 3:
				return "signature";

			case 4:
				return "sig_length";
		}
	}
	else if (func == ecc_mock_get_shared_secret_max_length) {
		switch (arg) {
			case 0:
				return "key";
		}
	}
	else if (func == ecc_mock_compute_shared_secret) {
		switch (arg) {
			case 0:
				return "priv_key";

			case 1:
				return "pub_key";

			case 2:
				return "secret";

			case 3:
				return "length";
		}
	}

	return "unknown";
}

/**
 * Initialize a mock for the ECC API.
 *
 * @param mock The mock to initialize.
 *
 * @return 0 if the mock was successfully initialized or an error code.
 */
int ecc_mock_init (struct ecc_engine_mock *mock)
{
	int status;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	memset (mock, 0, sizeof (struct ecc_engine_mock));

	status = mock_init (&mock->mock);
	if (status != 0) {
		return status;
	}

	mock_set_name (&mock->mock, "ecc");

	mock->base.init_key_pair = ecc_mock_init_key_pair;
	mock->base.init_public_key = ecc_mock_init_public_key;
	mock->base.generate_derived_key_pair = ecc_mock_generate_derived_key_pair;
	mock->base.generate_key_pair = ecc_mock_generate_key_pair;
	mock->base.release_key_pair = ecc_mock_release_key_pair;
	mock->base.get_signature_max_length = ecc_mock_get_signature_max_length;
	mock->base.get_private_key_der = ecc_mock_get_private_key_der;
	mock->base.get_public_key_der = ecc_mock_get_public_key_der;
	mock->base.sign = ecc_mock_sign;
	mock->base.verify = ecc_mock_verify;
	mock->base.get_shared_secret_max_length = ecc_mock_get_shared_secret_max_length;
	mock->base.compute_shared_secret = ecc_mock_compute_shared_secret;

	mock->mock.func_arg_count = ecc_mock_func_arg_count;
	mock->mock.func_name_map = ecc_mock_func_name_map;
	mock->mock.arg_name_map = ecc_mock_arg_name_map;

	return 0;
}

/**
 * Release a mock ECC API instance.
 *
 * @param mock The mock to release.
 */
void ecc_mock_release (struct ecc_engine_mock *mock)
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
int ecc_mock_validate_and_release (struct ecc_engine_mock *mock)
{
	int status = 1;

	if (mock != NULL) {
		status = mock_validate (&mock->mock);
		ecc_mock_release (mock);
	}

	return status;
}

/**
 * Custom validation routine for validating ecc_point_public_key arguments.
 *
 * @param arg_info Argument information from the mock for error messages.
 * @param expected The expected public key contents.
 * @param actual The actual public key contents.
 *
 * @return 0 if the public key contained the expected information or 1 if not.
 */
int ecc_mock_validate_point_public_key (const char *arg_info, void *expected, void *actual)
{
	struct ecc_point_public_key *pk_expected = (struct ecc_point_public_key*) expected;
	struct ecc_point_public_key *pk_actual = (struct ecc_point_public_key*) actual;
	int fail = 0;

	if (pk_expected->key_length != pk_actual->key_length) {
		platform_printf ("%sUnexpected key length: expected=0x%x, actual=0x%x" NEWLINE,
			arg_info, pk_expected->key_length, pk_actual->key_length);
		fail |= 1;
	}

	fail |= testing_validate_array_prefix_with_extra_info (pk_expected->x, pk_actual->x,
		pk_expected->key_length, arg_info, "(X) ");

	fail |= testing_validate_array_prefix_with_extra_info (pk_expected->y, pk_actual->y,
		pk_expected->key_length, arg_info, "(Y) ");

	return fail;
}

/**
 * Custom validation routine for validating ecc_ecdsa_signature arguments.
 *
 * @param arg_info Argument information from the mock for error messages.
 * @param expected The expected signature contents.
 * @param actual The actual signature contents.
 *
 * @return 0 if the signature contained the expected information or 1 if not.
 */
int ecc_mock_validate_ecdsa_signature (const char *arg_info, void *expected, void *actual)
{
	struct ecc_ecdsa_signature *sig_expected = (struct ecc_ecdsa_signature*) expected;
	struct ecc_ecdsa_signature *sig_actual = (struct ecc_ecdsa_signature*) actual;
	int fail = 0;

	if (sig_expected->length != sig_actual->length) {
		platform_printf ("%sUnexpected signature length: expected=0x%x, actual=0x%x" NEWLINE,
			arg_info, sig_expected->length, sig_actual->length);
		fail |= 1;
	}

	fail |= testing_validate_array_prefix_with_extra_info (sig_expected->r, sig_actual->r,
		sig_expected->length, arg_info, "(r) ");

	fail |= testing_validate_array_prefix_with_extra_info (sig_expected->s, sig_actual->s,
		sig_expected->length, arg_info, "(s) ");

	return fail;
}
