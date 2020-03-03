// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include "x509_mock.h"


static int x509_mock_create_csr (struct x509_engine *engine, const uint8_t *priv_key,
	size_t key_length, const char *name, int type, const char *eku,
	const struct x509_dice_tcbinfo *dice, uint8_t **csr, size_t *csr_length)
{
	struct x509_engine_mock *mock = (struct x509_engine_mock*) engine;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, x509_mock_create_csr, engine, MOCK_ARG_CALL (priv_key),
		MOCK_ARG_CALL (key_length), MOCK_ARG_CALL (name), MOCK_ARG_CALL (type), MOCK_ARG_CALL (eku),
		MOCK_ARG_CALL (dice), MOCK_ARG_CALL (csr), MOCK_ARG_CALL (csr_length));
}

static int x509_mock_create_self_signed_certificate (struct x509_engine *engine,
	struct x509_certificate *cert, const uint8_t *priv_key, size_t key_length,
	const uint8_t *serial_num, size_t serial_length, const char *name, int type,
	const struct x509_dice_tcbinfo *dice)
{
	struct x509_engine_mock *mock = (struct x509_engine_mock*) engine;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, x509_mock_create_self_signed_certificate, engine,
		MOCK_ARG_CALL (cert), MOCK_ARG_CALL (priv_key), MOCK_ARG_CALL (key_length),
		MOCK_ARG_CALL (serial_num),  MOCK_ARG_CALL (serial_length), MOCK_ARG_CALL (name),
		MOCK_ARG_CALL (type), MOCK_ARG_CALL (dice));
}

static int x509_mock_create_ca_signed_certificate (struct x509_engine *engine,
	struct x509_certificate *cert, const uint8_t *key, size_t key_length, const uint8_t *serial_num,
	size_t serial_length, const char *name, int type, const uint8_t* ca_priv_key,
	size_t ca_key_length, const struct x509_certificate *ca_cert,
	const struct x509_dice_tcbinfo *dice)
{
	struct x509_engine_mock *mock = (struct x509_engine_mock*) engine;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, x509_mock_create_ca_signed_certificate, engine,
		MOCK_ARG_CALL (cert), MOCK_ARG_CALL (key), MOCK_ARG_CALL (key_length),
		MOCK_ARG_CALL (serial_num),  MOCK_ARG_CALL (serial_length), MOCK_ARG_CALL (name),
		MOCK_ARG_CALL (type), MOCK_ARG_CALL (ca_priv_key), MOCK_ARG_CALL (ca_key_length),
		MOCK_ARG_CALL (ca_cert), MOCK_ARG_CALL (dice));
}

static int x509_mock_load_certificate (struct x509_engine *engine, struct x509_certificate *cert,
	const uint8_t *der, size_t length)
{
	struct x509_engine_mock *mock = (struct x509_engine_mock*) engine;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, x509_mock_load_certificate, engine, MOCK_ARG_CALL (cert),
		MOCK_ARG_CALL (der), MOCK_ARG_CALL (length));
}

static void x509_mock_release_certificate (struct x509_engine *engine,
	struct x509_certificate *cert)
{
	struct x509_engine_mock *mock = (struct x509_engine_mock*) engine;

	if (mock == NULL) {
		return;
	}

	MOCK_VOID_RETURN (&mock->mock, x509_mock_release_certificate, engine, MOCK_ARG_CALL (cert));
}

static int x509_mock_get_certificate_der (struct x509_engine *engine,
	const struct x509_certificate *cert, uint8_t **der, size_t *length)
{
	struct x509_engine_mock *mock = (struct x509_engine_mock*) engine;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, x509_mock_get_certificate_der, engine, MOCK_ARG_CALL (cert),
		MOCK_ARG_CALL (der), MOCK_ARG_CALL (length));
}

static int x509_mock_get_certificate_version (struct x509_engine *engine,
	const struct x509_certificate *cert)
{
	struct x509_engine_mock *mock = (struct x509_engine_mock*) engine;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, x509_mock_get_certificate_version, engine, MOCK_ARG_CALL (cert));
}

static int x509_mock_get_serial_number (struct x509_engine *engine,
	const struct x509_certificate *cert, uint8_t *serial_num, size_t length)
{
	struct x509_engine_mock *mock = (struct x509_engine_mock*) engine;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, x509_mock_get_serial_number, engine, MOCK_ARG_CALL (cert),
		MOCK_ARG_CALL (serial_num), MOCK_ARG_CALL (length));
}

static int x509_mock_get_public_key_type (struct x509_engine *engine,
	const struct x509_certificate *cert)
{
	struct x509_engine_mock *mock = (struct x509_engine_mock*) engine;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, x509_mock_get_public_key_type, engine, MOCK_ARG_CALL (cert));
}

static int x509_mock_get_public_key_length (struct x509_engine *engine,
	const struct x509_certificate *cert)
{
	struct x509_engine_mock *mock = (struct x509_engine_mock*) engine;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, x509_mock_get_public_key_length, engine, MOCK_ARG_CALL (cert));
}

static int x509_mock_get_public_key (struct x509_engine *engine,
	const struct x509_certificate *cert, uint8_t **key, size_t *key_length)
{
	struct x509_engine_mock *mock = (struct x509_engine_mock*) engine;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, x509_mock_get_public_key, engine, MOCK_ARG_CALL (cert),
		MOCK_ARG_CALL (key), MOCK_ARG_CALL (key_length));
}

static int x509_mock_init_ca_cert_store (struct x509_engine *engine, struct x509_ca_certs *store)
{
	struct x509_engine_mock *mock = (struct x509_engine_mock*) engine;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, x509_mock_init_ca_cert_store, engine,
		MOCK_ARG_CALL (store));
}

static void x509_mock_release_ca_cert_store (struct x509_engine *engine,
	struct x509_ca_certs *store)
{
	struct x509_engine_mock *mock = (struct x509_engine_mock*) engine;

	if (mock == NULL) {
		return;
	}

	MOCK_VOID_RETURN (&mock->mock, x509_mock_release_ca_cert_store, engine,
		MOCK_ARG_CALL (store));
}

static int x509_mock_add_root_ca (struct x509_engine *engine, struct x509_ca_certs *store,
	const uint8_t *der, size_t length)
{
	struct x509_engine_mock *mock = (struct x509_engine_mock*) engine;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, x509_mock_add_root_ca, engine, MOCK_ARG_CALL (store),
		MOCK_ARG_CALL (der), MOCK_ARG_CALL (length));
}

static int x509_mock_add_intermediate_ca (struct x509_engine *engine,
	struct x509_ca_certs *store, const uint8_t *der, size_t length)
{
	struct x509_engine_mock *mock = (struct x509_engine_mock*) engine;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, x509_mock_add_intermediate_ca, engine, MOCK_ARG_CALL (store),
		MOCK_ARG_CALL (der), MOCK_ARG_CALL (length));
}

static int x509_mock_authenticate (struct x509_engine *engine, const struct x509_certificate *cert,
	const struct x509_ca_certs *store)
{
	struct x509_engine_mock *mock = (struct x509_engine_mock*) engine;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, x509_mock_authenticate, engine, MOCK_ARG_CALL (cert),
		MOCK_ARG_CALL (store));
}

static int x509_mock_func_arg_count (void *func)
{
	if (func == x509_mock_create_ca_signed_certificate) {
		return 11;
	}
	else if ((func == x509_mock_create_csr) || (func == x509_mock_create_self_signed_certificate)) {
		return 8;
	}
	else if ((func == x509_mock_load_certificate) || (func == x509_mock_get_certificate_der) ||
		(func == x509_mock_get_serial_number) || (func == x509_mock_get_public_key) ||
		(func == x509_mock_add_root_ca) || (func == x509_mock_add_intermediate_ca)) {
		return 3;
	}
	else if (func == x509_mock_authenticate) {
		return 2;
	}
	else if ((func == x509_mock_release_certificate) ||
		(func == x509_mock_get_certificate_version) || (func == x509_mock_get_public_key_type) ||
		(func == x509_mock_get_public_key_length) || (func == x509_mock_init_ca_cert_store) ||
		(func == x509_mock_release_ca_cert_store)) {
		return 1;
	}
	else {
		return 0;
	}
}

static const char* x509_mock_func_name_map (void *func)
{
	if (func == x509_mock_create_csr) {
		return "create_csr";
	}
	else if (func == x509_mock_create_self_signed_certificate) {
		return "create_self_signed_certificate";
	}
	else if (func == x509_mock_create_ca_signed_certificate) {
		return "create_ca_signed_certificate";
	}
	else if (func == x509_mock_load_certificate) {
		return "load_certificate";
	}
	else if (func == x509_mock_release_certificate) {
		return "release_certificate";
	}
	else if (func == x509_mock_get_certificate_der) {
		return "get_certificate_der";
	}
	else if (func == x509_mock_get_certificate_version) {
		return "get_certificate_version";
	}
	else if (func == x509_mock_get_serial_number) {
		return "get_serial_number";
	}
	else if (func == x509_mock_get_public_key_type) {
		return "get_public_key_type";
	}
	else if (func == x509_mock_get_public_key_length) {
		return "get_public_key_length";
	}
	else if (func == x509_mock_get_public_key) {
		return "get_public_key";
	}
	else if (func == x509_mock_init_ca_cert_store) {
		return "init_ca_cert_store";
	}
	else if (func == x509_mock_release_ca_cert_store) {
		return "release_ca_cert_store";
	}
	else if (func == x509_mock_add_root_ca) {
		return "add_root_ca";
	}
	else if (func == x509_mock_add_intermediate_ca) {
		return "add_intermediate_ca";
	}
	else if (func == x509_mock_authenticate) {
		return "authenticate";
	}
	else {
		return "unknown";
	}
}

static const char* x509_mock_arg_name_map (void *func, int arg)
{
	if (func == x509_mock_create_csr) {
		switch (arg) {
			case 0:
				return "priv_key";

			case 1:
				return "key_length";

			case 2:
				return "name";

			case 3:
				return "type";

			case 4:
				return "eku";

			case 5:
				return "dice";

			case 6:
				return "csr";

			case 7:
				return "csr_length";
		}
	}
	else if (func == x509_mock_create_self_signed_certificate) {
		switch (arg) {
			case 0:
				return "cert";

			case 1:
				return "key";

			case 2:
				return "key_length";

			case 3:
				return "serial_num";

			case 4:
				return "serial_length";

			case 5:
				return "name";

			case 6:
				return "type";

			case 7:
				return "dice";
		}
	}
	else if (func == x509_mock_create_ca_signed_certificate) {
		switch (arg) {
			case 0:
				return "cert";

			case 1:
				return "priv_key";

			case 2:
				return "key_length";

			case 3:
				return "serial_num";

			case 4:
				return "serial_length";

			case 5:
				return "name";

			case 6:
				return "type";

			case 7:
				return "ca_priv_key";

			case 8:
				return "ca_key_length";

			case 9:
				return "ca_cert";

			case 10:
				return "dice";
		}
	}
	else if (func == x509_mock_load_certificate) {
		switch (arg) {
			case 0:
				return "cert";

			case 1:
				return "der";

			case 2:
				return "length";
		}
	}
	else if (func == x509_mock_release_certificate) {
		switch (arg) {
			case 0:
				return "cert";
		}
	}
	else if (func == x509_mock_get_certificate_der) {
		switch (arg) {
			case 0:
				return "cert";

			case 1:
				return "der";

			case 2:
				return "length";
		}
	}
	else if (func == x509_mock_get_certificate_version) {
		switch (arg) {
			case 0:
				return "cert";
		}
	}
	else if (func == x509_mock_get_serial_number) {
		switch (arg) {
			case 0:
				return "cert";

			case 1:
				return "serial_num";

			case 2:
				return "length";
		}
	}
	else if (func == x509_mock_get_public_key_type) {
		switch (arg) {
			case 0:
				return "cert";
		}
	}
	else if (func == x509_mock_get_public_key_length) {
		switch (arg) {
			case 0:
				return "cert";
		}
	}
	else if (func == x509_mock_get_public_key) {
		switch (arg) {
			case 0:
				return "cert";

			case 1:
				return "key";

			case 2:
				return "length";
		}
	}
	else if (func == x509_mock_init_ca_cert_store) {
		switch (arg) {
			case 0:
				return "store";
		}
	}
	else if (func == x509_mock_release_ca_cert_store) {
		switch (arg) {
			case 0:
				return "store";
		}
	}
	else if (func == x509_mock_add_root_ca) {
		switch (arg) {
			case 0:
				return "store";

			case 1:
				return "der";

			case 2:
				return "length";
		}
	}
	else if (func == x509_mock_add_intermediate_ca) {
		switch (arg) {
			case 0:
				return "store";

			case 1:
				return "der";

			case 2:
				return "length";
		}
	}
	else if (func == x509_mock_authenticate)
	{
		switch (arg) {
			case 0:
				return "cert";

			case 1:
				return "store";
		}
	}

	return "unknown";
}

/**
 * Initialize a mock for the X.509 API.
 *
 * @param mock The mock to initialize.
 *
 * @return 0 if the mock was successfully initialized or an error code.
 */
int x509_mock_init (struct x509_engine_mock *mock)
{
	int status;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	memset (mock, 0, sizeof (struct x509_engine_mock));

	status = mock_init (&mock->mock);
	if (status != 0) {
		return status;
	}

	mock_set_name (&mock->mock, "x509");

	mock->base.create_csr = x509_mock_create_csr;
	mock->base.create_self_signed_certificate = x509_mock_create_self_signed_certificate;
	mock->base.create_ca_signed_certificate = x509_mock_create_ca_signed_certificate;
	mock->base.load_certificate = x509_mock_load_certificate;
	mock->base.release_certificate = x509_mock_release_certificate;
	mock->base.get_certificate_der = x509_mock_get_certificate_der;
	mock->base.get_certificate_version = x509_mock_get_certificate_version;
	mock->base.get_serial_number = x509_mock_get_serial_number;
	mock->base.get_public_key_type = x509_mock_get_public_key_type;
	mock->base.get_public_key_length = x509_mock_get_public_key_length;
	mock->base.get_public_key = x509_mock_get_public_key;
	mock->base.init_ca_cert_store = x509_mock_init_ca_cert_store;
	mock->base.release_ca_cert_store = x509_mock_release_ca_cert_store;
	mock->base.add_root_ca = x509_mock_add_root_ca;
	mock->base.add_intermediate_ca = x509_mock_add_intermediate_ca;
	mock->base.authenticate = x509_mock_authenticate;

	mock->mock.func_arg_count = x509_mock_func_arg_count;
	mock->mock.func_name_map = x509_mock_func_name_map;
	mock->mock.arg_name_map = x509_mock_arg_name_map;

	return 0;
}

/**
 * Release a mock X.509 API instance.
 *
 * @param mock The mock to release.
 */
void x509_mock_release (struct x509_engine_mock *mock)
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
int x509_mock_validate_and_release (struct x509_engine_mock *mock)
{
	int status = 1;

	if (mock != NULL) {
		status = mock_validate (&mock->mock);
		x509_mock_release (mock);
	}

	return status;
}
