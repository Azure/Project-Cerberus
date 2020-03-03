// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include "firmware_image_mock.h"


static int firmware_image_mock_load (struct firmware_image *fw, struct flash *flash,
	uint32_t base_addr)
{
	struct firmware_image_mock *mock = (struct firmware_image_mock*) fw;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, firmware_image_mock_load, fw, MOCK_ARG_CALL (flash),
		MOCK_ARG_CALL (base_addr));
}

static int firmware_image_mock_verify (struct firmware_image *fw, struct hash_engine *hash,
	struct rsa_engine *rsa)
{
	struct firmware_image_mock *mock = (struct firmware_image_mock*) fw;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, firmware_image_mock_verify, fw, MOCK_ARG_CALL (hash),
		MOCK_ARG_CALL (rsa));
}

static int firmware_image_mock_get_image_size (struct firmware_image *fw)
{
	struct firmware_image_mock *mock = (struct firmware_image_mock*) fw;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN_NO_ARGS (&mock->mock, firmware_image_mock_get_image_size, fw);
}

static struct key_manifest* firmware_image_mock_get_key_manifest (struct firmware_image *fw)
{
	struct firmware_image_mock *mock = (struct firmware_image_mock*) fw;

	if (mock == NULL) {
		return NULL;
	}

	MOCK_RETURN_NO_ARGS_CAST (&mock->mock, struct key_manifest*,
		firmware_image_mock_get_key_manifest, fw);
}

static struct firmware_header* firmware_image_mock_get_firmware_header (struct firmware_image *fw)
{
	struct firmware_image_mock *mock = (struct firmware_image_mock*) fw;

	if (mock == NULL) {
		return NULL;
	}

	MOCK_RETURN_NO_ARGS_CAST (&mock->mock, struct firmware_header*,
		firmware_image_mock_get_firmware_header, fw);
}

static int firmware_image_mock_func_arg_count (void *func)
{
	if ((func == firmware_image_mock_load) || (func == firmware_image_mock_verify)) {
		return 2;
	}
	else {
		return 0;
	}
}

static const char* firmware_image_mock_func_name_map (void *func)
{
	if (func == firmware_image_mock_load) {
		return "load";
	}
	else if (func == firmware_image_mock_verify) {
		return "verify";
	}
	else if (func == firmware_image_mock_get_image_size) {
		return "get_image_size";
	}
	else if (func == firmware_image_mock_get_key_manifest) {
		return "get_key_manifest";
	}
	else if (func == firmware_image_mock_get_firmware_header) {
		return "get_firmware_header";
	}
	else {
		return "unknown";
	}
}

static const char* firmware_image_mock_arg_name_map (void *func, int arg)
{
	if (func == firmware_image_mock_load) {
		switch (arg) {
			case 0:
				return "flash";

			case 1:
				return "base_addr";
		}
	}
	else if (func == firmware_image_mock_verify) {
		switch (arg) {
			case 0:
				return "hash";

			case 1:
				return "rsa";
		}
	}

	return "unknown";
}

/**
 * Initialize a mock for a firmware image interface.
 *
 * @param mock The firmware image mock to initialize.
 *
 * @return 0 if the mock instance was initialized successfully or an error code.
 */
int firmware_image_mock_init (struct firmware_image_mock *mock)
{
	int status;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	memset (mock, 0, sizeof (struct firmware_image_mock));

	status = mock_init (&mock->mock);
	if (status != 0) {
		return status;
	}

	mock_set_name (&mock->mock, "firmware_image");

	mock->base.load = firmware_image_mock_load;
	mock->base.verify = firmware_image_mock_verify;
	mock->base.get_image_size = firmware_image_mock_get_image_size;
	mock->base.get_key_manifest = firmware_image_mock_get_key_manifest;
	mock->base.get_firmware_header = firmware_image_mock_get_firmware_header;

	mock->mock.func_arg_count = firmware_image_mock_func_arg_count;
	mock->mock.func_name_map = firmware_image_mock_func_name_map;
	mock->mock.arg_name_map = firmware_image_mock_arg_name_map;

	return 0;
}

/**
 * Release the resources used by the firmware image mock.
 *
 * @param mock The mock to release.
 */
void firmware_image_mock_release (struct firmware_image_mock *mock)
{
	if (mock != NULL) {
		mock_release (&mock->mock);
	}
}

/**
 * Verify that all expected calls were executed and release the mock.
 *
 * @param mock The mock to verify.
 *
 * @return 0 if the expectations were all met or 1 if not.
 */
int firmware_image_mock_validate_and_release (struct firmware_image_mock *mock)
{
	int status = 1;

	if (mock != NULL) {
		status = mock_validate (&mock->mock);
		firmware_image_mock_release (mock);
	}

	return status;
}

