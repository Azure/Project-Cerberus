// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <string.h>
#include "recovery_image_mock.h"
#include "manifest/pfm/pfm_manager.h"


static int recovery_image_mock_verify (struct recovery_image *img, struct hash_engine *hash,
	struct signature_verification *verification, uint8_t *hash_out, size_t hash_length,
	struct pfm_manager *pfm)
{
	struct recovery_image_mock *mock = (struct recovery_image_mock*) img;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, recovery_image_mock_verify, img, MOCK_ARG_CALL (hash),
		MOCK_ARG_CALL (verification), MOCK_ARG_CALL (hash_out), MOCK_ARG_CALL (hash_length),
		MOCK_ARG_CALL (pfm));
}

static int recovery_image_mock_get_hash (struct recovery_image *img, struct hash_engine *hash,
	uint8_t *hash_out, size_t hash_length)
{
	struct recovery_image_mock *mock = (struct recovery_image_mock*) img;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, recovery_image_mock_get_hash, img, MOCK_ARG_CALL (hash),
		MOCK_ARG_CALL (hash_out), MOCK_ARG_CALL (hash_length));
}

static int recovery_image_mock_get_version (struct recovery_image *img, char *version, size_t len)
{
	struct recovery_image_mock *mock = (struct recovery_image_mock*) img;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, recovery_image_mock_get_version, img, MOCK_ARG_CALL (version),
		MOCK_ARG_CALL (len));
}

static int recovery_image_mock_apply_to_flash (struct recovery_image *img, struct spi_flash *flash)
{
	struct recovery_image_mock *mock = (struct recovery_image_mock*) img;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, recovery_image_mock_apply_to_flash, img, MOCK_ARG_CALL (flash));
}

static int recovery_image_mock_func_arg_count (void *func)
{
	if (func == recovery_image_mock_verify) {
		return 5;
	}
	else if (func == recovery_image_mock_get_hash) {
		return 3;
	}
	else if (func == recovery_image_mock_get_version) {
		return 2;
	}
	else if (func == recovery_image_mock_apply_to_flash) {
		return 1;
	}
	else {
		return 0;
	}
}

static const char* recovery_image_mock_func_name_map (void *func)
{
	if (func == recovery_image_mock_verify) {
		return "verify";
	}
	else if (func == recovery_image_mock_get_hash) {
		return "get_hash";
	}
	else if (func == recovery_image_mock_get_version) {
		return "get_version";
	}
	else if (func == recovery_image_mock_apply_to_flash) {
		return "apply_to_flash";
	}
	else {
		return "unknown";
	}
}

static const char* recovery_image_mock_arg_name_map (void *func, int arg)
{
	if (func == recovery_image_mock_verify) {
		switch (arg) {
			case 0:
				return "hash";

			case 1:
				return "verification";

			case 2:
				return "hash_out";

			case 3:
				return "hash_length";

			case 4:
				return "pfm";
		}
	}
	else if (func == recovery_image_mock_get_hash) {
		switch (arg) {
			case 0:
				return "hash";

			case 1:
				return "hash_out";

			case 2:
				return "hash_length";
		}
	}
	else if (func == recovery_image_mock_get_version) {
		switch (arg) {
			case 0:
				return "version";
			case 1:
				return "len";	
		}
	}
	else if (func == recovery_image_mock_apply_to_flash) {
		switch (arg) {
			case 0:
				return "flash";
		}
	}

	return "unknown";
}

/**
 * Initialize a mock instance for a recovery image.
 *
 * @param mock The mock to initialize.
 *
 * @return 0 if the mock was initialized successfully or an error code.
 */
int recovery_image_mock_init (struct recovery_image_mock *mock)
{
	int status;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	memset (mock, 0, sizeof (struct recovery_image_mock));

	status = mock_init (&mock->mock);
	if (status != 0) {
		return status;
	}

	mock_set_name (&mock->mock, "recovery_image");

	mock->base.verify = recovery_image_mock_verify;
	mock->base.get_hash = recovery_image_mock_get_hash;
	mock->base.get_version = recovery_image_mock_get_version;
	mock->base.apply_to_flash = recovery_image_mock_apply_to_flash;

	mock->mock.func_arg_count = recovery_image_mock_func_arg_count;
	mock->mock.func_name_map = recovery_image_mock_func_name_map;
	mock->mock.arg_name_map = recovery_image_mock_arg_name_map;

	return 0;
}

/**
 * Free the resources used by a recovery image mock instance.
 *
 * @param mock The mock to release.
 */
void recovery_image_mock_release (struct recovery_image_mock *mock)
{
	if (mock != NULL) {
		mock_release (&mock->mock);
	}
}

/**
 * Validate the recovery image mock instance was called as expected and release it.
 *
 * @param mock The mock instance to validate.
 *
 * @return 0 if the mock was called as expected or 1 if not.
 */
int recovery_image_mock_validate_and_release (struct recovery_image_mock *mock)
{
	int status = 1;

	if (mock != NULL) {
		status = mock_validate (&mock->mock);
		recovery_image_mock_release (mock);
	}

	return status;
}
