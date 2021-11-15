// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include "firmware_update_mock.h"


int firmware_update_mock_finalize_image (struct firmware_update *updater, struct flash *flash,
	uint32_t address)
{
	struct firmware_update_mock *mock = (struct firmware_update_mock*) updater;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, firmware_update_mock_finalize_image, updater, MOCK_ARG_CALL (flash),
		MOCK_ARG_CALL (address));
}

int firmware_update_mock_verify_boot_image (struct firmware_update *updater, struct flash *flash,
	uint32_t address)
{
	struct firmware_update_mock *mock = (struct firmware_update_mock*) updater;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, firmware_update_mock_verify_boot_image, updater,
		MOCK_ARG_CALL (flash), MOCK_ARG_CALL (address));
}

static int firmware_update_mock_func_arg_count (void *func)
{
	if ((func == firmware_update_mock_finalize_image) ||
		(func == firmware_update_mock_verify_boot_image)) {
		return 2;
	}
	else {
		return 0;
	}
}

static const char* firmware_update_mock_func_name_map (void *func)
{
	if (func == firmware_update_mock_finalize_image) {
		return "finalize_image";
	}
	else if (func == firmware_update_mock_verify_boot_image) {
		return "verify_boot_image";
	}
	else {
		return "unknown";
	}
}

static const char* firmware_update_mock_arg_name_map (void *func, int arg)
{
	if (func == firmware_update_mock_finalize_image) {
		switch (arg) {
			case 0:
				return "flash";

			case 1:
				return "address";
		}
	}
	else if (func == firmware_update_mock_verify_boot_image) {
		switch (arg) {
			case 0:
				return "flash";

			case 1:
				return "address";
		}
	}

	return "unknown";
}

/**
 * Initialize mock firmware updater.
 *
 * @param mock The mock instance to initialize.
 * @param flash The device and address mapping for firmware images.
 * @param context The application context API.
 * @param fw The platform handler for firmware images.
 * @param hash The hash engine to use during updates.
 * @param rsa The RSA engine to use for signature verification.
 * @param allowed_revision The lowest image ID that will be allowed for firmware updates.
 *
 * @return 0 if the mock was initialized successfully or an error code.
 */
int firmware_update_mock_init (struct firmware_update_mock *mock,
	const struct firmware_flash_map *flash, struct app_context *context, struct firmware_image *fw,
	struct hash_engine *hash, struct rsa_engine *rsa, int allowed_revision)
{
	int status;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	memset (mock, 0, sizeof (struct firmware_update_mock));

	status = firmware_update_init (&mock->base, flash, context, fw, hash, rsa, allowed_revision);
	if (status != 0) {
		return status;
	}

	status = mock_init (&mock->mock);
	if (status != 0) {
		firmware_update_release (&mock->base);
		return status;
	}

	mock_set_name (&mock->mock, "firmware_update");

	mock->mock.func_arg_count = firmware_update_mock_func_arg_count;
	mock->mock.func_name_map = firmware_update_mock_func_name_map;
	mock->mock.arg_name_map = firmware_update_mock_arg_name_map;

	return 0;
}

/**
 * Release the resources used by a mock firmware updater.
 *
 * @param mock The mock instance to release.
 */
void firmware_update_mock_release (struct firmware_update_mock *mock)
{
	if (mock != NULL) {
		firmware_update_release (&mock->base);
		mock_release (&mock->mock);
	}
}

/**
 * Verify that a mock was called as expected and release the instance.
 *
 * @param mock The mock to validate.
 *
 * @return 0 if all expectations were met or 1 if not.
 */
int firmware_update_mock_validate_and_release (struct firmware_update_mock *mock)
{
	int status = 1;

	if (mock != NULL) {
		status = mock_validate (&mock->mock);
		firmware_update_mock_release (mock);
	}

	return status;
}

/**
 * Enable the internal hook for finalize_image.
 *
 * @param mock The mock to update.
 */
void firmware_update_mock_enable_finalize_image (struct firmware_update_mock *mock)
{
	if (mock) {
		mock->base.internal.finalize_image = firmware_update_mock_finalize_image;
	}
}

/**
 * Enable the internal hook for verify_boot_image.
 *
 * @param mock The mock to update.
 */
void firmware_update_mock_enable_verify_boot_image (struct firmware_update_mock *mock)
{
	if (mock) {
		mock->base.internal.verify_boot_image = firmware_update_mock_verify_boot_image;
	}
}
