// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include "pcd_mock.h"


static int pcd_mock_verify (struct manifest *pcd, struct hash_engine *hash,
	struct signature_verification *verification, uint8_t *hash_out, size_t hash_length)
{
	struct pcd_mock *mock = (struct pcd_mock*) pcd;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, pcd_mock_verify, pcd, MOCK_ARG_CALL (hash),
		MOCK_ARG_CALL (verification), MOCK_ARG_CALL (hash_out), MOCK_ARG_CALL (hash_length));
}

static int pcd_mock_get_id (struct manifest *pcd, uint32_t *id)
{
	struct pcd_mock *mock = (struct pcd_mock*) pcd;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, pcd_mock_get_id, pcd, MOCK_ARG_CALL (id));
}

static int pcd_mock_get_platform_id (struct manifest *pcd, char **id, size_t length)
{
	struct pcd_mock *mock = (struct pcd_mock*) pcd;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, pcd_mock_get_platform_id, pcd, MOCK_ARG_CALL (id),
		MOCK_ARG_CALL (length));
}

static void pcd_mock_free_platform_id (struct manifest *pcd, char *id)
{
	struct pcd_mock *mock = (struct pcd_mock*) pcd;

	if (mock == NULL) {
		return;
	}

	MOCK_VOID_RETURN (&mock->mock, pcd_mock_free_platform_id, pcd, MOCK_ARG_CALL (id));
}

static int pcd_mock_get_hash (struct manifest *pcd, struct hash_engine *hash, uint8_t *hash_out,
	size_t hash_length)
{
	struct pcd_mock *mock = (struct pcd_mock*) pcd;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, pcd_mock_get_hash, pcd, MOCK_ARG_CALL (hash),
		MOCK_ARG_CALL (hash_out), MOCK_ARG_CALL (hash_length));
}

static int pcd_mock_get_signature (struct manifest *pcd, uint8_t *signature, size_t length)
{
	struct pcd_mock *mock = (struct pcd_mock*) pcd;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, pcd_mock_get_signature, pcd, MOCK_ARG_CALL (signature),
		MOCK_ARG_CALL (length));
}

static int pcd_mock_is_empty (struct manifest *pcd)
{
	struct pcd_mock *mock = (struct pcd_mock*) pcd;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN_NO_ARGS (&mock->mock, pcd_mock_is_empty, pcd);
}

static int pcd_mock_get_devices_info (struct pcd *pcd, struct device_manager_info **devices,
	size_t *num_devices)
{
	struct pcd_mock *mock = (struct pcd_mock*) pcd;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, pcd_mock_get_devices_info, pcd, MOCK_ARG_CALL (devices),
		MOCK_ARG_CALL (num_devices));
}

static int pcd_mock_get_rot_info (struct pcd *pcd, struct pcd_rot_info *info)
{
	struct pcd_mock *mock = (struct pcd_mock*) pcd;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, pcd_mock_get_rot_info, pcd, MOCK_ARG_CALL (info));
}

static int pcd_mock_get_port_info (struct pcd *pcd, uint8_t port_id, struct pcd_port_info *info)
{
	struct pcd_mock *mock = (struct pcd_mock*) pcd;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, pcd_mock_get_port_info, pcd, MOCK_ARG_CALL (port_id),
		MOCK_ARG_CALL (info));
}

static int pcd_mock_get_power_controller_info (struct pcd *pcd,
	struct pcd_power_controller_info *info)
{
	struct pcd_mock *mock = (struct pcd_mock*) pcd;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, pcd_mock_get_power_controller_info, pcd, MOCK_ARG_CALL (info));
}

static int pcd_mock_func_arg_count (void *func)
{
	if (func == pcd_mock_verify) {
		return 4;
	}
	else if (func == pcd_mock_get_hash) {
		return 3;
	}
	else if ((func == pcd_mock_get_platform_id) || (func == pcd_mock_get_signature) ||
		(func == pcd_mock_get_devices_info) || (func == pcd_mock_get_port_info)) {
		return 2;
	}
	else if ((func == pcd_mock_get_id) || (func == pcd_mock_free_platform_id) ||
		(func == pcd_mock_get_rot_info) || (func == pcd_mock_get_power_controller_info)) {
		return 1;
	}
	else {
		return 0;
	}
}

static const char* pcd_mock_func_name_map (void *func)
{
	if (func == pcd_mock_verify) {
		return "verify";
	}
	else if (func == pcd_mock_get_id) {
		return "get_id";
	}
	else if (func == pcd_mock_get_platform_id) {
		return "get_platform_id";
	}
	else if (func == pcd_mock_free_platform_id) {
		return "free_platform_id";
	}
	else if (func == pcd_mock_get_hash) {
		return "get_hash";
	}
	else if (func == pcd_mock_get_signature) {
		return "get_signature";
	}
	else if (func == pcd_mock_is_empty) {
		return "is_empty";
	}
	else if (func == pcd_mock_get_devices_info) {
		return "get_devices_info";
	}
	else if (func == pcd_mock_get_rot_info) {
		return "get_rot_info";
	}
	else if (func == pcd_mock_get_port_info) {
		return "get_port_info";
	}
	else if (func == pcd_mock_get_power_controller_info) {
		return "get_power_controller_info";
	}
	else {
		return "unknown";
	}
}

static const char* pcd_mock_arg_name_map (void *func, int arg)
{
	if (func == pcd_mock_verify) {
		switch (arg) {
			case 0:
				return "hash";

			case 1:
				return "verification";

			case 2:
				return "hash_out";

			case 3:
				return "hash_length";
		}
	}
	else if (func == pcd_mock_get_id) {
		switch (arg) {
			case 0:
				return "id";
		}
	}
	else if (func == pcd_mock_get_platform_id) {
		switch (arg) {
			case 0:
				return "id";

			case 1:
				return "length";
		}
	}
	else if (func == pcd_mock_free_platform_id) {
		switch (arg) {
			case 0:
				return "id";
		}
	}
	else if (func == pcd_mock_get_hash) {
		switch (arg) {
			case 0:
				return "hash";

			case 1:
				return "hash_out";

			case 2:
				return "hash_length";
		}
	}
	else if (func == pcd_mock_get_signature) {
		switch (arg) {
			case 0:
				return "signature";

			case 1:
				return "length";
		}
	}
	else if (func == pcd_mock_get_devices_info) {
		switch (arg) {
			case 0:
				return "devices";

			case 1:
				return "num_devices";
		}
	}
	else if (func == pcd_mock_get_rot_info) {
		switch (arg) {
			case 0:
				return "info";
		}
	}
	else if (func == pcd_mock_get_port_info) {
		switch (arg) {
			case 0:
				return "port_id";

			case 1:
				return "info";
		}
	}
	else if (func == pcd_mock_get_power_controller_info) {
		switch (arg) {
			case 0:
				return "info";
		}
	}

	return "unknown";
}

/**
 * Initialize a mock instance for a pcd.
 *
 * @param mock The mock to initialize.
 *
 * @return 0 if the mock was initialized successfully or an error code.
 */
int pcd_mock_init (struct pcd_mock *mock)
{
	int status;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	memset (mock, 0, sizeof (struct pcd_mock));

	status = mock_init (&mock->mock);
	if (status != 0) {
		return status;
	}

	mock_set_name (&mock->mock, "pcd");

	mock->base.base.verify = pcd_mock_verify;
	mock->base.base.get_id = pcd_mock_get_id;
	mock->base.base.get_platform_id = pcd_mock_get_platform_id;
	mock->base.base.free_platform_id = pcd_mock_free_platform_id;
	mock->base.base.get_hash = pcd_mock_get_hash;
	mock->base.base.get_signature = pcd_mock_get_signature;
	mock->base.base.is_empty = pcd_mock_is_empty;

	mock->base.get_devices_info = pcd_mock_get_devices_info;
	mock->base.get_rot_info = pcd_mock_get_rot_info;
	mock->base.get_port_info = pcd_mock_get_port_info;
	mock->base.get_power_controller_info = pcd_mock_get_power_controller_info;

	mock->mock.func_arg_count = pcd_mock_func_arg_count;
	mock->mock.func_name_map = pcd_mock_func_name_map;
	mock->mock.arg_name_map = pcd_mock_arg_name_map;

	return 0;
}

/**
 * Free the resources used by a pcd mock instance.
 *
 * @param mock The mock to release.
 */
void pcd_mock_release (struct pcd_mock *mock)
{
	if (mock != NULL) {
		mock_release (&mock->mock);
	}
}

/**
 * Validate that the pcd mock instance was called as expected and release it.
 *
 * @param mock The mock instance to validate.
 *
 * @return 0 if the mock was called as expected or 1 if not.
 */
int pcd_mock_validate_and_release (struct pcd_mock *mock)
{
	int status = 1;

	if (mock != NULL) {
		status = mock_validate (&mock->mock);
		pcd_mock_release (mock);
	}

	return status;
}
