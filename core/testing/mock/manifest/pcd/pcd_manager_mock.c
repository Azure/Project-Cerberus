// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "pcd_manager_mock.h"


static const struct pcd* pcd_manager_mock_get_active_pcd (const struct pcd_manager *manager)
{
	struct pcd_manager_mock *mock = (struct pcd_manager_mock*) manager;

	if (mock == NULL) {
		return NULL;
	}

	MOCK_RETURN_NO_ARGS_CAST_PTR (&mock->mock, const struct pcd*, pcd_manager_mock_get_active_pcd,
		manager);
}

static void pcd_manager_mock_free_pcd (const struct pcd_manager *manager, const struct pcd *pcd)
{
	struct pcd_manager_mock *mock = (struct pcd_manager_mock*) manager;

	if (mock == NULL) {
		return;
	}

	MOCK_VOID_RETURN (&mock->mock, pcd_manager_mock_free_pcd, manager, MOCK_ARG_PTR_CALL (pcd));
}

static int pcd_manager_mock_activate_pending_manifest (const struct manifest_manager *manager)
{
	struct pcd_manager_mock *mock = (struct pcd_manager_mock*) manager;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN_NO_ARGS (&mock->mock, pcd_manager_mock_activate_pending_manifest, manager);
}

static int pcd_manager_mock_clear_pending_region (const struct manifest_manager *manager,
	size_t size)
{
	struct pcd_manager_mock *mock = (struct pcd_manager_mock*) manager;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, pcd_manager_mock_clear_pending_region, manager, MOCK_ARG_CALL (size));
}

static int pcd_manager_mock_write_pending_data (const struct manifest_manager *manager,
	const uint8_t *data, size_t length)
{
	struct pcd_manager_mock *mock = (struct pcd_manager_mock*) manager;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, pcd_manager_mock_write_pending_data, manager,
		MOCK_ARG_PTR_CALL (data), MOCK_ARG_CALL (length));
}

static int pcd_manager_mock_verify_pending_manifest (const struct manifest_manager *manager)
{
	struct pcd_manager_mock *mock = (struct pcd_manager_mock*) manager;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN_NO_ARGS (&mock->mock, pcd_manager_mock_verify_pending_manifest, manager);
}

static int pcd_manager_mock_clear_all_manifests (const struct manifest_manager *manager)
{
	struct pcd_manager_mock *mock = (struct pcd_manager_mock*) manager;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN_NO_ARGS (&mock->mock, pcd_manager_mock_clear_all_manifests, manager);
}

static int pcd_manager_mock_func_arg_count (void *func)
{
	if (func == pcd_manager_mock_write_pending_data) {
		return 2;
	}
	if ((func == pcd_manager_mock_free_pcd) || (func == pcd_manager_mock_clear_pending_region)) {
		return 1;
	}
	else {
		return 0;
	}
}

static const char* pcd_manager_mock_func_name_map (void *func)
{
	if (func == pcd_manager_mock_get_active_pcd) {
		return "get_active_pcd";
	}
	else if (func == pcd_manager_mock_free_pcd) {
		return "free_pcd";
	}
	else if (func == pcd_manager_mock_activate_pending_manifest) {
		return "activate_pending_manifest";
	}
	else if (func == pcd_manager_mock_clear_pending_region) {
		return "clear_pending_region";
	}
	else if (func == pcd_manager_mock_write_pending_data) {
		return "write_pending_data";
	}
	else if (func == pcd_manager_mock_verify_pending_manifest) {
		return "verify_pending_manifest";
	}
	else if (func == pcd_manager_mock_clear_all_manifests) {
		return "clear_all_manifests";
	}
	else {
		return "unknown";
	}
}

static const char* pcd_manager_mock_arg_name_map (void *func, int arg)
{
	if (func == pcd_manager_mock_free_pcd) {
		switch (arg) {
			case 0:
				return "pcd";
		}
	}
	else if (func == pcd_manager_mock_clear_pending_region) {
		switch (arg) {
			case 0:
				return "size";
		}
	}
	else if (func == pcd_manager_mock_write_pending_data) {
		switch (arg) {
			case 0:
				return "data";

			case 1:
				return "length";
		}
	}

	return "unknown";
}

/**
 * Initialize the mock instance for pcd management.
 *
 * @param mock The mock to initialize.
 *
 * @return 0 if the mock was successfully initialized or an error code.
 */
int pcd_manager_mock_init (struct pcd_manager_mock *mock)
{
	int status;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	memset (mock, 0, sizeof (struct pcd_manager_mock));

	status = HASH_TESTING_ENGINE_INIT (&mock->hash);
	if (status != 0) {
		return status;
	}

	status = pcd_manager_init (&mock->base, &mock->state, &mock->hash.base);
	if (status != 0) {
		return status;
	}

	status = mock_init (&mock->mock);
	if (status != 0) {
		pcd_manager_release (&mock->base);

		return status;
	}

	mock_set_name (&mock->mock, "pcd_manager");

	mock->base.get_active_pcd = pcd_manager_mock_get_active_pcd;
	mock->base.free_pcd = pcd_manager_mock_free_pcd;
	mock->base.base.activate_pending_manifest = pcd_manager_mock_activate_pending_manifest;
	mock->base.base.clear_pending_region = pcd_manager_mock_clear_pending_region;
	mock->base.base.write_pending_data = pcd_manager_mock_write_pending_data;
	mock->base.base.verify_pending_manifest = pcd_manager_mock_verify_pending_manifest;
	mock->base.base.clear_all_manifests = pcd_manager_mock_clear_all_manifests;

	mock->mock.func_arg_count = pcd_manager_mock_func_arg_count;
	mock->mock.func_name_map = pcd_manager_mock_func_name_map;
	mock->mock.arg_name_map = pcd_manager_mock_arg_name_map;

	return 0;
}

/**
 * Release the resources used by a pcd management mock.
 *
 * @param mock The mock to release.
 */
void pcd_manager_mock_release (struct pcd_manager_mock *mock)
{
	if (mock) {
		HASH_TESTING_ENGINE_RELEASE (&mock->hash);
		pcd_manager_release (&mock->base);
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
int pcd_manager_mock_validate_and_release (struct pcd_manager_mock *mock)
{
	int status = 1;

	if (mock != NULL) {
		status = mock_validate (&mock->mock);
		pcd_manager_mock_release (mock);
	}

	return status;
}
