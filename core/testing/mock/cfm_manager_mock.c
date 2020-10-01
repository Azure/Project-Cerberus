// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include "cfm_manager_mock.h"
#include "testing/engines/hash_testing_engine.h"


static struct cfm* cfm_manager_mock_get_active_cfm (struct cfm_manager *manager)
{
	struct cfm_manager_mock *mock = (struct cfm_manager_mock*) manager;

	if (mock == NULL) {
		return NULL;
	}

	MOCK_RETURN_NO_ARGS_CAST (&mock->mock, struct cfm*, cfm_manager_mock_get_active_cfm, manager);
}

static struct cfm* cfm_manager_mock_get_pending_cfm (struct cfm_manager *manager)
{
	struct cfm_manager_mock *mock = (struct cfm_manager_mock*) manager;

	if (mock == NULL) {
		return NULL;
	}

	MOCK_RETURN_NO_ARGS_CAST (&mock->mock, struct cfm*, cfm_manager_mock_get_pending_cfm, manager);
}

static void cfm_manager_mock_free_cfm (struct cfm_manager *manager,
	struct cfm *cfm)
{
	struct cfm_manager_mock *mock = (struct cfm_manager_mock*) manager;

	if (mock == NULL) {
		return;
	}

	MOCK_VOID_RETURN (&mock->mock, cfm_manager_mock_free_cfm, manager, MOCK_ARG_CALL (cfm));
}

static int cfm_manager_mock_activate_pending_manifest (struct manifest_manager *manager)
{
	struct cfm_manager_mock *mock = (struct cfm_manager_mock*) manager;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN_NO_ARGS (&mock->mock, cfm_manager_mock_activate_pending_manifest, manager);
}

static int cfm_manager_mock_clear_pending_region (struct manifest_manager *manager, size_t size)
{
	struct cfm_manager_mock *mock = (struct cfm_manager_mock*) manager;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, cfm_manager_mock_clear_pending_region, manager, MOCK_ARG_CALL (size));
}

static int cfm_manager_mock_write_pending_data (struct manifest_manager *manager,
	const uint8_t *data, size_t length)
{
	struct cfm_manager_mock *mock = (struct cfm_manager_mock*) manager;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, cfm_manager_mock_write_pending_data, manager, MOCK_ARG_CALL (data),
		MOCK_ARG_CALL (length));
}

static int cfm_manager_mock_verify_pending_manifest (struct manifest_manager *manager)
{
	struct cfm_manager_mock *mock = (struct cfm_manager_mock*) manager;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN_NO_ARGS (&mock->mock, cfm_manager_mock_verify_pending_manifest, manager);
}

static int cfm_manager_mock_clear_all_manifests (struct manifest_manager *manager)
{
	struct cfm_manager_mock *mock = (struct cfm_manager_mock*) manager;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN_NO_ARGS (&mock->mock, cfm_manager_mock_clear_all_manifests, manager);
}

static int cfm_manager_mock_func_arg_count (void *func)
{
	if (func == cfm_manager_mock_write_pending_data) {
		return 2;
	}
	if ((func == cfm_manager_mock_free_cfm) || (func == cfm_manager_mock_clear_pending_region)) {
		return 1;
	}
	else {
		return 0;
	}
}

static const char* cfm_manager_mock_func_name_map (void *func)
{
	if (func == cfm_manager_mock_get_active_cfm) {
		return "get_active_cfm";
	}
	else if (func == cfm_manager_mock_get_pending_cfm) {
		return "get_pending_cfm";
	}
	else if (func == cfm_manager_mock_free_cfm) {
		return "free_cfm";
	}
	else if (func == cfm_manager_mock_activate_pending_manifest) {
		return "activate_pending_cfm";
	}
	else if (func == cfm_manager_mock_clear_pending_region) {
		return "clear_pending_region";
	}
	else if (func == cfm_manager_mock_write_pending_data) {
		return "write_pending_data";
	}
	else if (func == cfm_manager_mock_verify_pending_manifest) {
		return "verify_pending_cfm";
	}
	else if (func == cfm_manager_mock_clear_all_manifests) {
		return "clear_all_manifests";
	}
	else {
		return "unknown";
	}
}

static const char* cfm_manager_mock_arg_name_map (void *func, int arg)
{
	if (func == cfm_manager_mock_free_cfm) {
		switch (arg) {
			case 0:
				return "cfm";
		}
	}
	else if (func == cfm_manager_mock_clear_pending_region) {
		switch (arg) {
			case 0:
				return "size";
		}
	}
	else if (func == cfm_manager_mock_write_pending_data) {
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
 * Initialize the mock instance for cfm management.
 *
 * @param mock The mock to initialize.
 *
 * @return 0 if the mock was successfully initialized or an error code.
 */
int cfm_manager_mock_init (struct cfm_manager_mock *mock)
{
	HASH_TESTING_ENGINE *hash;
	int status;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	memset (mock, 0, sizeof (struct cfm_manager_mock));

	hash = platform_malloc (sizeof (HASH_TESTING_ENGINE));
	if (hash == NULL) {
		return MOCK_NO_MEMORY;
	}

	status = HASH_TESTING_ENGINE_INIT (hash);
	if (status != 0) {
		platform_free (hash);
		return status;
	}

	status = cfm_manager_init (&mock->base, &hash->base);
	if (status != 0) {
		platform_free (hash);
		return status;
	}

	status = mock_init (&mock->mock);
	if (status != 0) {
		platform_free (hash);
		cfm_manager_release (&mock->base);
		return status;
	}

	mock_set_name (&mock->mock, "cfm_manager");

	mock->base.get_active_cfm = cfm_manager_mock_get_active_cfm;
	mock->base.get_pending_cfm = cfm_manager_mock_get_pending_cfm;
	mock->base.free_cfm = cfm_manager_mock_free_cfm;
	mock->base.base.activate_pending_manifest = cfm_manager_mock_activate_pending_manifest;
	mock->base.base.clear_pending_region = cfm_manager_mock_clear_pending_region;
	mock->base.base.write_pending_data = cfm_manager_mock_write_pending_data;
	mock->base.base.verify_pending_manifest = cfm_manager_mock_verify_pending_manifest;
	mock->base.base.clear_all_manifests = cfm_manager_mock_clear_all_manifests;

	mock->mock.func_arg_count = cfm_manager_mock_func_arg_count;
	mock->mock.func_name_map = cfm_manager_mock_func_name_map;
	mock->mock.arg_name_map = cfm_manager_mock_arg_name_map;

	return 0;
}

/**
 * Release the resources used by a cfm management mock.
 *
 * @param mock The mock to release.
 */
void cfm_manager_mock_release (struct cfm_manager_mock *mock)
{
	if (mock) {
		HASH_TESTING_ENGINE_RELEASE ((HASH_TESTING_ENGINE*) mock->base.base.hash);
		platform_free (mock->base.base.hash);
		cfm_manager_release (&mock->base);
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
int cfm_manager_mock_validate_and_release (struct cfm_manager_mock *mock)
{
	int status = 1;

	if (mock != NULL) {
		status = mock_validate (&mock->mock);
		cfm_manager_mock_release (mock);
	}

	return status;
}
