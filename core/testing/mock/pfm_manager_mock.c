// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include "pfm_manager_mock.h"
#include "testing/engines/hash_testing_engine.h"


static struct pfm* pfm_manager_mock_get_active_pfm (struct pfm_manager *manager)
{
	struct pfm_manager_mock *mock = (struct pfm_manager_mock*) manager;

	if (mock == NULL) {
		return NULL;
	}

	MOCK_RETURN_NO_ARGS_CAST (&mock->mock, struct pfm*, pfm_manager_mock_get_active_pfm, manager);
}

static struct pfm* pfm_manager_mock_get_pending_pfm (struct pfm_manager *manager)
{
	struct pfm_manager_mock *mock = (struct pfm_manager_mock*) manager;

	if (mock == NULL) {
		return NULL;
	}

	MOCK_RETURN_NO_ARGS_CAST (&mock->mock, struct pfm*, pfm_manager_mock_get_pending_pfm, manager);
}

static void pfm_manager_mock_free_pfm (struct pfm_manager *manager,
	struct pfm *pfm)
{
	struct pfm_manager_mock *mock = (struct pfm_manager_mock*) manager;

	if (mock == NULL) {
		return;
	}

	MOCK_VOID_RETURN (&mock->mock, pfm_manager_mock_free_pfm, manager, MOCK_ARG_CALL (pfm));
}

static int pfm_manager_mock_activate_pending_manifest (struct manifest_manager *manager)
{
	struct pfm_manager_mock *mock = (struct pfm_manager_mock*) manager;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN_NO_ARGS (&mock->mock, pfm_manager_mock_activate_pending_manifest, manager);
}

static int pfm_manager_mock_clear_pending_region (struct manifest_manager *manager, size_t size)
{
	struct pfm_manager_mock *mock = (struct pfm_manager_mock*) manager;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, pfm_manager_mock_clear_pending_region, manager,
		MOCK_ARG_CALL (size));
}

static int pfm_manager_mock_write_pending_data (struct manifest_manager *manager,
	const uint8_t *data, size_t length)
{
	struct pfm_manager_mock *mock = (struct pfm_manager_mock*) manager;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, pfm_manager_mock_write_pending_data, manager, MOCK_ARG_CALL (data),
		MOCK_ARG_CALL (length));
}

static int pfm_manager_mock_verify_pending_manifest (struct manifest_manager *manager)
{
	struct pfm_manager_mock *mock = (struct pfm_manager_mock*) manager;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN_NO_ARGS (&mock->mock, pfm_manager_mock_verify_pending_manifest, manager);
}

static int pfm_manager_mock_clear_all_manifests (struct manifest_manager *manager)
{
	struct pfm_manager_mock *mock = (struct pfm_manager_mock*) manager;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN_NO_ARGS (&mock->mock, pfm_manager_mock_clear_all_manifests, manager);
}

static int pfm_manager_mock_func_arg_count (void *func)
{
	if (func == pfm_manager_mock_write_pending_data) {
		return 2;
	}
	else if ((func == pfm_manager_mock_free_pfm) ||
		(func == pfm_manager_mock_clear_pending_region)) {
		return 1;
	}
	else {
		return 0;
	}
}

static const char* pfm_manager_mock_func_name_map (void *func)
{
	if (func == pfm_manager_mock_get_active_pfm) {
		return "get_active_pfm";
	}
	else if (func == pfm_manager_mock_get_pending_pfm) {
		return "get_pending_pfm";
	}
	else if (func == pfm_manager_mock_free_pfm) {
		return "free_pfm";
	}
	else if (func == pfm_manager_mock_activate_pending_manifest) {
		return "activate_pending_pfm";
	}
	else if (func == pfm_manager_mock_clear_pending_region) {
		return "clear_pending_region";
	}
	else if (func == pfm_manager_mock_write_pending_data) {
		return "write_pending_data";
	}
	else if (func == pfm_manager_mock_verify_pending_manifest) {
		return "verify_pending_pfm";
	}
	else if (func == pfm_manager_mock_clear_all_manifests) {
		return "clear_all_manifests";
	}
	else {
		return "unknown";
	}
}

static const char* pfm_manager_mock_arg_name_map (void *func, int arg)
{
	if (func == pfm_manager_mock_free_pfm) {
		switch (arg) {
			case 0:
				return "pfm";
		}
	}
	else if (func == pfm_manager_mock_clear_pending_region) {
		switch (arg) {
			case 0:
				return "size";
		}
	}
	else if (func == pfm_manager_mock_write_pending_data) {
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
 * Initialize the mock instance for PFM management.
 *
 * @param mock The mock to initialize.
 *
 * @return 0 if the mock was successfully initialized or an error code.
 */
int pfm_manager_mock_init (struct pfm_manager_mock *mock)
{
	HASH_TESTING_ENGINE *hash;
	int status;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	memset (mock, 0, sizeof (struct pfm_manager_mock));

	hash = platform_malloc (sizeof (HASH_TESTING_ENGINE));
	if (hash == NULL) {
		return MOCK_NO_MEMORY;
	}

	status = HASH_TESTING_ENGINE_INIT (hash);
	if (status != 0) {
		platform_free (hash);
		return status;
	}

	status = pfm_manager_init (&mock->base, &hash->base, -1);
	if (status != 0) {
		platform_free (hash);
		return status;
	}

	status = mock_init (&mock->mock);
	if (status != 0) {
		platform_free (hash);
		pfm_manager_release (&mock->base);
		return status;
	}

	mock_set_name (&mock->mock, "pfm_manager");

	mock->base.get_active_pfm = pfm_manager_mock_get_active_pfm;
	mock->base.get_pending_pfm = pfm_manager_mock_get_pending_pfm;
	mock->base.free_pfm = pfm_manager_mock_free_pfm;
	mock->base.base.activate_pending_manifest = pfm_manager_mock_activate_pending_manifest;
	mock->base.base.clear_pending_region = pfm_manager_mock_clear_pending_region;
	mock->base.base.write_pending_data = pfm_manager_mock_write_pending_data;
	mock->base.base.verify_pending_manifest = pfm_manager_mock_verify_pending_manifest;
	mock->base.base.clear_all_manifests = pfm_manager_mock_clear_all_manifests;

	mock->mock.func_arg_count = pfm_manager_mock_func_arg_count;
	mock->mock.func_name_map = pfm_manager_mock_func_name_map;
	mock->mock.arg_name_map = pfm_manager_mock_arg_name_map;

	return 0;
}

/**
 * Release the resources used by a PFM management mock.
 *
 * @param mock The mock to release.
 */
void pfm_manager_mock_release (struct pfm_manager_mock *mock)
{
	if (mock) {
		HASH_TESTING_ENGINE_RELEASE ((HASH_TESTING_ENGINE*) mock->base.base.hash);
		platform_free (mock->base.base.hash);
		pfm_manager_release (&mock->base);
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
int pfm_manager_mock_validate_and_release (struct pfm_manager_mock *mock)
{
	int status = 1;

	if (mock != NULL) {
		status = mock_validate (&mock->mock);
		pfm_manager_mock_release (mock);
	}

	return status;
}
