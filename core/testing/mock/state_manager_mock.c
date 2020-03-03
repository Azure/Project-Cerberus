// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include "state_manager_mock.h"


static int state_manager_mock_save_active_manifest (struct state_manager *manager, 
	uint8_t manifest_index, enum manifest_region active)
{
	struct state_manager_mock *mock = (struct state_manager_mock*) manager;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, state_manager_mock_save_active_manifest, manager,
		MOCK_ARG_CALL (manifest_index), MOCK_ARG_CALL (active));
}

static enum manifest_region state_manager_mock_get_active_manifest (struct state_manager *manager, 
	uint8_t manifest_index)
{
	struct state_manager_mock *mock = (struct state_manager_mock*) manager;

	if (mock == NULL) {
		return (enum manifest_region) MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN_CAST (&mock->mock, enum manifest_region, state_manager_mock_get_active_manifest, 
		manager, MOCK_ARG_CALL (manifest_index));
}

static int state_manager_mock_restore_default_state (struct state_manager *manager)
{
	struct state_manager_mock *mock = (struct state_manager_mock*) manager;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN_NO_ARGS (&mock->mock, state_manager_mock_restore_default_state, manager);
}

static int state_manager_mock_is_manifest_valid (struct state_manager *manager, 
	uint8_t manifest_index)
{
	struct state_manager_mock *mock = (struct state_manager_mock*) manager;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, state_manager_mock_is_manifest_valid, manager, 
		MOCK_ARG_CALL (manifest_index));
}

static int state_manager_mock_func_arg_count (void *func)
{
	if (func == state_manager_mock_save_active_manifest) {
		return 2;
	}
	else if (func == state_manager_mock_get_active_manifest) {
		return 1;
	}
	if (func == state_manager_mock_is_manifest_valid) {
		return 1;
	}
	else {
		return 0;
	}
}

static const char* state_manager_mock_func_name_map (void *func)
{
	if (func == state_manager_mock_save_active_manifest) {
		return "save_active_manifest";
	}
	else if (func == state_manager_mock_get_active_manifest) {
		return "get_active_manifest";
	}
	else if (func == state_manager_mock_restore_default_state) {
		return "restore_default_state";
	}
	else if (func == state_manager_mock_is_manifest_valid) {
		return "is_manifest_valid";
	}
	else {
		return "unknown";
	}
}

static const char* state_manager_mock_arg_name_map (void *func, int arg)
{
	if (func == state_manager_mock_save_active_manifest) {
		switch (arg) {
			case 0:
				return "manifest_index";
			case 1:
				return "active";
		}
	}
	else if (func == state_manager_mock_get_active_manifest) {
		switch (arg) {
			case 0:
				return "manifest_index";
		}
	}
	else if (func == state_manager_mock_is_manifest_valid) {
		switch (arg) {
			case 0:
				return "manifest_index";
		}
	}

	return "unknown";
}

/**
 * Initialize a mock for state management.
 *
 * @param mock The mock to initialize.
 *
 * @return 0 if the mock was successfully initialized or an error code.
 */
int state_manager_mock_init (struct state_manager_mock *mock)
{
	int status;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	memset (mock, 0, sizeof (struct state_manager_mock));

	status = mock_init (&mock->mock);
	if (status != 0) {
		return status;
	}

	mock_set_name (&mock->mock, "state_manager");

	mock->base.save_active_manifest = state_manager_mock_save_active_manifest;
	mock->base.get_active_manifest = state_manager_mock_get_active_manifest;
	mock->base.restore_default_state = state_manager_mock_restore_default_state;
	mock->base.is_manifest_valid = state_manager_mock_is_manifest_valid;

	mock->mock.func_arg_count = state_manager_mock_func_arg_count;
	mock->mock.func_name_map = state_manager_mock_func_name_map;
	mock->mock.arg_name_map = state_manager_mock_arg_name_map;

	return 0;
}

/**
 * Release the resources used by a mock state manager.
 *
 * @param mock The mock to release.
 */
void state_manager_mock_release (struct state_manager_mock *mock)
{
	if (mock != NULL) {
		mock_release (&mock->mock);
	}
}

/**
 * Verify a mock was called as expected and release the instance.
 *
 * @param mock The mock to validate.
 *
 * @return 0 if all expectations were met or 1 if not.
 */
int state_manager_mock_validate_and_release (struct state_manager_mock *mock)
{
	int status = 1;

	if (mock != NULL) {
		status = mock_validate (&mock->mock);
		state_manager_mock_release (mock);
	}

	return status;
}
