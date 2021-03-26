// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include "cfm_mock.h"


static int cfm_mock_verify (struct manifest *cfm, struct hash_engine *hash,
	struct signature_verification *verification, uint8_t *hash_out, size_t hash_length)
{
	struct cfm_mock *mock = (struct cfm_mock*) cfm;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, cfm_mock_verify, cfm, MOCK_ARG_CALL (hash),
		MOCK_ARG_CALL (verification), MOCK_ARG_CALL (hash_out), MOCK_ARG_CALL (hash_length));
}

static int cfm_mock_get_id (struct manifest *cfm, uint32_t *id)
{
	struct cfm_mock *mock = (struct cfm_mock*) cfm;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, cfm_mock_get_id, cfm, MOCK_ARG_CALL (id));
}

static int cfm_mock_get_platform_id (struct manifest *cfm, char **id, size_t length)
{
	struct cfm_mock *mock = (struct cfm_mock*) cfm;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, cfm_mock_get_platform_id, cfm, MOCK_ARG_CALL (id),
		MOCK_ARG_CALL (length));
}

static void cfm_mock_free_platform_id (struct manifest *cfm, char *id)
{
	struct cfm_mock *mock = (struct cfm_mock*) cfm;

	if (mock == NULL) {
		return;
	}

	MOCK_VOID_RETURN (&mock->mock, cfm_mock_free_platform_id, cfm, MOCK_ARG_CALL (id));
}

static int cfm_mock_get_hash (struct manifest *cfm, struct hash_engine *hash, uint8_t *hash_out,
	size_t hash_length)
{
	struct cfm_mock *mock = (struct cfm_mock*) cfm;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, cfm_mock_get_hash, cfm, MOCK_ARG_CALL (hash),
		MOCK_ARG_CALL (hash_out), MOCK_ARG_CALL (hash_length));
}

static int cfm_mock_get_signature (struct manifest *cfm, uint8_t *signature, size_t length)
{
	struct cfm_mock *mock = (struct cfm_mock*) cfm;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, cfm_mock_get_signature, cfm, MOCK_ARG_CALL (signature),
		MOCK_ARG_CALL (length));
}

static int cfm_mock_is_empty (struct manifest *cfm)
{
	struct cfm_mock *mock = (struct cfm_mock*) cfm;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN_NO_ARGS (&mock->mock, cfm_mock_is_empty, cfm);
}

static int cfm_mock_get_supported_component_ids (struct cfm *cfm, struct cfm_component_ids *ids)
{
	struct cfm_mock *mock = (struct cfm_mock*) cfm;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, cfm_mock_get_supported_component_ids, cfm, MOCK_ARG_CALL (ids));
}

static void cfm_mock_free_component_ids (struct cfm *cfm, struct cfm_component_ids *ids)
{
	struct cfm_mock *mock = (struct cfm_mock*) cfm;

	if (mock == NULL) {
		return;
	}

	MOCK_VOID_RETURN (&mock->mock, cfm_mock_free_component_ids, cfm, MOCK_ARG_CALL (ids));
}

static int cfm_mock_get_component (struct cfm *cfm, uint32_t component_id,
	struct cfm_component *component)
{
	struct cfm_mock *mock = (struct cfm_mock*) cfm;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, cfm_mock_get_component, cfm, MOCK_ARG_CALL (component_id),
		MOCK_ARG_CALL (component));
}

static void cfm_mock_free_component (struct cfm *cfm, struct cfm_component *component)
{
	struct cfm_mock *mock = (struct cfm_mock*) cfm;

	if (mock == NULL) {
		return;
	}

	MOCK_VOID_RETURN (&mock->mock, cfm_mock_free_component, cfm, MOCK_ARG_CALL (component));
}

static int cfm_mock_func_arg_count (void *func)
{
	if (func == cfm_mock_verify) {
		return 4;
	}
	else if (func == cfm_mock_get_hash) {
		return 3;
	}
	else if ((func == cfm_mock_get_platform_id) || (func == cfm_mock_get_component) ||
		(func == cfm_mock_get_signature)) {
		return 2;
	}
	else if ((func == cfm_mock_get_id) || (func == cfm_mock_free_platform_id) ||
		(func == cfm_mock_get_supported_component_ids) || (func == cfm_mock_free_component_ids) ||
		(func == cfm_mock_free_component)) {
		return 1;
	}
	else {
		return 0;
	}
}

static const char* cfm_mock_func_name_map (void *func)
{
	if (func == cfm_mock_verify) {
		return "verify";
	}
	else if (func == cfm_mock_get_id) {
		return "get_id";
	}
	else if (func == cfm_mock_get_platform_id) {
		return "get_platform_id";
	}
	else if (func == cfm_mock_free_platform_id) {
		return "free_platform_id";
	}
	else if (func == cfm_mock_get_hash) {
		return "get_hash";
	}
	else if (func == cfm_mock_get_signature) {
		return "get_signature";
	}
	else if (func == cfm_mock_is_empty) {
		return "is_empty";
	}
	else if (func == cfm_mock_get_supported_component_ids) {
		return "get_supported_component_ids";
	}
	else if (func == cfm_mock_free_component_ids) {
		return "free_component_ids";
	}
	else if (func == cfm_mock_get_component) {
		return "get_component";
	}
	else if (func == cfm_mock_free_component) {
		return "free_component";
	}
	else {
		return "unknown";
	}
}

static const char* cfm_mock_arg_name_map (void *func, int arg)
{
	if (func == cfm_mock_verify) {
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
	else if (func == cfm_mock_get_id) {
		switch (arg) {
			case 0:
				return "id";
		}
	}
	else if (func == cfm_mock_get_platform_id) {
		switch (arg) {
			case 0:
				return "id";

			case 1:
				return "length";
		}
	}
	else if (func == cfm_mock_free_platform_id) {
		switch (arg) {
			case 0:
				return "id";
		}
	}
	else if (func == cfm_mock_get_hash) {
		switch (arg) {
			case 0:
				return "hash";

			case 1:
				return "hash_out";

			case 2:
				return "hash_length";
		}
	}
	else if (func == cfm_mock_get_signature) {
		switch (arg) {
			case 0:
				return "signature";

			case 1:
				return "length";
		}
	}
	else if (func == cfm_mock_get_supported_component_ids) {
		switch (arg) {
			case 0:
				return "ids";
		}
	}
	else if (func == cfm_mock_free_component_ids) {
		switch (arg) {
			case 0:
				return "ids";
		}
	}
	else if (func == cfm_mock_get_component) {
		switch (arg) {
			case 0:
				return "component_id";
			case 1:
				return "component";
		}
	}
	else if (func == cfm_mock_free_component) {
		switch (arg) {
			case 0:
				return "component";
		}
	}

	return "unknown";
}

/**
 * Initialize a mock instance for a cfm.
 *
 * @param mock The mock to initialize.
 *
 * @return 0 if the mock was initialized successfully or an error code.
 */
int cfm_mock_init (struct cfm_mock *mock)
{
	int status;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	memset (mock, 0, sizeof (struct cfm_mock));

	status = mock_init (&mock->mock);
	if (status != 0) {
		return status;
	}

	mock_set_name (&mock->mock, "cfm");

	mock->base.base.verify = cfm_mock_verify;
	mock->base.base.get_id = cfm_mock_get_id;
	mock->base.base.get_platform_id = cfm_mock_get_platform_id;
	mock->base.base.free_platform_id = cfm_mock_free_platform_id;
	mock->base.base.get_hash = cfm_mock_get_hash;
	mock->base.base.get_signature = cfm_mock_get_signature;
	mock->base.base.is_empty = cfm_mock_is_empty;

	mock->base.get_supported_component_ids = cfm_mock_get_supported_component_ids;
	mock->base.free_component_ids = cfm_mock_free_component_ids;
	mock->base.get_component = cfm_mock_get_component;
	mock->base.free_component = cfm_mock_free_component;

	mock->mock.func_arg_count = cfm_mock_func_arg_count;
	mock->mock.func_name_map = cfm_mock_func_name_map;
	mock->mock.arg_name_map = cfm_mock_arg_name_map;

	return 0;
}

/**
 * Free the resources used by a cfm mock instance.
 *
 * @param mock The mock to release.
 */
void cfm_mock_release (struct cfm_mock *mock)
{
	if (mock != NULL) {
		mock_release (&mock->mock);
	}
}

/**
 * Validate that the cfm mock instance was called as expected and release it.
 *
 * @param mock The mock instance to validate.
 *
 * @return 0 if the mock was called as expected or 1 if not.
 */
int cfm_mock_validate_and_release (struct cfm_mock *mock)
{
	int status = 1;

	if (mock != NULL) {
		status = mock_validate (&mock->mock);
		cfm_mock_release (mock);
	}

	return status;
}
