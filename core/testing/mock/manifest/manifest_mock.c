// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include "manifest_mock.h"


static int manifest_mock_verify (struct manifest *manifest, struct hash_engine *hash,
	struct signature_verification *verification, uint8_t *hash_out, size_t hash_length)
{
	struct manifest_mock *mock = (struct manifest_mock*) manifest;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, manifest_mock_verify, manifest, MOCK_ARG_CALL (hash),
		MOCK_ARG_CALL (verification), MOCK_ARG_CALL (hash_out), MOCK_ARG_CALL (hash_length));
}

static int manifest_mock_get_id (struct manifest *manifest, uint32_t *id)
{
	struct manifest_mock *mock = (struct manifest_mock*) manifest;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, manifest_mock_get_id, manifest, MOCK_ARG_CALL (id));
}

static int manifest_mock_get_platform_id (struct manifest *manifest, char **id, size_t length)
{
	struct manifest_mock *mock = (struct manifest_mock*) manifest;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, manifest_mock_get_platform_id, manifest, MOCK_ARG_CALL (id),
		MOCK_ARG_CALL (length));
}

static void manifest_mock_free_platform_id (struct manifest *manifest, char *id)
{
	struct manifest_mock *mock = (struct manifest_mock*) manifest;

	if (mock == NULL) {
		return;
	}

	MOCK_VOID_RETURN (&mock->mock, manifest_mock_free_platform_id, manifest, MOCK_ARG_CALL (id));
}

static int manifest_mock_get_hash (struct manifest *manifest, struct hash_engine *hash,
	uint8_t *hash_out, size_t hash_length)
{
	struct manifest_mock *mock = (struct manifest_mock*) manifest;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, manifest_mock_get_hash, manifest, MOCK_ARG_CALL (hash),
		MOCK_ARG_CALL (hash_out), MOCK_ARG_CALL (hash_length));
}

static int manifest_mock_get_signature (struct manifest *manifest, uint8_t *signature, size_t length)
{
	struct manifest_mock *mock = (struct manifest_mock*) manifest;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, manifest_mock_get_signature, manifest, MOCK_ARG_CALL (signature),
		MOCK_ARG_CALL (length));
}

static int manifest_mock_is_empty (struct manifest *manifest)
{
	struct manifest_mock *mock = (struct manifest_mock*) manifest;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN_NO_ARGS (&mock->mock, manifest_mock_is_empty, manifest);
}

static int manifest_mock_func_arg_count (void *func)
{
	if (func == manifest_mock_verify) {
		return 4;
	}
	else if (func == manifest_mock_get_hash) {
		return 3;
	}
	else if ((func == manifest_mock_get_platform_id) || (func == manifest_mock_get_signature)) {
		return 2;
	}
	else if ((func == manifest_mock_get_id) || (func == manifest_mock_free_platform_id)) {
		return 1;
	}
	else {
		return 0;
	}
}

static const char* manifest_mock_func_name_map (void *func)
{
	if (func == manifest_mock_verify) {
		return "verify";
	}
	else if (func == manifest_mock_get_id) {
		return "get_id";
	}
	else if (func == manifest_mock_get_platform_id) {
		return "get_platform_id";
	}
	else if (func == manifest_mock_free_platform_id) {
		return "free_platform_id";
	}
	else if (func == manifest_mock_get_hash) {
		return "get_hash";
	}
	else if (func == manifest_mock_get_signature) {
		return "get_signature";
	}
	else if (func == manifest_mock_is_empty) {
		return "is_empty";
	}
	else {
		return "unknown";
	}
}

static const char* manifest_mock_arg_name_map (void *func, int arg)
{
	if (func == manifest_mock_verify) {
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
	else if (func == manifest_mock_get_id) {
		switch (arg) {
			case 0:
				return "id";
		}
	}
	else if (func == manifest_mock_get_platform_id) {
		switch (arg) {
			case 0:
				return "id";

			case 1:
				return "length";
		}
	}
	else if (func == manifest_mock_free_platform_id) {
		switch (arg) {
			case 0:
				return "id";
		}
	}
	else if (func == manifest_mock_get_hash) {
		switch (arg) {
			case 0:
				return "hash";

			case 1:
				return "hash_out";

			case 2:
				return "hash_length";
		}
	}
	else if (func == manifest_mock_get_signature) {
		switch (arg) {
			case 0:
				return "signature";

			case 1:
				return "length";
		}
	}

	return "unknown";
}

/**
 * Initialize a mock instance for a manifest.
 *
 * @param mock The mock to initialize.
 *
 * @return 0 if the mock was initialized successfully or an error code.
 */
int manifest_mock_init (struct manifest_mock *mock)
{
	int status;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	memset (mock, 0, sizeof (struct manifest_mock));

	status = mock_init (&mock->mock);
	if (status != 0) {
		return status;
	}

	mock_set_name (&mock->mock, "manifest");

	mock->base.verify = manifest_mock_verify;
	mock->base.get_id = manifest_mock_get_id;
	mock->base.get_platform_id = manifest_mock_get_platform_id;
	mock->base.free_platform_id = manifest_mock_free_platform_id;
	mock->base.get_hash = manifest_mock_get_hash;
	mock->base.get_signature = manifest_mock_get_signature;
	mock->base.is_empty = manifest_mock_is_empty;

	mock->mock.func_arg_count = manifest_mock_func_arg_count;
	mock->mock.func_name_map = manifest_mock_func_name_map;
	mock->mock.arg_name_map = manifest_mock_arg_name_map;

	return 0;
}

/**
 * Free the resources used by a PFM mock instance.
 *
 * @param mock The mock to release.
 */
void manifest_mock_release (struct manifest_mock *mock)
{
	if (mock != NULL) {
		mock_release (&mock->mock);
	}
}

/**
 * Validate the manifest mock instance was called as expected and release it.
 *
 * @param mock The mock instance to validate.
 *
 * @return 0 if the mock was called as expected or 1 if not.
 */
int manifest_mock_validate_and_release (struct manifest_mock *mock)
{
	int status = 1;

	if (mock != NULL) {
		status = mock_validate (&mock->mock);
		manifest_mock_release (mock);
	}

	return status;
}
