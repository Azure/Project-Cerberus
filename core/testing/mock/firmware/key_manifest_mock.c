// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "key_manifest_mock.h"


static int key_manifest_mock_verify (const struct key_manifest *manifest, struct hash_engine *hash)
{
	struct key_manifest_mock *mock = (struct key_manifest_mock*) manifest;

	if ((mock == NULL) || (hash == NULL)) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, key_manifest_mock_verify, manifest, MOCK_ARG_CALL (hash));
}

static int key_manifest_mock_is_allowed (const struct key_manifest *manifest)
{
	struct key_manifest_mock *mock = (struct key_manifest_mock*) manifest;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN_NO_ARGS (&mock->mock, key_manifest_mock_is_allowed, manifest);
}

static int key_manifest_mock_revokes_old_manifest (const struct key_manifest *manifest)
{
	struct key_manifest_mock *mock = (struct key_manifest_mock*) manifest;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN_NO_ARGS (&mock->mock, key_manifest_mock_revokes_old_manifest, manifest);
}

static int key_manifest_mock_update_revocation (const struct key_manifest *manifest)
{
	struct key_manifest_mock *mock = (struct key_manifest_mock*) manifest;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN_NO_ARGS (&mock->mock, key_manifest_mock_update_revocation, manifest);
}

static const struct key_manifest_public_key* key_manifest_mock_get_root_key (
	const struct key_manifest *manifest)
{
	struct key_manifest_mock *mock = (struct key_manifest_mock*) manifest;

	if (mock == NULL) {
		return NULL;
	}

	MOCK_RETURN_NO_ARGS_CAST (&mock->mock, struct key_manifest_public_key*,
		key_manifest_mock_get_root_key, manifest);
}

static const struct key_manifest_public_key* key_manifest_mock_get_app_key (
	const struct key_manifest *manifest)
{
	struct key_manifest_mock *mock = (struct key_manifest_mock*) manifest;

	if (mock == NULL) {
		return NULL;
	}

	MOCK_RETURN_NO_ARGS_CAST (&mock->mock, struct key_manifest_public_key*,
		key_manifest_mock_get_app_key, manifest);
}

static const struct key_manifest_public_key* key_manifest_mock_get_manifest_key (
	const struct key_manifest *manifest)
{
	struct key_manifest_mock *mock = (struct key_manifest_mock*) manifest;

	if (mock == NULL) {
		return NULL;
	}

	MOCK_RETURN_NO_ARGS_CAST (&mock->mock, struct key_manifest_public_key*,
		key_manifest_mock_get_manifest_key, manifest);
}

static int key_manifest_mock_func_arg_count (void *func)
{
	if (func == key_manifest_mock_verify) {
		return 1;
	}
	else {
		return 0;
	}
}

static const char* key_manifest_mock_func_name_map (void *func)
{
	if (func == key_manifest_mock_verify) {
		return "verify";
	}
	else if (func == key_manifest_mock_is_allowed) {
		return "is_allowed";
	}
	else if (func == key_manifest_mock_revokes_old_manifest) {
		return "revokes_old_manifest";
	}
	else if (func == key_manifest_mock_update_revocation) {
		return "update_revocation";
	}
	else if (func == key_manifest_mock_get_root_key) {
		return "get_root_key";
	}
	else if (func == key_manifest_mock_get_app_key) {
		return "get_app_key";
	}
	else if (func == key_manifest_mock_get_manifest_key) {
		return "get_manifest_key";
	}
	else {
		return "unknown";
	}
}

static const char* key_manifest_mock_arg_name_map (void *func, int arg)
{
	if (func == key_manifest_mock_verify) {
		switch (arg) {
			case 0:
				return "hash";
		}
	}

	return "unknown";
}

/**
 * Initialize the key manifest mock instance.
 *
 * @param mock The mock instance to initialize.
 *
 * @return 0 if the mock instance was successfully initialized or an error code.
 */
int key_manifest_mock_init (struct key_manifest_mock *mock)
{
	int status;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	memset (mock, 0, sizeof (struct key_manifest));

	status = mock_init (&mock->mock);
	if (status != 0) {
		return status;
	}

	mock_set_name (&mock->mock, "key_manifest");

	mock->base.verify = key_manifest_mock_verify;
	mock->base.is_allowed = key_manifest_mock_is_allowed;
	mock->base.revokes_old_manifest = key_manifest_mock_revokes_old_manifest;
	mock->base.update_revocation = key_manifest_mock_update_revocation;
	mock->base.get_root_key = key_manifest_mock_get_root_key;
	mock->base.get_app_key = key_manifest_mock_get_app_key;
	mock->base.get_manifest_key = key_manifest_mock_get_manifest_key;

	mock->mock.func_arg_count = key_manifest_mock_func_arg_count;
	mock->mock.func_name_map = key_manifest_mock_func_name_map;
	mock->mock.arg_name_map = key_manifest_mock_arg_name_map;

	return 0;
}

/**
 * Release the resources used by a key manifest mock.
 *
 * @param mock The mock to release.
 */
void key_manifest_mock_release (struct key_manifest_mock *mock)
{
	if (mock != NULL) {
		mock_release (&mock->mock);
	}
}

/**
 * Verify the expected functions were executed by the mock and release it.
 *
 * @param mock The mock instance to verify.
 *
 * @return 0 if the mock was executed as expected or 1 if not.
 */
int key_manifest_mock_validate_and_release (struct key_manifest_mock *mock)
{
	int status = 1;

	if (mock != NULL) {
		status = mock_validate (&mock->mock);
		key_manifest_mock_release (mock);
	}

	return status;
}
