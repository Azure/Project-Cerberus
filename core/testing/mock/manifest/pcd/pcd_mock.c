// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "pcd_mock.h"


static int pcd_mock_verify (const struct manifest *pcd, const struct hash_engine *hash,
	const struct signature_verification *verification, uint8_t *hash_out, size_t hash_length)
{
	struct pcd_mock *mock = (struct pcd_mock*) pcd;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, pcd_mock_verify, pcd, MOCK_ARG_PTR_CALL (hash),
		MOCK_ARG_PTR_CALL (verification), MOCK_ARG_PTR_CALL (hash_out),
		MOCK_ARG_CALL (hash_length));
}

static int pcd_mock_get_id (const struct manifest *pcd, uint32_t *id)
{
	struct pcd_mock *mock = (struct pcd_mock*) pcd;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, pcd_mock_get_id, pcd, MOCK_ARG_PTR_CALL (id));
}

static int pcd_mock_get_platform_id (const struct manifest *pcd, char **id, size_t length)
{
	struct pcd_mock *mock = (struct pcd_mock*) pcd;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, pcd_mock_get_platform_id, pcd, MOCK_ARG_PTR_CALL (id),
		MOCK_ARG_CALL (length));
}

static void pcd_mock_free_platform_id (const struct manifest *pcd, char *id)
{
	struct pcd_mock *mock = (struct pcd_mock*) pcd;

	if (mock == NULL) {
		return;
	}

	MOCK_VOID_RETURN (&mock->mock, pcd_mock_free_platform_id, pcd, MOCK_ARG_PTR_CALL (id));
}

static int pcd_mock_get_hash (const struct manifest *pcd, const struct hash_engine *hash,
	uint8_t *hash_out, size_t hash_length)
{
	struct pcd_mock *mock = (struct pcd_mock*) pcd;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, pcd_mock_get_hash, pcd, MOCK_ARG_PTR_CALL (hash),
		MOCK_ARG_PTR_CALL (hash_out), MOCK_ARG_CALL (hash_length));
}

static int pcd_mock_get_signature (const struct manifest *pcd, uint8_t *signature, size_t length)
{
	struct pcd_mock *mock = (struct pcd_mock*) pcd;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, pcd_mock_get_signature, pcd, MOCK_ARG_PTR_CALL (signature),
		MOCK_ARG_CALL (length));
}

static int pcd_mock_is_empty (const struct manifest *pcd)
{
	struct pcd_mock *mock = (struct pcd_mock*) pcd;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN_NO_ARGS (&mock->mock, pcd_mock_is_empty, pcd);
}

static int pcd_mock_buffer_supported_components (const struct pcd *pcd, size_t offset,
	size_t length, uint8_t *components)
{
	struct pcd_mock *mock = (struct pcd_mock*) pcd;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, pcd_mock_buffer_supported_components, pcd, MOCK_ARG_CALL (offset),
		MOCK_ARG_CALL (length), MOCK_ARG_PTR_CALL (components));
}

static int pcd_mock_get_rot_info (const struct pcd *pcd, struct pcd_rot_info *info)
{
	struct pcd_mock *mock = (struct pcd_mock*) pcd;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, pcd_mock_get_rot_info, pcd, MOCK_ARG_PTR_CALL (info));
}

static int pcd_mock_get_port_info (const struct pcd *pcd, uint8_t port_id,
	struct pcd_port_info *info)
{
	struct pcd_mock *mock = (struct pcd_mock*) pcd;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, pcd_mock_get_port_info, pcd, MOCK_ARG_CALL (port_id),
		MOCK_ARG_PTR_CALL (info));
}

static int pcd_mock_get_power_controller_info (const struct pcd *pcd,
	struct pcd_power_controller_info *info)
{
	struct pcd_mock *mock = (struct pcd_mock*) pcd;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, pcd_mock_get_power_controller_info, pcd, MOCK_ARG_PTR_CALL (info));
}

static int pcd_mock_get_next_component (const struct pcd *pcd, struct pcd_component_info *component,
	bool first)
{
	struct pcd_mock *mock = (struct pcd_mock*) pcd;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, pcd_mock_get_next_component, pcd,	MOCK_ARG_PTR_CALL (component),
		MOCK_ARG_CALL (first));
}

static void pcd_mock_free_component (const struct pcd *pcd, struct pcd_component_info *component)
{
	struct pcd_mock *mock = (struct pcd_mock*) pcd;

	if (mock == NULL) {
		return;
	}

	MOCK_VOID_RETURN (&mock->mock, pcd_mock_free_component, pcd, MOCK_ARG_PTR_CALL (component));
}

// *INDENT-OFF*
MOCK_FUNCTION_TABLE_BEGIN (pcd, 4)
    MOCK_FUNCTION (pcd, verify, 4,
        MOCK_FUNCTION_ARGS ("hash", "verification", "hash_out", "hash_length"))
    MOCK_FUNCTION (pcd, get_id, 1, MOCK_FUNCTION_ARGS ("id"))
    MOCK_FUNCTION (pcd, get_platform_id, 2, MOCK_FUNCTION_ARGS ("id", "length"))
    MOCK_FUNCTION (pcd, free_platform_id, 1, MOCK_FUNCTION_ARGS ("id"))
    MOCK_FUNCTION (pcd, get_hash, 3, MOCK_FUNCTION_ARGS ("hash", "hash_out", "hash_length"))
    MOCK_FUNCTION (pcd, get_signature, 2, MOCK_FUNCTION_ARGS ("signature", "length"))
    MOCK_FUNCTION (pcd, is_empty, 0, MOCK_FUNCTION_ARGS ())
    MOCK_FUNCTION (pcd, buffer_supported_components, 3, 
		MOCK_FUNCTION_ARGS ("offset", "length", "components"))
    MOCK_FUNCTION (pcd, get_rot_info, 1, MOCK_FUNCTION_ARGS ("info"))
    MOCK_FUNCTION (pcd, get_port_info, 2, MOCK_FUNCTION_ARGS ("port_id", "info"))
    MOCK_FUNCTION (pcd, get_power_controller_info, 1, MOCK_FUNCTION_ARGS ("info"))
    MOCK_FUNCTION (pcd, get_next_component, 2, MOCK_FUNCTION_ARGS ("component", "first"))
	MOCK_FUNCTION (pcd, free_component, 2, MOCK_FUNCTION_ARGS ("component"))
MOCK_FUNCTION_TABLE_END (pcd)
// *INDENT-ON*


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

	mock->base.buffer_supported_components = pcd_mock_buffer_supported_components;
	mock->base.get_rot_info = pcd_mock_get_rot_info;
	mock->base.get_port_info = pcd_mock_get_port_info;
	mock->base.get_power_controller_info = pcd_mock_get_power_controller_info;
	mock->base.get_next_component = pcd_mock_get_next_component;
	mock->base.free_component = pcd_mock_free_component;

	MOCK_INTERFACE_INIT (mock->mock, pcd);

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
