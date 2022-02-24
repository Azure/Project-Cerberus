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

static int cfm_mock_get_component_pmr (struct cfm *cfm, const char *component_type, uint8_t pmr_id,
	struct cfm_pmr *pmr)
{
	struct cfm_mock *mock = (struct cfm_mock*) cfm;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, cfm_mock_get_component_pmr, cfm, MOCK_ARG_CALL (component_type),
		MOCK_ARG_CALL (pmr_id), MOCK_ARG_CALL (pmr));
}

static int cfm_mock_get_component_pmr_digest (struct cfm *cfm, const char *component_type,
	uint8_t pmr_id, struct cfm_pmr_digest *pmr_digest)
{
	struct cfm_mock *mock = (struct cfm_mock*) cfm;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, cfm_mock_get_component_pmr_digest, cfm,
		MOCK_ARG_CALL (component_type), MOCK_ARG_CALL (pmr_id), MOCK_ARG_CALL (pmr_digest));
}

static void cfm_mock_free_component_pmr_digest (struct cfm *cfm, struct cfm_pmr_digest *pmr_digest)
{
	struct cfm_mock *mock = (struct cfm_mock*) cfm;

	if (mock == NULL) {
		return;
	}

	MOCK_VOID_RETURN (&mock->mock, cfm_mock_free_component_pmr_digest, cfm,
		MOCK_ARG_CALL (pmr_digest));
}

static int cfm_mock_buffer_supported_components (struct cfm *cfm, size_t offset, size_t length,
	uint8_t *components)
{
	struct cfm_mock *mock = (struct cfm_mock*) cfm;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, cfm_mock_buffer_supported_components, cfm, MOCK_ARG_CALL (offset),
		MOCK_ARG_CALL (length), MOCK_ARG_CALL (components));
}

static int cfm_mock_get_component_device (struct cfm *cfm, const char *component_type,
	struct cfm_component_device *component)
{
	struct cfm_mock *mock = (struct cfm_mock*) cfm;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, cfm_mock_get_component_device, cfm, MOCK_ARG_CALL (component_type),
		MOCK_ARG_CALL (component));
}

static void cfm_mock_free_component_device (struct cfm *cfm, struct cfm_component_device *component)
{
	struct cfm_mock *mock = (struct cfm_mock*) cfm;

	if (mock == NULL) {
		return;
	}

	MOCK_VOID_RETURN (&mock->mock, cfm_mock_free_component_device, cfm, MOCK_ARG_CALL (component));
}

static int cfm_mock_get_next_measurement (struct cfm *cfm, const char *component_type,
	struct cfm_measurement *pmr_measurement, bool first)
{
	struct cfm_mock *mock = (struct cfm_mock*) cfm;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, cfm_mock_get_next_measurement, cfm, MOCK_ARG_CALL (component_type),
		MOCK_ARG_CALL (pmr_measurement), MOCK_ARG_CALL (first));
}

static void cfm_mock_free_measurement (struct cfm *cfm, struct cfm_measurement *pmr_measurement)
{
	struct cfm_mock *mock = (struct cfm_mock*) cfm;

	if (mock == NULL) {
		return;
	}

	MOCK_VOID_RETURN (&mock->mock, cfm_mock_free_measurement, cfm, MOCK_ARG_CALL (pmr_measurement));
}

static int cfm_mock_get_next_measurement_data (struct cfm *cfm, const char *component_type,
	struct cfm_measurement_data *measurement_data,	bool first)
{
	struct cfm_mock *mock = (struct cfm_mock*) cfm;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, cfm_mock_get_next_measurement_data, cfm,
		MOCK_ARG_CALL (component_type), MOCK_ARG_CALL (measurement_data), MOCK_ARG_CALL (first));
}

static void cfm_mock_free_measurement_data (struct cfm *cfm,
	struct cfm_measurement_data *measurement_data)
{
	struct cfm_mock *mock = (struct cfm_mock*) cfm;

	if (mock == NULL) {
		return;
	}

	MOCK_VOID_RETURN (&mock->mock, cfm_mock_free_measurement_data, cfm,
		MOCK_ARG_CALL (measurement_data));
}

static int cfm_mock_get_root_ca_digest (struct cfm *cfm, const char *component_type,
	struct cfm_root_ca_digests *root_ca_digest)
{
	struct cfm_mock *mock = (struct cfm_mock*) cfm;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, cfm_mock_get_root_ca_digest, cfm, MOCK_ARG_CALL (component_type),
		MOCK_ARG_CALL (root_ca_digest));
}

static void cfm_mock_free_root_ca_digest (struct cfm *cfm,
	struct cfm_root_ca_digests *root_ca_digest)
{
	struct cfm_mock *mock = (struct cfm_mock*) cfm;

	if (mock == NULL) {
		return;
	}

	MOCK_VOID_RETURN (&mock->mock, cfm_mock_free_root_ca_digest, cfm,
		MOCK_ARG_CALL (root_ca_digest));
}

static int cfm_mock_get_next_pfm (struct cfm *cfm, const char *component_type,
	struct cfm_manifest *allowable_pfm, bool first)
{
	struct cfm_mock *mock = (struct cfm_mock*) cfm;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, cfm_mock_get_next_pfm, cfm, MOCK_ARG_CALL (component_type),
		MOCK_ARG_CALL (allowable_pfm), MOCK_ARG_CALL (first));
}

static int cfm_mock_get_next_cfm (struct cfm *cfm, const char *component_type,
	struct cfm_manifest *allowable_cfm, bool first)
{
	struct cfm_mock *mock = (struct cfm_mock*) cfm;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, cfm_mock_get_next_cfm, cfm, MOCK_ARG_CALL (component_type),
		MOCK_ARG_CALL (allowable_cfm), MOCK_ARG_CALL (first));
}

static int cfm_mock_get_pcd (struct cfm *cfm, const char *component_type,
	struct cfm_manifest *allowable_pcd)
{
	struct cfm_mock *mock = (struct cfm_mock*) cfm;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, cfm_mock_get_pcd, cfm, MOCK_ARG_CALL (component_type),
		MOCK_ARG_CALL (allowable_pcd));
}

static void cfm_mock_free_manifest (struct cfm *cfm, struct cfm_manifest *manifest)
{
	struct cfm_mock *mock = (struct cfm_mock*) cfm;

	if (mock == NULL) {
		return;
	}

	MOCK_VOID_RETURN (&mock->mock, cfm_mock_free_manifest, cfm, MOCK_ARG_CALL (manifest));
}

static int cfm_mock_func_arg_count (void *func)
{
	if (func == cfm_mock_verify) {
		return 4;
	}
	else if ((func == cfm_mock_get_hash) || (func == cfm_mock_buffer_supported_components) ||
		(func == cfm_mock_get_component_pmr) || (func == cfm_mock_get_component_pmr_digest) ||
		(func == cfm_mock_get_next_measurement) || (func == cfm_mock_get_next_measurement_data) ||
		(func == cfm_mock_get_next_pfm) || (func == cfm_mock_get_next_cfm)) {
		return 3;
	}
	else if ((func == cfm_mock_get_platform_id) || (func == cfm_mock_get_signature) ||
		(func == cfm_mock_get_component_device) || (func == cfm_mock_get_root_ca_digest) ||
		(func == cfm_mock_get_pcd)) {
		return 2;
	}
	else if ((func == cfm_mock_get_id) || (func == cfm_mock_free_platform_id) ||
		(func == cfm_mock_free_component_device) || (func == cfm_mock_free_component_pmr_digest) ||
		(func == cfm_mock_free_measurement) || (func == cfm_mock_free_measurement_data) ||
		(func == cfm_mock_free_root_ca_digest) || (func == cfm_mock_free_manifest)) {
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
	else if (func == cfm_mock_get_component_pmr) {
		return "get_component_pmr";
	}
	else if (func == cfm_mock_get_component_pmr_digest) {
		return "get_component_pmr_digest";
	}
	else if (func == cfm_mock_free_component_pmr_digest) {
		return "free_component_pmr_digest";
	}
	else if (func == cfm_mock_buffer_supported_components) {
		return "buffer_supported_components";
	}
	else if (func == cfm_mock_get_component_device) {
		return "get_component_device";
	}
	else if (func == cfm_mock_free_component_device) {
		return "free_component_device";
	}
	else if (func == cfm_mock_get_next_measurement) {
		return "get_next_measurement";
	}
	else if (func == cfm_mock_free_measurement) {
		return "free_measurement";
	}
	else if (func == cfm_mock_get_next_measurement_data) {
		return "get_next_measurement_data";
	}
	else if (func == cfm_mock_free_measurement_data) {
		return "free_measurement_data";
	}
	else if (func == cfm_mock_get_root_ca_digest) {
		return "get_root_ca_digest";
	}
	else if (func == cfm_mock_free_root_ca_digest) {
		return "free_root_ca_digest";
	}
	else if (func == cfm_mock_get_next_pfm) {
		return "get_next_pfm";
	}
	else if (func == cfm_mock_get_next_cfm) {
		return "get_next_cfm";
	}
	else if (func == cfm_mock_get_pcd) {
		return "get_pcd";
	}
	else if (func == cfm_mock_free_manifest) {
		return "free_manifest";
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
	else if (func == cfm_mock_get_component_pmr) {
		switch (arg) {
			case 0:
				return "component_type";

			case 1:
				return "pmr_id";

			case 2:
				return "pmr";
		}
	}
	else if (func == cfm_mock_get_component_pmr_digest) {
		switch (arg) {
			case 0:
				return "component_type";

			case 1:
				return "pmr_id";

			case 2:
				return "pmr_digest";
		}
	}
	else if (func == cfm_mock_free_component_pmr_digest) {
		switch (arg) {
			case 0:
				return "pmr_digest";
		}
	}
	else if (func == cfm_mock_buffer_supported_components) {
		switch (arg) {
			case 0:
				return "components";

			case 1:
				return "components_len";

			case 2:
				return "offset";
		}
	}
	else if (func == cfm_mock_get_component_device) {
		switch (arg) {
			case 0:
				return "component_type";

			case 1:
				return "component";
		}
	}
	else if (func == cfm_mock_free_component_device) {
		switch (arg) {
			case 0:
				return "component";
		}
	}
	else if (func == cfm_mock_get_next_measurement) {
		switch (arg) {
			case 0:
				return "component_type";

			case 1:
				return "pmr_measurement";

			case 2:
				return "first";
		}
	}
	else if (func == cfm_mock_free_measurement) {
		switch (arg) {
			case 0:
				return "pmr_measurement";
		}
	}
	else if (func == cfm_mock_get_next_measurement_data) {
		switch (arg) {
			case 0:
				return "component_type";

			case 1:
				return "measurement_data";

			case 2:
				return "first";
		}
	}
	else if (func == cfm_mock_free_measurement_data) {
		switch (arg) {
			case 0:
				return "measurement_data";
		}
	}
	else if (func == cfm_mock_get_root_ca_digest) {
		switch (arg) {
			case 0:
				return "component_type";

			case 1:
				return "root_ca_digest";
		}
	}
	else if (func == cfm_mock_free_root_ca_digest) {
		switch (arg) {
			case 0:
				return "root_ca_digest";
		}
	}
	else if (func == cfm_mock_get_next_pfm) {
		switch (arg) {
			case 0:
				return "component_type";

			case 1:
				return "allowable_pfm";

			case 2:
				return "first";
		}
	}
	else if (func == cfm_mock_get_next_cfm) {
		switch (arg) {
			case 0:
				return "component_type";

			case 1:
				return "allowable_cfm";

			case 2:
				return "first";
		}
	}
	else if (func == cfm_mock_get_pcd) {
		switch (arg) {
			case 0:
				return "component_type";

			case 1:
				return "allowable_pcd";
		}
	}
	else if (func == cfm_mock_free_manifest) {
		switch (arg) {
			case 0:
				return "manifest";
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

	mock->base.buffer_supported_components = cfm_mock_buffer_supported_components;
	mock->base.get_component_device = cfm_mock_get_component_device;
	mock->base.free_component_device = cfm_mock_free_component_device;
	mock->base.get_component_pmr = cfm_mock_get_component_pmr;
	mock->base.get_component_pmr_digest = cfm_mock_get_component_pmr_digest;
	mock->base.free_component_pmr_digest = cfm_mock_free_component_pmr_digest;
	mock->base.get_next_measurement = cfm_mock_get_next_measurement;
	mock->base.free_measurement = cfm_mock_free_measurement;
	mock->base.get_next_measurement_data = cfm_mock_get_next_measurement_data;
	mock->base.free_measurement_data = cfm_mock_free_measurement_data;
	mock->base.get_root_ca_digest = cfm_mock_get_root_ca_digest;
	mock->base.free_root_ca_digest = cfm_mock_free_root_ca_digest;
	mock->base.get_next_pfm = cfm_mock_get_next_pfm;
	mock->base.get_next_cfm = cfm_mock_get_next_cfm;
	mock->base.get_pcd = cfm_mock_get_pcd;
	mock->base.free_manifest = cfm_mock_free_manifest;

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
