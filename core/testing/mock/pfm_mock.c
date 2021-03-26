// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include "pfm_mock.h"


static int pfm_mock_verify (struct manifest *pfm, struct hash_engine *hash,
	struct signature_verification *verification, uint8_t *hash_out, size_t hash_length)
{
	struct pfm_mock *mock = (struct pfm_mock*) pfm;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, pfm_mock_verify, pfm, MOCK_ARG_CALL (hash),
		MOCK_ARG_CALL (verification), MOCK_ARG_CALL (hash_out), MOCK_ARG_CALL (hash_length));
}

static int pfm_mock_get_id (struct manifest *pfm, uint32_t *id)
{
	struct pfm_mock *mock = (struct pfm_mock*) pfm;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, pfm_mock_get_id, pfm, MOCK_ARG_CALL (id));
}

static int pfm_mock_get_platform_id (struct manifest *pfm, char **id, size_t length)
{
	struct pfm_mock *mock = (struct pfm_mock*) pfm;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, pfm_mock_get_platform_id, pfm, MOCK_ARG_CALL (id),
		MOCK_ARG_CALL (length));
}

static void pfm_mock_free_platform_id (struct manifest *pfm, char *id)
{
	struct pfm_mock *mock = (struct pfm_mock*) pfm;

	if (mock == NULL) {
		return;
	}

	MOCK_VOID_RETURN (&mock->mock, pfm_mock_free_platform_id, pfm, MOCK_ARG_CALL (id));
}

static int pfm_mock_get_hash (struct manifest *pfm, struct hash_engine *hash, uint8_t *hash_out,
	size_t hash_length)
{
	struct pfm_mock *mock = (struct pfm_mock*) pfm;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, pfm_mock_get_hash, pfm, MOCK_ARG_CALL (hash),
		MOCK_ARG_CALL (hash_out), MOCK_ARG_CALL (hash_length));
}

static int pfm_mock_get_signature (struct manifest *pfm, uint8_t *signature, size_t length)
{
	struct pfm_mock *mock = (struct pfm_mock*) pfm;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, pfm_mock_get_signature, pfm, MOCK_ARG_CALL (signature),
		MOCK_ARG_CALL (length));
}

static int pfm_mock_is_empty (struct manifest *pfm)
{
	struct pfm_mock *mock = (struct pfm_mock*) pfm;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN_NO_ARGS (&mock->mock, pfm_mock_is_empty, pfm);
}

static int pfm_mock_get_firmware (struct pfm *pfm, struct pfm_firmware *fw)
{
	struct pfm_mock *mock = (struct pfm_mock*) pfm;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, pfm_mock_get_firmware, pfm, MOCK_ARG_CALL (fw));
}

static void pfm_mock_free_firmware (struct pfm *pfm, struct pfm_firmware *fw)
{
	struct pfm_mock *mock = (struct pfm_mock*) pfm;

	if (mock == NULL) {
		return;
	}

	MOCK_VOID_RETURN (&mock->mock, pfm_mock_free_firmware, pfm, MOCK_ARG_CALL (fw));
}

static int pfm_mock_get_supported_versions (struct pfm *pfm, const char *fw,
	struct pfm_firmware_versions *ver_list)
{
	struct pfm_mock *mock = (struct pfm_mock*) pfm;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, pfm_mock_get_supported_versions, pfm, MOCK_ARG_CALL (fw),
		MOCK_ARG_CALL (ver_list));
}

static void pfm_mock_free_fw_versions (struct pfm *pfm, struct pfm_firmware_versions *ver_list)
{
	struct pfm_mock *mock = (struct pfm_mock*) pfm;

	if (mock == NULL) {
		return;
	}

	MOCK_VOID_RETURN (&mock->mock, pfm_mock_free_fw_versions, pfm, MOCK_ARG_CALL (ver_list));
}

static int pfm_mock_buffer_supported_versions (struct pfm *pfm, const char *fw, size_t offset,
	size_t length, uint8_t *ver_list)
{
	struct pfm_mock *mock = (struct pfm_mock*) pfm;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, pfm_mock_buffer_supported_versions, pfm, MOCK_ARG_CALL (fw),
		MOCK_ARG_CALL (offset), MOCK_ARG_CALL (length), MOCK_ARG_CALL (ver_list));
}

static int pfm_mock_get_read_write_regions (struct pfm *pfm, const char *fw, const char *version,
	struct pfm_read_write_regions *writable)
{
	struct pfm_mock *mock = (struct pfm_mock*) pfm;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, pfm_mock_get_read_write_regions, pfm, MOCK_ARG_CALL (fw),
		MOCK_ARG_CALL (version), MOCK_ARG_CALL (writable));
}

static void pfm_mock_free_read_write_regions (struct pfm *pfm,
	struct pfm_read_write_regions *writable)
{
	struct pfm_mock *mock = (struct pfm_mock*) pfm;

	if (mock == NULL) {
		return;
	}

	MOCK_VOID_RETURN (&mock->mock, pfm_mock_free_read_write_regions, pfm, MOCK_ARG_CALL (writable));
}

static int pfm_mock_get_firmware_images (struct pfm *pfm, const char *fw, const char *version,
	struct pfm_image_list *img_list)
{
	struct pfm_mock *mock = (struct pfm_mock*) pfm;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, pfm_mock_get_firmware_images, pfm, MOCK_ARG_CALL (fw),
		MOCK_ARG_CALL (version), MOCK_ARG_CALL (img_list));
}

static void pfm_mock_free_firmware_images (struct pfm *pfm, struct pfm_image_list *img_list)
{
	struct pfm_mock *mock = (struct pfm_mock*) pfm;

	if (mock == NULL) {
		return;
	}

	MOCK_VOID_RETURN (&mock->mock, pfm_mock_free_firmware_images, pfm, MOCK_ARG_CALL (img_list));
}

static int pfm_mock_func_arg_count (void *func)
{
	if ((func == pfm_mock_verify) || (func == pfm_mock_buffer_supported_versions)) {
		return 4;
	}
	else if ((func == pfm_mock_get_hash) || (func == pfm_mock_get_read_write_regions) ||
		(func == pfm_mock_get_firmware_images)) {
		return 3;
	}
	else if ((func == pfm_mock_get_platform_id) || (func == pfm_mock_get_signature) ||
		(func == pfm_mock_get_supported_versions)) {
		return 2;
	}
	else if ((func == pfm_mock_get_id) || (func == pfm_mock_free_platform_id) ||
		(func == pfm_mock_get_firmware) || (func == pfm_mock_free_firmware) ||
		(func == pfm_mock_free_fw_versions) || (func == pfm_mock_free_read_write_regions) ||
		(func == pfm_mock_free_firmware_images)) {
		return 1;
	}
	else {
		return 0;
	}
}

static const char* pfm_mock_func_name_map (void *func)
{
	if (func == pfm_mock_verify) {
		return "verify";
	}
	else if (func == pfm_mock_get_id) {
		return "get_id";
	}
	else if (func == pfm_mock_get_platform_id) {
		return "get_platform_id";
	}
	else if (func == pfm_mock_free_platform_id) {
		return "free_platform_id";
	}
	else if (func == pfm_mock_get_hash) {
		return "get_hash";
	}
	else if (func == pfm_mock_get_signature) {
		return "get_signature";
	}
	else if (func == pfm_mock_is_empty) {
		return "is_empty";
	}
	else if (func == pfm_mock_get_firmware) {
		return "get_firmware";
	}
	else if (func == pfm_mock_free_firmware) {
		return "free_firmware";
	}
	else if (func == pfm_mock_get_supported_versions) {
		return "get_supported_versions";
	}
	else if (func == pfm_mock_free_fw_versions) {
		return "free_fw_versions";
	}
	else if (func == pfm_mock_buffer_supported_versions) {
		return "buffer_supported_versions";
	}
	else if (func == pfm_mock_get_read_write_regions) {
		return "get_read_write_regions";
	}
	else if (func == pfm_mock_free_read_write_regions) {
		return "free_read_write_regions";
	}
	else if (func == pfm_mock_get_firmware_images) {
		return "get_firmware_images";
	}
	else if (func == pfm_mock_free_firmware_images) {
		return "free_firmware_images";
	}
	else {
		return "unknown";
	}
}

static const char* pfm_mock_arg_name_map (void *func, int arg)
{
	if (func == pfm_mock_verify) {
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
	else if (func == pfm_mock_get_id) {
		switch (arg) {
			case 0:
				return "id";
		}
	}
	else if (func == pfm_mock_get_platform_id) {
		switch (arg) {
			case 0:
				return "id";

			case 1:
				return "length";
		}
	}
	else if (func == pfm_mock_free_platform_id) {
		switch (arg) {
			case 0:
				return "id";
		}
	}
	else if (func == pfm_mock_get_hash) {
		switch (arg) {
			case 0:
				return "hash";

			case 1:
				return "hash_out";

			case 2:
				return "hash_length";
		}
	}
	else if (func == pfm_mock_get_signature) {
		switch (arg) {
			case 0:
				return "signature";

			case 1:
				return "length";
		}
	}
	else if (func == pfm_mock_get_firmware) {
		switch (arg) {
			case 0:
				return "fw";
		}
	}
	else if (func == pfm_mock_free_firmware) {
		switch (arg) {
			case 0:
				return "fw";
		}
	}
	else if (func == pfm_mock_get_supported_versions) {
		switch (arg) {
			case 0:
				return "fw";

			case 1:
				return "ver_list";
		}
	}
	else if (func == pfm_mock_free_fw_versions) {
		switch (arg) {
			case 0:
				return "ver_list";
		}
	}
	else if (func == pfm_mock_buffer_supported_versions) {
		switch (arg) {
			case 0:
				return "fw";

			case 1:
				return "offset";

			case 2:
				return "length";

			case 3:
				return "ver_list";
		}
	}
	else if (func == pfm_mock_get_read_write_regions) {
		switch (arg) {
			case 0:
				return "fw";

			case 1:
				return "version";

			case 2:
				return "writable";
		}
	}
	else if (func == pfm_mock_free_read_write_regions) {
		switch (arg) {
			case 0:
				return "writable";
		}
	}
	else if (func == pfm_mock_get_firmware_images) {
		switch (arg) {
			case 0:
				return "fw";

			case 1:
				return "version";

			case 2:
				return "img_list";
		}
	}
	else if (func == pfm_mock_free_firmware_images) {
		switch (arg) {
			case 0:
				return "img_list";
		}
	}

	return "unknown";
}

/**
 * Initialize a mock instance for a PFM.
 *
 * @param mock The mock to initialize.
 *
 * @return 0 if the mock was initialized successfully or an error code.
 */
int pfm_mock_init (struct pfm_mock *mock)
{
	int status;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	memset (mock, 0, sizeof (struct pfm_mock));

	status = mock_init (&mock->mock);
	if (status != 0) {
		return status;
	}

	mock_set_name (&mock->mock, "pfm");

	mock->base.base.verify = pfm_mock_verify;
	mock->base.base.get_id = pfm_mock_get_id;
	mock->base.base.get_platform_id = pfm_mock_get_platform_id;
	mock->base.base.free_platform_id = pfm_mock_free_platform_id;
	mock->base.base.get_hash = pfm_mock_get_hash;
	mock->base.base.get_signature = pfm_mock_get_signature;
	mock->base.base.is_empty = pfm_mock_is_empty;

	mock->base.get_firmware = pfm_mock_get_firmware;
	mock->base.free_firmware = pfm_mock_free_firmware;
	mock->base.get_supported_versions = pfm_mock_get_supported_versions;
	mock->base.free_fw_versions = pfm_mock_free_fw_versions;
	mock->base.buffer_supported_versions = pfm_mock_buffer_supported_versions;
	mock->base.get_read_write_regions = pfm_mock_get_read_write_regions;
	mock->base.free_read_write_regions = pfm_mock_free_read_write_regions;
	mock->base.get_firmware_images = pfm_mock_get_firmware_images;
	mock->base.free_firmware_images = pfm_mock_free_firmware_images;

	mock->mock.func_arg_count = pfm_mock_func_arg_count;
	mock->mock.func_name_map = pfm_mock_func_name_map;
	mock->mock.arg_name_map = pfm_mock_arg_name_map;

	return 0;
}

/**
 * Free the resources used by a PFM mock instance.
 *
 * @param mock The mock to release.
 */
void pfm_mock_release (struct pfm_mock *mock)
{
	if (mock != NULL) {
		mock_release (&mock->mock);
	}
}

/**
 * Validate the PFM mock instance was called as expected and release it.
 *
 * @param mock The mock instance to validate.
 *
 * @return 0 if the mock was called as expected or 1 if not.
 */
int pfm_mock_validate_and_release (struct pfm_mock *mock)
{
	int status = 1;

	if (mock != NULL) {
		status = mock_validate (&mock->mock);
		pfm_mock_release (mock);
	}

	return status;
}
