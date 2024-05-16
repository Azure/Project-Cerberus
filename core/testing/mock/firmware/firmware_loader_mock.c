// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "firmware_loader_mock.h"


static int firmware_loader_mock_is_address_valid (const struct firmware_loader *loader,
	uint64_t phy_addr, size_t length)
{
	struct firmware_loader_mock *mock = (struct firmware_loader_mock*) loader;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, firmware_loader_mock_is_address_valid, loader,
		MOCK_ARG_CALL (phy_addr), MOCK_ARG_CALL (length));
}

static int firmware_loader_mock_map_address (const struct firmware_loader *loader,
	uint64_t phy_addr, size_t length, void **virt_addr)
{
	struct firmware_loader_mock *mock = (struct firmware_loader_mock*) loader;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, firmware_loader_mock_map_address, loader, MOCK_ARG_CALL (phy_addr),
		MOCK_ARG_CALL (length), MOCK_ARG_PTR_CALL (virt_addr));
}

static void firmware_loader_mock_unmap_address (const struct firmware_loader *loader,
	void *virt_addr)
{
	struct firmware_loader_mock *mock = (struct firmware_loader_mock*) loader;

	if (mock == NULL) {
		return;
	}

	MOCK_VOID_RETURN (&mock->mock, firmware_loader_mock_unmap_address, loader,
		MOCK_ARG_PTR_CALL (virt_addr));
}

static int firmware_loader_mock_load_image (const struct firmware_loader *loader,
	const struct flash *flash, uint32_t src_addr, size_t length, uint8_t *dest_addr,
	const uint8_t *iv, size_t iv_length, struct hash_engine *hash, enum hash_type hash_algo,
	uint8_t *digest, size_t digest_length)
{
	struct firmware_loader_mock *mock = (struct firmware_loader_mock*) loader;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, firmware_loader_mock_load_image, loader, MOCK_ARG_PTR_CALL (flash),
		MOCK_ARG_CALL (src_addr), MOCK_ARG_CALL (length), MOCK_ARG_PTR_CALL (dest_addr),
		MOCK_ARG_PTR_CALL (iv), MOCK_ARG_CALL (iv_length), MOCK_ARG_PTR_CALL (hash),
		MOCK_ARG_CALL (hash_algo), MOCK_ARG_PTR_CALL (digest), MOCK_ARG_CALL (digest_length));
}

static int firmware_loader_mock_load_image_update_digest (const struct firmware_loader *loader,
	const struct flash *flash, uint32_t src_addr, size_t length, uint8_t *dest_addr,
	const uint8_t *iv, size_t iv_length, struct hash_engine *hash)
{
	struct firmware_loader_mock *mock = (struct firmware_loader_mock*) loader;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, firmware_loader_mock_load_image_update_digest, loader,
		MOCK_ARG_PTR_CALL (flash), MOCK_ARG_CALL (src_addr), MOCK_ARG_CALL (length),
		MOCK_ARG_PTR_CALL (dest_addr), MOCK_ARG_PTR_CALL (iv), MOCK_ARG_CALL (iv_length),
		MOCK_ARG_PTR_CALL (hash));
}

static int firmware_loader_mock_copy_image (const struct firmware_loader *loader,
	const uint8_t *src_addr, size_t length, uint8_t *dest_addr, const uint8_t *iv, size_t iv_length,
	struct hash_engine *hash, enum hash_type hash_algo, uint8_t *digest, size_t digest_length)
{
	struct firmware_loader_mock *mock = (struct firmware_loader_mock*) loader;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, firmware_loader_mock_copy_image, loader, MOCK_ARG_PTR_CALL (src_addr),
		MOCK_ARG_CALL (length), MOCK_ARG_PTR_CALL (dest_addr), MOCK_ARG_PTR_CALL (iv),
		MOCK_ARG_CALL (iv_length), MOCK_ARG_PTR_CALL (hash), MOCK_ARG_CALL (hash_algo),
		MOCK_ARG_PTR_CALL (digest), MOCK_ARG_CALL (digest_length));
}

static int firmware_loader_mock_copy_image_update_digest (const struct firmware_loader *loader,
	const uint8_t *src_addr, size_t length, uint8_t *dest_addr, const uint8_t *iv, size_t iv_length,
	struct hash_engine *hash)
{
	struct firmware_loader_mock *mock = (struct firmware_loader_mock*) loader;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, firmware_loader_mock_copy_image_update_digest, loader,
		MOCK_ARG_PTR_CALL (src_addr), MOCK_ARG_CALL (length), MOCK_ARG_PTR_CALL (dest_addr),
		MOCK_ARG_PTR_CALL (iv), MOCK_ARG_CALL (iv_length), MOCK_ARG_PTR_CALL (hash));
}

static int firmware_loader_mock_func_arg_count (void *func)
{
	if (func == firmware_loader_mock_load_image) {
		return 10;
	}
	else if (func == firmware_loader_mock_copy_image) {
		return 9;
	}
	else if (func == firmware_loader_mock_load_image_update_digest) {
		return 7;
	}
	else if (func == firmware_loader_mock_copy_image_update_digest) {
		return 6;
	}
	else if (func == firmware_loader_mock_map_address) {
		return 3;
	}
	else if (func == firmware_loader_mock_is_address_valid) {
		return 2;
	}
	else if (func == firmware_loader_mock_unmap_address) {
		return 1;
	}
	else {
		return 0;
	}
}

static const char* firmware_loader_mock_func_name_map (void *func)
{
	if (func == firmware_loader_mock_is_address_valid) {
		return "is_address_valid";
	}
	else if (func == firmware_loader_mock_map_address) {
		return "map_address";
	}
	else if (func == firmware_loader_mock_unmap_address) {
		return "unmap_address";
	}
	else if (func == firmware_loader_mock_load_image) {
		return "load_image";
	}
	else if (func == firmware_loader_mock_load_image_update_digest) {
		return "load_image_update_digest";
	}
	else if (func == firmware_loader_mock_copy_image) {
		return "copy_image";
	}
	else if (func == firmware_loader_mock_copy_image_update_digest) {
		return "copy_image_update_digest";
	}
	else {
		return "unknown";
	}
}

static const char* firmware_loader_mock_arg_name_map (void *func, int arg)
{
	if (func == firmware_loader_mock_is_address_valid) {
		switch (arg) {
			case 0:
				return "phy_addr";

			case 1:
				return "length";
		}
	}
	else if (func == firmware_loader_mock_map_address) {
		switch (arg) {
			case 0:
				return "phy_addr";

			case 1:
				return "length";

			case 2:
				return "virt_addr";
		}
	}
	else if (func == firmware_loader_mock_unmap_address) {
		switch (arg) {
			case 0:
				return "virt_addr";
		}
	}
	else if (func == firmware_loader_mock_load_image) {
		switch (arg) {
			case 0:
				return "flash";

			case 1:
				return "src_addr";

			case 2:
				return "length";

			case 3:
				return "dest_addr";

			case 4:
				return "iv";

			case 5:
				return "iv_length";

			case 6:
				return "hash";

			case 7:
				return "hash_algo";

			case 8:
				return "digest";

			case 9:
				return "digest_length";
		}
	}
	else if (func == firmware_loader_mock_load_image_update_digest) {
		switch (arg) {
			case 0:
				return "flash";

			case 1:
				return "src_addr";

			case 2:
				return "length";

			case 3:
				return "dest_addr";

			case 4:
				return "iv";

			case 5:
				return "iv_length";

			case 6:
				return "hash";
		}
	}
	else if (func == firmware_loader_mock_copy_image) {
		switch (arg) {
			case 0:
				return "src_addr";

			case 1:
				return "length";

			case 2:
				return "dest_addr";

			case 3:
				return "iv";

			case 4:
				return "iv_length";

			case 5:
				return "hash";

			case 6:
				return "hash_algo";

			case 7:
				return "digest";

			case 8:
				return "digest_length";
		}
	}
	else if (func == firmware_loader_mock_copy_image_update_digest) {
		switch (arg) {
			case 0:
				return "src_addr";

			case 1:
				return "length";

			case 2:
				return "dest_addr";

			case 3:
				return "iv";

			case 4:
				return "iv_length";

			case 5:
				return "hash";
		}
	}

	return "unknown";
}

/**
 * Initialize a mock instance for a handler to load firmware.
 *
 * @param mock The mock to initialize.
 *
 * @return 0 if the mock was successfully initialized or an error code.
 */
int firmware_loader_mock_init (struct firmware_loader_mock *mock)
{
	int status;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	memset (mock, 0, sizeof (struct firmware_loader_mock));

	status = mock_init (&mock->mock);
	if (status != 0) {
		return status;
	}

	mock_set_name (&mock->mock, "firmware_loader");

	mock->base.is_address_valid = firmware_loader_mock_is_address_valid;
	mock->base.map_address = firmware_loader_mock_map_address;
	mock->base.unmap_address = firmware_loader_mock_unmap_address;
	mock->base.load_image = firmware_loader_mock_load_image;
	mock->base.load_image_update_digest = firmware_loader_mock_load_image_update_digest;
	mock->base.copy_image = firmware_loader_mock_copy_image;
	mock->base.copy_image_update_digest = firmware_loader_mock_copy_image_update_digest;

	mock->mock.func_arg_count = firmware_loader_mock_func_arg_count;
	mock->mock.func_name_map = firmware_loader_mock_func_name_map;
	mock->mock.arg_name_map = firmware_loader_mock_arg_name_map;

	return 0;
}

/**
 * Release the resources used by the mock API.
 *
 * @param mock The mock to release.
 */
void firmware_loader_mock_release (struct firmware_loader_mock *mock)
{
	if (mock) {
		mock_release (&mock->mock);
	}
}

/**
 * Validate all mock expectations were called and release the mock instance.
 *
 * @param mock The mock to validate.
 *
 * @return 0 if the expectations were met or 1 if not.
 */
int firmware_loader_mock_validate_and_release (struct firmware_loader_mock *mock)
{
	int status = 1;

	if (mock != NULL) {
		status = mock_validate (&mock->mock);
		firmware_loader_mock_release (mock);
	}

	return status;
}
