// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef MANIFEST_FLASH_V2_TESTING_H_
#define MANIFEST_FLASH_V2_TESTING_H_

#include <stdint.h>
#include <stddef.h>
#include "manifest/manifest_flash.h"
#include "testing/mock/crypto/signature_verification_mock.h"
#include "testing/mock/crypto/hash_mock.h"
#include "testing/mock/flash/flash_mock.h"
#include "testing/engines/hash_testing_engine.h"
#include "testing/manifest/manifest_v2_testing.h"


/**
 * Dependencies for testing v2 manifests.
 */
struct manifest_flash_v2_testing {
	HASH_TESTING_ENGINE hash;							/**< Hashing engine for validation. */
	struct hash_engine_mock hash_mock;					/**< Mock hashing engine for error testing. */
	struct signature_verification_mock verification;	/**< PFM signature verification. */
	struct flash_mock flash;							/**< Flash where the PFM is stored. */
	uint32_t addr;										/**< Base address of the PFM. */
	uint8_t signature[512];								/**< Buffer for the manifest signature. */
	uint8_t platform_id[256];							/**< Cache for the platform ID. */
	struct manifest_flash test;							/**< Manifest instance for common testing. */
};


void manifest_flash_v2_testing_init_dependencies (CuTest *test,
	struct manifest_flash_v2_testing *manifest, uint32_t address);
void manifest_flash_v2_testing_validate_and_release_dependencies (CuTest *test,
	struct manifest_flash_v2_testing *manifest);

void manifest_flash_v2_testing_init_common (CuTest *test,
	struct manifest_flash_v2_testing *manifest, uint32_t block_size);

void manifest_flash_v2_testing_verify_manifest (CuTest *test,
	struct manifest_flash_v2_testing *manifest, const struct manifest_v2_testing_data *data,
	int sig_result);
void manifest_flash_v2_testing_verify_manifest_mocked_hash (CuTest *test,
	struct manifest_flash_v2_testing *manifest, const struct manifest_v2_testing_data *data,
	int sig_result, int hash_result);

void manifest_flash_v2_testing_read_element (CuTest *test,
	struct manifest_flash_v2_testing *manifest, const struct manifest_v2_testing_data *data,
	int entry, int start, int hash_id, uint32_t offset, size_t length, size_t read_len,
	uint32_t read_offset);
void manifest_flash_v2_testing_read_element_mocked_hash (CuTest *test,
	struct manifest_flash_v2_testing *manifest, const struct manifest_v2_testing_data *data,
	int entry, int start, int hash_id, uint32_t offset, size_t length, size_t read_len,
	uint32_t read_offset);

void manifest_flash_v2_testing_get_num_child_elements (CuTest *test,
	struct manifest_flash_v2_testing *manifest, const struct manifest_v2_testing_data *data,
	int entry, int last_entry);


#endif /* MANIFEST_FLASH_V2_TESTING_H_ */
