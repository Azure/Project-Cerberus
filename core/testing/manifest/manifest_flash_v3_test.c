// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "manifest_flash_v3_testing.h"
#include "testing.h"
#include "crypto/ecc.h"
#include "crypto/rsa.h"
#include "manifest/cfm/cfm_format.h"
#include "manifest/manifest.h"
#include "manifest/manifest_flash.h"
#include "manifest/manifest_flash_static.h"
#include "manifest/manifest_format.h"
#include "manifest/pfm/pfm_format.h"
#include "testing/manifest/cfm/cfm_testing.h"
#include "testing/manifest/pcd/pcd_testing.h"
#include "testing/manifest/pfm/pfm_flash_v2_testing.h"
#include "testing/manifest/pfm/pfm_testing.h"


TEST_SUITE_LABEL ("manifest_flash_v3");


/**
 * Initialize common manifest testing dependencies.
 *
 * @param test The testing framework.
 * @param manifest The testing components to initialize.
 * @param address The base address for the manifest data.
 */
void manifest_flash_v3_testing_init_dependencies (CuTest *test,
	struct manifest_flash_v3_testing *manifest, uint32_t address)
{
	int status;

	status = HASH_TESTING_ENGINE_INIT (&manifest->hash);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_init (&manifest->hash_mock);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&manifest->verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&manifest->flash);
	CuAssertIntEquals (test, 0, status);

	manifest->addr = address;
}

/**
 * Release test dependencies and validate all mocks.
 *
 * @param test The testing framework.
 * @param manifest The testing components to release.
 */
void manifest_flash_v3_testing_validate_and_release_dependencies (CuTest *test,
	struct manifest_flash_v3_testing *manifest)
{
	int status;

	status = flash_mock_validate_and_release (&manifest->flash);
	status |= signature_verification_mock_validate_and_release (&manifest->verification);
	status |= hash_mock_validate_and_release (&manifest->hash_mock);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&manifest->hash);
}

/**
 * Initialize manifest for testing.
 *
 * @param test The testing framework.
 * @param manifest The testing components to initialize.
 * @param address The base address for the manifest data.
 * @param magic_v1 The manifest v1 type identifier.
 * @param magic_v2 The manifest v2 type identifier.
 * @param magiv_v3 The manifest v3 type identifier.
 */
static void manifest_flash_v3_testing_init (CuTest *test,
	struct manifest_flash_v3_testing *manifest, uint32_t address, uint16_t magic_v1,
	uint16_t magic_v2, uint16_t magic_v3)
{
	int status;

	manifest_flash_v3_testing_init_dependencies (test, manifest, address);
	manifest_flash_v3_testing_init_common (test, manifest, 0x1000);

	status = manifest_flash_v3_init (&manifest->test, &manifest->state, &manifest->flash.base,
		&manifest->hash.base, address, magic_v1, magic_v2, magic_v3, manifest->signature,
		sizeof (manifest->signature), manifest->platform_id, sizeof (manifest->platform_id));
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&manifest->flash.mock);
	status |= mock_validate (&manifest->verification.mock);
	status |= mock_validate (&manifest->hash_mock.mock);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Initialize a static manifest for testing.
 *
 * @param test The testing framework.
 * @param manifest The testing components to initialize.
 * @param address The base address for the manifest data.
 */
static void manifest_flash_v3_testing_init_static (CuTest *test,
	struct manifest_flash_v3_testing *manifest, uint32_t address)
{
	int status;

	manifest_flash_v3_testing_init_dependencies (test, manifest, address);
	manifest_flash_v3_testing_init_common (test, manifest, 0x1000);

	status = manifest_flash_init_state (&manifest->test);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&manifest->flash.mock);
	status |= mock_validate (&manifest->verification.mock);
	status |= mock_validate (&manifest->hash_mock.mock);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Release a test instance and validate all mocks.
 *
 * @param test The testing framework.
 * @param manifest The testing components to release.
 */
static void manifest_flash_v3_testing_validate_and_release (CuTest *test,
	struct manifest_flash_v3_testing *manifest)
{
	manifest_flash_release (&manifest->test);

	manifest_flash_v3_testing_validate_and_release_dependencies (test, manifest);
}

/**
 * Set expectations for common initialization flows.
 *
 * @param test The testing framework.
 * @param manifest The components for the test.
 * @param block_size The flash block size to report.
 */
void manifest_flash_v3_testing_init_common (CuTest *test,
	struct manifest_flash_v3_testing *manifest, uint32_t block_size)
{
	int status;

	status = mock_expect (&manifest->flash.mock, manifest->flash.base.get_block_size,
		&manifest->flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output_tmp (&manifest->flash.mock, 0, &block_size, sizeof (block_size),
		-1);

	CuAssertIntEquals (test, 0, status);
}

/**
 * Set expectations on mocks for v2 manifest verification.
 *
 * @param test The testing framework.
 * @param manifest The components for the test.
 * @param data Manifest data for the test.
 * @param sig_result Result of the signature verification call.
 */
void manifest_flash_v3_testing_verify_manifest (CuTest *test,
	struct manifest_flash_v3_testing *manifest, const struct manifest_v2_testing_data *data,
	int sig_result)
{
	const struct manifest_toc_entry *toc_entries =
		(struct manifest_toc_entry*) (data->raw + MANIFEST_V2_TOC_ENTRY_OFFSET);
	const uint8_t *plat_id = data->raw + data->plat_id_offset + MANIFEST_V2_PLATFORM_HEADER_SIZE;

	uint32_t validate_start = data->toc_hash_offset + data->toc_hash_len;
	uint32_t validate_end = data->plat_id_offset;
	uint32_t validate_resume =
		data->plat_id_offset + MANIFEST_V2_PLATFORM_HEADER_SIZE + data->plat_id_str_len;
	int status;
	int i;
	int toc_ext_idx;
	const struct manifest_v2_toc_testing_data *toc_ext;

	/* Read manifest header. */
	status = mock_expect (&manifest->flash.mock, manifest->flash.base.read, &manifest->flash, 0,
		MOCK_ARG (manifest->addr), MOCK_ARG_NOT_NULL, MOCK_ARG (MANIFEST_V2_HEADER_SIZE));
	status |= mock_expect_output (&manifest->flash.mock, 1, data->raw, data->length, 2);

	/* Read manifest signature. */
	status |= mock_expect (&manifest->flash.mock, manifest->flash.base.read, &manifest->flash, 0,
		MOCK_ARG (manifest->addr + data->sig_offset), MOCK_ARG_NOT_NULL, MOCK_ARG (data->sig_len));
	status |= mock_expect_output (&manifest->flash.mock, 1, data->signature, data->sig_len, 2);

	/* Read table of contents header. */
	status |= flash_mock_expect_read_and_hash (&manifest->flash, NULL,
		manifest->addr + MANIFEST_V2_TOC_HDR_OFFSET, data->toc, MANIFEST_V2_TOC_HEADER_SIZE);

	/* Iterate over all TOC entries. */
	for (i = 0; i < data->toc_entries; i++) {
		status |= flash_mock_expect_read_and_hash (&manifest->flash, NULL,
			manifest->addr + MANIFEST_V2_TOC_ENTRY_OFFSET + (i * MANIFEST_V2_TOC_ENTRY_SIZE),
			(uint8_t*) &toc_entries[i], MANIFEST_V2_TOC_ENTRY_SIZE);
	}

	/* Hash the hash table */
	status |= flash_mock_expect_verify_flash (&manifest->flash,
		manifest->addr + MANIFEST_V2_TOC_ENTRY_OFFSET +
		(data->toc_entries * MANIFEST_V2_TOC_ENTRY_SIZE),
		data->raw + MANIFEST_V2_TOC_ENTRY_OFFSET + (data->toc_entries * MANIFEST_V2_TOC_ENTRY_SIZE),
		data->toc_hash_len * data->toc_hashes);

	/* Read table of contents hash. */
	status |= flash_mock_expect_read_and_hash (&manifest->flash, NULL,
		manifest->addr + data->toc_hash_offset,	data->toc_hash, data->toc_hash_len);

	status |= flash_mock_expect_verify_flash (&manifest->flash, manifest->addr + validate_start,
		data->raw + validate_start, validate_end - validate_start);

	/* Read the platform ID header. */
	status |= flash_mock_expect_read_and_hash (&manifest->flash, NULL,
		manifest->addr + data->plat_id_offset, data->plat_id, MANIFEST_V2_PLATFORM_HEADER_SIZE);

	/* Read the platform ID string. */
	status |= flash_mock_expect_read_and_hash (&manifest->flash, NULL,
		manifest->addr + data->plat_id_offset + MANIFEST_V2_PLATFORM_HEADER_SIZE, plat_id,
		data->plat_id_str_len);

	for (toc_ext_idx = 0; toc_ext_idx < data->toc_extension_count; ++toc_ext_idx) {
		toc_ext = &data->toc_extensions[toc_ext_idx];
		toc_entries = (struct manifest_toc_entry*) (toc_ext->toc + MANIFEST_V2_TOC_HEADER_SIZE);

		/* Hash data until ToC extension */
		status |= flash_mock_expect_verify_flash (&manifest->flash,
			manifest->addr + validate_resume, data->raw + validate_resume,
			toc_ext->toc_offset - validate_resume);

		validate_resume = toc_ext->toc_offset + toc_ext->toc_len;

		/* Read table of contents header. */
		status |= flash_mock_expect_read_and_hash (&manifest->flash, NULL,
			manifest->addr + toc_ext->toc_offset, toc_ext->toc, MANIFEST_V2_TOC_HEADER_SIZE);

		/* Iterate over all TOC entries. */
		for (i = 0; i < toc_ext->entries_count; i++) {
			status |= flash_mock_expect_read_and_hash (&manifest->flash, NULL,
				manifest->addr + toc_ext->toc_offset + MANIFEST_V2_TOC_HEADER_SIZE +
				(i * MANIFEST_V2_TOC_ENTRY_SIZE), (uint8_t*) &toc_entries[i],
				MANIFEST_V2_TOC_ENTRY_SIZE);
		}

		/* Hash the hash table */
		status |= flash_mock_expect_verify_flash (&manifest->flash,
			manifest->addr + toc_ext->toc_offset + MANIFEST_V2_TOC_HEADER_SIZE +
			(toc_ext->entries_count * MANIFEST_V2_TOC_ENTRY_SIZE),
			toc_ext->toc + MANIFEST_V2_TOC_HEADER_SIZE +
			(toc_ext->entries_count * MANIFEST_V2_TOC_ENTRY_SIZE),
			data->toc_hash_len * toc_ext->hashes_count);
	}

	status |= flash_mock_expect_verify_flash (&manifest->flash, manifest->addr + validate_resume,
		data->raw + validate_resume, data->sig_offset - validate_resume);

	status |= mock_expect (&manifest->verification.mock,
		manifest->verification.base.verify_signature, &manifest->verification, sig_result,
		MOCK_ARG_PTR_CONTAINS (data->hash, data->hash_len), MOCK_ARG (data->hash_len),
		MOCK_ARG_PTR_CONTAINS (data->signature, data->sig_len), MOCK_ARG (data->sig_len));

	CuAssertIntEquals (test, 0, status);
}


/**
 * Set expectations on mocks for v2 manifest verification.  The mocked hashing engine will be used.
 *
 * @param test The testing framework.
 * @param manifest The components for the test.
 * @param data Manifest data for the test.
 * @param sig_result Result of the signature verification call.
 * @param hash_result Result of the call to finalize the manifest hash.
 */
void manifest_flash_v3_testing_verify_manifest_mocked_hash (CuTest *test,
	struct manifest_flash_v3_testing *manifest, const struct manifest_v2_testing_data *data,
	int sig_result, int hash_result)
{
	uint32_t toc_entry_offset = MANIFEST_V2_TOC_ENTRY_OFFSET;
	const struct manifest_toc_entry *toc_entries =
		(struct manifest_toc_entry*) (data->raw + toc_entry_offset);
	const uint8_t *plat_id = data->raw + data->plat_id_offset + MANIFEST_V2_PLATFORM_HEADER_SIZE;
	uint32_t validate_toc_start = toc_entry_offset;
	uint32_t validate_start = data->toc_hash_offset + data->toc_hash_len;
	uint32_t validate_end = data->plat_id_offset;
	uint32_t validate_resume =
		data->plat_id_offset + MANIFEST_V2_PLATFORM_HEADER_SIZE + data->plat_id_str_len;
	int status;
	int i;
	int toc_ext_idx;
	const struct manifest_v2_toc_testing_data *toc_ext;

	/* Read manifest header. */
	status = mock_expect (&manifest->flash.mock, manifest->flash.base.read, &manifest->flash, 0,
		MOCK_ARG (manifest->addr), MOCK_ARG_NOT_NULL, MOCK_ARG (MANIFEST_V2_HEADER_SIZE));
	status |= mock_expect_output (&manifest->flash.mock, 1, data->raw, data->length, 2);

	/* Read manifest signature. */
	status |= mock_expect (&manifest->flash.mock, manifest->flash.base.read, &manifest->flash, 0,
		MOCK_ARG (manifest->addr + data->sig_offset), MOCK_ARG_NOT_NULL, MOCK_ARG (data->sig_len));
	status |= mock_expect_output (&manifest->flash.mock, 1, data->signature, data->sig_len, 2);

	/* Hash */
	status |= hash_mock_expect_hash_start (&manifest->hash_mock, data->sig_hash_type);

	status |= mock_expect (&manifest->hash_mock.mock, manifest->hash_mock.base.update,
		&manifest->hash_mock, 0, MOCK_ARG_PTR_CONTAINS (data->raw, MANIFEST_V2_HEADER_SIZE),
		MOCK_ARG (MANIFEST_V2_HEADER_SIZE));

	/* Read table of contents header. */
	status |= flash_mock_expect_read_and_hash (&manifest->flash, &manifest->hash_mock,
		manifest->addr + MANIFEST_V2_TOC_HDR_OFFSET, data->toc, MANIFEST_V2_TOC_HEADER_SIZE);

	/* Iterate over all TOC entries. */
	for (i = 0; i < data->toc_entries; i++, validate_toc_start += MANIFEST_V2_TOC_ENTRY_SIZE) {
		status |= flash_mock_expect_read_and_hash (&manifest->flash, &manifest->hash_mock,
			manifest->addr + MANIFEST_V2_TOC_ENTRY_OFFSET + (i * MANIFEST_V2_TOC_ENTRY_SIZE),
			(uint8_t*) &toc_entries[i], MANIFEST_V2_TOC_ENTRY_SIZE);
	}

	status |= flash_mock_expect_verify_flash_and_hash (&manifest->flash, &manifest->hash_mock,
		manifest->addr + validate_toc_start, data->raw + validate_toc_start,
		data->toc_hash_offset - validate_toc_start);

	/* Read table of contents hash. */
	status |= flash_mock_expect_read_and_hash (&manifest->flash, &manifest->hash_mock,
		manifest->addr + data->toc_hash_offset,	data->toc_hash, data->toc_hash_len);

	status |= flash_mock_expect_verify_flash_and_hash (&manifest->flash, &manifest->hash_mock,
		manifest->addr + validate_start, data->raw + validate_start, validate_end - validate_start);

	/* Read the platform ID header. */
	status |= flash_mock_expect_read_and_hash (&manifest->flash, &manifest->hash_mock,
		manifest->addr + data->plat_id_offset, data->plat_id, MANIFEST_V2_PLATFORM_HEADER_SIZE);

	/* Read the platform ID string. */
	status |= flash_mock_expect_read_and_hash (&manifest->flash, &manifest->hash_mock,
		manifest->addr + data->plat_id_offset + MANIFEST_V2_PLATFORM_HEADER_SIZE, plat_id,
		data->plat_id_str_len);

	for (toc_ext_idx = 0; toc_ext_idx < data->toc_extension_count; ++toc_ext_idx) {
		toc_ext = &data->toc_extensions[toc_ext_idx];
		toc_entries = (struct manifest_toc_entry*) (toc_ext->toc + MANIFEST_V2_TOC_HEADER_SIZE);

		/* Hash data until ToC extension */
		status |= flash_mock_expect_verify_flash_and_hash (&manifest->flash, &manifest->hash_mock,
			manifest->addr + validate_resume, data->raw + validate_resume,
			toc_ext->toc_offset - validate_resume);

		validate_resume = toc_ext->toc_offset + toc_ext->toc_len;

		/* Read table of contents header. */
		status |= flash_mock_expect_read_and_hash (&manifest->flash, &manifest->hash_mock,
			manifest->addr + toc_ext->toc_offset, toc_ext->toc, MANIFEST_V2_TOC_HEADER_SIZE);

		/* Iterate over all TOC entries. */
		for (i = 0; i < toc_ext->entries_count; i++) {
			status |= flash_mock_expect_read_and_hash (&manifest->flash, &manifest->hash_mock,
				manifest->addr + toc_ext->toc_offset + MANIFEST_V2_TOC_HEADER_SIZE +
				(i * MANIFEST_V2_TOC_ENTRY_SIZE), (uint8_t*) &toc_entries[i],
				MANIFEST_V2_TOC_ENTRY_SIZE);
		}

		/* Hash the hash table */
		status |= flash_mock_expect_verify_flash_and_hash (&manifest->flash, &manifest->hash_mock,
			manifest->addr + toc_ext->toc_offset + MANIFEST_V2_TOC_HEADER_SIZE +
			(toc_ext->entries_count * MANIFEST_V2_TOC_ENTRY_SIZE),
			data->raw + toc_ext->toc_offset + MANIFEST_V2_TOC_HEADER_SIZE +
			(toc_ext->entries_count * MANIFEST_V2_TOC_ENTRY_SIZE),
			data->toc_hash_len * toc_ext->hashes_count);
	}

	status |= flash_mock_expect_verify_flash_and_hash (&manifest->flash, &manifest->hash_mock,
		manifest->addr + validate_resume, data->raw + validate_resume,
		data->sig_offset - validate_resume);

	status |= mock_expect (&manifest->hash_mock.mock, manifest->hash_mock.base.get_active_algorithm,
		&manifest->hash_mock, data->sig_hash_type);

	status |= mock_expect (&manifest->hash_mock.mock, manifest->hash_mock.base.finish,
		&manifest->hash_mock, hash_result, MOCK_ARG_NOT_NULL, MOCK_ARG_ANY);

	if (hash_result == 0) {
		status |= mock_expect_output (&manifest->hash_mock.mock, 0, data->hash, data->hash_len, 1);

		status |= mock_expect (&manifest->verification.mock,
			manifest->verification.base.verify_signature, &manifest->verification, sig_result,
			MOCK_ARG_PTR_CONTAINS (data->hash, data->hash_len), MOCK_ARG (data->hash_len),
			MOCK_ARG_PTR_CONTAINS (data->signature, data->sig_len), MOCK_ARG (data->sig_len));
	}
	else {
		status |= mock_expect (&manifest->hash_mock.mock, manifest->hash_mock.base.cancel,
			&manifest->hash_mock, 0);
	}

	CuAssertIntEquals (test, 0, status);
}

/**
 * Initialize a manifest for testing.  Run verification to load the manifest information.
 *
 * @param test The testing framework.
 * @param manifest The testing components to initialize.
 * @param address The base address for the manifest data.
 * @param magic_v1 The manifest v1 type identifier.
 * @param magic_v2 The manifest v2 type identifier.
 * @param magic_v3 The manifest v3 type identifier.
 * @param data Manifest data for the test.
 * @param sig_result Result of the signature verification call.
 * @param use_mock true to use the mock hash engine.
 * @param hash_result Result of the final hash call when using the mock hash engine.
 * @param is_static true if the manifest instance was statically initialized.
 */
static void manifest_flash_v3_testing_init_and_verify_ex (CuTest *test,
	struct manifest_flash_v3_testing *manifest, uint32_t address, uint16_t magic_v1,
	uint16_t magic_v2, uint16_t magic_v3, const struct manifest_v2_testing_data *data,
	int sig_result, bool use_mock, int hash_result, bool is_static)
{
	struct hash_engine *hash = (!use_mock) ? &manifest->hash.base : &manifest->hash_mock.base;
	int status;

	if (!is_static) {
		manifest_flash_v3_testing_init (test, manifest, address, magic_v1, magic_v2, magic_v3);
	}
	else {
		manifest_flash_v3_testing_init_static (test, manifest, address);
	}

	if (!use_mock) {
		manifest_flash_v3_testing_verify_manifest (test, manifest, data, sig_result);
	}
	else {
		manifest_flash_v3_testing_verify_manifest_mocked_hash (test, manifest, data, sig_result,
			hash_result);
	}

	status = manifest_flash_verify (&manifest->test, hash, &manifest->verification.base, NULL, 0);
	CuAssertIntEquals (test, sig_result, status);

	status = mock_validate (&manifest->flash.mock);
	status |= mock_validate (&manifest->verification.mock);
	status |= mock_validate (&manifest->hash_mock.mock);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Initialize a manifest for testing.  Run verification to load the manifest information.
 *
 * @param test The testing framework.
 * @param manifest The testing components to initialize.
 * @param address The base address for the manifest data.
 * @param magic_v1 The manifest v1 type identifier.
 * @param magic_v2 The manifest v2 type identifier.
 * @param magic_v3 The manifest v2 ext type identifier.
 * @param data Manifest data for the test.
 * @param sig_result Result of the signature verification call.
 * @param use_mock true to use the mock hash engine.
 * @param hash_result Result of the final hash call when using the mock hash engine.
 */
static void manifest_flash_v3_testing_init_and_verify (CuTest *test,
	struct manifest_flash_v3_testing *manifest, uint32_t address, uint16_t magic_v1,
	uint16_t magic_v2, uint16_t magic_v3, const struct manifest_v2_testing_data *data,
	int sig_result, bool use_mock, int hash_result)
{
	manifest_flash_v3_testing_init_and_verify_ex (test, manifest, address, magic_v1, magic_v2,
		magic_v3, data, sig_result, use_mock, hash_result, false);
}

/**
 * Set expectations on mocks for reading an element from a v2 manifest,
 * common implementation with mocked hash and not.
 *
 * @param test The testing framework.
 * @param manifest The components for the test.
 * @param data Manifest data for the test.
 * @param entry The entry index to read.
 * @param start The entry index to start reading.
 * @param hash_id The hash index to read.
 * @param offset Address offset of the element to read.
 * @param length Length of the element data.
 * @param read_len Maximum length of the element data to read.
 * @param read_offset Offset to starting reading the element data.
 * @param element_entry Optional data to be used as element entry.
 * @param element_data Optional data to use as element data.
 */
void manifest_flash_v3_testing_read_element_common (CuTest *test,
	struct manifest_flash_v3_testing *manifest, const struct manifest_v2_testing_data *data,
	int entry, int start, int hash_id, uint32_t offset, size_t length, size_t read_len,
	uint32_t read_offset, bool use_mocked_hash, const struct manifest_toc_entry *element_entry,
	const uint8_t *element_data)
{
	struct hash_engine_mock *hash_mock = use_mocked_hash ? &manifest->hash_mock : NULL;

	uint32_t toc_entry_offset = MANIFEST_V2_TOC_ENTRY_OFFSET;

	int status = 0;
	int i;
	int toc_ext_idx;
	int current_hash_id;
	int global_base;

	bool element_found = false;

	uint32_t toc_ext_addr;
	uint32_t hash_offset = UINT32_MAX;

	const struct manifest_v2_toc_testing_data *toc_ext;
	const struct manifest_toc_entry *toc_entries =
		(const struct manifest_toc_entry*) (data->raw + toc_entry_offset);

	/* Starting Root ToC. */

	/* local_start: first entry index to read individually in the root ToC.
	 * Clamp to the last entry if start is beyond the root ToC, so we still
	 * traverse the block to find the extension entry. */
	int local_start = (start < data->toc_entries) ? start : (data->toc_entries - 1);

	/* entry_in_root: entry is reachable (>= start) and is in the root ToC.
	 * Otherwise we always read through to the last entry (either the extension entry
	 * when entry is beyond the root, or all entries when entry < start). */
	bool entry_in_this_toc = (entry >= start) && (entry >= 0) && (entry < data->toc_entries);
	int local_last = entry_in_this_toc ? entry : (data->toc_entries - 1);

	uint32_t least_entry_offset = toc_entry_offset +
		(MANIFEST_V2_TOC_ENTRY_SIZE * (local_last + 1));

	if (use_mocked_hash) {
		status |= hash_mock_expect_hash_start (&manifest->hash_mock, data->toc_hash_type);
	}

	status |= flash_mock_expect_read_and_hash (&manifest->flash, hash_mock,
		manifest->addr + MANIFEST_V2_TOC_HDR_OFFSET, data->toc, MANIFEST_V2_TOC_HEADER_SIZE);

	/* Hash TOC entries before local_start. */
	status |= flash_mock_expect_verify_flash_and_hash (&manifest->flash, hash_mock,
		manifest->addr + toc_entry_offset, data->raw + toc_entry_offset,
		local_start * MANIFEST_V2_TOC_ENTRY_SIZE);

	/* Individually read entries from local_start through local_last. */
	for (i = local_start; i <= local_last - 1 && local_start != local_last; i++) {
		status |= flash_mock_expect_read_and_hash (&manifest->flash, hash_mock,
			manifest->addr + toc_entry_offset + (i * MANIFEST_V2_TOC_ENTRY_SIZE),
			(uint8_t*) &toc_entries[i], MANIFEST_V2_TOC_ENTRY_SIZE);
	}

	/* For bad entry insertion */
	status |= flash_mock_expect_read_and_hash (&manifest->flash, hash_mock,
		manifest->addr + toc_entry_offset + (i * MANIFEST_V2_TOC_ENTRY_SIZE),
		(uint8_t*) ((entry_in_this_toc &&
			(element_entry != NULL)) ? element_entry : &toc_entries[i]),
		MANIFEST_V2_TOC_ENTRY_SIZE);

	current_hash_id = -1;

	if (entry_in_this_toc) {
		current_hash_id = hash_id;
		element_found = true;
	}
	else if (data->toc_extension_count > 0) {
		/* Entry is not in the root ToC — either it's beyond (following extension) or
		 * entry < start (not found).  In both cases the implementation reads through to
		 * the last entry (the extension entry) and handles the ToC identically: pull out
		 * the extension entry's hash slot (will always be the last one),
		 * then fall through to scan the extension blocks. */
		current_hash_id = data->toc_hashes - 1;
	}

	if (current_hash_id >= 0) {
		/* Hash remainder of entries + hash table, pulling out the element hash if present. */

		hash_offset = toc_entry_offset +
			(MANIFEST_V2_TOC_ENTRY_SIZE * data->toc_entries) +
			(data->toc_hash_len * current_hash_id);

		status |= flash_mock_expect_verify_flash_and_hash (&manifest->flash, hash_mock,
			manifest->addr + least_entry_offset, data->raw + least_entry_offset,
			hash_offset - least_entry_offset);

		status |= flash_mock_expect_read_and_hash (&manifest->flash, hash_mock,
			manifest->addr + hash_offset, data->raw + hash_offset, data->toc_hash_len);

		status |= flash_mock_expect_verify_flash_and_hash (&manifest->flash, hash_mock,
			manifest->addr + hash_offset + data->toc_hash_len,
			data->raw + hash_offset + data->toc_hash_len,
			data->toc_hash_offset - hash_offset - data->toc_hash_len);
	}
	else if (element_found) {
		status |= flash_mock_expect_verify_flash_and_hash (&manifest->flash, hash_mock,
			manifest->addr + least_entry_offset, data->raw + least_entry_offset,
			data->toc_hash_offset - least_entry_offset);
	}
	else {
		goto cancel;
	}

	if (use_mocked_hash) {
		/* TOC hash */
		status |= mock_expect (&manifest->hash_mock.mock, manifest->hash_mock.base.finish,
			&manifest->hash_mock, 0, MOCK_ARG_NOT_NULL, MOCK_ARG (SHA512_HASH_LENGTH));
		status |= mock_expect_output (&manifest->hash_mock.mock, 0, data->toc_hash,
			data->toc_hash_len,	1);
	}

	/* ToC extensions. */
	global_base = data->toc_entries;
	toc_entry_offset = MANIFEST_V2_TOC_HEADER_SIZE;

	for (toc_ext_idx = 0; toc_ext_idx < data->toc_extension_count && !element_found;
		toc_ext_idx++) {
		toc_ext = &data->toc_extensions[toc_ext_idx];
		toc_entries = (const struct manifest_toc_entry*) (toc_ext->toc +
			MANIFEST_V2_TOC_HEADER_SIZE);

		toc_ext_addr = manifest->addr + toc_ext->toc_offset;

		/* local_start for this extension block. */
		local_start = 0;
		if (start > global_base) {
			local_start = start - global_base;
			if (local_start >= toc_ext->entries_count) {
				local_start = toc_ext->entries_count - 1;
			}
		}

		/* entry_in_this_toc: reachable and lives here.
			* Otherwise: read through to last entry (next extension or not-found),
			* pull out its hash slot, and fall through to the next block. */
		entry_in_this_toc = (entry >= global_base + local_start) &&
			(entry < global_base + toc_ext->entries_count);

		local_last =
			entry_in_this_toc ? (entry - global_base) : (toc_ext->entries_count - 1);

		least_entry_offset = toc_entry_offset + (MANIFEST_V2_TOC_ENTRY_SIZE * (local_last + 1));

		if (use_mocked_hash) {
			status |= hash_mock_expect_hash_start (&manifest->hash_mock, data->toc_hash_type);
		}

		/* Read the extension header. */
		status |= flash_mock_expect_read_and_hash (&manifest->flash, hash_mock, toc_ext_addr,
			toc_ext->toc, MANIFEST_V2_TOC_HEADER_SIZE);

		/* Hash entries before ext_local_start. */
		status |= flash_mock_expect_verify_flash_and_hash (&manifest->flash, hash_mock,
			toc_ext_addr + toc_entry_offset, toc_ext->toc + toc_entry_offset,
			local_start * MANIFEST_V2_TOC_ENTRY_SIZE);

		/* Individually read entries from ext_local_start through ext_local_last. */
		for (i = local_start; i <= local_last - 1 && local_start != local_last; i++) {
			status |= flash_mock_expect_read_and_hash (&manifest->flash, hash_mock,
				toc_ext_addr + toc_entry_offset + (i * MANIFEST_V2_TOC_ENTRY_SIZE),
				(uint8_t*) &toc_entries[i], MANIFEST_V2_TOC_ENTRY_SIZE);
		}

		/* For bad entry insertion */
		status |= flash_mock_expect_read_and_hash (&manifest->flash, hash_mock,
			toc_ext_addr + toc_entry_offset + (i * MANIFEST_V2_TOC_ENTRY_SIZE),
			(uint8_t*) ((entry_in_this_toc &&
				(element_entry != NULL)) ? element_entry : &toc_entries[i]),
			MANIFEST_V2_TOC_ENTRY_SIZE);

		current_hash_id = -1;

		if (entry_in_this_toc) {
			current_hash_id = hash_id;
			element_found = true;
		}
		else {
			/* Entry is not in this extension block — either it's beyond (following next
			 * extension) or entry < start (not found).  Either way the implementation
			 * reads through to the last entry (the next extension entry) and handles
			 * the block identically: pull out that entry's hash slot, fall through. */
			current_hash_id = toc_ext->hashes_count - 1;
		}

		if (current_hash_id >= 0) {
			/* Hash remainder of entries + hash table, pulling out the element hash if present. */

			hash_offset = toc_entry_offset +
				(MANIFEST_V2_TOC_ENTRY_SIZE * toc_ext->entries_count) +
				(data->toc_hash_len * current_hash_id);

			status |= flash_mock_expect_verify_flash_and_hash (&manifest->flash, hash_mock,
				toc_ext_addr + least_entry_offset, toc_ext->toc + least_entry_offset,
				hash_offset - least_entry_offset);

			status |= flash_mock_expect_read_and_hash (&manifest->flash, hash_mock,
				toc_ext_addr + hash_offset, toc_ext->toc + hash_offset, data->toc_hash_len);

			status |= flash_mock_expect_verify_flash_and_hash (&manifest->flash, hash_mock,
				toc_ext_addr + hash_offset + data->toc_hash_len,
				toc_ext->toc + hash_offset + data->toc_hash_len,
				toc_ext->toc_len - hash_offset - data->toc_hash_len);
		}
		else if (element_found) {
			status |= flash_mock_expect_verify_flash_and_hash (&manifest->flash, hash_mock,
				toc_ext_addr + least_entry_offset, toc_ext->toc + least_entry_offset,
				toc_ext->toc_len - least_entry_offset);
		}
		else {
			goto cancel;
		}

		if (use_mocked_hash) {
			/* TOC hash */
			status |= mock_expect (&manifest->hash_mock.mock, manifest->hash_mock.base.finish,
				&manifest->hash_mock, 0, MOCK_ARG_NOT_NULL, MOCK_ARG (SHA512_HASH_LENGTH));
			status |= mock_expect_output (&manifest->hash_mock.mock, 0, toc_ext->hash,
				data->toc_hash_len,	1);
		}

		global_base += toc_ext->entries_count;
	}

	/* Exhausted all blocks without finding the entry. */
	if (!element_found) {
		goto done;
	}

	if ((read_offset >= length) || (read_len == 0)) {
		goto done;
	}

	if (use_mocked_hash) {
		status |= hash_mock_expect_hash_start (&manifest->hash_mock, data->toc_hash_type);
	}

	/* Read element data */
	if (read_offset != 0) {
		if (hash_id >= 0) {
			status |= flash_mock_expect_verify_flash_and_hash (&manifest->flash, hash_mock,
				manifest->addr + offset, (element_data != NULL) ? element_data : data->raw + offset,
				read_offset);
		}

		length -= read_offset;
		offset += read_offset;
	}

	if (length < read_len) {
		read_len = length;
	}

	status |= mock_expect (&manifest->flash.mock, manifest->flash.base.read, &manifest->flash, 0,
		MOCK_ARG (manifest->addr + offset), MOCK_ARG_NOT_NULL, MOCK_ARG (read_len));
	status |= mock_expect_output_tmp (&manifest->flash.mock, 1,
		(element_data != NULL) ? element_data + read_offset : data->raw + offset, read_len, 2);

	/* Element hash */
	if (hash_id >= 0) {
		if (use_mocked_hash) {
			status |= mock_expect (&manifest->hash_mock.mock, manifest->hash_mock.base.update,
				&manifest->hash_mock, 0, MOCK_ARG_PTR_CONTAINS_TMP ((element_data !=
					NULL) ? element_data + read_offset : data->raw + offset, read_len),
				MOCK_ARG (read_len));
		}

		if (read_len < length) {
			status |= flash_mock_expect_verify_flash_and_hash (&manifest->flash, hash_mock,
				manifest->addr + offset + read_len,	data->raw + offset + read_len,
				length - read_len);
		}

		if (use_mocked_hash) {
			status |= mock_expect (&manifest->hash_mock.mock, manifest->hash_mock.base.finish,
				&manifest->hash_mock, 0, MOCK_ARG_NOT_NULL, MOCK_ARG (SHA512_HASH_LENGTH));
			status |= mock_expect_output (&manifest->hash_mock.mock, 0, &data->raw[hash_offset],
				data->toc_hash_len, 1);
		}
	}

done:
	CuAssertIntEquals (test, 0, status);

	return;

cancel:
	if (use_mocked_hash) {
		status |= mock_expect (&manifest->hash_mock.mock, manifest->hash_mock.base.cancel,
			&manifest->hash_mock, 0);
	}

	CuAssertIntEquals (test, 0, status);
}


/**
 * Set expectations on mocks for reading an element from a v2 manifest.
 *
 * @param test The testing framework.
 * @param manifest The components for the test.
 * @param data Manifest data for the test.
 * @param entry The entry index to read.
 * @param start The entry index to start reading.
 * @param hash_id The hash index to read.
 * @param offset Address offset of the element to read.
 * @param length Length of the element data.
 * @param read_len Maximum length of the element data to read.
 * @param read_offset Offset to starting reading the element data.
 */
void manifest_flash_v3_testing_read_element (CuTest *test,
	struct manifest_flash_v3_testing *manifest, const struct manifest_v2_testing_data *data,
	int entry, int start, int hash_id, uint32_t offset, size_t length, size_t read_len,
	uint32_t read_offset)
{
	return manifest_flash_v3_testing_read_element_common (test, manifest, data, entry, start,
		hash_id, offset, length, read_len, read_offset, false, NULL, NULL);
}

/**
 * Set expectations on mocks for reading an element from a v2 manifest.  The mocked hashing engine
 * will be used.
 *
 * @param test The testing framework.
 * @param manifest The components for the test.
 * @param data Manifest data for the test.
 * @param entry The entry index to read.
 * @param start The entry index to start reading.
 * @param hash_id The hash index to read.
 * @param offset Address offset of the element to read.
 * @param length Length of the element data.
 * @param read_len Maximum length of the element data to read.
 * @param read_offset Offset to starting reading the element data.
 */
void manifest_flash_v3_testing_read_element_mocked_hash (CuTest *test,
	struct manifest_flash_v3_testing *manifest, const struct manifest_v2_testing_data *data,
	int entry, int start, int hash_id, uint32_t offset, size_t length, size_t read_len,
	uint32_t read_offset)
{
	return manifest_flash_v3_testing_read_element_common (test, manifest, data, entry, start,
		hash_id, offset, length, read_len, read_offset, true, NULL, NULL);
}

/**
 * Set expectations on mocks for reading a bad entry from a v2 manifest.  The mocked hashing engine
 * will be used.
 *
 * @param test The testing framework.
 * @param manifest The components for the test.
 * @param data Manifest data for the test.
 * @param entry The entry index to read.
 * @param start The entry index to start reading.
 * @param hash_id The hash index to read.
 * @param offset Address offset of the element to read.
 * @param length Length of the element data.
 * @param read_len Maximum length of the element data to read.
 * @param read_offset Offset to start reading the element data.
 * @param element_entry The bad element entry.
 * @param element_data Optional data to use as element data. If null, garbage data will be used.
 */
void manifest_flash_v3_testing_read_element_mocked_hash_bad_entry (CuTest *test,
	struct manifest_flash_v3_testing *manifest, const struct manifest_v2_testing_data *data,
	int entry, int start, int hash_id, uint32_t offset, size_t length, size_t read_len,
	uint32_t read_offset, const struct manifest_toc_entry *element_entry,
	const uint8_t *element_data)
{
	uint8_t element_data_arr[length];

	/* Create bad element. */
	if (element_data) {
		memcpy (element_data_arr, element_data, length);
	}
	else {
		memset (element_data_arr, 0x55, length);
	}

	return manifest_flash_v3_testing_read_element_common (test, manifest, data, entry, start,
		hash_id, offset, length, read_len, read_offset, true, element_entry, element_data_arr);
}

/**
 * Set expectations on mocks for iterating through manifest TOC in a v2 manifest.
 * Common function with ability to use mocked hash and skip verification at the end.
 *
 * @param test The testing framework.
 * @param manifest The components for the test.
 * @param data Manifest data for the test.
 * @param entry The table of contents index to start searching at.
 * @param last_entry The last entry index to check.
 */
void manifest_flash_v3_testing_iterate_manifest_toc_common (CuTest *test,
	struct manifest_flash_v3_testing *manifest, const struct manifest_v2_testing_data *data,
	int entry, int last_entry, bool exit_early_no_verify, bool use_mocked_hash)
{
	struct hash_engine_mock *hash_mock = use_mocked_hash ? &manifest->hash_mock : NULL;

	uint32_t toc_entry_offset = MANIFEST_V2_TOC_ENTRY_OFFSET;
	int status = 0;
	int i;
	int toc_ext_idx;

	uint32_t toc_ext_addr;
	uint32_t hash_offset;

	const struct manifest_v2_toc_testing_data *toc_ext;

	const struct manifest_toc_entry *toc_entries =
		(const struct manifest_toc_entry*) (data->raw + MANIFEST_V2_TOC_ENTRY_OFFSET);

	/* Root ToC. */

	/* Clamp local_start and local_last to the root ToC's entry range. */
	int local_start = (entry < data->toc_entries) ? entry : (data->toc_entries - 1);
	int local_last = (last_entry < data->toc_entries) ? last_entry : (data->toc_entries - 1);

	bool last_entry_in_this_toc = (last_entry < data->toc_entries);
	bool reached_last_entry = false;

	uint32_t least_entry_offset = toc_entry_offset +
		(MANIFEST_V2_TOC_ENTRY_SIZE * (local_last + 1));

	if (use_mocked_hash) {
		status |= hash_mock_expect_hash_start (&manifest->hash_mock, data->toc_hash_type);
	}

	status |= flash_mock_expect_read_and_hash (&manifest->flash, hash_mock,
		manifest->addr + MANIFEST_V2_TOC_HDR_OFFSET, data->toc, MANIFEST_V2_TOC_HEADER_SIZE);

	/* Hash TOC entries before local_start. */
	status |= flash_mock_expect_verify_flash_and_hash (&manifest->flash, hash_mock,
		manifest->addr + toc_entry_offset, data->raw + toc_entry_offset,
		local_start * MANIFEST_V2_TOC_ENTRY_SIZE);

	/* Individually read entries from local_start through local_last. */
	for (i = local_start; i <= local_last; i++) {
		status |= flash_mock_expect_read_and_hash (&manifest->flash, hash_mock,
			manifest->addr + MANIFEST_V2_TOC_ENTRY_OFFSET + (i * MANIFEST_V2_TOC_ENTRY_SIZE),
			(uint8_t*) &toc_entries[i], MANIFEST_V2_TOC_ENTRY_SIZE);
	}

	if (exit_early_no_verify && last_entry_in_this_toc) {
		goto cancel;
	}
	else {
		if (last_entry_in_this_toc || (data->toc_extension_count == 0)) {
			/* last_entry is in root ToC, OR beyond root but no extension: verify remainder of ToC. */

			status |= flash_mock_expect_verify_flash_and_hash (&manifest->flash, hash_mock,
				manifest->addr + least_entry_offset, data->raw + least_entry_offset,
				data->toc_hash_offset - least_entry_offset);

			reached_last_entry = true;
		}
		else {
			/* last_entry is beyond the root ToC and there is an extension. */

			/* ToC extension hash is always the last one. */
			hash_offset = toc_entry_offset +
				(MANIFEST_V2_TOC_ENTRY_SIZE * data->toc_entries) +
				(data->toc_hash_len * (data->toc_hashes - 1));

			status |= flash_mock_expect_verify_flash_and_hash (&manifest->flash, hash_mock,
				manifest->addr + least_entry_offset, data->raw + least_entry_offset,
				hash_offset - least_entry_offset);

			status |= flash_mock_expect_read_and_hash (&manifest->flash, hash_mock,
				manifest->addr + hash_offset, data->raw + hash_offset, data->toc_hash_len);

			status |= flash_mock_expect_verify_flash_and_hash (&manifest->flash, hash_mock,
				manifest->addr + hash_offset + data->toc_hash_len,
				data->raw + hash_offset + data->toc_hash_len,
				data->toc_hash_offset - hash_offset - data->toc_hash_len);
		}

		if (use_mocked_hash) {
			/* TOC hash */
			status |= mock_expect (&manifest->hash_mock.mock, manifest->hash_mock.base.finish,
				&manifest->hash_mock, 0, MOCK_ARG_NOT_NULL, MOCK_ARG (SHA512_HASH_LENGTH));
			status |= mock_expect_output (&manifest->hash_mock.mock, 0, data->toc_hash,
				data->toc_hash_len,	1);
		}
	}

	/* ToC extensions. */

	int global_base = data->toc_entries;

	toc_entry_offset = MANIFEST_V2_TOC_HEADER_SIZE;

	for (toc_ext_idx = 0; toc_ext_idx < data->toc_extension_count && !reached_last_entry;
		toc_ext_idx++) {
		toc_ext = &data->toc_extensions[toc_ext_idx];
		toc_entries = (const struct manifest_toc_entry*) (toc_ext->toc +
			MANIFEST_V2_TOC_HEADER_SIZE);

		toc_ext_addr = manifest->addr + toc_ext->toc_offset;

		local_start = (entry > global_base) ? (entry - global_base) : 0;

		if (local_start >= toc_ext->entries_count) {
			local_start = toc_ext->entries_count - 1;
		}

		last_entry_in_this_toc = (last_entry >= global_base) &&
			(last_entry < global_base + toc_ext->entries_count);
		local_last = last_entry_in_this_toc ?
				(last_entry - global_base) : (toc_ext->entries_count - 1);

		least_entry_offset = toc_entry_offset + ((local_last + 1) * MANIFEST_V2_TOC_ENTRY_SIZE);

		if (use_mocked_hash) {
			status |= hash_mock_expect_hash_start (&manifest->hash_mock, data->toc_hash_type);
		}

		/* Read the extension header. */
		status |= flash_mock_expect_read_and_hash (&manifest->flash, hash_mock, toc_ext_addr,
			toc_ext->toc, MANIFEST_V2_TOC_HEADER_SIZE);

		/* Hash entries before ext_local_start. */
		status |= flash_mock_expect_verify_flash_and_hash (&manifest->flash, hash_mock,
			toc_ext_addr + toc_entry_offset, (uint8_t*) toc_entries,
			local_start * MANIFEST_V2_TOC_ENTRY_SIZE);

		/* Individually read entries from ext_local_start through ext_local_last. */
		for (i = local_start; i <= local_last; i++) {
			status |= flash_mock_expect_read_and_hash (&manifest->flash, hash_mock,
				toc_ext_addr + toc_entry_offset + (i * MANIFEST_V2_TOC_ENTRY_SIZE),
				(uint8_t*) &toc_entries[i], MANIFEST_V2_TOC_ENTRY_SIZE);
		}

		if (exit_early_no_verify && last_entry_in_this_toc) {
			goto cancel;
		}
		else {
			if (last_entry_in_this_toc || (toc_ext_idx + 1 >= data->toc_extension_count)) {
				/* last_entry is in this ToC, OR beyond ToC but no following extension: verify remainder of ToC. */

				status |= flash_mock_expect_verify_flash_and_hash (&manifest->flash, hash_mock,
					toc_ext_addr + least_entry_offset, toc_ext->toc + least_entry_offset,
					toc_ext->toc_len - least_entry_offset);

				reached_last_entry = true;
			}
			else {
				/* last_entry is beyond the root ToC and there is an extension. */

				/* ToC extension hash is always the last one. */
				hash_offset = toc_entry_offset +
					(MANIFEST_V2_TOC_ENTRY_SIZE * toc_ext->entries_count) +
					(data->toc_hash_len * (toc_ext->hashes_count - 1));

				status |= flash_mock_expect_verify_flash_and_hash (&manifest->flash, hash_mock,
					toc_ext_addr + least_entry_offset, toc_ext->toc + least_entry_offset,
					hash_offset - least_entry_offset);

				status |= flash_mock_expect_read_and_hash (&manifest->flash, hash_mock,
					toc_ext_addr + hash_offset, toc_ext->toc + hash_offset, data->toc_hash_len);

				status |= flash_mock_expect_verify_flash_and_hash (&manifest->flash, hash_mock,
					toc_ext_addr + hash_offset + data->toc_hash_len,
					toc_ext->toc + hash_offset + data->toc_hash_len,
					toc_ext->toc_len - hash_offset - data->toc_hash_len);
			}

			if (use_mocked_hash) {
				/* TOC hash */
				status |= mock_expect (&manifest->hash_mock.mock, manifest->hash_mock.base.finish,
					&manifest->hash_mock, 0, MOCK_ARG_NOT_NULL, MOCK_ARG (SHA512_HASH_LENGTH));
				status |= mock_expect_output (&manifest->hash_mock.mock, 0, data->toc_hash,
					data->toc_hash_len,	1);
			}
		}

		global_base += toc_ext->entries_count;
	}

	CuAssertIntEquals (test, 0, status);

	return;

cancel:
	if (use_mocked_hash) {
		status |= mock_expect (&manifest->hash_mock.mock, manifest->hash_mock.base.cancel,
			&manifest->hash_mock, 0);
	}

	CuAssertIntEquals (test, 0, status);
}


/**
 * Set expectations on mocks for iterating through manifest TOC in a v2 manifest.
 *
 * @param test The testing framework.
 * @param manifest The components for the test.
 * @param data Manifest data for the test.
 * @param entry The table of contents index to start searching at.
 * @param last_entry The last entry index to check.
 */
void manifest_flash_v3_testing_iterate_manifest_toc (CuTest *test,
	struct manifest_flash_v3_testing *manifest, const struct manifest_v2_testing_data *data,
	int entry, int last_entry)
{
	return manifest_flash_v3_testing_iterate_manifest_toc_common (test, manifest, data, entry,
		last_entry, false, false);
}

/**
 * Set expectations on mocks for iterating through manifest TOC in a v2 manifest but do not verify
 * TOC after iteration.
 *
 * @param test The testing framework.
 * @param manifest The components for the test.
 * @param data Manifest data for the test.
 * @param entry The table of contents index to start searching at.
 * @param last_entry The last entry index to check.
 */
void manifest_flash_v3_testing_iterate_manifest_toc_no_verify (CuTest *test,
	struct manifest_flash_v3_testing *manifest, const struct manifest_v2_testing_data *data,
	int entry, int last_entry)
{
	return manifest_flash_v3_testing_iterate_manifest_toc_common (test, manifest, data, entry,
		last_entry, true, false);
}

/**
 * Set expectations on mocks for getting number of child elements for an element in a v2 manifest.
 * The mocked hashing engine will be used.
 *
 * @param test The testing framework.
 * @param manifest The components for the test.
 * @param data Manifest data for the test.
 * @param entry The table of contents index to start searching at.
 * @param last_entry The last entry index to check.
 */
void manifest_flash_v3_testing_iterate_manifest_toc_mocked_hash (CuTest *test,
	struct manifest_flash_v3_testing *manifest, const struct manifest_v2_testing_data *data,
	int entry, int last_entry)
{
	return manifest_flash_v3_testing_iterate_manifest_toc_common (test, manifest, data, entry,
		last_entry, false, true);
}

/*******************
 * Test cases
 *******************/

static void manifest_flash_v3_test_init (CuTest *test)
{
	struct manifest_flash_v3_testing manifest;
	uint32_t bytes = 0x1000;
	int status;

	TEST_START;

	manifest_flash_v3_testing_init_dependencies (test, &manifest, 0x10000);

	status = mock_expect (&manifest.flash.mock, manifest.flash.base.get_block_size, &manifest.flash,
		0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manifest.flash.mock, 0, &bytes, sizeof (bytes), -1);

	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_v3_init (&manifest.test, &manifest.state, &manifest.flash.base,
		&manifest.hash.base, 0x10000, MANIFEST_NOT_SUPPORTED, CFM_V2_MAGIC_NUM, CFM_V3_MAGIC_NUM,
		manifest.signature,	sizeof (manifest.signature), manifest.platform_id,
		sizeof (manifest.platform_id));
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, 0x10000, manifest_flash_get_addr (&manifest.test));
	CuAssertPtrEquals (test, &manifest.flash, (void*) manifest_flash_get_flash (&manifest.test));

	manifest_flash_v3_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_v3_test_init_null (CuTest *test)
{
	struct manifest_flash_v3_testing manifest;
	int status;

	TEST_START;

	manifest_flash_v3_testing_init_dependencies (test, &manifest, 0x10000);

	status = manifest_flash_v3_init (NULL, &manifest.state, &manifest.flash.base,
		&manifest.hash.base, 0x10000, MANIFEST_NOT_SUPPORTED, CFM_V2_MAGIC_NUM, CFM_V3_MAGIC_NUM,
		manifest.signature,	sizeof (manifest.signature), manifest.platform_id,
		sizeof (manifest.platform_id));
	CuAssertIntEquals (test, MANIFEST_INVALID_ARGUMENT, status);

	status = manifest_flash_v3_init (&manifest.test, NULL, &manifest.flash.base,
		&manifest.hash.base, 0x10000, MANIFEST_NOT_SUPPORTED, CFM_V2_MAGIC_NUM, CFM_V3_MAGIC_NUM,
		manifest.signature,	sizeof (manifest.signature), manifest.platform_id,
		sizeof (manifest.platform_id));
	CuAssertIntEquals (test, MANIFEST_INVALID_ARGUMENT, status);

	status = manifest_flash_v3_init (&manifest.test, &manifest.state, NULL,	&manifest.hash.base,
		0x10000, MANIFEST_NOT_SUPPORTED, CFM_V2_MAGIC_NUM, CFM_V3_MAGIC_NUM, manifest.signature,
		sizeof (manifest.signature), manifest.platform_id, sizeof (manifest.platform_id));
	CuAssertIntEquals (test, MANIFEST_INVALID_ARGUMENT, status);

	status = manifest_flash_v3_init (&manifest.test, &manifest.state, &manifest.flash.base,	NULL,
		0x10000, MANIFEST_NOT_SUPPORTED, CFM_V2_MAGIC_NUM, CFM_V3_MAGIC_NUM, manifest.signature,
		sizeof (manifest.signature), manifest.platform_id, sizeof (manifest.platform_id));
	CuAssertIntEquals (test, MANIFEST_INVALID_ARGUMENT, status);

	status = manifest_flash_v3_init (&manifest.test, &manifest.state, &manifest.flash.base,
		&manifest.hash.base, 0x10000, MANIFEST_NOT_SUPPORTED, CFM_V2_MAGIC_NUM, CFM_V3_MAGIC_NUM,
		NULL, sizeof (manifest.signature), manifest.platform_id, sizeof (manifest.platform_id));
	CuAssertIntEquals (test, MANIFEST_INVALID_ARGUMENT, status);

	status = manifest_flash_v3_init (&manifest.test, &manifest.state, &manifest.flash.base,
		&manifest.hash.base, 0x10000, MANIFEST_NOT_SUPPORTED, CFM_V2_MAGIC_NUM, CFM_V3_MAGIC_NUM,
		manifest.signature,	sizeof (manifest.signature), NULL, sizeof (manifest.platform_id));
	CuAssertIntEquals (test, MANIFEST_INVALID_ARGUMENT, status);

	manifest_flash_v3_testing_validate_and_release_dependencies (test, &manifest);
}

static void manifest_flash_v3_test_init_not_aligned (CuTest *test)
{
	struct manifest_flash_v3_testing manifest;
	uint32_t bytes = 0x1000;
	int status;

	TEST_START;

	manifest_flash_v3_testing_init_dependencies (test, &manifest, 0x10100);

	status = mock_expect (&manifest.flash.mock, manifest.flash.base.get_block_size, &manifest.flash,
		0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manifest.flash.mock, 0, &bytes, sizeof (bytes), -1);

	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_v3_init (&manifest.test, &manifest.state, &manifest.flash.base,
		&manifest.hash.base, 0x10100, MANIFEST_NOT_SUPPORTED, CFM_V2_MAGIC_NUM, CFM_V3_MAGIC_NUM,
		manifest.signature,	sizeof (manifest.signature), manifest.platform_id,
		sizeof (manifest.platform_id));
	CuAssertIntEquals (test, MANIFEST_STORAGE_NOT_ALIGNED, status);

	manifest_flash_v3_testing_validate_and_release_dependencies (test, &manifest);
}

static void manifest_flash_v3_test_init_block_size_error (CuTest *test)
{
	struct manifest_flash_v3_testing manifest;
	int status;

	TEST_START;

	manifest_flash_v3_testing_init_dependencies (test, &manifest, 0x10000);

	status = mock_expect (&manifest.flash.mock, manifest.flash.base.get_block_size, &manifest.flash,
		FLASH_BLOCK_SIZE_FAILED, MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_v3_init (&manifest.test, &manifest.state, &manifest.flash.base,
		&manifest.hash.base, 0x10000, MANIFEST_NOT_SUPPORTED, CFM_V2_MAGIC_NUM, CFM_V3_MAGIC_NUM,
		manifest.signature,	sizeof (manifest.signature), manifest.platform_id,
		sizeof (manifest.platform_id));
	CuAssertIntEquals (test, FLASH_BLOCK_SIZE_FAILED, status);

	manifest_flash_v3_testing_validate_and_release_dependencies (test, &manifest);
}

static void manifest_flash_v3_test_static_init (CuTest *test)
{
	struct manifest_flash_v3_testing manifest = {
		.test = manifest_flash_v3_static_init (&manifest.state, &manifest.flash.base,
			&manifest.hash.base, 0x10000, MANIFEST_NOT_SUPPORTED, CFM_V2_MAGIC_NUM,
			CFM_V3_MAGIC_NUM, manifest.signature, sizeof (manifest.signature), manifest.platform_id,
			sizeof (manifest.platform_id))
	};
	uint32_t bytes = 0x1000;
	int status;

	TEST_START;

	manifest_flash_v3_testing_init_dependencies (test, &manifest, 0x10000);

	status = mock_expect (&manifest.flash.mock, manifest.flash.base.get_block_size, &manifest.flash,
		0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manifest.flash.mock, 0, &bytes, sizeof (bytes), -1);

	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_init_state (&manifest.test);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, 0x10000, manifest_flash_get_addr (&manifest.test));
	CuAssertPtrEquals (test, &manifest.flash, (void*) manifest_flash_get_flash (&manifest.test));

	manifest_flash_v3_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_v3_test_static_init_null (CuTest *test)
{
	struct manifest_flash_v3_testing manifest = {
		.test = manifest_flash_v3_static_init (&manifest.state, &manifest.flash.base,
			&manifest.hash.base, 0x10000, MANIFEST_NOT_SUPPORTED, CFM_V2_MAGIC_NUM,
			CFM_V3_MAGIC_NUM, manifest.signature, sizeof (manifest.signature), manifest.platform_id,
			sizeof (manifest.platform_id))
	};

	struct manifest_flash null_state = manifest_flash_v3_static_init (NULL, &manifest.flash.base,
		&manifest.hash.base, 0x10000, MANIFEST_NOT_SUPPORTED, CFM_V2_MAGIC_NUM, CFM_V3_MAGIC_NUM,
		manifest.signature,	sizeof (manifest.signature), manifest.platform_id,
		sizeof (manifest.platform_id));

	struct manifest_flash null_flash = manifest_flash_v3_static_init (&manifest.state, NULL,
		&manifest.hash.base, 0x10000, MANIFEST_NOT_SUPPORTED, CFM_V2_MAGIC_NUM, CFM_V3_MAGIC_NUM,
		manifest.signature,	sizeof (manifest.signature), manifest.platform_id,
		sizeof (manifest.platform_id));

	struct manifest_flash null_hash = manifest_flash_v3_static_init (&manifest.state,
		&manifest.flash.base, NULL, 0x10000, MANIFEST_NOT_SUPPORTED, CFM_V2_MAGIC_NUM,
		CFM_V3_MAGIC_NUM, manifest.signature, sizeof (manifest.signature), manifest.platform_id,
		sizeof (manifest.platform_id));

	struct manifest_flash null_sig = manifest_flash_v3_static_init (&manifest.state,
		&manifest.flash.base, &manifest.hash.base, 0x10000, MANIFEST_NOT_SUPPORTED,
		CFM_V2_MAGIC_NUM, CFM_V3_MAGIC_NUM, NULL, sizeof (manifest.signature), manifest.platform_id,
		sizeof (manifest.platform_id));

	struct manifest_flash null_plat_id = manifest_flash_v3_static_init (&manifest.state,
		&manifest.flash.base, &manifest.hash.base, 0x10000, MANIFEST_NOT_SUPPORTED,
		CFM_V2_MAGIC_NUM, CFM_V3_MAGIC_NUM,	manifest.signature, sizeof (manifest.signature), NULL,
		sizeof (manifest.platform_id));
	int status;

	TEST_START;

	manifest_flash_v3_testing_init_dependencies (test, &manifest, 0x10000);

	status = manifest_flash_init_state (NULL);
	CuAssertIntEquals (test, MANIFEST_INVALID_ARGUMENT, status);

	status = manifest_flash_init_state (&null_state);
	CuAssertIntEquals (test, MANIFEST_INVALID_ARGUMENT, status);

	status = manifest_flash_init_state (&null_flash);
	CuAssertIntEquals (test, MANIFEST_INVALID_ARGUMENT, status);

	status = manifest_flash_init_state (&null_hash);
	CuAssertIntEquals (test, MANIFEST_INVALID_ARGUMENT, status);

	status = manifest_flash_init_state (&null_sig);
	CuAssertIntEquals (test, MANIFEST_INVALID_ARGUMENT, status);

	status = manifest_flash_init_state (&null_plat_id);
	CuAssertIntEquals (test, MANIFEST_INVALID_ARGUMENT, status);

	manifest_flash_v3_testing_validate_and_release_dependencies (test, &manifest);
}

static void manifest_flash_v3_test_verify_v1_unsupported (CuTest *test)
{
	struct manifest_flash_v3_testing manifest;
	int status;

	TEST_START;

	manifest_flash_v3_testing_init (test, &manifest, 0x10000, MANIFEST_NOT_SUPPORTED,
		CFM_V2_MAGIC_NUM, CFM_V3_MAGIC_NUM);

	status = mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash, 0,
		MOCK_ARG (manifest.addr), MOCK_ARG_NOT_NULL, MOCK_ARG (PFM_HEADER_SIZE));
	status |= mock_expect_output (&manifest.flash.mock, 1, PFM_DATA, PFM_DATA_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_verify (&manifest.test, &manifest.hash.base,
		&manifest.verification.base, NULL, 0);
	CuAssertIntEquals (test, MANIFEST_BAD_MAGIC_NUMBER, status);

	manifest_flash_v3_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_v3_test_verify_v1_unsupported_static_init (CuTest *test)
{
	struct manifest_flash_v3_testing manifest = {
		.test = manifest_flash_v3_static_init (&manifest.state, &manifest.flash.base,
			&manifest.hash.base, 0x10000, MANIFEST_NOT_SUPPORTED, CFM_V2_MAGIC_NUM,
			CFM_V3_MAGIC_NUM, manifest.signature, sizeof (manifest.signature), manifest.platform_id,
			sizeof (manifest.platform_id))
	};
	int status;

	TEST_START;

	manifest_flash_v3_testing_init_static (test, &manifest, 0x10000);

	status = mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash, 0,
		MOCK_ARG (manifest.addr), MOCK_ARG_NOT_NULL, MOCK_ARG (PFM_HEADER_SIZE));
	status |= mock_expect_output (&manifest.flash.mock, 1, PFM_DATA, PFM_DATA_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_verify (&manifest.test, &manifest.hash.base,
		&manifest.verification.base, NULL, 0);
	CuAssertIntEquals (test, MANIFEST_BAD_MAGIC_NUMBER, status);

	manifest_flash_v3_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_v3_test_verify_v2_unsupported (CuTest *test)
{
	struct manifest_flash_v3_testing manifest;
	int status;

	TEST_START;

	manifest_flash_v3_testing_init (test, &manifest, 0x10000, MANIFEST_NOT_SUPPORTED,
		MANIFEST_NOT_SUPPORTED, CFM_V3_MAGIC_NUM);

	status = mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash, 0,
		MOCK_ARG (manifest.addr), MOCK_ARG_NOT_NULL, MOCK_ARG (MANIFEST_V2_HEADER_SIZE));
	status |= mock_expect_output (&manifest.flash.mock, 1, CFM_TESTING.manifest.raw,
		MANIFEST_V2_HEADER_SIZE, 2);

	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_verify (&manifest.test, &manifest.hash.base,
		&manifest.verification.base, NULL, 0);
	CuAssertIntEquals (test, MANIFEST_BAD_MAGIC_NUMBER, status);

	manifest_flash_v3_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_v3_test_verify_v2_unsupported_static_init (CuTest *test)
{
	struct manifest_flash_v3_testing manifest = {
		.test = manifest_flash_v3_static_init (&manifest.state, &manifest.flash.base,
			&manifest.hash.base, 0x10000, MANIFEST_NOT_SUPPORTED, MANIFEST_NOT_SUPPORTED,
			CFM_V3_MAGIC_NUM, manifest.signature, sizeof (manifest.signature), manifest.platform_id,
			sizeof (manifest.platform_id))
	};
	int status;

	TEST_START;

	manifest_flash_v3_testing_init_static (test, &manifest, 0x10000);

	status = mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash, 0,
		MOCK_ARG (manifest.addr), MOCK_ARG_NOT_NULL, MOCK_ARG (MANIFEST_V2_HEADER_SIZE));
	status |= mock_expect_output (&manifest.flash.mock, 1, CFM_TESTING.manifest.raw,
		MANIFEST_V2_HEADER_SIZE, 2);

	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_verify (&manifest.test, &manifest.hash.base,
		&manifest.verification.base, NULL, 0);
	CuAssertIntEquals (test, MANIFEST_BAD_MAGIC_NUMBER, status);

	manifest_flash_v3_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_v3_test_verify_bad_magic_number (CuTest *test)
{
	struct manifest_flash_v3_testing manifest;
	int status;
	struct manifest_header header;

	TEST_START;

	memcpy (&header, PFM_V2.manifest.raw, sizeof (header));
	header.magic ^= 0x55;

	manifest_flash_v3_testing_init (test, &manifest, 0x10000, PFM_MAGIC_NUM, PFM_V2_MAGIC_NUM,
		CFM_V3_MAGIC_NUM);

	status = mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash, 0,
		MOCK_ARG (manifest.addr), MOCK_ARG_NOT_NULL, MOCK_ARG (MANIFEST_V2_HEADER_SIZE));
	status |= mock_expect_output (&manifest.flash.mock, 1, &header, sizeof (header), 2);

	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_verify (&manifest.test, &manifest.hash.base,
		&manifest.verification.base, NULL, 0);
	CuAssertIntEquals (test, MANIFEST_BAD_MAGIC_NUMBER, status);

	manifest_flash_v3_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_v3_test_verify_bad_magic_number_v1_unsupported (CuTest *test)
{
	struct manifest_flash_v3_testing manifest;
	int status;
	struct manifest_header header;

	TEST_START;

	memcpy (&header, PFM_V2.manifest.raw, sizeof (header));
	header.magic = MANIFEST_NOT_SUPPORTED;

	manifest_flash_v3_testing_init (test, &manifest, 0x10000, MANIFEST_NOT_SUPPORTED,
		CFM_V2_MAGIC_NUM, CFM_V3_MAGIC_NUM);

	status = mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash, 0,
		MOCK_ARG (manifest.addr), MOCK_ARG_NOT_NULL, MOCK_ARG (MANIFEST_V2_HEADER_SIZE));
	status |= mock_expect_output (&manifest.flash.mock, 1, &header, sizeof (header), 2);

	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_verify (&manifest.test, &manifest.hash.base,
		&manifest.verification.base, NULL, 0);
	CuAssertIntEquals (test, MANIFEST_BAD_MAGIC_NUMBER, status);

	manifest_flash_v3_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_v3_test_verify_bad_magic_number_v2_unsupported (CuTest *test)
{
	struct manifest_flash_v3_testing manifest;
	int status;
	struct manifest_header header;

	TEST_START;

	memcpy (&header, PFM_V2.manifest.raw, sizeof (header));
	header.magic = MANIFEST_NOT_SUPPORTED;

	manifest_flash_v3_testing_init (test, &manifest, 0x10000, PFM_MAGIC_NUM, MANIFEST_NOT_SUPPORTED,
		MANIFEST_NOT_SUPPORTED);

	status = mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash, 0,
		MOCK_ARG (manifest.addr), MOCK_ARG_NOT_NULL, MOCK_ARG (MANIFEST_V2_HEADER_SIZE));
	status |= mock_expect_output (&manifest.flash.mock, 1, &header, sizeof (header), 2);

	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_verify (&manifest.test, &manifest.hash.base,
		&manifest.verification.base, NULL, 0);
	CuAssertIntEquals (test, MANIFEST_BAD_MAGIC_NUMBER, status);

	manifest_flash_v3_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_v3_test_verify_bad_magic_number_v3_unsupported (CuTest *test)
{
	struct manifest_flash_v3_testing manifest;
	int status;
	struct manifest_header header;

	TEST_START;

	memcpy (&header, PFM_V2.manifest.raw, sizeof (header));
	header.magic = MANIFEST_NOT_SUPPORTED;

	manifest_flash_v3_testing_init (test, &manifest, 0x10000, PFM_MAGIC_NUM, PFM_V2_MAGIC_NUM,
		MANIFEST_NOT_SUPPORTED);

	status = mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash, 0,
		MOCK_ARG (manifest.addr), MOCK_ARG_NOT_NULL, MOCK_ARG (MANIFEST_V2_HEADER_SIZE));
	status |= mock_expect_output (&manifest.flash.mock, 1, &header, sizeof (header), 2);

	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_verify (&manifest.test, &manifest.hash.base,
		&manifest.verification.base, NULL, 0);
	CuAssertIntEquals (test, MANIFEST_BAD_MAGIC_NUMBER, status);

	manifest_flash_v3_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_v3_test_verify_bad_magic_number_none_supported (CuTest *test)
{
	struct manifest_flash_v3_testing manifest;
	int status;
	struct manifest_header header;

	TEST_START;

	memcpy (&header, PFM_V2.manifest.raw, sizeof (header));
	header.magic = 0x1234;

	manifest_flash_v3_testing_init (test, &manifest, 0x10000, MANIFEST_NOT_SUPPORTED,
		MANIFEST_NOT_SUPPORTED,	MANIFEST_NOT_SUPPORTED);

	status = mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash, 0,
		MOCK_ARG (manifest.addr), MOCK_ARG_NOT_NULL, MOCK_ARG (MANIFEST_V2_HEADER_SIZE));
	status |= mock_expect_output (&manifest.flash.mock, 1, &header, sizeof (header), 2);

	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_verify (&manifest.test, &manifest.hash.base,
		&manifest.verification.base, NULL, 0);
	CuAssertIntEquals (test, MANIFEST_BAD_MAGIC_NUMBER, status);

	manifest_flash_v3_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_v3_test_verify_toc_extension (CuTest *test)
{
	struct manifest_flash_v3_testing manifest;
	int status;

	TEST_START;

	manifest_flash_v3_testing_init (test, &manifest, 0x10000, MANIFEST_NOT_SUPPORTED,
		CFM_V2_MAGIC_NUM, CFM_V3_MAGIC_NUM);

	manifest_flash_v3_testing_verify_manifest (test, &manifest,
		&CFM_MANY_MEASUREMENTS_TESTING.manifest, 0);

	status = manifest_flash_verify (&manifest.test, &manifest.hash.base,
		&manifest.verification.base, NULL, 0);
	CuAssertIntEquals (test, 0, status);

	manifest_flash_v3_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_v3_test_verify_toc_extension_with_mock_hash (CuTest *test)
{
	struct manifest_flash_v3_testing manifest;
	int status;

	TEST_START;

	manifest_flash_v3_testing_init (test, &manifest, 0x10000, MANIFEST_NOT_SUPPORTED,
		CFM_V2_MAGIC_NUM, CFM_V3_MAGIC_NUM);

	manifest_flash_v3_testing_verify_manifest_mocked_hash (test, &manifest,
		&CFM_MANY_MEASUREMENTS_TESTING.manifest, 0, 0);

	status = manifest_flash_verify (&manifest.test, &manifest.hash_mock.base,
		&manifest.verification.base, NULL, 0);
	CuAssertIntEquals (test, 0, status);

	manifest_flash_v3_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_v3_test_verify_toc_extension_not_allowed (CuTest *test)
{
	struct manifest_flash_v3_testing manifest;
	int status;
	const struct manifest_v2_testing_data *data = &CFM_MANY_MEASUREMENTS_TESTING.manifest;
	uint32_t toc_entry_offset = MANIFEST_V2_TOC_ENTRY_OFFSET;
	const struct manifest_toc_entry *toc_entries =
		(struct manifest_toc_entry*) (data->raw + toc_entry_offset);
	uint32_t validate_toc_start = toc_entry_offset;
	int i;
	struct manifest_header manifest_header;

	TEST_START;

	manifest_header = *(struct manifest_header*) data->raw;
	manifest_header.magic = CFM_V2_MAGIC_NUM;

	manifest_flash_v3_testing_init (test, &manifest, 0x10000, MANIFEST_NOT_SUPPORTED,
		CFM_V2_MAGIC_NUM, MANIFEST_NOT_SUPPORTED);

	status = mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash, 0,
		MOCK_ARG (manifest.addr), MOCK_ARG_NOT_NULL, MOCK_ARG (MANIFEST_V2_HEADER_SIZE));
	status |= mock_expect_output (&manifest.flash.mock, 1, &manifest_header,
		MANIFEST_V2_HEADER_SIZE, 2);

	status |= mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash, 0,
		MOCK_ARG (manifest.addr + data->sig_offset), MOCK_ARG_NOT_NULL, MOCK_ARG (data->sig_len));
	status |= mock_expect_output (&manifest.flash.mock, 1, data->signature, data->sig_len, 2);

	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.start_sha256,
		&manifest.hash_mock, 0);

	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.update,
		&manifest.hash_mock, 0, MOCK_ARG_PTR_CONTAINS (&manifest_header, MANIFEST_V2_HEADER_SIZE),
		MOCK_ARG (MANIFEST_V2_HEADER_SIZE));

	status |= flash_mock_expect_read_and_hash (&manifest.flash, &manifest.hash_mock,
		manifest.addr + MANIFEST_V2_TOC_HDR_OFFSET, data->toc, MANIFEST_V2_TOC_HEADER_SIZE);

	for (i = 0; i < data->toc_entries; i++, validate_toc_start += MANIFEST_V2_TOC_ENTRY_SIZE) {
		status |= flash_mock_expect_read_and_hash (&manifest.flash, &manifest.hash_mock,
			manifest.addr + toc_entry_offset + (i * MANIFEST_V2_TOC_ENTRY_SIZE),
			(uint8_t*) &toc_entries[i], MANIFEST_V2_TOC_ENTRY_SIZE);
	}

	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.cancel,
		&manifest.hash_mock, 0);

	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_verify (&manifest.test, &manifest.hash_mock.base,
		&manifest.verification.base, NULL, 0);
	CuAssertIntEquals (test, MANIFEST_TOC_EXTENSION_INVALID, status);

	manifest_flash_v3_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_v3_test_verify_toc_extension_not_the_last_entry (CuTest *test)
{
	struct manifest_flash_v3_testing manifest;
	int status;
	const struct manifest_v2_testing_data *data = &CFM_MANY_MEASUREMENTS_TESTING.manifest;
	uint32_t toc_entry_offset = MANIFEST_V2_TOC_ENTRY_OFFSET;
	const struct manifest_toc_entry *toc_entries =
		(struct manifest_toc_entry*) (data->raw + toc_entry_offset);
	uint32_t validate_toc_start = toc_entry_offset;
	int i;

	TEST_START;

	manifest_flash_v3_testing_init (test, &manifest, 0x10000, MANIFEST_NOT_SUPPORTED,
		CFM_V2_MAGIC_NUM, CFM_V3_MAGIC_NUM);

	status = mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash, 0,
		MOCK_ARG (manifest.addr), MOCK_ARG_NOT_NULL, MOCK_ARG (MANIFEST_V2_HEADER_SIZE));
	status |= mock_expect_output (&manifest.flash.mock, 1, data->raw, MANIFEST_V2_HEADER_SIZE, 2);

	status |= mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash, 0,
		MOCK_ARG (manifest.addr + data->sig_offset), MOCK_ARG_NOT_NULL, MOCK_ARG (data->sig_len));
	status |= mock_expect_output (&manifest.flash.mock, 1, data->signature, data->sig_len, 2);

	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.start_sha256,
		&manifest.hash_mock, 0);
	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.update,
		&manifest.hash_mock, 0, MOCK_ARG_PTR_CONTAINS (data->raw, MANIFEST_V2_HEADER_SIZE),
		MOCK_ARG (MANIFEST_V2_HEADER_SIZE));

	status |= flash_mock_expect_read_and_hash (&manifest.flash, &manifest.hash_mock,
		manifest.addr + MANIFEST_V2_TOC_HDR_OFFSET, data->toc, MANIFEST_V2_TOC_HEADER_SIZE);

	for (i = 0; i < (data->toc_entries - 2);
		i++, validate_toc_start += MANIFEST_V2_TOC_ENTRY_SIZE) {
		status |= flash_mock_expect_read_and_hash (&manifest.flash, &manifest.hash_mock,
			manifest.addr + toc_entry_offset + (i * MANIFEST_V2_TOC_ENTRY_SIZE),
			(uint8_t*) &toc_entries[i], MANIFEST_V2_TOC_ENTRY_SIZE);
	}

	status |= flash_mock_expect_read_and_hash (&manifest.flash, &manifest.hash_mock,
		manifest.addr + toc_entry_offset + (i * MANIFEST_V2_TOC_ENTRY_SIZE),
		(uint8_t*) &toc_entries[i + 1], MANIFEST_V2_TOC_ENTRY_SIZE);

	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.cancel,
		&manifest.hash_mock, 0);

	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_verify (&manifest.test, &manifest.hash_mock.base,
		&manifest.verification.base, NULL, 0);
	CuAssertIntEquals (test, MANIFEST_TOC_EXTENSION_INVALID, status);

	manifest_flash_v3_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_v3_test_verify_toc_extension_hash_mismatch (CuTest *test)
{
	struct manifest_flash_v3_testing manifest;
	int status;
	const struct manifest_v2_testing_data *data = &CFM_MANY_MEASUREMENTS_TESTING.manifest;
	uint32_t toc_entry_offset = MANIFEST_V2_TOC_ENTRY_OFFSET;
	const struct manifest_toc_entry *toc_entries =
		(struct manifest_toc_entry*) (data->raw + toc_entry_offset);
	uint32_t validate_toc_start = toc_entry_offset;
	uint32_t validate_start = data->toc_hash_offset + data->toc_hash_len;
	uint32_t validate_end = data->plat_id_offset;
	uint32_t validate_resume =
		data->plat_id_offset + MANIFEST_V2_PLATFORM_HEADER_SIZE + data->plat_id_str_len;

	int i;
	struct manifest_toc_header hdr =
		*(struct manifest_toc_header*) (data->raw + MANIFEST_V2_TOC_HDR_OFFSET);

	TEST_START;

	hdr.hash_type += 1;

	manifest_flash_v3_testing_init (test, &manifest, 0x10000, MANIFEST_NOT_SUPPORTED,
		CFM_V2_MAGIC_NUM, CFM_V3_MAGIC_NUM);

	status = mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash, 0,
		MOCK_ARG (manifest.addr), MOCK_ARG_NOT_NULL, MOCK_ARG (MANIFEST_V2_HEADER_SIZE));
	status |= mock_expect_output (&manifest.flash.mock, 1, data->raw, MANIFEST_V2_HEADER_SIZE, 2);

	status |= mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash, 0,
		MOCK_ARG (manifest.addr + data->sig_offset), MOCK_ARG_NOT_NULL, MOCK_ARG (data->sig_len));
	status |= mock_expect_output (&manifest.flash.mock, 1, data->signature, data->sig_len, 2);

	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.start_sha256,
		&manifest.hash_mock, 0);
	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.update,
		&manifest.hash_mock, 0, MOCK_ARG_PTR_CONTAINS (data->raw, MANIFEST_V2_HEADER_SIZE),
		MOCK_ARG (MANIFEST_V2_HEADER_SIZE));

	status |= flash_mock_expect_read_and_hash (&manifest.flash, &manifest.hash_mock,
		manifest.addr + MANIFEST_V2_TOC_HDR_OFFSET, data->toc, MANIFEST_V2_TOC_HEADER_SIZE);

	for (i = 0; i < data->toc_entries; i++, validate_toc_start += MANIFEST_V2_TOC_ENTRY_SIZE) {
		status |= flash_mock_expect_read_and_hash (&manifest.flash, &manifest.hash_mock,
			manifest.addr + toc_entry_offset + (i * MANIFEST_V2_TOC_ENTRY_SIZE),
			(uint8_t*) &toc_entries[i], MANIFEST_V2_TOC_ENTRY_SIZE);
	}

	status |= flash_mock_expect_verify_flash_and_hash (&manifest.flash, &manifest.hash_mock,
		manifest.addr + validate_toc_start, data->raw + validate_toc_start,
		data->toc_hash_offset - validate_toc_start);

	status |= flash_mock_expect_read_and_hash (&manifest.flash, &manifest.hash_mock,
		manifest.addr + data->toc_hash_offset, data->toc_hash, data->toc_hash_len);

	status |= flash_mock_expect_verify_flash_and_hash (&manifest.flash, &manifest.hash_mock,
		manifest.addr + validate_start, data->raw + validate_start, validate_end - validate_start);

	status |= flash_mock_expect_read_and_hash (&manifest.flash, &manifest.hash_mock,
		manifest.addr + data->plat_id_offset, data->plat_id, MANIFEST_V2_PLATFORM_HEADER_SIZE);

	status |= flash_mock_expect_read_and_hash (&manifest.flash, &manifest.hash_mock,
		manifest.addr + data->plat_id_offset + MANIFEST_V2_PLATFORM_HEADER_SIZE, data->plat_id,
		data->plat_id_str_len);

	status |= flash_mock_expect_verify_flash_and_hash (&manifest.flash, &manifest.hash_mock,
		manifest.addr + validate_resume, data->raw + validate_resume,
		data->toc_extensions[0].toc_offset - validate_resume);

	status |= mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash, 0,
		MOCK_ARG (manifest.addr + data->toc_extensions[0].toc_offset), MOCK_ARG_NOT_NULL,
		MOCK_ARG (MANIFEST_V2_TOC_HEADER_SIZE));
	status |= mock_expect_output (&manifest.flash.mock, 1, &hdr, MANIFEST_V2_TOC_HEADER_SIZE, 2);

	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.update,
		&manifest.hash_mock, 0, MOCK_ARG_PTR_CONTAINS (&hdr, MANIFEST_V2_TOC_HEADER_SIZE),
		MOCK_ARG (MANIFEST_V2_TOC_HEADER_SIZE));

	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.cancel,
		&manifest.hash_mock, 0);

	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_verify (&manifest.test, &manifest.hash_mock.base,
		&manifest.verification.base, NULL, 0);
	CuAssertIntEquals (test, MANIFEST_TOC_HASH_ALGO_MISMATCH, status);

	manifest_flash_v3_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_v3_test_verify_toc_extension_length_mismatch (CuTest *test)
{
	struct manifest_flash_v3_testing manifest;
	int status;
	const struct manifest_v2_testing_data *data = &CFM_MANY_MEASUREMENTS_TESTING.manifest;
	uint32_t toc_entry_offset = MANIFEST_V2_TOC_ENTRY_OFFSET;
	const struct manifest_toc_entry *toc_entries =
		(struct manifest_toc_entry*) (data->raw + toc_entry_offset);
	uint32_t validate_toc_start = toc_entry_offset;
	uint32_t validate_start = data->toc_hash_offset + data->toc_hash_len;
	uint32_t validate_end = data->plat_id_offset;
	uint32_t validate_resume =
		data->plat_id_offset + MANIFEST_V2_PLATFORM_HEADER_SIZE + data->plat_id_str_len;

	int i;
	struct manifest_toc_header hdr =
		*(struct manifest_toc_header*) (data->toc_extensions[0].toc);

	TEST_START;

	hdr.hash_count -= 1;

	manifest_flash_v3_testing_init (test, &manifest, 0x10000, MANIFEST_NOT_SUPPORTED,
		CFM_V2_MAGIC_NUM, CFM_V3_MAGIC_NUM);

	status = mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash, 0,
		MOCK_ARG (manifest.addr), MOCK_ARG_NOT_NULL, MOCK_ARG (MANIFEST_V2_HEADER_SIZE));
	status |= mock_expect_output (&manifest.flash.mock, 1, data->raw, MANIFEST_V2_HEADER_SIZE, 2);

	status |= mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash, 0,
		MOCK_ARG (manifest.addr + data->sig_offset), MOCK_ARG_NOT_NULL, MOCK_ARG (data->sig_len));
	status |= mock_expect_output (&manifest.flash.mock, 1, data->signature, data->sig_len, 2);

	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.start_sha256,
		&manifest.hash_mock, 0);
	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.update,
		&manifest.hash_mock, 0, MOCK_ARG_PTR_CONTAINS (data->raw, MANIFEST_V2_HEADER_SIZE),
		MOCK_ARG (MANIFEST_V2_HEADER_SIZE));

	status |= flash_mock_expect_read_and_hash (&manifest.flash, &manifest.hash_mock,
		manifest.addr + MANIFEST_V2_TOC_HDR_OFFSET, data->toc, MANIFEST_V2_TOC_HEADER_SIZE);

	for (i = 0; i < data->toc_entries; i++, validate_toc_start += MANIFEST_V2_TOC_ENTRY_SIZE) {
		status |= flash_mock_expect_read_and_hash (&manifest.flash, &manifest.hash_mock,
			manifest.addr + toc_entry_offset + (i * MANIFEST_V2_TOC_ENTRY_SIZE),
			(uint8_t*) &toc_entries[i], MANIFEST_V2_TOC_ENTRY_SIZE);
	}

	status |= flash_mock_expect_verify_flash_and_hash (&manifest.flash, &manifest.hash_mock,
		manifest.addr + validate_toc_start, data->raw + validate_toc_start,
		data->toc_hash_offset - validate_toc_start);

	status |= flash_mock_expect_read_and_hash (&manifest.flash, &manifest.hash_mock,
		manifest.addr + data->toc_hash_offset, data->toc_hash, data->toc_hash_len);

	status |= flash_mock_expect_verify_flash_and_hash (&manifest.flash, &manifest.hash_mock,
		manifest.addr + validate_start, data->raw + validate_start, validate_end - validate_start);

	status |= flash_mock_expect_read_and_hash (&manifest.flash, &manifest.hash_mock,
		manifest.addr + data->plat_id_offset, data->plat_id, MANIFEST_V2_PLATFORM_HEADER_SIZE);

	status |= flash_mock_expect_read_and_hash (&manifest.flash, &manifest.hash_mock,
		manifest.addr + data->plat_id_offset + MANIFEST_V2_PLATFORM_HEADER_SIZE, data->plat_id,
		data->plat_id_str_len);

	status |= flash_mock_expect_verify_flash_and_hash (&manifest.flash, &manifest.hash_mock,
		manifest.addr + validate_resume, data->raw + validate_resume,
		data->toc_extensions[0].toc_offset - validate_resume);

	status |= mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash, 0,
		MOCK_ARG (manifest.addr + data->toc_extensions[0].toc_offset), MOCK_ARG_NOT_NULL,
		MOCK_ARG (MANIFEST_V2_TOC_HEADER_SIZE));
	status |= mock_expect_output (&manifest.flash.mock, 1, &hdr, MANIFEST_V2_TOC_HEADER_SIZE, 2);

	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.update,
		&manifest.hash_mock, 0, MOCK_ARG_PTR_CONTAINS (&hdr, MANIFEST_V2_TOC_HEADER_SIZE),
		MOCK_ARG (MANIFEST_V2_TOC_HEADER_SIZE));

	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.cancel,
		&manifest.hash_mock, 0);

	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_verify (&manifest.test, &manifest.hash_mock.base,
		&manifest.verification.base, NULL, 0);
	CuAssertIntEquals (test, MANIFEST_TOC_EXTENSION_INVALID, status);

	manifest_flash_v3_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_v3_test_verify_toc_extension_zero_entries (CuTest *test)
{
	struct manifest_flash_v3_testing manifest;
	int status;
	const struct manifest_v2_testing_data *data = &CFM_MANY_MEASUREMENTS_TESTING.manifest;
	uint32_t toc_entry_offset = MANIFEST_V2_TOC_ENTRY_OFFSET;
	const struct manifest_toc_entry *toc_entries =
		(struct manifest_toc_entry*) (data->raw + toc_entry_offset);
	uint32_t validate_toc_start = toc_entry_offset;
	uint32_t validate_start = data->toc_hash_offset + data->toc_hash_len;
	uint32_t validate_end = data->plat_id_offset;
	uint32_t validate_resume =
		data->plat_id_offset + MANIFEST_V2_PLATFORM_HEADER_SIZE + data->plat_id_str_len;

	int i;
	struct manifest_toc_header hdr =
		*(struct manifest_toc_header*) (data->toc_extensions[0].toc);

	TEST_START;

	hdr.entry_count = 0;

	manifest_flash_v3_testing_init (test, &manifest, 0x10000, MANIFEST_NOT_SUPPORTED,
		CFM_V2_MAGIC_NUM, CFM_V3_MAGIC_NUM);

	status = mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash, 0,
		MOCK_ARG (manifest.addr), MOCK_ARG_NOT_NULL, MOCK_ARG (MANIFEST_V2_HEADER_SIZE));
	status |= mock_expect_output (&manifest.flash.mock, 1, data->raw, MANIFEST_V2_HEADER_SIZE, 2);

	status |= mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash, 0,
		MOCK_ARG (manifest.addr + data->sig_offset), MOCK_ARG_NOT_NULL, MOCK_ARG (data->sig_len));
	status |= mock_expect_output (&manifest.flash.mock, 1, data->signature, data->sig_len, 2);

	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.start_sha256,
		&manifest.hash_mock, 0);
	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.update,
		&manifest.hash_mock, 0, MOCK_ARG_PTR_CONTAINS (data->raw, MANIFEST_V2_HEADER_SIZE),
		MOCK_ARG (MANIFEST_V2_HEADER_SIZE));

	status |= flash_mock_expect_read_and_hash (&manifest.flash, &manifest.hash_mock,
		manifest.addr + MANIFEST_V2_TOC_HDR_OFFSET, data->toc, MANIFEST_V2_TOC_HEADER_SIZE);

	for (i = 0; i < data->toc_entries; i++, validate_toc_start += MANIFEST_V2_TOC_ENTRY_SIZE) {
		status |= flash_mock_expect_read_and_hash (&manifest.flash, &manifest.hash_mock,
			manifest.addr + toc_entry_offset + (i * MANIFEST_V2_TOC_ENTRY_SIZE),
			(uint8_t*) &toc_entries[i], MANIFEST_V2_TOC_ENTRY_SIZE);
	}

	status |= flash_mock_expect_verify_flash_and_hash (&manifest.flash, &manifest.hash_mock,
		manifest.addr + validate_toc_start, data->raw + validate_toc_start,
		data->toc_hash_offset - validate_toc_start);

	status |= flash_mock_expect_read_and_hash (&manifest.flash, &manifest.hash_mock,
		manifest.addr + data->toc_hash_offset, data->toc_hash, data->toc_hash_len);

	status |= flash_mock_expect_verify_flash_and_hash (&manifest.flash, &manifest.hash_mock,
		manifest.addr + validate_start, data->raw + validate_start, validate_end - validate_start);

	status |= flash_mock_expect_read_and_hash (&manifest.flash, &manifest.hash_mock,
		manifest.addr + data->plat_id_offset, data->plat_id, MANIFEST_V2_PLATFORM_HEADER_SIZE);

	status |= flash_mock_expect_read_and_hash (&manifest.flash, &manifest.hash_mock,
		manifest.addr + data->plat_id_offset + MANIFEST_V2_PLATFORM_HEADER_SIZE, data->plat_id,
		data->plat_id_str_len);

	status |= flash_mock_expect_verify_flash_and_hash (&manifest.flash, &manifest.hash_mock,
		manifest.addr + validate_resume, data->raw + validate_resume,
		data->toc_extensions[0].toc_offset - validate_resume);

	status |= flash_mock_expect_read_and_hash (&manifest.flash, &manifest.hash_mock,
		manifest.addr + data->toc_extensions[0].toc_offset, (uint8_t*) &hdr,
		MANIFEST_V2_TOC_HEADER_SIZE);

	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.cancel,
		&manifest.hash_mock, 0);

	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_verify (&manifest.test, &manifest.hash_mock.base,
		&manifest.verification.base, NULL, 0);
	CuAssertIntEquals (test, MANIFEST_TOC_INVALID, status);

	manifest_flash_v3_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_v3_test_verify_toc_extension_without_hash (CuTest *test)
{
	struct manifest_flash_v3_testing manifest;
	int status;
	const struct manifest_v2_testing_data *data = &CFM_MANY_MEASUREMENTS_TESTING.manifest;
	uint32_t toc_entry_offset = MANIFEST_V2_TOC_ENTRY_OFFSET;
	const struct manifest_toc_entry *toc_entries =
		(struct manifest_toc_entry*) (data->raw + toc_entry_offset);
	uint32_t validate_toc_start = toc_entry_offset;

	int i;
	struct manifest_toc_entry bad_ext = toc_entries[data->toc_entries - 1];

	TEST_START;

	bad_ext.hash_id = 0xff;

	manifest_flash_v3_testing_init (test, &manifest, 0x10000, MANIFEST_NOT_SUPPORTED,
		CFM_V2_MAGIC_NUM, CFM_V3_MAGIC_NUM);

	status = mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash, 0,
		MOCK_ARG (manifest.addr), MOCK_ARG_NOT_NULL, MOCK_ARG (MANIFEST_V2_HEADER_SIZE));
	status |= mock_expect_output (&manifest.flash.mock, 1, data->raw, MANIFEST_V2_HEADER_SIZE, 2);

	status |= mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash, 0,
		MOCK_ARG (manifest.addr + data->sig_offset), MOCK_ARG_NOT_NULL, MOCK_ARG (data->sig_len));
	status |= mock_expect_output (&manifest.flash.mock, 1, data->signature, data->sig_len, 2);

	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.start_sha256,
		&manifest.hash_mock, 0);
	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.update,
		&manifest.hash_mock, 0, MOCK_ARG_PTR_CONTAINS (data->raw, MANIFEST_V2_HEADER_SIZE),
		MOCK_ARG (MANIFEST_V2_HEADER_SIZE));

	status |= flash_mock_expect_read_and_hash (&manifest.flash, &manifest.hash_mock,
		manifest.addr + MANIFEST_V2_TOC_HDR_OFFSET, data->toc, MANIFEST_V2_TOC_HEADER_SIZE);

	for (i = 0; i < (data->toc_entries - 1);
		i++, validate_toc_start += MANIFEST_V2_TOC_ENTRY_SIZE) {
		status |= flash_mock_expect_read_and_hash (&manifest.flash, &manifest.hash_mock,
			manifest.addr + toc_entry_offset + (i * MANIFEST_V2_TOC_ENTRY_SIZE),
			(uint8_t*) &toc_entries[i], MANIFEST_V2_TOC_ENTRY_SIZE);
	}

	status |= flash_mock_expect_read_and_hash (&manifest.flash, &manifest.hash_mock,
		manifest.addr + toc_entry_offset + (i * MANIFEST_V2_TOC_ENTRY_SIZE), (uint8_t*) &bad_ext,
		MANIFEST_V2_TOC_ENTRY_SIZE);

	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.cancel,
		&manifest.hash_mock, 0);

	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_verify (&manifest.test, &manifest.hash_mock.base,
		&manifest.verification.base, NULL, 0);
	CuAssertIntEquals (test, MANIFEST_TOC_EXTENSION_INVALID, status);

	manifest_flash_v3_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_v3_test_verify_toc_extension_root_manifest_content_read_error (
	CuTest *test)
{
	struct manifest_flash_v3_testing manifest;
	int status;
	const struct manifest_v2_testing_data *data = &CFM_MANY_MEASUREMENTS_TESTING.manifest;
	uint32_t toc_entry_offset = MANIFEST_V2_TOC_ENTRY_OFFSET;
	const struct manifest_toc_entry *toc_entries =
		(struct manifest_toc_entry*) (data->raw + toc_entry_offset);
	uint32_t validate_toc_start = toc_entry_offset;
	uint32_t validate_start = data->toc_hash_offset + data->toc_hash_len;
	uint32_t validate_end = data->plat_id_offset;
	uint32_t validate_resume =
		data->plat_id_offset + MANIFEST_V2_PLATFORM_HEADER_SIZE + data->plat_id_str_len;

	int i;
	struct manifest_toc_header hdr =
		*(struct manifest_toc_header*) (data->raw + MANIFEST_V2_TOC_HDR_OFFSET);

	TEST_START;

	hdr.hash_type += 1;

	manifest_flash_v3_testing_init (test, &manifest, 0x10000, MANIFEST_NOT_SUPPORTED,
		CFM_V2_MAGIC_NUM, CFM_V3_MAGIC_NUM);

	status = mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash, 0,
		MOCK_ARG (manifest.addr), MOCK_ARG_NOT_NULL, MOCK_ARG (MANIFEST_V2_HEADER_SIZE));
	status |= mock_expect_output (&manifest.flash.mock, 1, data->raw, MANIFEST_V2_HEADER_SIZE, 2);

	status |= mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash, 0,
		MOCK_ARG (manifest.addr + data->sig_offset), MOCK_ARG_NOT_NULL, MOCK_ARG (data->sig_len));
	status |= mock_expect_output (&manifest.flash.mock, 1, data->signature, data->sig_len, 2);

	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.start_sha256,
		&manifest.hash_mock, 0);
	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.update,
		&manifest.hash_mock, 0, MOCK_ARG_PTR_CONTAINS (data->raw, MANIFEST_V2_HEADER_SIZE),
		MOCK_ARG (MANIFEST_V2_HEADER_SIZE));

	status |= flash_mock_expect_read_and_hash (&manifest.flash, &manifest.hash_mock,
		manifest.addr + MANIFEST_V2_TOC_HDR_OFFSET, data->toc, MANIFEST_V2_TOC_HEADER_SIZE);

	for (i = 0; i < data->toc_entries; i++, validate_toc_start += MANIFEST_V2_TOC_ENTRY_SIZE) {
		status |= flash_mock_expect_read_and_hash (&manifest.flash, &manifest.hash_mock,
			manifest.addr + toc_entry_offset + (i * MANIFEST_V2_TOC_ENTRY_SIZE),
			(uint8_t*) &toc_entries[i], MANIFEST_V2_TOC_ENTRY_SIZE);
	}

	status |= flash_mock_expect_verify_flash_and_hash (&manifest.flash, &manifest.hash_mock,
		manifest.addr + validate_toc_start, data->raw + validate_toc_start,
		data->toc_hash_offset - validate_toc_start);

	status |= flash_mock_expect_read_and_hash (&manifest.flash, &manifest.hash_mock,
		manifest.addr + data->toc_hash_offset, data->toc_hash, data->toc_hash_len);

	status |= flash_mock_expect_verify_flash_and_hash (&manifest.flash, &manifest.hash_mock,
		manifest.addr + validate_start, data->raw + validate_start, validate_end - validate_start);

	status |= flash_mock_expect_read_and_hash (&manifest.flash, &manifest.hash_mock,
		manifest.addr + data->plat_id_offset, data->plat_id, MANIFEST_V2_PLATFORM_HEADER_SIZE);

	status |= flash_mock_expect_read_and_hash (&manifest.flash, &manifest.hash_mock,
		manifest.addr + data->plat_id_offset + MANIFEST_V2_PLATFORM_HEADER_SIZE, data->plat_id,
		data->plat_id_str_len);

	status |= mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash,
		FLASH_READ_FAILED, MOCK_ARG (manifest.addr + validate_resume), MOCK_ARG_NOT_NULL,
		MOCK_ARG_ANY);

	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.cancel,
		&manifest.hash_mock, 0);

	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_verify (&manifest.test, &manifest.hash_mock.base,
		&manifest.verification.base, NULL, 0);
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	manifest_flash_v3_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_v3_test_read_element_data_long_manifest_with_toc_extension (CuTest *test)
{
	struct manifest_flash_v3_testing manifest;
	int status;
	uint8_t buffer[CFM_MANY_MEASUREMENTS_TESTING.component_device2_len];
	uint8_t *element = buffer;
	size_t total = 0;
	uint8_t format = 0xff;
	int found = -1;

	TEST_START;

	manifest_flash_v3_testing_init_and_verify (test, &manifest, 0x10000, MANIFEST_NOT_SUPPORTED,
		CFM_V2_MAGIC_NUM, CFM_V3_MAGIC_NUM, &CFM_MANY_MEASUREMENTS_TESTING.manifest, 0, false, 0);

	manifest_flash_v3_testing_read_element (test, &manifest,
		&CFM_MANY_MEASUREMENTS_TESTING.manifest,
		CFM_MANY_MEASUREMENTS_TESTING.component_device1_entry, 0,
		CFM_MANY_MEASUREMENTS_TESTING.component_device1_hash,
		CFM_MANY_MEASUREMENTS_TESTING.component_device1_offset,
		CFM_MANY_MEASUREMENTS_TESTING.component_device1_len, sizeof (buffer), 0);

	manifest_flash_v3_testing_read_element (test, &manifest,
		&CFM_MANY_MEASUREMENTS_TESTING.manifest,
		CFM_MANY_MEASUREMENTS_TESTING.component_device2_entry, 5,
		CFM_MANY_MEASUREMENTS_TESTING.component_device2_hash,
		CFM_MANY_MEASUREMENTS_TESTING.component_device2_offset,
		CFM_MANY_MEASUREMENTS_TESTING.component_device2_len, sizeof (buffer), 0);

	manifest_flash_v3_testing_read_element (test, &manifest,
		&CFM_MANY_MEASUREMENTS_TESTING.manifest,
		CFM_MANY_MEASUREMENTS_TESTING.component_device2_entry, 270,
		CFM_MANY_MEASUREMENTS_TESTING.component_device2_hash,
		CFM_MANY_MEASUREMENTS_TESTING.component_device2_offset,
		CFM_MANY_MEASUREMENTS_TESTING.component_device2_len, sizeof (buffer), 0);

	status = manifest_flash_read_element_data (&manifest.test, &manifest.hash.base,
		CFM_COMPONENT_DEVICE, 0, MANIFEST_NO_PARENT, 0, &found, &format, &total, &element,
		sizeof (buffer));
	CuAssertIntEquals (test, CFM_MANY_MEASUREMENTS_TESTING.component_device1_len, status);
	CuAssertIntEquals (test, CFM_MANY_MEASUREMENTS_TESTING.component_device1_entry, found);
	CuAssertIntEquals (test, 0, format);
	CuAssertIntEquals (test, CFM_MANY_MEASUREMENTS_TESTING.component_device1_len, total);

	status = testing_validate_array (CFM_MANY_MEASUREMENTS_TESTING.manifest.raw +
		CFM_MANY_MEASUREMENTS_TESTING.component_device1_offset, buffer, status);
	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_read_element_data (&manifest.test, &manifest.hash.base,
		CFM_COMPONENT_DEVICE, 5, MANIFEST_NO_PARENT, 0, &found, &format, &total, &element,
		sizeof (buffer));
	CuAssertIntEquals (test, CFM_MANY_MEASUREMENTS_TESTING.component_device2_len, status);
	CuAssertIntEquals (test, CFM_MANY_MEASUREMENTS_TESTING.component_device2_entry, found);
	CuAssertIntEquals (test, 0, format);
	CuAssertIntEquals (test, CFM_MANY_MEASUREMENTS_TESTING.component_device2_len, total);

	status = testing_validate_array (CFM_MANY_MEASUREMENTS_TESTING.manifest.raw +
		CFM_MANY_MEASUREMENTS_TESTING.component_device2_offset, buffer, status);
	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_read_element_data (&manifest.test, &manifest.hash.base,
		CFM_COMPONENT_DEVICE, 270, MANIFEST_NO_PARENT, 0, &found, &format, &total, &element,
		sizeof (buffer));
	CuAssertIntEquals (test, CFM_MANY_MEASUREMENTS_TESTING.component_device2_len, status);
	CuAssertIntEquals (test, CFM_MANY_MEASUREMENTS_TESTING.component_device2_entry, found);
	CuAssertIntEquals (test, 0, format);
	CuAssertIntEquals (test, CFM_MANY_MEASUREMENTS_TESTING.component_device2_len, total);

	status = testing_validate_array (CFM_MANY_MEASUREMENTS_TESTING.manifest.raw +
		CFM_MANY_MEASUREMENTS_TESTING.component_device2_offset, buffer, status);
	CuAssertIntEquals (test, 0, status);

	manifest_flash_v3_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_v3_test_read_element_data_toc_extension_zero_entries (CuTest *test)
{
	struct manifest_flash_v3_testing manifest;
	int status;
	uint8_t buffer[CFM_MANY_MEASUREMENTS_TESTING.component_device2_len];
	uint8_t *element = buffer;
	size_t total = 0;
	uint8_t format = 0xff;
	int found = -1;
	const struct manifest_v2_testing_data *data = &CFM_MANY_MEASUREMENTS_TESTING.manifest;
	int start = 5;
	uint32_t toc_entry_offset = MANIFEST_V2_TOC_ENTRY_OFFSET;
	uint32_t first_entry = toc_entry_offset + (MANIFEST_V2_TOC_ENTRY_SIZE * start);
	uint32_t last_entry = toc_entry_offset + (MANIFEST_V2_TOC_ENTRY_SIZE * (254 + 1));
	uint32_t hash_offset;
	uint32_t after_hash;
	const struct manifest_toc_entry *toc_entries =
		(struct manifest_toc_entry*) (data->raw + toc_entry_offset);
	struct manifest_toc_header extension_hdr =
		*(struct manifest_toc_header*) (data->toc_extensions[0].toc);
	int i;

	TEST_START;

	manifest_flash_v3_testing_init_and_verify (test, &manifest, 0x10000, MANIFEST_NOT_SUPPORTED,
		CFM_V2_MAGIC_NUM, CFM_V3_MAGIC_NUM, &CFM_MANY_MEASUREMENTS_TESTING.manifest, 0, false, 0);

	hash_offset = toc_entry_offset + (MANIFEST_V2_TOC_ENTRY_SIZE * data->toc_entries) +
		(data->toc_hash_len * 254);
	after_hash = hash_offset + data->toc_hash_len;

	status = mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.start_sha256,
		&manifest.hash_mock, 0);

	/* Read toc header */
	status |= flash_mock_expect_read_and_hash (&manifest.flash, &manifest.hash_mock,
		manifest.addr + MANIFEST_V2_TOC_HDR_OFFSET, data->toc, MANIFEST_V2_TOC_HEADER_SIZE);

	/* Hash unneeded toc entries */
	status |= flash_mock_expect_verify_flash_and_hash (&manifest.flash, &manifest.hash_mock,
		manifest.addr + toc_entry_offset, data->raw + toc_entry_offset,
		first_entry - toc_entry_offset);

	for (i = start; i <= 254; i++) {
		status |= flash_mock_expect_read_and_hash (&manifest.flash, &manifest.hash_mock,
			manifest.addr + toc_entry_offset + (i * MANIFEST_V2_TOC_ENTRY_SIZE),
			(uint8_t*) &toc_entries[i], MANIFEST_V2_TOC_ENTRY_SIZE);
	}

	status |= flash_mock_expect_verify_flash_and_hash (&manifest.flash, &manifest.hash_mock,
		manifest.addr + last_entry, data->raw + last_entry, hash_offset - last_entry);

	status |= flash_mock_expect_read_and_hash (&manifest.flash, &manifest.hash_mock,
		manifest.addr + hash_offset, data->raw + hash_offset, data->toc_hash_len);

	status |= flash_mock_expect_verify_flash_and_hash (&manifest.flash, &manifest.hash_mock,
		manifest.addr + after_hash, data->raw + after_hash, data->toc_hash_offset - after_hash);

	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.finish,
		&manifest.hash_mock, 0, MOCK_ARG_NOT_NULL, MOCK_ARG (SHA512_HASH_LENGTH));
	status |= mock_expect_output (&manifest.hash_mock.mock, 0, data->toc_hash, data->toc_hash_len,
		1);

	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.start_sha256,
		&manifest.hash_mock, 0);

	extension_hdr.entry_count = 0;
	extension_hdr.hash_count = 0;

	status |= flash_mock_expect_read_and_hash (&manifest.flash, &manifest.hash_mock,
		manifest.addr + data->toc_extensions[0].toc_offset, (uint8_t*) &extension_hdr,
		MANIFEST_V2_TOC_HEADER_SIZE);

	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.cancel,
		&manifest.hash_mock, 0);

	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_read_element_data (&manifest.test, &manifest.hash_mock.base,
		CFM_COMPONENT_DEVICE, start, MANIFEST_NO_PARENT, 0, &found, &format, &total, &element,
		sizeof (buffer));
	CuAssertIntEquals (test, MANIFEST_TOC_INVALID, status);

	manifest_flash_v3_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_v3_test_read_element_data_toc_extension_hash_mismatch (CuTest *test)
{
	struct manifest_flash_v3_testing manifest;
	int status;
	uint8_t buffer[CFM_MANY_MEASUREMENTS_TESTING.component_device2_len];
	uint8_t *element = buffer;
	size_t total = 0;
	uint8_t format = 0xff;
	int found = -1;
	const struct manifest_v2_testing_data *data = &CFM_MANY_MEASUREMENTS_TESTING.manifest;
	int start = 5;
	uint32_t toc_entry_offset = MANIFEST_V2_TOC_ENTRY_OFFSET;
	uint32_t first_entry = toc_entry_offset + (MANIFEST_V2_TOC_ENTRY_SIZE * start);
	uint32_t last_entry = toc_entry_offset + (MANIFEST_V2_TOC_ENTRY_SIZE * (254 + 1));
	uint32_t hash_offset;
	uint32_t after_hash;
	const struct manifest_toc_entry *toc_entries =
		(struct manifest_toc_entry*) (data->raw + toc_entry_offset);
	struct manifest_toc_header extension_hdr =
		*(struct manifest_toc_header*) (data->toc_extensions[0].toc);
	int i;

	TEST_START;

	manifest_flash_v3_testing_init_and_verify (test, &manifest, 0x10000, MANIFEST_NOT_SUPPORTED,
		CFM_V2_MAGIC_NUM, CFM_V3_MAGIC_NUM, &CFM_MANY_MEASUREMENTS_TESTING.manifest, 0, false, 0);

	hash_offset = toc_entry_offset + (MANIFEST_V2_TOC_ENTRY_SIZE * data->toc_entries) +
		(data->toc_hash_len * 254);
	after_hash = hash_offset + data->toc_hash_len;

	status = mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.start_sha256,
		&manifest.hash_mock, 0);

	/* Read toc header */
	status |= flash_mock_expect_read_and_hash (&manifest.flash, &manifest.hash_mock,
		manifest.addr + MANIFEST_V2_TOC_HDR_OFFSET, data->toc, MANIFEST_V2_TOC_HEADER_SIZE);

	/* Hash unneeded toc entries */
	status |= flash_mock_expect_verify_flash_and_hash (&manifest.flash, &manifest.hash_mock,
		manifest.addr + toc_entry_offset, data->raw + toc_entry_offset,
		first_entry - toc_entry_offset);

	for (i = start; i <= 254; i++) {
		status |= flash_mock_expect_read_and_hash (&manifest.flash, &manifest.hash_mock,
			manifest.addr + toc_entry_offset + (i * MANIFEST_V2_TOC_ENTRY_SIZE),
			(uint8_t*) &toc_entries[i], MANIFEST_V2_TOC_ENTRY_SIZE);
	}

	status |= flash_mock_expect_verify_flash_and_hash (&manifest.flash, &manifest.hash_mock,
		manifest.addr + last_entry, data->raw + last_entry, hash_offset - last_entry);

	status |= flash_mock_expect_read_and_hash (&manifest.flash, &manifest.hash_mock,
		manifest.addr + hash_offset, data->raw + hash_offset, data->toc_hash_len);

	status |= flash_mock_expect_verify_flash_and_hash (&manifest.flash, &manifest.hash_mock,
		manifest.addr + after_hash, data->raw + after_hash, data->toc_hash_offset - after_hash);

	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.finish,
		&manifest.hash_mock, 0, MOCK_ARG_NOT_NULL, MOCK_ARG (SHA512_HASH_LENGTH));
	status |= mock_expect_output (&manifest.hash_mock.mock, 0, data->toc_hash, data->toc_hash_len,
		1);

	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.start_sha256,
		&manifest.hash_mock, 0);

	extension_hdr.hash_type += 1;

	status |= flash_mock_expect_read_and_hash (&manifest.flash, &manifest.hash_mock,
		manifest.addr + data->toc_extensions[0].toc_offset, (uint8_t*) &extension_hdr,
		MANIFEST_V2_TOC_HEADER_SIZE);

	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.cancel,
		&manifest.hash_mock, 0);

	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_read_element_data (&manifest.test, &manifest.hash_mock.base,
		CFM_COMPONENT_DEVICE, start, MANIFEST_NO_PARENT, 0, &found, &format, &total, &element,
		sizeof (buffer));
	CuAssertIntEquals (test, MANIFEST_TOC_HASH_ALGO_MISMATCH, status);

	manifest_flash_v3_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_v3_test_read_element_data_toc_extension_not_the_last_entry (CuTest *test)
{
	struct manifest_flash_v3_testing manifest;
	int status;
	uint8_t buffer[CFM_MANY_MEASUREMENTS_TESTING.component_device2_len];
	uint8_t *element = buffer;
	size_t total = 0;
	uint8_t format = 0xff;
	int found = -1;
	const struct manifest_v2_testing_data *data = &CFM_MANY_MEASUREMENTS_TESTING.manifest;
	int start = 5;
	uint32_t toc_entry_offset = MANIFEST_V2_TOC_ENTRY_OFFSET;
	uint32_t first_entry = toc_entry_offset + (MANIFEST_V2_TOC_ENTRY_SIZE * start);
	const struct manifest_toc_entry *toc_entries =
		(struct manifest_toc_entry*) (data->raw + toc_entry_offset);
	int i;

	TEST_START;

	manifest_flash_v3_testing_init_and_verify (test, &manifest, 0x10000, MANIFEST_NOT_SUPPORTED,
		CFM_V2_MAGIC_NUM, CFM_V3_MAGIC_NUM, &CFM_MANY_MEASUREMENTS_TESTING.manifest, 0, false, 0);

	status = mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.start_sha256,
		&manifest.hash_mock, 0);

	/* Read toc header */
	status |= flash_mock_expect_read_and_hash (&manifest.flash, &manifest.hash_mock,
		manifest.addr + MANIFEST_V2_TOC_HDR_OFFSET, data->toc, MANIFEST_V2_TOC_HEADER_SIZE);

	/* Hash unneeded toc entries */
	status |= flash_mock_expect_verify_flash_and_hash (&manifest.flash, &manifest.hash_mock,
		manifest.addr + toc_entry_offset, data->raw + toc_entry_offset,
		first_entry - toc_entry_offset);

	for (i = start; i <= 252; i++) {
		status |= flash_mock_expect_read_and_hash (&manifest.flash, &manifest.hash_mock,
			manifest.addr + toc_entry_offset + (i * MANIFEST_V2_TOC_ENTRY_SIZE),
			(uint8_t*) &toc_entries[i], MANIFEST_V2_TOC_ENTRY_SIZE);
	}

	status |= flash_mock_expect_read_and_hash (&manifest.flash, &manifest.hash_mock,
		manifest.addr + toc_entry_offset + (i * MANIFEST_V2_TOC_ENTRY_SIZE),
		(uint8_t*) &toc_entries[i + 1], MANIFEST_V2_TOC_ENTRY_SIZE);

	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.cancel,
		&manifest.hash_mock, 0);

	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_read_element_data (&manifest.test, &manifest.hash_mock.base,
		CFM_COMPONENT_DEVICE, start, MANIFEST_NO_PARENT, 0, &found, &format, &total, &element,
		sizeof (buffer));
	CuAssertIntEquals (test, MANIFEST_TOC_EXTENSION_INVALID, status);

	manifest_flash_v3_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_v3_test_get_child_elements_info_toc_invalid (CuTest *test)
{
	struct manifest_flash_v3_testing manifest;
	uint8_t validate_hash[SHA512_HASH_LENGTH] = {0};
	uint32_t offset = MANIFEST_V2_TOC_ENTRY_OFFSET;
	size_t child_len;
	int num_child;
	int status;

	TEST_START;

	manifest_flash_v3_testing_init_and_verify (test, &manifest, 0x10000, MANIFEST_NOT_SUPPORTED,
		CFM_V2_MAGIC_NUM, CFM_V3_MAGIC_NUM, &CFM_TESTING.manifest, 0, true, 0);

	status = mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.start_sha256,
		&manifest.hash_mock, 0);

	status |= flash_mock_expect_read_and_hash (&manifest.flash, &manifest.hash_mock,
		manifest.addr + MANIFEST_V2_TOC_HDR_OFFSET, CFM_TESTING.manifest.toc,
		MANIFEST_V2_TOC_HEADER_SIZE);

	status = flash_mock_expect_verify_flash_and_hash (&manifest.flash, &manifest.hash_mock,
		manifest.addr + MANIFEST_V2_TOC_ENTRY_OFFSET,
		CFM_TESTING.manifest.raw + MANIFEST_V2_TOC_ENTRY_OFFSET, MANIFEST_V2_TOC_ENTRY_SIZE * 2);
	CuAssertIntEquals (test, 0, status);

	offset += MANIFEST_V2_TOC_ENTRY_SIZE * 2;

	for (int i = 2; i <= 26; ++i) {
		status |= flash_mock_expect_read_and_hash (&manifest.flash, &manifest.hash_mock,
			manifest.addr + offset, CFM_TESTING.manifest.raw + offset, MANIFEST_V2_TOC_ENTRY_SIZE);

		offset += MANIFEST_V2_TOC_ENTRY_SIZE;
	}
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_expect_verify_flash_and_hash (&manifest.flash, &manifest.hash_mock,
		manifest.addr + offset, CFM_TESTING.manifest.raw + offset, MANIFEST_V2_TOC_ENTRY_SIZE * 12 +
		CFM_TESTING.manifest.toc_hash_len * 39);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.finish,
		&manifest.hash_mock, 0, MOCK_ARG_NOT_NULL, MOCK_ARG (SHA512_HASH_LENGTH));
	status |= mock_expect_output (&manifest.hash_mock.mock, 0, validate_hash,
		sizeof (validate_hash), -1);
	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_get_child_elements_info (&manifest.test, &manifest.hash_mock.base, 2,
		CFM_COMPONENT_DEVICE, MANIFEST_NO_PARENT, CFM_ALLOWABLE_PFM, &child_len, &num_child, NULL);
	CuAssertIntEquals (test, MANIFEST_TOC_INVALID, status);

	manifest_flash_v3_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_v3_test_get_child_elements_info_long_manifest_with_extensions (
	CuTest *test)
{
	struct manifest_flash_v3_testing manifest;
	size_t child_len;
	int num_child;
	int entry;
	int status;

	TEST_START;

	manifest_flash_v3_testing_init_and_verify (test, &manifest, 0x10000, MANIFEST_NOT_SUPPORTED,
		CFM_V2_MAGIC_NUM, CFM_V3_MAGIC_NUM, &CFM_MANY_MEASUREMENTS_TESTING.manifest, 0, false, 0);

	manifest_flash_v3_testing_iterate_manifest_toc (test, &manifest,
		&CFM_MANY_MEASUREMENTS_TESTING.manifest, 2, 524);
	manifest_flash_v3_testing_iterate_manifest_toc (test, &manifest,
		&CFM_MANY_MEASUREMENTS_TESTING.manifest, 525, 769);
	manifest_flash_v3_testing_iterate_manifest_toc (test, &manifest,
		&CFM_MANY_MEASUREMENTS_TESTING.manifest, 525, 769);

	status = manifest_flash_get_child_elements_info (&manifest.test, &manifest.hash.base, 2,
		CFM_COMPONENT_DEVICE, MANIFEST_NO_PARENT, CFM_ROOT_CA, &child_len, &num_child, &entry);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 2, entry);
	CuAssertIntEquals (test, 0x44, child_len);
	CuAssertIntEquals (test, 1, num_child);

	status = manifest_flash_get_child_elements_info (&manifest.test, &manifest.hash.base, 525,
		CFM_COMPONENT_DEVICE, MANIFEST_NO_PARENT, CFM_ROOT_CA, &child_len, &num_child, &entry);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 525, entry);
	CuAssertIntEquals (test, 0x34, child_len);
	CuAssertIntEquals (test, 1, num_child);

	status = manifest_flash_get_child_elements_info (&manifest.test, &manifest.hash.base, 525,
		CFM_COMPONENT_DEVICE, MANIFEST_NO_PARENT, CFM_MEASUREMENT, &child_len, &num_child, &entry);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 528, entry);
	CuAssertIntEquals (test, 0x3448, child_len);
	CuAssertIntEquals (test, 239, num_child);

	manifest_flash_v3_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_v3_test_get_child_elements_info_toc_extension_zero_entries (
	CuTest *test)
{
	struct manifest_flash_v3_testing manifest;
	size_t child_len;
	int num_child;
	int entry;
	int status;
	const struct manifest_v2_testing_data *data = &CFM_MANY_MEASUREMENTS_TESTING.manifest;
	int start = 2;
	uint32_t toc_entry_offset = MANIFEST_V2_TOC_ENTRY_OFFSET;
	uint32_t first_entry = toc_entry_offset + (MANIFEST_V2_TOC_ENTRY_SIZE * start);
	uint32_t last_entry = toc_entry_offset + (MANIFEST_V2_TOC_ENTRY_SIZE * (254 + 1));
	uint32_t hash_offset;
	uint32_t after_hash;
	const struct manifest_toc_entry *toc_entries =
		(struct manifest_toc_entry*) (data->raw + toc_entry_offset);
	struct manifest_toc_header extension_hdr =
		*(struct manifest_toc_header*) (data->toc_extensions[0].toc);
	int i;

	TEST_START;

	manifest_flash_v3_testing_init_and_verify (test, &manifest, 0x10000, MANIFEST_NOT_SUPPORTED,
		CFM_V2_MAGIC_NUM, CFM_V3_MAGIC_NUM, &CFM_MANY_MEASUREMENTS_TESTING.manifest, 0, true, 0);

	hash_offset = toc_entry_offset + (MANIFEST_V2_TOC_ENTRY_SIZE * data->toc_entries) +
		(data->toc_hash_len * 254);
	after_hash = hash_offset + data->toc_hash_len;

	status = mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.start_sha256,
		&manifest.hash_mock, 0);

	/* Read toc header */
	status |= flash_mock_expect_read_and_hash (&manifest.flash, &manifest.hash_mock,
		manifest.addr + MANIFEST_V2_TOC_HDR_OFFSET, data->toc, MANIFEST_V2_TOC_HEADER_SIZE);

	/* Hash unneeded toc entries */
	status |= flash_mock_expect_verify_flash_and_hash (&manifest.flash, &manifest.hash_mock,
		manifest.addr + toc_entry_offset, data->raw + toc_entry_offset,
		first_entry - toc_entry_offset);

	for (i = start; i <= 254; i++) {
		status |= flash_mock_expect_read_and_hash (&manifest.flash, &manifest.hash_mock,
			manifest.addr + toc_entry_offset + (i * MANIFEST_V2_TOC_ENTRY_SIZE),
			(uint8_t*) &toc_entries[i], MANIFEST_V2_TOC_ENTRY_SIZE);
	}

	status |= flash_mock_expect_verify_flash_and_hash (&manifest.flash, &manifest.hash_mock,
		manifest.addr + last_entry, data->raw + last_entry, hash_offset - last_entry);

	status |= flash_mock_expect_read_and_hash (&manifest.flash, &manifest.hash_mock,
		manifest.addr + hash_offset, data->raw + hash_offset, data->toc_hash_len);

	status |= flash_mock_expect_verify_flash_and_hash (&manifest.flash, &manifest.hash_mock,
		manifest.addr + after_hash, data->raw + after_hash, data->toc_hash_offset - after_hash);

	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.finish,
		&manifest.hash_mock, 0, MOCK_ARG_NOT_NULL, MOCK_ARG (SHA512_HASH_LENGTH));
	status |= mock_expect_output (&manifest.hash_mock.mock, 0, data->toc_hash, data->toc_hash_len,
		1);

	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.start_sha256,
		&manifest.hash_mock, 0);

	extension_hdr.entry_count = 0;
	extension_hdr.hash_count = 0;

	status |= flash_mock_expect_read_and_hash (&manifest.flash, &manifest.hash_mock,
		manifest.addr + data->toc_extensions[0].toc_offset, (uint8_t*) &extension_hdr,
		MANIFEST_V2_TOC_HEADER_SIZE);

	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.cancel,
		&manifest.hash_mock, 0);

	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_get_child_elements_info (&manifest.test, &manifest.hash_mock.base, 2,
		CFM_COMPONENT_DEVICE, MANIFEST_NO_PARENT, CFM_ROOT_CA, &child_len, &num_child, &entry);
	CuAssertIntEquals (test, MANIFEST_TOC_INVALID, status);

	manifest_flash_v3_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_v3_test_get_child_elements_info_toc_extension_hash_mismatch (
	CuTest *test)
{
	struct manifest_flash_v3_testing manifest;
	size_t child_len;
	int num_child;
	int entry;
	int status;
	const struct manifest_v2_testing_data *data = &CFM_MANY_MEASUREMENTS_TESTING.manifest;
	int start = 2;
	uint32_t toc_entry_offset = MANIFEST_V2_TOC_ENTRY_OFFSET;
	uint32_t first_entry = toc_entry_offset + (MANIFEST_V2_TOC_ENTRY_SIZE * start);
	uint32_t last_entry = toc_entry_offset + (MANIFEST_V2_TOC_ENTRY_SIZE * (254 + 1));
	uint32_t hash_offset;
	uint32_t after_hash;
	const struct manifest_toc_entry *toc_entries =
		(struct manifest_toc_entry*) (data->raw + toc_entry_offset);
	struct manifest_toc_header extension_hdr =
		*(struct manifest_toc_header*) (data->toc_extensions[0].toc);
	int i;

	TEST_START;

	manifest_flash_v3_testing_init_and_verify (test, &manifest, 0x10000, MANIFEST_NOT_SUPPORTED,
		CFM_V2_MAGIC_NUM, CFM_V3_MAGIC_NUM, &CFM_MANY_MEASUREMENTS_TESTING.manifest, 0, true, 0);

	hash_offset = toc_entry_offset + (MANIFEST_V2_TOC_ENTRY_SIZE * data->toc_entries) +
		(data->toc_hash_len * 254);
	after_hash = hash_offset + data->toc_hash_len;

	status = mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.start_sha256,
		&manifest.hash_mock, 0);

	/* Read toc header */
	status |= flash_mock_expect_read_and_hash (&manifest.flash, &manifest.hash_mock,
		manifest.addr + MANIFEST_V2_TOC_HDR_OFFSET, data->toc, MANIFEST_V2_TOC_HEADER_SIZE);

	/* Hash unneeded toc entries */
	status |= flash_mock_expect_verify_flash_and_hash (&manifest.flash, &manifest.hash_mock,
		manifest.addr + toc_entry_offset, data->raw + toc_entry_offset,
		first_entry - toc_entry_offset);

	for (i = start; i <= 254; i++) {
		status |= flash_mock_expect_read_and_hash (&manifest.flash, &manifest.hash_mock,
			manifest.addr + toc_entry_offset + (i * MANIFEST_V2_TOC_ENTRY_SIZE),
			(uint8_t*) &toc_entries[i], MANIFEST_V2_TOC_ENTRY_SIZE);
	}

	status |= flash_mock_expect_verify_flash_and_hash (&manifest.flash, &manifest.hash_mock,
		manifest.addr + last_entry, data->raw + last_entry, hash_offset - last_entry);

	status |= flash_mock_expect_read_and_hash (&manifest.flash, &manifest.hash_mock,
		manifest.addr + hash_offset, data->raw + hash_offset, data->toc_hash_len);

	status |= flash_mock_expect_verify_flash_and_hash (&manifest.flash, &manifest.hash_mock,
		manifest.addr + after_hash, data->raw + after_hash, data->toc_hash_offset - after_hash);

	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.finish,
		&manifest.hash_mock, 0, MOCK_ARG_NOT_NULL, MOCK_ARG (SHA512_HASH_LENGTH));
	status |= mock_expect_output (&manifest.hash_mock.mock, 0, data->toc_hash, data->toc_hash_len,
		1);

	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.start_sha256,
		&manifest.hash_mock, 0);

	extension_hdr.hash_type += 1;

	status |= flash_mock_expect_read_and_hash (&manifest.flash, &manifest.hash_mock,
		manifest.addr + data->toc_extensions[0].toc_offset, (uint8_t*) &extension_hdr,
		MANIFEST_V2_TOC_HEADER_SIZE);

	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.cancel,
		&manifest.hash_mock, 0);

	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_get_child_elements_info (&manifest.test, &manifest.hash_mock.base, 2,
		CFM_COMPONENT_DEVICE, MANIFEST_NO_PARENT, CFM_ROOT_CA, &child_len, &num_child, &entry);
	CuAssertIntEquals (test, MANIFEST_TOC_HASH_ALGO_MISMATCH, status);

	manifest_flash_v3_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_v3_test_get_child_elements_info_toc_extension_not_the_last_entry (
	CuTest *test)
{
	struct manifest_flash_v3_testing manifest;
	size_t child_len;
	int num_child;
	int entry;
	int status;
	const struct manifest_v2_testing_data *data = &CFM_MANY_MEASUREMENTS_TESTING.manifest;
	int start = 2;
	uint32_t toc_entry_offset = MANIFEST_V2_TOC_ENTRY_OFFSET;
	uint32_t first_entry = toc_entry_offset + (MANIFEST_V2_TOC_ENTRY_SIZE * start);
	const struct manifest_toc_entry *toc_entries =
		(struct manifest_toc_entry*) (data->raw + toc_entry_offset);
	int i;

	TEST_START;

	manifest_flash_v3_testing_init_and_verify (test, &manifest, 0x10000, MANIFEST_NOT_SUPPORTED,
		CFM_V2_MAGIC_NUM, CFM_V3_MAGIC_NUM, &CFM_MANY_MEASUREMENTS_TESTING.manifest, 0, true, 0);

	status = mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.start_sha256,
		&manifest.hash_mock, 0);

	/* Read toc header */
	status |= flash_mock_expect_read_and_hash (&manifest.flash, &manifest.hash_mock,
		manifest.addr + MANIFEST_V2_TOC_HDR_OFFSET, data->toc, MANIFEST_V2_TOC_HEADER_SIZE);

	/* Hash unneeded toc entries */
	status |= flash_mock_expect_verify_flash_and_hash (&manifest.flash, &manifest.hash_mock,
		manifest.addr + toc_entry_offset, data->raw + toc_entry_offset,
		first_entry - toc_entry_offset);

	for (i = start; i <= 252; i++) {
		status |= flash_mock_expect_read_and_hash (&manifest.flash, &manifest.hash_mock,
			manifest.addr + toc_entry_offset + (i * MANIFEST_V2_TOC_ENTRY_SIZE),
			(uint8_t*) &toc_entries[i], MANIFEST_V2_TOC_ENTRY_SIZE);
	}

	status |= flash_mock_expect_read_and_hash (&manifest.flash, &manifest.hash_mock,
		manifest.addr + toc_entry_offset + (i * MANIFEST_V2_TOC_ENTRY_SIZE),
		(uint8_t*) &toc_entries[i + 1], MANIFEST_V2_TOC_ENTRY_SIZE);

	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.cancel,
		&manifest.hash_mock, 0);

	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_get_child_elements_info (&manifest.test, &manifest.hash_mock.base, 2,
		CFM_COMPONENT_DEVICE, MANIFEST_NO_PARENT, CFM_ROOT_CA, &child_len, &num_child, &entry);
	CuAssertIntEquals (test, MANIFEST_TOC_EXTENSION_INVALID, status);

	manifest_flash_v3_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_v3_test_get_child_elements_info_toc_extension_before_hash_read_error (
	CuTest *test)
{
	struct manifest_flash_v3_testing manifest;
	size_t child_len;
	int num_child;
	int entry;
	int status;
	const struct manifest_v2_testing_data *data = &CFM_MANY_MEASUREMENTS_TESTING.manifest;
	int start = 2;
	uint32_t toc_entry_offset = MANIFEST_V2_TOC_ENTRY_OFFSET;
	uint32_t first_entry = toc_entry_offset + (MANIFEST_V2_TOC_ENTRY_SIZE * start);
	uint32_t last_entry = toc_entry_offset + (MANIFEST_V2_TOC_ENTRY_SIZE * (254 + 1));
	const struct manifest_toc_entry *toc_entries =
		(struct manifest_toc_entry*) (data->raw + toc_entry_offset);
	int i;

	TEST_START;

	manifest_flash_v3_testing_init_and_verify (test, &manifest, 0x10000, MANIFEST_NOT_SUPPORTED,
		CFM_V2_MAGIC_NUM, CFM_V3_MAGIC_NUM, &CFM_MANY_MEASUREMENTS_TESTING.manifest, 0, true, 0);

	status = mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.start_sha256,
		&manifest.hash_mock, 0);

	/* Read toc header */
	status |= flash_mock_expect_read_and_hash (&manifest.flash, &manifest.hash_mock,
		manifest.addr + MANIFEST_V2_TOC_HDR_OFFSET, data->toc, MANIFEST_V2_TOC_HEADER_SIZE);

	/* Hash unneeded toc entries */
	status |= flash_mock_expect_verify_flash_and_hash (&manifest.flash, &manifest.hash_mock,
		manifest.addr + toc_entry_offset, data->raw + toc_entry_offset,
		first_entry - toc_entry_offset);

	for (i = start; i <= 254; i++) {
		status |= flash_mock_expect_read_and_hash (&manifest.flash, &manifest.hash_mock,
			manifest.addr + toc_entry_offset + (i * MANIFEST_V2_TOC_ENTRY_SIZE),
			(uint8_t*) &toc_entries[i], MANIFEST_V2_TOC_ENTRY_SIZE);
	}

	status |= mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash,
		FLASH_READ_FAILED, MOCK_ARG (manifest.addr + last_entry), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FLASH_VERIFICATION_BLOCK));

	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.cancel,
		&manifest.hash_mock, 0);

	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_get_child_elements_info (&manifest.test, &manifest.hash_mock.base, 2,
		CFM_COMPONENT_DEVICE, MANIFEST_NO_PARENT, CFM_ROOT_CA, &child_len, &num_child, &entry);
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	manifest_flash_v3_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_v3_test_get_child_elements_info_toc_extension_hash_read_error (
	CuTest *test)
{
	struct manifest_flash_v3_testing manifest;
	size_t child_len;
	int num_child;
	int entry;
	int status;
	const struct manifest_v2_testing_data *data = &CFM_MANY_MEASUREMENTS_TESTING.manifest;
	int start = 2;
	uint32_t toc_entry_offset = MANIFEST_V2_TOC_ENTRY_OFFSET;
	uint32_t first_entry = toc_entry_offset + (MANIFEST_V2_TOC_ENTRY_SIZE * start);
	uint32_t last_entry = toc_entry_offset + (MANIFEST_V2_TOC_ENTRY_SIZE * (254 + 1));
	uint32_t hash_offset;
	const struct manifest_toc_entry *toc_entries =
		(struct manifest_toc_entry*) (data->raw + toc_entry_offset);
	int i;

	TEST_START;

	manifest_flash_v3_testing_init_and_verify (test, &manifest, 0x10000, MANIFEST_NOT_SUPPORTED,
		CFM_V2_MAGIC_NUM, CFM_V3_MAGIC_NUM, &CFM_MANY_MEASUREMENTS_TESTING.manifest, 0, true, 0);

	hash_offset = toc_entry_offset + (MANIFEST_V2_TOC_ENTRY_SIZE * data->toc_entries) +
		(data->toc_hash_len * 254);

	status = mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.start_sha256,
		&manifest.hash_mock, 0);

	/* Read toc header */
	status |= flash_mock_expect_read_and_hash (&manifest.flash, &manifest.hash_mock,
		manifest.addr + MANIFEST_V2_TOC_HDR_OFFSET, data->toc, MANIFEST_V2_TOC_HEADER_SIZE);

	/* Hash unneeded toc entries */
	status |= flash_mock_expect_verify_flash_and_hash (&manifest.flash, &manifest.hash_mock,
		manifest.addr + toc_entry_offset, data->raw + toc_entry_offset,
		first_entry - toc_entry_offset);

	for (i = start; i <= 254; i++) {
		status |= flash_mock_expect_read_and_hash (&manifest.flash, &manifest.hash_mock,
			manifest.addr + toc_entry_offset + (i * MANIFEST_V2_TOC_ENTRY_SIZE),
			(uint8_t*) &toc_entries[i], MANIFEST_V2_TOC_ENTRY_SIZE);
	}

	status |= flash_mock_expect_verify_flash_and_hash (&manifest.flash, &manifest.hash_mock,
		manifest.addr + last_entry, data->raw + last_entry, hash_offset - last_entry);

	status |= mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash,
		FLASH_READ_FAILED, MOCK_ARG (manifest.addr + hash_offset), MOCK_ARG_NOT_NULL,
		MOCK_ARG (data->toc_hash_len));

	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.cancel,
		&manifest.hash_mock, 0);

	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_get_child_elements_info (&manifest.test, &manifest.hash_mock.base, 2,
		CFM_COMPONENT_DEVICE, MANIFEST_NO_PARENT, CFM_ROOT_CA, &child_len, &num_child, &entry);
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	manifest_flash_v3_testing_validate_and_release (test, &manifest);
}


// *INDENT-OFF*
TEST_SUITE_START (manifest_flash_v3);

TEST (manifest_flash_v3_test_init);
TEST (manifest_flash_v3_test_init_null);
TEST (manifest_flash_v3_test_init_not_aligned);
TEST (manifest_flash_v3_test_init_block_size_error);
TEST (manifest_flash_v3_test_static_init);
TEST (manifest_flash_v3_test_static_init_null);
TEST (manifest_flash_v3_test_verify_v1_unsupported);
TEST (manifest_flash_v3_test_verify_v1_unsupported_static_init);
TEST (manifest_flash_v3_test_verify_v2_unsupported);
TEST (manifest_flash_v3_test_verify_v2_unsupported_static_init);
TEST (manifest_flash_v3_test_verify_bad_magic_number);
TEST (manifest_flash_v3_test_verify_bad_magic_number_v1_unsupported);
TEST (manifest_flash_v3_test_verify_bad_magic_number_v2_unsupported);
TEST (manifest_flash_v3_test_verify_bad_magic_number_v3_unsupported);
TEST (manifest_flash_v3_test_verify_bad_magic_number_none_supported);
TEST (manifest_flash_v3_test_verify_toc_extension);
TEST (manifest_flash_v3_test_verify_toc_extension_with_mock_hash);
TEST (manifest_flash_v3_test_verify_toc_extension_not_allowed);
TEST (manifest_flash_v3_test_verify_toc_extension_not_the_last_entry);
TEST (manifest_flash_v3_test_verify_toc_extension_hash_mismatch);
TEST (manifest_flash_v3_test_verify_toc_extension_length_mismatch);
TEST (manifest_flash_v3_test_verify_toc_extension_zero_entries);
TEST (manifest_flash_v3_test_verify_toc_extension_without_hash);
TEST (manifest_flash_v3_test_verify_toc_extension_root_manifest_content_read_error);
TEST (manifest_flash_v3_test_read_element_data_long_manifest_with_toc_extension);
TEST (manifest_flash_v3_test_read_element_data_toc_extension_zero_entries);
TEST (manifest_flash_v3_test_read_element_data_toc_extension_hash_mismatch);
TEST (manifest_flash_v3_test_read_element_data_toc_extension_not_the_last_entry);
TEST (manifest_flash_v3_test_get_child_elements_info_toc_invalid);
TEST (manifest_flash_v3_test_get_child_elements_info_long_manifest_with_extensions);
TEST (manifest_flash_v3_test_get_child_elements_info_toc_extension_zero_entries);
TEST (manifest_flash_v3_test_get_child_elements_info_toc_extension_hash_mismatch);
TEST (manifest_flash_v3_test_get_child_elements_info_toc_extension_not_the_last_entry);
TEST (manifest_flash_v3_test_get_child_elements_info_toc_extension_before_hash_read_error);
TEST (manifest_flash_v3_test_get_child_elements_info_toc_extension_hash_read_error);

TEST_SUITE_END;
// *INDENT-ON*
