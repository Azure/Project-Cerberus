// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "testing.h"
#include "manifest/manifest_flash.h"
#include "manifest/manifest_format.h"
#include "manifest/manifest.h"
#include "manifest/cfm/cfm_format.h"
#include "manifest/pfm/pfm_format.h"
#include "crypto/ecc.h"
#include "crypto/rsa.h"
#include "manifest_flash_v2_testing.h"
#include "pfm_flash_v2_testing.h"
#include "pcd_testing.h"
#include "cfm_testing.h"


TEST_SUITE_LABEL ("manifest_flash_v2");


/**
 * Initialize common manifest testing dependencies.
 *
 * @param test The testing framework.
 * @param manifest The testing components to initialize.
 * @param address The base address for the manifest data.
 */
void manifest_flash_v2_testing_init_dependencies (CuTest *test,
	struct manifest_flash_v2_testing *manifest, uint32_t address)
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
void manifest_flash_v2_testing_validate_and_release_dependencies (CuTest *test,
	struct manifest_flash_v2_testing *manifest)
{
	int status;

	status = flash_mock_validate_and_release (&manifest->flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&manifest->verification);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_validate_and_release (&manifest->hash_mock);
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
 */
static void manifest_flash_v2_testing_init (CuTest *test,
	struct manifest_flash_v2_testing *manifest, uint32_t address, uint16_t magic_v1,
	uint16_t magic_v2)
{
	int status;

	manifest_flash_v2_testing_init_dependencies (test, manifest, address);
	manifest_flash_v2_testing_init_common (test, manifest, 0x1000);

	status = manifest_flash_v2_init (&manifest->test, &manifest->flash.base, &manifest->hash.base,
		address, magic_v1, magic_v2, manifest->signature, sizeof (manifest->signature),
		manifest->platform_id, sizeof (manifest->platform_id));
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&manifest->flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&manifest->verification.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&manifest->hash_mock.mock);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Release a test instance and validate all mocks.
 *
 * @param test The testing framework.
 * @param manifest The testing components to release.
 */
static void manifest_flash_v2_testing_validate_and_release (CuTest *test,
	struct manifest_flash_v2_testing *manifest)
{
	manifest_flash_release (&manifest->test);

	manifest_flash_v2_testing_validate_and_release_dependencies (test, manifest);
}

/**
 * Set expectations for common initialization flows.
 *
 * @param test The testing framawork.
 * @param manifest The components for the test.
 * @param block_size The flash block size to report.
 */
void manifest_flash_v2_testing_init_common (CuTest *test,
	struct manifest_flash_v2_testing *manifest, uint32_t block_size)
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
void manifest_flash_v2_testing_verify_manifest (CuTest *test,
	struct manifest_flash_v2_testing *manifest, const struct manifest_v2_testing_data *data,
	int sig_result)
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

	/* Read manifest header. */
	status = mock_expect (&manifest->flash.mock, manifest->flash.base.read, &manifest->flash, 0,
		MOCK_ARG (manifest->addr), MOCK_ARG_NOT_NULL, MOCK_ARG (MANIFEST_V2_HEADER_SIZE));
	status |= mock_expect_output (&manifest->flash.mock, 1, data->raw, data->length, 2);

	/* Read manifest signature. */
	status |= mock_expect (&manifest->flash.mock, manifest->flash.base.read, &manifest->flash, 0,
		MOCK_ARG (manifest->addr + data->sig_offset), MOCK_ARG_NOT_NULL, MOCK_ARG (data->sig_len));
	status |= mock_expect_output (&manifest->flash.mock, 1, data->signature, data->sig_len, 2);

	/* Read table of contents header. */
	status |= mock_expect (&manifest->flash.mock, manifest->flash.base.read, &manifest->flash, 0,
		MOCK_ARG (manifest->addr + MANIFEST_V2_TOC_HDR_OFFSET), MOCK_ARG_NOT_NULL,
		MOCK_ARG (MANIFEST_V2_TOC_HEADER_SIZE));
	status |= mock_expect_output (&manifest->flash.mock, 1, data->toc,
		data->length - MANIFEST_V2_TOC_HDR_OFFSET, 2);

	/* Find the platform ID TOC entry. */
	for (i = 0; i <= data->plat_id_entry; i++, validate_toc_start += MANIFEST_V2_TOC_ENTRY_SIZE) {
		status |= mock_expect (&manifest->flash.mock, manifest->flash.base.read, &manifest->flash,
			0, MOCK_ARG (manifest->addr + toc_entry_offset + (i * MANIFEST_V2_TOC_ENTRY_SIZE)),
			MOCK_ARG_NOT_NULL, MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));
		status |= mock_expect_output (&manifest->flash.mock, 1, &toc_entries[i],
			MANIFEST_V2_TOC_ENTRY_SIZE, 2);
	}

	status |= flash_mock_expect_verify_flash (&manifest->flash, manifest->addr + validate_toc_start,
		data->raw + validate_toc_start, data->toc_hash_offset - validate_toc_start);

	/* Read table of contents hash. */
	status |= mock_expect (&manifest->flash.mock, manifest->flash.base.read, &manifest->flash, 0,
		MOCK_ARG (manifest->addr + data->toc_hash_offset), MOCK_ARG_NOT_NULL,
		MOCK_ARG (data->toc_hash_len));
	status |= mock_expect_output (&manifest->flash.mock, 1, data->toc_hash,
		data->length - data->toc_hash_offset, 2);

	status |= flash_mock_expect_verify_flash (&manifest->flash, manifest->addr + validate_start,
		data->raw + validate_start, validate_end - validate_start);

	/* Read the platform ID header. */
	status |= mock_expect (&manifest->flash.mock, manifest->flash.base.read, &manifest->flash, 0,
		MOCK_ARG (manifest->addr + data->plat_id_offset), MOCK_ARG_NOT_NULL,
		MOCK_ARG (MANIFEST_V2_PLATFORM_HEADER_SIZE));
	status |= mock_expect_output (&manifest->flash.mock, 1, data->plat_id,
		data->length - data->plat_id_offset, 2);

	/* Read the platform ID string. */
	status |= mock_expect (&manifest->flash.mock, manifest->flash.base.read, &manifest->flash, 0,
		MOCK_ARG (manifest->addr + data->plat_id_offset + MANIFEST_V2_PLATFORM_HEADER_SIZE),
		MOCK_ARG_NOT_NULL, MOCK_ARG (data->plat_id_str_len));
	status |= mock_expect_output (&manifest->flash.mock, 1, plat_id,
		data->length - data->plat_id_offset + MANIFEST_V2_PLATFORM_HEADER_SIZE, 2);

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
void manifest_flash_v2_testing_verify_manifest_mocked_hash (CuTest *test,
	struct manifest_flash_v2_testing *manifest, const struct manifest_v2_testing_data *data,
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

	/* Read manifest header. */
	status = mock_expect (&manifest->flash.mock, manifest->flash.base.read, &manifest->flash, 0,
		MOCK_ARG (manifest->addr), MOCK_ARG_NOT_NULL, MOCK_ARG (MANIFEST_V2_HEADER_SIZE));
	status |= mock_expect_output (&manifest->flash.mock, 1, data->raw, data->length, 2);

	/* Read manifest signature. */
	status |= mock_expect (&manifest->flash.mock, manifest->flash.base.read, &manifest->flash, 0,
		MOCK_ARG (manifest->addr + data->sig_offset), MOCK_ARG_NOT_NULL, MOCK_ARG (data->sig_len));
	status |= mock_expect_output (&manifest->flash.mock, 1, data->signature, data->sig_len, 2);

	/* Hash */
	switch (data->sig_hash_type) {
		case HASH_TYPE_SHA256:
			status |= mock_expect (&manifest->hash_mock.mock, manifest->hash_mock.base.start_sha256,
				&manifest->hash_mock, 0);
			break;

		case HASH_TYPE_SHA384:
			status |= mock_expect (&manifest->hash_mock.mock, manifest->hash_mock.base.start_sha384,
				&manifest->hash_mock, 0);
			break;

		case HASH_TYPE_SHA512:
			status |= mock_expect (&manifest->hash_mock.mock, manifest->hash_mock.base.start_sha512,
				&manifest->hash_mock, 0);
			break;

		default:
			break;
	}
	status |= mock_expect (&manifest->hash_mock.mock, manifest->hash_mock.base.update,
		&manifest->hash_mock, 0, MOCK_ARG_PTR_CONTAINS (data->raw, MANIFEST_V2_HEADER_SIZE),
		MOCK_ARG (MANIFEST_V2_HEADER_SIZE));

	/* Read table of contents header. */
	status |= mock_expect (&manifest->flash.mock, manifest->flash.base.read, &manifest->flash, 0,
		MOCK_ARG (manifest->addr + MANIFEST_V2_TOC_HDR_OFFSET), MOCK_ARG_NOT_NULL,
		MOCK_ARG (MANIFEST_V2_TOC_HEADER_SIZE));
	status |= mock_expect_output (&manifest->flash.mock, 1, data->toc,
		data->length - MANIFEST_V2_TOC_HDR_OFFSET, 2);

	status |= mock_expect (&manifest->hash_mock.mock, manifest->hash_mock.base.update,
		&manifest->hash_mock, 0, MOCK_ARG_PTR_CONTAINS (data->toc, MANIFEST_V2_TOC_HEADER_SIZE),
		MOCK_ARG (MANIFEST_V2_TOC_HEADER_SIZE));

	/* Find the platform ID TOC entry. */
	for (i = 0; i <= data->plat_id_entry; i++, validate_toc_start += MANIFEST_V2_TOC_ENTRY_SIZE) {
		status |= mock_expect (&manifest->flash.mock, manifest->flash.base.read, &manifest->flash,
			0, MOCK_ARG (manifest->addr + toc_entry_offset + (i * MANIFEST_V2_TOC_ENTRY_SIZE)),
			MOCK_ARG_NOT_NULL, MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));
		status |= mock_expect_output (&manifest->flash.mock, 1, &toc_entries[i],
			MANIFEST_V2_TOC_ENTRY_SIZE, 2);

		status |= mock_expect (&manifest->hash_mock.mock, manifest->hash_mock.base.update,
			&manifest->hash_mock, 0,
			MOCK_ARG_PTR_CONTAINS (&toc_entries[i], MANIFEST_V2_TOC_ENTRY_SIZE),
			MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));
	}

	status |= flash_mock_expect_verify_flash_and_hash (&manifest->flash, &manifest->hash_mock,
		manifest->addr + validate_toc_start, data->raw + validate_toc_start,
		data->toc_hash_offset - validate_toc_start);

	/* Read table of contents hash. */
	status |= mock_expect (&manifest->flash.mock, manifest->flash.base.read, &manifest->flash, 0,
		MOCK_ARG (manifest->addr + data->toc_hash_offset), MOCK_ARG_NOT_NULL,
		MOCK_ARG (data->toc_hash_len));
	status |= mock_expect_output (&manifest->flash.mock, 1, data->toc_hash,
		data->length - data->toc_hash_offset, 2);

	status |= mock_expect (&manifest->hash_mock.mock, manifest->hash_mock.base.update,
		&manifest->hash_mock, 0, MOCK_ARG_PTR_CONTAINS (data->toc_hash, data->toc_hash_len),
		MOCK_ARG (data->toc_hash_len));

	status |= flash_mock_expect_verify_flash_and_hash (&manifest->flash, &manifest->hash_mock,
		manifest->addr + validate_start, data->raw + validate_start, validate_end - validate_start);

	/* Read the platform ID header. */
	status |= mock_expect (&manifest->flash.mock, manifest->flash.base.read, &manifest->flash, 0,
		MOCK_ARG (manifest->addr + data->plat_id_offset), MOCK_ARG_NOT_NULL,
		MOCK_ARG (MANIFEST_V2_PLATFORM_HEADER_SIZE));
	status |= mock_expect_output (&manifest->flash.mock, 1, data->plat_id,
		data->length - data->plat_id_offset, 2);

	status |= mock_expect (&manifest->hash_mock.mock, manifest->hash_mock.base.update,
		&manifest->hash_mock, 0,
		MOCK_ARG_PTR_CONTAINS (data->plat_id, MANIFEST_V2_PLATFORM_HEADER_SIZE),
		MOCK_ARG (MANIFEST_V2_PLATFORM_HEADER_SIZE));

	/* Read the platform ID string. */
	status |= mock_expect (&manifest->flash.mock, manifest->flash.base.read, &manifest->flash, 0,
		MOCK_ARG (manifest->addr + data->plat_id_offset + MANIFEST_V2_PLATFORM_HEADER_SIZE),
		MOCK_ARG_NOT_NULL, MOCK_ARG (data->plat_id_str_len));
	status |= mock_expect_output (&manifest->flash.mock, 1, plat_id,
		data->length - data->plat_id_offset + MANIFEST_V2_PLATFORM_HEADER_SIZE, 2);

	status |= mock_expect (&manifest->hash_mock.mock, manifest->hash_mock.base.update,
		&manifest->hash_mock, 0, MOCK_ARG_PTR_CONTAINS (plat_id, data->plat_id_str_len),
		MOCK_ARG (data->plat_id_str_len));

	status |= flash_mock_expect_verify_flash_and_hash (&manifest->flash,&manifest->hash_mock,
		manifest->addr + validate_resume, data->raw + validate_resume,
		data->sig_offset - validate_resume);

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
 * @param data Manifest data for the test.
 * @param sig_result Result of the signature verification call.
 * @param use_mock true to use the mock hash engine.
 * @param hash_result Result of the final hash call when using the mock hash engine.
 */
static void manifest_flash_v2_testing_init_and_verify (CuTest *test,
	struct manifest_flash_v2_testing *manifest, uint32_t address, uint16_t magic_v1,
	uint16_t magic_v2, const struct manifest_v2_testing_data *data, int sig_result, bool use_mock,
	int hash_result)
{
	struct hash_engine *hash = (!use_mock) ? &manifest->hash.base : &manifest->hash_mock.base;
	int status;

	manifest_flash_v2_testing_init (test, manifest, address, magic_v1, magic_v2);
	if (!use_mock) {
		manifest_flash_v2_testing_verify_manifest (test, manifest, data, sig_result);
	}
	else {
		manifest_flash_v2_testing_verify_manifest_mocked_hash (test, manifest, data, sig_result,
			hash_result);
	}

	status = manifest_flash_verify (&manifest->test, hash, &manifest->verification.base, NULL, 0);
	CuAssertIntEquals (test, sig_result, status);

	status = mock_validate (&manifest->flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&manifest->verification.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&manifest->hash_mock.mock);
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
void manifest_flash_v2_testing_read_element (CuTest *test,
	struct manifest_flash_v2_testing *manifest, const struct manifest_v2_testing_data *data,
	int entry, int start, int hash_id, uint32_t offset, size_t length, size_t read_len,
	uint32_t read_offset)
{
	uint32_t toc_entry_offset = MANIFEST_V2_TOC_ENTRY_OFFSET;
	uint32_t first_entry = toc_entry_offset + (MANIFEST_V2_TOC_ENTRY_SIZE * start);
	uint32_t last_entry = toc_entry_offset + (MANIFEST_V2_TOC_ENTRY_SIZE * (entry + 1));
	uint32_t hash_offset;
	uint32_t after_hash;
	const struct manifest_toc_entry *toc_entries =
		(struct manifest_toc_entry*) (data->raw + toc_entry_offset);
	int i;
	int entry_read;
	int status;

	if (hash_id >= 0) {
		hash_offset = toc_entry_offset + (MANIFEST_V2_TOC_ENTRY_SIZE * data->toc_entries) +
			(data->toc_hash_len * hash_id);
		after_hash = hash_offset + data->toc_hash_len;
	}

	/* Start hashing the table of contents data. */
	status = flash_mock_expect_verify_flash (&manifest->flash, manifest->addr + toc_entry_offset,
		data->raw + toc_entry_offset, first_entry - toc_entry_offset);

	/* Find the desired TOC entry. */
	entry_read = (entry >= start) ? entry : data->toc_entries - 1;
	for (i = start; i <= entry_read; i++) {
		status |= mock_expect (&manifest->flash.mock, manifest->flash.base.read, &manifest->flash,
			0, MOCK_ARG (manifest->addr + toc_entry_offset + (i * MANIFEST_V2_TOC_ENTRY_SIZE)),
			MOCK_ARG_NOT_NULL, MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));
		status |= mock_expect_output (&manifest->flash.mock, 1, &toc_entries[i],
			MANIFEST_V2_TOC_ENTRY_SIZE, 2);
	}

	if (entry < start) {
		/* Entry will not be found in the manifest. */
		goto done;
	}

	if (hash_id >= 0) {
		/* Hash TOC data until element hash. */
		status |= flash_mock_expect_verify_flash (&manifest->flash, manifest->addr + last_entry,
			data->raw + last_entry, hash_offset - last_entry);

		/* Read element hash. */
		status |= mock_expect (&manifest->flash.mock, manifest->flash.base.read, &manifest->flash,
			0, MOCK_ARG (manifest->addr + hash_offset), MOCK_ARG_NOT_NULL,
			MOCK_ARG (data->toc_hash_len));
		status |= mock_expect_output (&manifest->flash.mock, 1, data->raw + hash_offset,
			data->length - hash_offset, 2);

		/* Hash remaining TOC data. */
		status |= flash_mock_expect_verify_flash (&manifest->flash, manifest->addr + after_hash,
			data->raw + after_hash, data->toc_hash_offset - after_hash);
	}
	else {
		/* Hash remaining TOC data. */
		status |= flash_mock_expect_verify_flash (&manifest->flash, manifest->addr + last_entry,
			data->raw + last_entry, data->toc_hash_offset - last_entry);
	}

	if ((read_offset >= length) || (read_len == 0)) {
		goto done;
	}

	/* Read element data */
	if (read_offset != 0) {
		if (hash_id >= 0) {
			status |= flash_mock_expect_verify_flash (&manifest->flash, manifest->addr + offset,
				data->raw + offset, read_offset);
		}

		length -= read_offset;
		offset += read_offset;
	}
	if (length < read_len) {
		read_len = length;
	}

	status |= mock_expect (&manifest->flash.mock, manifest->flash.base.read, &manifest->flash, 0,
		MOCK_ARG (manifest->addr + offset), MOCK_ARG_NOT_NULL, MOCK_ARG (read_len));
	status |= mock_expect_output (&manifest->flash.mock, 1, data->raw + offset,
		data->length - offset, 2);

	if ((hash_id >= 0) && (read_len < length)) {
		status |= flash_mock_expect_verify_flash (&manifest->flash,
			manifest->addr + offset + read_len, data->raw + offset + read_len, length - read_len);
	}

done:
	CuAssertIntEquals (test, 0, status);
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
void manifest_flash_v2_testing_read_element_mocked_hash (CuTest *test,
	struct manifest_flash_v2_testing *manifest, const struct manifest_v2_testing_data *data,
	int entry, int start, int hash_id, uint32_t offset, size_t length, size_t read_len,
	uint32_t read_offset)
{
	uint32_t toc_entry_offset = MANIFEST_V2_TOC_ENTRY_OFFSET;
	uint32_t first_entry = toc_entry_offset + (MANIFEST_V2_TOC_ENTRY_SIZE * start);
	uint32_t last_entry = toc_entry_offset + (MANIFEST_V2_TOC_ENTRY_SIZE * (entry + 1));
	uint32_t hash_offset;
	uint32_t after_hash;
	const struct manifest_toc_entry *toc_entries =
		(struct manifest_toc_entry*) (data->raw + toc_entry_offset);
	int i;
	int entry_read;
	int status;

	if (hash_id >= 0) {
		hash_offset = toc_entry_offset + (MANIFEST_V2_TOC_ENTRY_SIZE * data->toc_entries) +
			(data->toc_hash_len * hash_id);
		after_hash = hash_offset + data->toc_hash_len;
	}

	/* Start hashing the table of contents data. */
	switch (data->toc_hash_type) {
		case HASH_TYPE_SHA256:
			status = mock_expect (&manifest->hash_mock.mock, manifest->hash_mock.base.start_sha256,
				&manifest->hash_mock, 0);
			break;

		case HASH_TYPE_SHA384:
			status = mock_expect (&manifest->hash_mock.mock, manifest->hash_mock.base.start_sha384,
				&manifest->hash_mock, 0);
			break;

		case HASH_TYPE_SHA512:
			status = mock_expect (&manifest->hash_mock.mock, manifest->hash_mock.base.start_sha512,
				&manifest->hash_mock, 0);
			break;

		default:
			status = 0;
			break;
	}
	status |= mock_expect (&manifest->hash_mock.mock, manifest->hash_mock.base.update,
		&manifest->hash_mock, 0, MOCK_ARG_PTR_CONTAINS (data->toc, MANIFEST_V2_TOC_HEADER_SIZE),
		MOCK_ARG (MANIFEST_V2_TOC_HEADER_SIZE));

	status |= flash_mock_expect_verify_flash_and_hash (&manifest->flash, &manifest->hash_mock,
		manifest->addr + toc_entry_offset, data->raw + toc_entry_offset,
		first_entry - toc_entry_offset);

	/* Find the desired TOC entry. */
	entry_read = (entry >= start) ? entry : data->toc_entries - 1;
	for (i = start; i <= entry_read; i++) {
		status |= mock_expect (&manifest->flash.mock, manifest->flash.base.read, &manifest->flash,
			0, MOCK_ARG (manifest->addr + toc_entry_offset + (i * MANIFEST_V2_TOC_ENTRY_SIZE)),
			MOCK_ARG_NOT_NULL, MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));
		status |= mock_expect_output (&manifest->flash.mock, 1, &toc_entries[i],
			MANIFEST_V2_TOC_ENTRY_SIZE, 2);

		status |= mock_expect (&manifest->hash_mock.mock, manifest->hash_mock.base.update,
			&manifest->hash_mock, 0,
			MOCK_ARG_PTR_CONTAINS (&toc_entries[i], MANIFEST_V2_TOC_ENTRY_SIZE),
			MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));
	}

	if (entry < start) {
		/* Entry will not be found in the manifest. */
		goto cancel;
	}

	if (hash_id >= 0) {
		/* Hash TOC data until element hash. */
		status |= flash_mock_expect_verify_flash_and_hash (&manifest->flash, &manifest->hash_mock,
			manifest->addr + last_entry, data->raw + last_entry, hash_offset - last_entry);

		/* Read element hash. */
		status |= mock_expect (&manifest->flash.mock, manifest->flash.base.read, &manifest->flash,
			0, MOCK_ARG (manifest->addr + hash_offset), MOCK_ARG_NOT_NULL,
			MOCK_ARG (data->toc_hash_len));
		status |= mock_expect_output (&manifest->flash.mock, 1, data->raw + hash_offset,
			data->length - hash_offset, 2);

		status |= mock_expect (&manifest->hash_mock.mock, manifest->hash_mock.base.update,
			&manifest->hash_mock, 0,
			MOCK_ARG_PTR_CONTAINS (&data->raw[hash_offset], data->toc_hash_len),
			MOCK_ARG (data->toc_hash_len));

		/* Hash remaining TOC data. */
		status |= flash_mock_expect_verify_flash_and_hash (&manifest->flash, &manifest->hash_mock,
			manifest->addr + after_hash, data->raw + after_hash,
			data->toc_hash_offset - after_hash);
	}
	else {
		/* Hash remaining TOC data. */
		status |= flash_mock_expect_verify_flash_and_hash (&manifest->flash, &manifest->hash_mock,
			manifest->addr + last_entry, data->raw + last_entry,
			data->toc_hash_offset - last_entry);
	}

	/* TOC hash */
	status |= mock_expect (&manifest->hash_mock.mock, manifest->hash_mock.base.finish,
		&manifest->hash_mock, 0, MOCK_ARG_NOT_NULL, MOCK_ARG (SHA512_HASH_LENGTH));
	status |= mock_expect_output (&manifest->hash_mock.mock, 0, data->toc_hash, data->toc_hash_len,
		1);

	if ((read_offset >= length) || (read_len == 0)) {
		goto done;
	}

	/* Read element data */
	if (hash_id >= 0) {
		switch (data->toc_hash_type) {
			case HASH_TYPE_SHA256:
				status |= mock_expect (&manifest->hash_mock.mock,
					manifest->hash_mock.base.start_sha256, &manifest->hash_mock, 0);
				break;

			case HASH_TYPE_SHA384:
				status |= mock_expect (&manifest->hash_mock.mock,
					manifest->hash_mock.base.start_sha384, &manifest->hash_mock, 0);
				break;

			case HASH_TYPE_SHA512:
				status |= mock_expect (&manifest->hash_mock.mock,
					manifest->hash_mock.base.start_sha512, &manifest->hash_mock, 0);
				break;

			default:
				break;
		}
	}

	if (read_offset != 0) {
		if (hash_id >= 0) {
			status |= flash_mock_expect_verify_flash_and_hash (&manifest->flash,
				&manifest->hash_mock, manifest->addr + offset, data->raw + offset, read_offset);
		}

		length -= read_offset;
		offset += read_offset;
	}
	if (length < read_len) {
		read_len = length;
	}

	status |= mock_expect (&manifest->flash.mock, manifest->flash.base.read, &manifest->flash, 0,
		MOCK_ARG (manifest->addr + offset), MOCK_ARG_NOT_NULL, MOCK_ARG (read_len));
	status |= mock_expect_output (&manifest->flash.mock, 1, data->raw + offset,
		data->length - offset, 2);

	/* Element hash */
	if (hash_id >= 0) {
		status |= mock_expect (&manifest->hash_mock.mock, manifest->hash_mock.base.update,
			&manifest->hash_mock, 0, MOCK_ARG_PTR_CONTAINS (data->raw + offset, read_len),
			MOCK_ARG (read_len));

		if (read_len < length) {
			status |= flash_mock_expect_verify_flash_and_hash (&manifest->flash,
				&manifest->hash_mock, manifest->addr + offset + read_len,
				data->raw + offset + read_len, length - read_len);
		}

		status |= mock_expect (&manifest->hash_mock.mock, manifest->hash_mock.base.finish,
			&manifest->hash_mock, 0, MOCK_ARG_NOT_NULL, MOCK_ARG (SHA512_HASH_LENGTH));
		status |= mock_expect_output (&manifest->hash_mock.mock, 0, &data->raw[hash_offset],
			data->toc_hash_len, 1);
	}

done:
	CuAssertIntEquals (test, 0, status);
	return;

cancel:
	status |= mock_expect (&manifest->hash_mock.mock, manifest->hash_mock.base.cancel,
		&manifest->hash_mock, 0);

	CuAssertIntEquals (test, 0, status);
}

/**
 * Set expectations on mocks for getting number of child elements for an element in a v2 manifest.
 *
 * @param test The testing framework.
 * @param manifest The components for the test.
 * @param data Manifest data for the test.
 * @param entry The table of contents index to start searching at.
 * @param last_entry The last entry index to check.
 */
void manifest_flash_v2_testing_get_num_child_elements (CuTest *test,
	struct manifest_flash_v2_testing *manifest, const struct manifest_v2_testing_data *data,
	int entry, int last_entry)
{
	uint32_t offset = MANIFEST_V2_TOC_ENTRY_OFFSET;
	int status;

	/* Start hashing the table of contents data. */
	status = flash_mock_expect_verify_flash (&manifest->flash, manifest->addr + offset,
		data->raw + offset,	MANIFEST_V2_TOC_ENTRY_SIZE * entry);
	CuAssertIntEquals (test, 0, status);

	offset += (MANIFEST_V2_TOC_ENTRY_SIZE * entry);

	for (int i = entry; i <= last_entry; ++i) {
		status |= mock_expect (&manifest->flash.mock, manifest->flash.base.read, &manifest->flash,
			0, MOCK_ARG (manifest->addr + offset), MOCK_ARG_NOT_NULL,
			MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));
		status |= mock_expect_output (&manifest->flash.mock, 1, data->raw + offset,
			MANIFEST_V2_TOC_ENTRY_SIZE, 2);

		offset += MANIFEST_V2_TOC_ENTRY_SIZE;
	}
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_expect_verify_flash (&manifest->flash, manifest->addr + offset,
		data->raw + offset, MANIFEST_V2_TOC_ENTRY_SIZE * (data->toc_entries - last_entry - 1) +
		data->toc_entries * data->toc_hash_len);
	CuAssertIntEquals (test, 0, status);
}

/*******************
 * Test cases
 *******************/

static void manifest_flash_v2_test_init (CuTest *test)
{
	struct manifest_flash_v2_testing manifest;
	uint32_t bytes = 0x1000;
	int status;

	TEST_START;

	manifest_flash_v2_testing_init_dependencies (test, &manifest, 0x10000);

	status = mock_expect (&manifest.flash.mock, manifest.flash.base.get_block_size, &manifest.flash,
		0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manifest.flash.mock, 0, &bytes, sizeof (bytes), -1);

	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_v2_init (&manifest.test, &manifest.flash.base, &manifest.hash.base,
		0x10000, PFM_MAGIC_NUM, PFM_V2_MAGIC_NUM, manifest.signature, sizeof (manifest.signature),
		manifest.platform_id, sizeof (manifest.platform_id));
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, 0x10000, manifest_flash_get_addr (&manifest.test));
	CuAssertPtrEquals (test, &manifest.flash, manifest_flash_get_flash (&manifest.test));

	manifest_flash_v2_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_v2_test_init_null (CuTest *test)
{
	struct manifest_flash_v2_testing manifest;
	int status;

	TEST_START;

	manifest_flash_v2_testing_init_dependencies (test, &manifest, 0x10000);

	status = manifest_flash_v2_init (NULL, &manifest.flash.base, &manifest.hash.base,
		0x10000, PFM_MAGIC_NUM, PFM_V2_MAGIC_NUM, manifest.signature, sizeof (manifest.signature),
		manifest.platform_id, sizeof (manifest.platform_id));
	CuAssertIntEquals (test, MANIFEST_INVALID_ARGUMENT, status);

	status = manifest_flash_v2_init (&manifest.test, NULL, &manifest.hash.base,
		0x10000, PFM_MAGIC_NUM, PFM_V2_MAGIC_NUM, manifest.signature, sizeof (manifest.signature),
		manifest.platform_id, sizeof (manifest.platform_id));
	CuAssertIntEquals (test, MANIFEST_INVALID_ARGUMENT, status);

	status = manifest_flash_v2_init (&manifest.test, &manifest.flash.base, NULL,
		0x10000, PFM_MAGIC_NUM, PFM_V2_MAGIC_NUM, manifest.signature, sizeof (manifest.signature),
		manifest.platform_id, sizeof (manifest.platform_id));
	CuAssertIntEquals (test, MANIFEST_INVALID_ARGUMENT, status);

	status = manifest_flash_v2_init (&manifest.test, &manifest.flash.base, &manifest.hash.base,
		0x10000, PFM_MAGIC_NUM, PFM_V2_MAGIC_NUM, NULL, sizeof (manifest.signature),
		manifest.platform_id, sizeof (manifest.platform_id));
	CuAssertIntEquals (test, MANIFEST_INVALID_ARGUMENT, status);

	status = manifest_flash_v2_init (&manifest.test, &manifest.flash.base, &manifest.hash.base,
		0x10000, PFM_MAGIC_NUM, PFM_V2_MAGIC_NUM, manifest.signature, sizeof (manifest.signature),
		NULL, sizeof (manifest.platform_id));
	CuAssertIntEquals (test, MANIFEST_INVALID_ARGUMENT, status);

	manifest_flash_v2_testing_validate_and_release_dependencies (test, &manifest);
}

static void manifest_flash_v2_test_init_not_aligned (CuTest *test)
{
	struct manifest_flash_v2_testing manifest;
	uint32_t bytes = 0x1000;
	int status;

	TEST_START;

	manifest_flash_v2_testing_init_dependencies (test, &manifest, 0x10100);

	status = mock_expect (&manifest.flash.mock, manifest.flash.base.get_block_size, &manifest.flash,
		0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manifest.flash.mock, 0, &bytes, sizeof (bytes), -1);

	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_v2_init (&manifest.test, &manifest.flash.base, &manifest.hash.base,
		0x10100, PFM_MAGIC_NUM, PFM_V2_MAGIC_NUM, manifest.signature, sizeof (manifest.signature),
		manifest.platform_id, sizeof (manifest.platform_id));
	CuAssertIntEquals (test, MANIFEST_STORAGE_NOT_ALIGNED, status);

	manifest_flash_v2_testing_validate_and_release_dependencies (test, &manifest);
}

static void manifest_flash_v2_test_init_block_size_error (CuTest *test)
{
	struct manifest_flash_v2_testing manifest;
	int status;

	TEST_START;

	manifest_flash_v2_testing_init_dependencies (test, &manifest, 0x10000);

	status = mock_expect (&manifest.flash.mock, manifest.flash.base.get_block_size, &manifest.flash,
		FLASH_BLOCK_SIZE_FAILED, MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_v2_init (&manifest.test, &manifest.flash.base, &manifest.hash.base,
		0x10000, PFM_MAGIC_NUM, PFM_V2_MAGIC_NUM, manifest.signature, sizeof (manifest.signature),
		manifest.platform_id, sizeof (manifest.platform_id));
	CuAssertIntEquals (test, FLASH_BLOCK_SIZE_FAILED, status);

	manifest_flash_v2_testing_validate_and_release_dependencies (test, &manifest);
}

static void manifest_flash_v2_test_verify (CuTest *test)
{
	struct manifest_flash_v2_testing manifest;
	int status;

	TEST_START;

	manifest_flash_v2_testing_init (test, &manifest, 0x10000, PFM_MAGIC_NUM, PFM_V2_MAGIC_NUM);

	manifest_flash_v2_testing_verify_manifest (test, &manifest, &PFM_V2.manifest, 0);

	status = manifest_flash_verify (&manifest.test, &manifest.hash.base,
		&manifest.verification.base, NULL, 0);
	CuAssertIntEquals (test, 0, status);

	manifest_flash_v2_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_v2_test_verify_with_mock_hash (CuTest *test)
{
	struct manifest_flash_v2_testing manifest;
	int status;

	TEST_START;

	manifest_flash_v2_testing_init (test, &manifest, 0x10000, PFM_MAGIC_NUM, PFM_V2_MAGIC_NUM);

	manifest_flash_v2_testing_verify_manifest_mocked_hash (test, &manifest, &PFM_V2.manifest, 0, 0);

	status = manifest_flash_verify (&manifest.test, &manifest.hash_mock.base,
		&manifest.verification.base, NULL, 0);
	CuAssertIntEquals (test, 0, status);

	manifest_flash_v2_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_v2_test_verify_platform_id_first (CuTest *test)
{
	struct manifest_flash_v2_testing manifest;
	int status;

	TEST_START;

	manifest_flash_v2_testing_init (test, &manifest, 0x10000, PFM_MAGIC_NUM, PFM_V2_MAGIC_NUM);

	manifest_flash_v2_testing_verify_manifest (test, &manifest, &PFM_V2_PLAT_FIRST.manifest, 0);

	status = manifest_flash_verify (&manifest.test, &manifest.hash.base,
		&manifest.verification.base, NULL, 0);
	CuAssertIntEquals (test, 0, status);

	manifest_flash_v2_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_v2_test_verify_ecc_signature (CuTest *test)
{
	struct manifest_flash_v2_testing manifest;
	int status;

	TEST_START;

	manifest_flash_v2_testing_init (test, &manifest, 0x10000, PFM_MAGIC_NUM, PFM_V2_MAGIC_NUM);

	manifest_flash_v2_testing_verify_manifest (test, &manifest, &PFM_V2_TWO_FW.manifest, 0);

	status = manifest_flash_verify (&manifest.test, &manifest.hash.base,
		&manifest.verification.base, NULL, 0);
	CuAssertIntEquals (test, 0, status);

	manifest_flash_v2_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_v2_test_verify_sha384 (CuTest *test)
{
	struct manifest_flash_v2_testing manifest;
	int status;

	TEST_START;

	manifest_flash_v2_testing_init (test, &manifest, 0x10000, PFM_MAGIC_NUM, PFM_V2_MAGIC_NUM);

	manifest_flash_v2_testing_verify_manifest (test, &manifest, &PFM_V2_SHA384.manifest, 0);

	status = manifest_flash_verify (&manifest.test, &manifest.hash.base,
		&manifest.verification.base, NULL, 0);
	CuAssertIntEquals (test, 0, status);

	manifest_flash_v2_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_v2_test_verify_sha512 (CuTest *test)
{
	struct manifest_flash_v2_testing manifest;
	int status;

	TEST_START;

	manifest_flash_v2_testing_init (test, &manifest, 0x10000, PFM_MAGIC_NUM, PFM_V2_MAGIC_NUM);

	manifest_flash_v2_testing_verify_manifest (test, &manifest, &PFM_V2_SHA512.manifest, 0);

	status = manifest_flash_verify (&manifest.test, &manifest.hash.base,
		&manifest.verification.base, NULL, 0);
	CuAssertIntEquals (test, 0, status);

	manifest_flash_v2_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_v2_test_verify_different_hash_types (CuTest *test)
{
	struct manifest_flash_v2_testing manifest;
	int status;

	TEST_START;

	manifest_flash_v2_testing_init (test, &manifest, 0x10000, PFM_MAGIC_NUM, PFM_V2_MAGIC_NUM);

	manifest_flash_v2_testing_verify_manifest (test, &manifest, &PFM_V2_DIFF_HASH_TYPE.manifest, 0);

	status = manifest_flash_verify (&manifest.test, &manifest.hash.base,
		&manifest.verification.base, NULL, 0);
	CuAssertIntEquals (test, 0, status);

	manifest_flash_v2_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_v2_test_verify_no_element_hashes (CuTest *test)
{
	struct manifest_flash_v2_testing manifest;
	int status;

	TEST_START;

	manifest_flash_v2_testing_init (test, &manifest, 0x10000, PFM_MAGIC_NUM, PFM_V2_MAGIC_NUM);

	manifest_flash_v2_testing_verify_manifest (test, &manifest, &PFM_V2_NO_TOC_HASHES.manifest, 0);

	status = manifest_flash_verify (&manifest.test, &manifest.hash.base,
		&manifest.verification.base, NULL, 0);
	CuAssertIntEquals (test, 0, status);

	manifest_flash_v2_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_v2_test_verify_partial_element_hashes (CuTest *test)
{
	struct manifest_flash_v2_testing manifest;
	int status;

	TEST_START;

	manifest_flash_v2_testing_init (test, &manifest, 0x10000, PFM_MAGIC_NUM, PFM_V2_MAGIC_NUM);

	manifest_flash_v2_testing_verify_manifest (test, &manifest, &PFM_V2_NO_FW_HASHES.manifest, 0);

	status = manifest_flash_verify (&manifest.test, &manifest.hash.base,
		&manifest.verification.base, NULL, 0);
	CuAssertIntEquals (test, 0, status);

	manifest_flash_v2_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_v2_test_verify_minimum_platform_id_buffer_length (CuTest *test)
{
	struct manifest_flash_v2_testing manifest;
	int status;

	TEST_START;

	manifest_flash_v2_testing_init_dependencies (test, &manifest, 0x10000);
	manifest_flash_v2_testing_init_common (test, &manifest, 0x1000);

	status = manifest_flash_v2_init (&manifest.test, &manifest.flash.base, &manifest.hash.base,
		0x10000, PFM_MAGIC_NUM, PFM_V2_MAGIC_NUM, manifest.signature, sizeof (manifest.signature),
		manifest.platform_id, PFM_V2.manifest.plat_id_str_len + 1);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&manifest.flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&manifest.verification.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&manifest.hash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	manifest_flash_v2_testing_verify_manifest (test, &manifest, &PFM_V2.manifest, 0);

	status = manifest_flash_verify (&manifest.test, &manifest.hash.base,
		&manifest.verification.base, NULL, 0);
	CuAssertIntEquals (test, 0, status);

	manifest_flash_v2_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_v2_test_verify_max_entries_and_hashes (CuTest *test)
{
	struct manifest_flash_v2_testing manifest;
	int status;
	union {
		struct {
			struct manifest_toc_entry entries[0xff];
			uint8_t hashes[0xff][SHA256_HASH_LENGTH];
		} data;
		uint8_t raw[(MANIFEST_V2_TOC_ENTRY_SIZE + SHA256_HASH_LENGTH) * 0xff];
	} toc;
	uint8_t data[PFM_V2.manifest.plat_id_len + PFM_V2.flash_dev_len];
	size_t toc_len = MANIFEST_V2_TOC_HEADER_SIZE + sizeof (toc) + SHA256_HASH_LENGTH;
	size_t sig_len = RSA_KEY_LENGTH_2K;
	uint32_t sig_offset = MANIFEST_V2_HEADER_SIZE + toc_len + sizeof (data);
	struct manifest_header header = {
		.length = sig_offset + sig_len,
		.magic = PFM_V2_MAGIC_NUM,
		.id = 100,
		.sig_length = sig_len,
		.sig_type = 0,
		.reserved = 0
	};
	struct manifest_toc_header toc_header = {
		.entry_count = 0xff,
		.hash_count = 0xff,
		.hash_type = 0,
		.reserved = 0,
	};
	uint32_t toc_entry_offset = MANIFEST_V2_TOC_ENTRY_OFFSET;
	const uint8_t *plat_id = data + MANIFEST_V2_PLATFORM_HEADER_SIZE;
	uint32_t validate_toc_start = toc_entry_offset;
	uint32_t toc_hash_offset = MANIFEST_V2_HEADER_SIZE + toc_len - SHA256_HASH_LENGTH;
	uint32_t plat_id_offset = MANIFEST_V2_HEADER_SIZE + toc_len;
	uint32_t fw_offset = plat_id_offset + PFM_V2.manifest.plat_id_len;
	uint32_t validate_resume =
		plat_id_offset + MANIFEST_V2_PLATFORM_HEADER_SIZE + PFM_V2.manifest.plat_id_str_len;
	int i;

	TEST_START;

	/* Fill the manifest data. */
	memcpy (data, PFM_V2.manifest.plat_id, PFM_V2.manifest.plat_id_len);
	memcpy (&data[PFM_V2.manifest.plat_id_len], PFM_V2.flash_dev, PFM_V2.flash_dev_len);

	/* Fill the TOC with entries and hashes. */
	for (i = 0; i < 0xff; i++) {
		if (i == 0x80) {
			memcpy (&toc.data.entries[i],
				PFM_V2.manifest.raw + toc_entry_offset +
					(MANIFEST_V2_TOC_ENTRY_SIZE * PFM_V2.manifest.plat_id_entry),
				MANIFEST_V2_TOC_ENTRY_SIZE);
			toc.data.entries[i].offset = plat_id_offset;
		}
		else {
			memcpy (&toc.data.entries[i], &PFM_V2.manifest.raw[toc_entry_offset],
				MANIFEST_V2_TOC_ENTRY_SIZE);
			toc.data.entries[i].offset = fw_offset;
		}
		toc.data.entries[i].format = 0x60;
		toc.data.entries[i].hash_id = i;

		memcpy (toc.data.hashes[i], &PFM_V2.manifest.toc_hash, SHA256_HASH_LENGTH);
		toc.data.hashes[i][0] ^= 0x55;
		toc.data.hashes[i][1] = i;
	}

	manifest_flash_v2_testing_init (test, &manifest, 0x10000, PFM_MAGIC_NUM, PFM_V2_MAGIC_NUM);

	/* Read manifest header. */
	status = mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash, 0,
		MOCK_ARG (manifest.addr), MOCK_ARG_NOT_NULL, MOCK_ARG (MANIFEST_V2_HEADER_SIZE));
	status |= mock_expect_output (&manifest.flash.mock, 1, &header, sizeof (header), 2);

	/* Read manifest signature. */
	status |= mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash, 0,
		MOCK_ARG (manifest.addr + sig_offset), MOCK_ARG_NOT_NULL, MOCK_ARG (sig_len));
	status |= mock_expect_output (&manifest.flash.mock, 1, PFM_V2.manifest.signature, sig_len, 2);

	/* Hash */
	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.start_sha256,
		&manifest.hash_mock, 0);

	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.update,
		&manifest.hash_mock, 0, MOCK_ARG_PTR_CONTAINS (&header, MANIFEST_V2_HEADER_SIZE),
		MOCK_ARG (MANIFEST_V2_HEADER_SIZE));

	/* Read table of contents header. */
	status |= mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash, 0,
		MOCK_ARG (manifest.addr + MANIFEST_V2_TOC_HDR_OFFSET), MOCK_ARG_NOT_NULL,
		MOCK_ARG (MANIFEST_V2_TOC_HEADER_SIZE));
	status |= mock_expect_output (&manifest.flash.mock, 1, &toc_header, sizeof (toc_header), 2);

	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.update,
		&manifest.hash_mock, 0, MOCK_ARG_PTR_CONTAINS (&toc_header, MANIFEST_V2_TOC_HEADER_SIZE),
		MOCK_ARG (MANIFEST_V2_TOC_HEADER_SIZE));

	/* Find the platform ID TOC entry. */
	for (i = 0; i <= 0x80; i++, validate_toc_start += MANIFEST_V2_TOC_ENTRY_SIZE) {
		status |= mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash,
			0, MOCK_ARG (manifest.addr + toc_entry_offset + (i * MANIFEST_V2_TOC_ENTRY_SIZE)),
			MOCK_ARG_NOT_NULL, MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));
		status |= mock_expect_output (&manifest.flash.mock, 1, &toc.data.entries[i],
			MANIFEST_V2_TOC_ENTRY_SIZE, 2);

		status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.update,
			&manifest.hash_mock, 0,
			MOCK_ARG_PTR_CONTAINS (&toc.data.entries[i], MANIFEST_V2_TOC_ENTRY_SIZE),
			MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));
	}

	status |= flash_mock_expect_verify_flash_and_hash (&manifest.flash, &manifest.hash_mock,
		manifest.addr + validate_toc_start, toc.raw + (validate_toc_start - toc_entry_offset),
		toc_hash_offset - validate_toc_start);

	/* Read table of contents hash. */
	status |= mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash, 0,
		MOCK_ARG (manifest.addr + toc_hash_offset), MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&manifest.flash.mock, 1, PFM_V2.manifest.toc_hash,
		SHA256_HASH_LENGTH, 2);

	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.update,
		&manifest.hash_mock, 0,
		MOCK_ARG_PTR_CONTAINS (PFM_V2.manifest.toc_hash, SHA256_HASH_LENGTH),
		MOCK_ARG (SHA256_HASH_LENGTH));

	/* Read the platform ID header. */
	status |= mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash, 0,
		MOCK_ARG (manifest.addr + plat_id_offset), MOCK_ARG_NOT_NULL,
		MOCK_ARG (MANIFEST_V2_PLATFORM_HEADER_SIZE));
	status |= mock_expect_output (&manifest.flash.mock, 1, data, sizeof (data), 2);

	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.update,
		&manifest.hash_mock, 0, MOCK_ARG_PTR_CONTAINS (data, MANIFEST_V2_PLATFORM_HEADER_SIZE),
		MOCK_ARG (MANIFEST_V2_PLATFORM_HEADER_SIZE));

	/* Read the platform ID string. */
	status |= mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash, 0,
		MOCK_ARG (manifest.addr + plat_id_offset + MANIFEST_V2_PLATFORM_HEADER_SIZE),
		MOCK_ARG_NOT_NULL, MOCK_ARG (PFM_V2.manifest.plat_id_str_len));
	status |= mock_expect_output (&manifest.flash.mock, 1, plat_id, PFM_V2.manifest.plat_id_len, 2);

	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.update,
		&manifest.hash_mock, 0, MOCK_ARG_PTR_CONTAINS (plat_id, PFM_V2.manifest.plat_id_str_len),
		MOCK_ARG (PFM_V2.manifest.plat_id_str_len));

	/* Hash remaining manifest and verify signature. */
	status |= flash_mock_expect_verify_flash_and_hash (&manifest.flash, &manifest.hash_mock,
		manifest.addr + validate_resume, data + validate_resume - plat_id_offset,
		sig_offset - validate_resume);

	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.finish,
		&manifest.hash_mock, 0, MOCK_ARG_NOT_NULL, MOCK_ARG_ANY);
	status |= mock_expect_output (&manifest.hash_mock.mock, 0, PFM_V2.manifest.hash,
		SHA256_HASH_LENGTH, 1);

	status |= mock_expect (&manifest.verification.mock,
		manifest.verification.base.verify_signature, &manifest.verification, 0,
		MOCK_ARG_PTR_CONTAINS (PFM_V2.manifest.hash, SHA256_HASH_LENGTH),
		MOCK_ARG (SHA256_HASH_LENGTH),
		MOCK_ARG_PTR_CONTAINS (PFM_V2.manifest.signature, sig_len), MOCK_ARG (sig_len));

	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_verify (&manifest.test, &manifest.hash_mock.base,
		&manifest.verification.base, NULL, 0);
	CuAssertIntEquals (test, 0, status);

	manifest_flash_v2_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_v2_test_verify_with_hash_out (CuTest *test)
{
	struct manifest_flash_v2_testing manifest;
	int status;
	uint8_t hash_out[SHA256_HASH_LENGTH];

	TEST_START;

	manifest_flash_v2_testing_init (test, &manifest, 0x10000, PFM_MAGIC_NUM, PFM_V2_MAGIC_NUM);

	manifest_flash_v2_testing_verify_manifest (test, &manifest, &PFM_V2.manifest, 0);

	status = manifest_flash_verify (&manifest.test, &manifest.hash.base,
		&manifest.verification.base, hash_out, sizeof (hash_out));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (PFM_V2.manifest.hash, hash_out, PFM_V2.manifest.hash_len);
	CuAssertIntEquals (test, 0, status);

	manifest_flash_v2_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_v2_test_verify_with_hash_out_sha384 (CuTest *test)
{
	struct manifest_flash_v2_testing manifest;
	int status;
	uint8_t hash_out[SHA384_HASH_LENGTH];

	TEST_START;

	manifest_flash_v2_testing_init (test, &manifest, 0x10000, PFM_MAGIC_NUM, PFM_V2_MAGIC_NUM);

	manifest_flash_v2_testing_verify_manifest (test, &manifest, &PFM_V2_SHA384.manifest, 0);

	status = manifest_flash_verify (&manifest.test, &manifest.hash.base,
		&manifest.verification.base, hash_out, sizeof (hash_out));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (PFM_V2_SHA384.manifest.hash, hash_out,
		PFM_V2_SHA384.manifest.hash_len);
	CuAssertIntEquals (test, 0, status);

	manifest_flash_v2_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_v2_test_verify_with_hash_out_sha512 (CuTest *test)
{
	struct manifest_flash_v2_testing manifest;
	int status;
	uint8_t hash_out[SHA512_HASH_LENGTH];

	TEST_START;

	manifest_flash_v2_testing_init (test, &manifest, 0x10000, PFM_MAGIC_NUM, PFM_V2_MAGIC_NUM);

	manifest_flash_v2_testing_verify_manifest (test, &manifest, &PFM_V2_SHA512.manifest, 0);

	status = manifest_flash_verify (&manifest.test, &manifest.hash.base,
		&manifest.verification.base, hash_out, sizeof (hash_out));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (PFM_V2_SHA512.manifest.hash, hash_out,
		PFM_V2_SHA512.manifest.hash_len);
	CuAssertIntEquals (test, 0, status);

	manifest_flash_v2_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_v2_test_verify_null (CuTest *test)
{
	struct manifest_flash_v2_testing manifest;
	int status;

	TEST_START;

	manifest_flash_v2_testing_init (test, &manifest, 0x10000, PFM_MAGIC_NUM, PFM_V2_MAGIC_NUM);

	status = manifest_flash_verify (NULL, &manifest.hash.base,
		&manifest.verification.base, NULL, 0);
	CuAssertIntEquals (test, MANIFEST_INVALID_ARGUMENT, status);

	status = manifest_flash_verify (&manifest.test, NULL,
		&manifest.verification.base, NULL, 0);
	CuAssertIntEquals (test, MANIFEST_INVALID_ARGUMENT, status);

	status = manifest_flash_verify (&manifest.test, &manifest.hash.base,
		NULL, NULL, 0);
	CuAssertIntEquals (test, MANIFEST_INVALID_ARGUMENT, status);

	manifest_flash_v2_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_v2_test_verify_small_hash_buffer (CuTest *test)
{
	struct manifest_flash_v2_testing manifest;
	int status;
	uint8_t hash_out[SHA256_HASH_LENGTH - 1];

	TEST_START;

	manifest_flash_v2_testing_init (test, &manifest, 0x10000, PFM_MAGIC_NUM, PFM_V2_MAGIC_NUM);

	status = manifest_flash_verify (&manifest.test, &manifest.hash.base,
		&manifest.verification.base, hash_out, sizeof (hash_out));
	CuAssertIntEquals (test, MANIFEST_HASH_BUFFER_TOO_SMALL, status);

	manifest_flash_v2_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_v2_test_verify_small_hash_buffer_sha384 (CuTest *test)
{
	struct manifest_flash_v2_testing manifest;
	int status;
	uint8_t hash_out[SHA384_HASH_LENGTH - 1];

	TEST_START;

	manifest_flash_v2_testing_init (test, &manifest, 0x10000, PFM_MAGIC_NUM, PFM_V2_MAGIC_NUM);

	status = mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash, 0,
		MOCK_ARG (manifest.addr), MOCK_ARG_NOT_NULL, MOCK_ARG (MANIFEST_V2_HEADER_SIZE));
	status |= mock_expect_output (&manifest.flash.mock, 1, PFM_V2_SHA384.manifest.raw,
		PFM_V2_SHA384.manifest.length, 2);

	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_verify (&manifest.test, &manifest.hash.base,
		&manifest.verification.base, hash_out, sizeof (hash_out));
	CuAssertIntEquals (test, MANIFEST_HASH_BUFFER_TOO_SMALL, status);

	manifest_flash_v2_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_v2_test_verify_small_hash_buffer_sha512 (CuTest *test)
{
	struct manifest_flash_v2_testing manifest;
	int status;
	uint8_t hash_out[SHA512_HASH_LENGTH - 1];

	TEST_START;

	manifest_flash_v2_testing_init (test, &manifest, 0x10000, PFM_MAGIC_NUM, PFM_V2_MAGIC_NUM);

	status = mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash, 0,
		MOCK_ARG (manifest.addr), MOCK_ARG_NOT_NULL, MOCK_ARG (MANIFEST_V2_HEADER_SIZE));
	status |= mock_expect_output (&manifest.flash.mock, 1, PFM_V2_SHA512.manifest.raw,
		PFM_V2_SHA512.manifest.length, 2);

	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_verify (&manifest.test, &manifest.hash.base,
		&manifest.verification.base, hash_out, sizeof (hash_out));
	CuAssertIntEquals (test, MANIFEST_HASH_BUFFER_TOO_SMALL, status);

	manifest_flash_v2_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_v2_test_verify_header_read_error (CuTest *test)
{
	struct manifest_flash_v2_testing manifest;
	int status;

	TEST_START;

	manifest_flash_v2_testing_init (test, &manifest, 0x10000, PFM_MAGIC_NUM, PFM_V2_MAGIC_NUM);

	status = mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash,
		FLASH_READ_FAILED, MOCK_ARG (manifest.addr), MOCK_ARG_NOT_NULL,
		MOCK_ARG (MANIFEST_V2_HEADER_SIZE));
	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_verify (&manifest.test, &manifest.hash.base,
		&manifest.verification.base, NULL, 0);
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	manifest_flash_v2_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_v2_test_verify_header_read_error_with_hash_out (CuTest *test)
{
	struct manifest_flash_v2_testing manifest;
	int status;
	uint8_t hash_out[SHA256_HASH_LENGTH];
	uint8_t empty[sizeof (hash_out)] = {0};

	TEST_START;

	memset (hash_out, 0xaa, sizeof (hash_out));

	manifest_flash_v2_testing_init (test, &manifest, 0x10000, PFM_MAGIC_NUM, PFM_V2_MAGIC_NUM);

	status = mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash,
		FLASH_READ_FAILED, MOCK_ARG (manifest.addr), MOCK_ARG_NOT_NULL,
		MOCK_ARG (MANIFEST_V2_HEADER_SIZE));
	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_verify (&manifest.test, &manifest.hash.base,
		&manifest.verification.base, hash_out, sizeof (hash_out));
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	status = testing_validate_array (empty, hash_out, sizeof (hash_out));
	CuAssertIntEquals (test, 0, status);

	manifest_flash_v2_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_v2_test_verify_bad_magic_number (CuTest *test)
{
	struct manifest_flash_v2_testing manifest;
	int status;
	struct manifest_header header;

	TEST_START;

	memcpy (&header, PFM_V2.manifest.raw, sizeof (header));
	header.magic ^= 0x55;

	manifest_flash_v2_testing_init (test, &manifest, 0x10000, PFM_MAGIC_NUM, PFM_V2_MAGIC_NUM);

	status = mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash, 0,
		MOCK_ARG (manifest.addr), MOCK_ARG_NOT_NULL, MOCK_ARG (MANIFEST_V2_HEADER_SIZE));
	status |= mock_expect_output (&manifest.flash.mock, 1, &header, sizeof (header), 2);

	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_verify (&manifest.test, &manifest.hash.base,
		&manifest.verification.base, NULL, 0);
	CuAssertIntEquals (test, MANIFEST_BAD_MAGIC_NUMBER, status);

	manifest_flash_v2_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_v2_test_verify_bad_magic_number_v1_unsupported (CuTest *test)
{
	struct manifest_flash_v2_testing manifest;
	int status;
	struct manifest_header header;

	TEST_START;

	memcpy (&header, PFM_V2.manifest.raw, sizeof (header));
	header.magic = MANIFEST_NOT_SUPPORTED;

	manifest_flash_v2_testing_init (test, &manifest, 0x10000, MANIFEST_NOT_SUPPORTED,
		PFM_V2_MAGIC_NUM);

	status = mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash, 0,
		MOCK_ARG (manifest.addr), MOCK_ARG_NOT_NULL, MOCK_ARG (MANIFEST_V2_HEADER_SIZE));
	status |= mock_expect_output (&manifest.flash.mock, 1, &header, sizeof (header), 2);

	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_verify (&manifest.test, &manifest.hash.base,
		&manifest.verification.base, NULL, 0);
	CuAssertIntEquals (test, MANIFEST_BAD_MAGIC_NUMBER, status);

	manifest_flash_v2_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_v2_test_verify_bad_magic_number_v2_unsupported (CuTest *test)
{
	struct manifest_flash_v2_testing manifest;
	int status;
	struct manifest_header header;

	TEST_START;

	memcpy (&header, PFM_V2.manifest.raw, sizeof (header));
	header.magic = MANIFEST_NOT_SUPPORTED;

	manifest_flash_v2_testing_init (test, &manifest, 0x10000, PFM_MAGIC_NUM,
		MANIFEST_NOT_SUPPORTED);

	status = mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash, 0,
		MOCK_ARG (manifest.addr), MOCK_ARG_NOT_NULL, MOCK_ARG (MANIFEST_V2_HEADER_SIZE));
	status |= mock_expect_output (&manifest.flash.mock, 1, &header, sizeof (header), 2);

	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_verify (&manifest.test, &manifest.hash.base,
		&manifest.verification.base, NULL, 0);
	CuAssertIntEquals (test, MANIFEST_BAD_MAGIC_NUMBER, status);

	manifest_flash_v2_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_v2_test_verify_sig_unknown_hash_type (CuTest *test)
{
	struct manifest_flash_v2_testing manifest;
	int status;
	struct manifest_header header;

	TEST_START;

	memcpy (&header, PFM_V2.manifest.raw, sizeof (header));
	header.sig_type = 0x03;

	manifest_flash_v2_testing_init (test, &manifest, 0x10000, PFM_MAGIC_NUM, PFM_V2_MAGIC_NUM);

	status = mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash, 0,
		MOCK_ARG (manifest.addr), MOCK_ARG_NOT_NULL, MOCK_ARG (MANIFEST_V2_HEADER_SIZE));
	status |= mock_expect_output (&manifest.flash.mock, 1, &header, sizeof (header), 2);

	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_verify (&manifest.test, &manifest.hash.base,
		&manifest.verification.base, NULL, 0);
	CuAssertIntEquals (test, MANIFEST_SIG_UNKNOWN_HASH_TYPE, status);

	manifest_flash_v2_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_v2_test_verify_sig_longer_than_manifest (CuTest *test)
{
	struct manifest_flash_v2_testing manifest;
	int status;
	struct manifest_header header;

	TEST_START;

	memcpy (&header, PFM_V2.manifest.raw, sizeof (header));
	header.sig_length = header.length + 1;

	manifest_flash_v2_testing_init (test, &manifest, 0x10000, PFM_MAGIC_NUM, PFM_V2_MAGIC_NUM);

	status = mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash, 0,
		MOCK_ARG (manifest.addr), MOCK_ARG_NOT_NULL, MOCK_ARG (MANIFEST_V2_HEADER_SIZE));
	status |= mock_expect_output (&manifest.flash.mock, 1, &header, sizeof (header), 2);

	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_verify (&manifest.test, &manifest.hash.base,
		&manifest.verification.base, NULL, 0);
	CuAssertIntEquals (test, MANIFEST_BAD_LENGTH, status);

	manifest_flash_v2_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_v2_test_verify_sig_same_length_as_manifest (CuTest *test)
{
	struct manifest_flash_v2_testing manifest;
	int status;
	struct manifest_header header;

	TEST_START;

	memcpy (&header, PFM_V2.manifest.raw, sizeof (header));
	header.sig_length = header.length;

	manifest_flash_v2_testing_init (test, &manifest, 0x10000, PFM_MAGIC_NUM, PFM_V2_MAGIC_NUM);

	status = mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash, 0,
		MOCK_ARG (manifest.addr), MOCK_ARG_NOT_NULL, MOCK_ARG (MANIFEST_V2_HEADER_SIZE));
	status |= mock_expect_output (&manifest.flash.mock, 1, &header, sizeof (header), 2);

	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_verify (&manifest.test, &manifest.hash.base,
		&manifest.verification.base, NULL, 0);
	CuAssertIntEquals (test, MANIFEST_BAD_LENGTH, status);

	manifest_flash_v2_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_v2_test_verify_sig_length_into_header (CuTest *test)
{
	struct manifest_flash_v2_testing manifest;
	int status;
	struct manifest_header header;

	TEST_START;

	memcpy (&header, PFM_V2.manifest.raw, sizeof (header));
	header.sig_length = (header.length - sizeof (header)) + 1;

	manifest_flash_v2_testing_init (test, &manifest, 0x10000, PFM_MAGIC_NUM, PFM_V2_MAGIC_NUM);

	status = mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash, 0,
		MOCK_ARG (manifest.addr), MOCK_ARG_NOT_NULL, MOCK_ARG (MANIFEST_V2_HEADER_SIZE));
	status |= mock_expect_output (&manifest.flash.mock, 1, &header, sizeof (header), 2);

	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_verify (&manifest.test, &manifest.hash.base,
		&manifest.verification.base, NULL, 0);
	CuAssertIntEquals (test, MANIFEST_BAD_LENGTH, status);

	manifest_flash_v2_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_v2_test_verify_sig_too_long (CuTest *test)
{
	struct manifest_flash_v2_testing manifest;
	int status;

	TEST_START;

	manifest_flash_v2_testing_init_dependencies (test, &manifest, 0x10000);
	manifest_flash_v2_testing_init_common (test, &manifest, 0x1000);

	status = manifest_flash_v2_init (&manifest.test, &manifest.flash.base, &manifest.hash.base,
		0x10000, PFM_MAGIC_NUM, PFM_V2_MAGIC_NUM, manifest.signature, PFM_V2.manifest.sig_len - 1,
		manifest.platform_id, sizeof (manifest.platform_id));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash, 0,
		MOCK_ARG (manifest.addr), MOCK_ARG_NOT_NULL, MOCK_ARG (MANIFEST_V2_HEADER_SIZE));
	status |= mock_expect_output (&manifest.flash.mock, 1, PFM_V2.manifest.raw,
		PFM_V2.manifest.length, 2);

	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_verify (&manifest.test, &manifest.hash.base,
		&manifest.verification.base, NULL, 0);
	CuAssertIntEquals (test, MANIFEST_SIG_BUFFER_TOO_SMALL, status);

	manifest_flash_v2_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_v2_test_verify_sig_read_error (CuTest *test)
{
	struct manifest_flash_v2_testing manifest;
	int status;

	TEST_START;

	manifest_flash_v2_testing_init (test, &manifest, 0x10000, PFM_MAGIC_NUM, PFM_V2_MAGIC_NUM);

	status = mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash, 0,
		MOCK_ARG (manifest.addr), MOCK_ARG_NOT_NULL, MOCK_ARG (MANIFEST_V2_HEADER_SIZE));
	status |= mock_expect_output (&manifest.flash.mock, 1, PFM_V2.manifest.raw,
		PFM_V2.manifest.length, 2);

	status |= mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash,
		FLASH_READ_FAILED, MOCK_ARG (manifest.addr + PFM_V2.manifest.sig_offset), MOCK_ARG_NOT_NULL,
		MOCK_ARG (PFM_V2.manifest.sig_len));

	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_verify (&manifest.test, &manifest.hash.base,
		&manifest.verification.base, NULL, 0);
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	manifest_flash_v2_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_v2_test_verify_bad_signature (CuTest *test)
{
	struct manifest_flash_v2_testing manifest;
	int status;

	TEST_START;

	manifest_flash_v2_testing_init (test, &manifest, 0x10000, PFM_MAGIC_NUM, PFM_V2_MAGIC_NUM);

	manifest_flash_v2_testing_verify_manifest (test, &manifest, &PFM_V2.manifest,
		RSA_ENGINE_BAD_SIGNATURE);

	status = manifest_flash_verify (&manifest.test, &manifest.hash.base,
		&manifest.verification.base, NULL, 0);
	CuAssertIntEquals (test, RSA_ENGINE_BAD_SIGNATURE, status);

	manifest_flash_v2_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_v2_test_verify_bad_signature_with_hash_out (CuTest *test)
{
	struct manifest_flash_v2_testing manifest;
	int status;
	uint8_t hash_out[SHA256_HASH_LENGTH];

	TEST_START;

	manifest_flash_v2_testing_init (test, &manifest, 0x10000, PFM_MAGIC_NUM, PFM_V2_MAGIC_NUM);

	manifest_flash_v2_testing_verify_manifest (test, &manifest, &PFM_V2.manifest,
		RSA_ENGINE_BAD_SIGNATURE);

	status = manifest_flash_verify (&manifest.test, &manifest.hash.base,
		&manifest.verification.base, hash_out, sizeof (hash_out));
	CuAssertIntEquals (test, RSA_ENGINE_BAD_SIGNATURE, status);

	status = testing_validate_array (PFM_V2.manifest.hash, hash_out, PFM_V2.manifest.hash_len);
	CuAssertIntEquals (test, 0, status);

	manifest_flash_v2_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_v2_test_verify_bad_signature_ecc_with_hash_out (CuTest *test)
{
	struct manifest_flash_v2_testing manifest;
	int status;
	uint8_t hash_out[SHA256_HASH_LENGTH];

	TEST_START;

	manifest_flash_v2_testing_init (test, &manifest, 0x10000, PFM_MAGIC_NUM, PFM_V2_MAGIC_NUM);

	manifest_flash_v2_testing_verify_manifest (test, &manifest, &PFM_V2_TWO_FW.manifest,
		ECC_ENGINE_BAD_SIGNATURE);

	status = manifest_flash_verify (&manifest.test, &manifest.hash.base,
		&manifest.verification.base, hash_out, sizeof (hash_out));
	CuAssertIntEquals (test, ECC_ENGINE_BAD_SIGNATURE, status);

	status = testing_validate_array (PFM_V2_TWO_FW.manifest.hash, hash_out,
		PFM_V2_TWO_FW.manifest.hash_len);
	CuAssertIntEquals (test, 0, status);

	manifest_flash_v2_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_v2_test_verify_start_hash_error (CuTest *test)
{
	struct manifest_flash_v2_testing manifest;
	int status;

	TEST_START;

	manifest_flash_v2_testing_init (test, &manifest, 0x10000, PFM_MAGIC_NUM, PFM_V2_MAGIC_NUM);

	status = mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash, 0,
		MOCK_ARG (manifest.addr), MOCK_ARG_NOT_NULL, MOCK_ARG (MANIFEST_V2_HEADER_SIZE));
	status |= mock_expect_output (&manifest.flash.mock, 1, PFM_V2.manifest.raw,
		PFM_V2.manifest.length, 2);

	status |= mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash, 0,
		MOCK_ARG (manifest.addr + PFM_V2.manifest.sig_offset), MOCK_ARG_NOT_NULL,
		MOCK_ARG (PFM_V2.manifest.sig_len));
	status |= mock_expect_output (&manifest.flash.mock, 1, PFM_V2.manifest.signature,
		PFM_V2.manifest.sig_len, 2);

	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.start_sha256,
		&manifest.hash_mock, HASH_ENGINE_START_SHA256_FAILED);

	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_verify (&manifest.test, &manifest.hash_mock.base,
		&manifest.verification.base, NULL, 0);
	CuAssertIntEquals (test, HASH_ENGINE_START_SHA256_FAILED, status);

	manifest_flash_v2_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_v2_test_verify_header_hash_error (CuTest *test)
{
	struct manifest_flash_v2_testing manifest;
	int status;

	TEST_START;

	manifest_flash_v2_testing_init (test, &manifest, 0x10000, PFM_MAGIC_NUM, PFM_V2_MAGIC_NUM);

	status = mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash, 0,
		MOCK_ARG (manifest.addr), MOCK_ARG_NOT_NULL, MOCK_ARG (MANIFEST_V2_HEADER_SIZE));
	status |= mock_expect_output (&manifest.flash.mock, 1, PFM_V2.manifest.raw,
		PFM_V2.manifest.length, 2);

	status |= mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash, 0,
		MOCK_ARG (manifest.addr + PFM_V2.manifest.sig_offset), MOCK_ARG_NOT_NULL,
		MOCK_ARG (PFM_V2.manifest.sig_len));
	status |= mock_expect_output (&manifest.flash.mock, 1, PFM_V2.manifest.signature,
		PFM_V2.manifest.sig_len, 2);

	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.start_sha256,
		&manifest.hash_mock, 0);
	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.update,
		&manifest.hash_mock, HASH_ENGINE_UPDATE_FAILED,
		MOCK_ARG_PTR_CONTAINS (PFM_V2.manifest.raw, MANIFEST_V2_HEADER_SIZE),
		MOCK_ARG (MANIFEST_V2_HEADER_SIZE));

	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.cancel,
		&manifest.hash_mock, 0);

	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_verify (&manifest.test, &manifest.hash_mock.base,
		&manifest.verification.base, NULL, 0);
	CuAssertIntEquals (test, HASH_ENGINE_UPDATE_FAILED, status);

	manifest_flash_v2_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_v2_test_verify_toc_unknown_hash_type (CuTest *test)
{
	struct manifest_flash_v2_testing manifest;
	int status;
	struct manifest_toc_header toc;

	TEST_START;

	memcpy (&toc, &PFM_V2.manifest.toc, sizeof (toc));
	toc.hash_type = 0x03;

	manifest_flash_v2_testing_init (test, &manifest, 0x10000, PFM_MAGIC_NUM, PFM_V2_MAGIC_NUM);

	status = mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash, 0,
		MOCK_ARG (manifest.addr), MOCK_ARG_NOT_NULL, MOCK_ARG (MANIFEST_V2_HEADER_SIZE));
	status |= mock_expect_output (&manifest.flash.mock, 1, PFM_V2.manifest.raw,
		PFM_V2.manifest.length, 2);

	status |= mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash, 0,
		MOCK_ARG (manifest.addr + PFM_V2.manifest.sig_offset), MOCK_ARG_NOT_NULL,
		MOCK_ARG (PFM_V2.manifest.sig_len));
	status |= mock_expect_output (&manifest.flash.mock, 1, PFM_V2.manifest.signature,
		PFM_V2.manifest.sig_len, 2);

	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.start_sha256,
		&manifest.hash_mock, 0);
	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.update,
		&manifest.hash_mock, 0,
		MOCK_ARG_PTR_CONTAINS (PFM_V2.manifest.raw, MANIFEST_V2_HEADER_SIZE),
		MOCK_ARG (MANIFEST_V2_HEADER_SIZE));

	status |= mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash, 0,
		MOCK_ARG (manifest.addr + MANIFEST_V2_TOC_HDR_OFFSET), MOCK_ARG_NOT_NULL,
		MOCK_ARG (MANIFEST_V2_TOC_HEADER_SIZE));
	status |= mock_expect_output (&manifest.flash.mock, 1, &toc, sizeof (toc), 2);

	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.cancel,
		&manifest.hash_mock, 0);

	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_verify (&manifest.test, &manifest.hash_mock.base,
		&manifest.verification.base, NULL, 0);
	CuAssertIntEquals (test, MANIFEST_TOC_UNKNOWN_HASH_TYPE, status);

	manifest_flash_v2_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_v2_test_verify_toc_no_platform_id_element (CuTest *test)
{
	struct manifest_flash_v2_testing manifest;
	int status;
	uint8_t toc[PFM_V2.manifest.toc_len];
	int entry_offset =
		MANIFEST_V2_TOC_HEADER_SIZE + (PFM_V2.manifest.plat_id_entry * MANIFEST_V2_TOC_ENTRY_SIZE);
	uint32_t toc_entry_offset = MANIFEST_V2_TOC_ENTRY_OFFSET;
	const struct manifest_toc_entry *toc_entries =
		(struct manifest_toc_entry*) (toc + MANIFEST_V2_TOC_HEADER_SIZE);
	uint32_t validate_toc_start = toc_entry_offset;
	int i;

	TEST_START;

	memcpy (&toc, PFM_V2.manifest.toc, sizeof (toc));
	((struct manifest_toc_entry*) &toc[entry_offset])->type_id = 0x55;

	manifest_flash_v2_testing_init (test, &manifest, 0x10000, PFM_MAGIC_NUM, PFM_V2_MAGIC_NUM);

	status = mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash, 0,
		MOCK_ARG (manifest.addr), MOCK_ARG_NOT_NULL, MOCK_ARG (MANIFEST_V2_HEADER_SIZE));
	status |= mock_expect_output (&manifest.flash.mock, 1, PFM_V2.manifest.raw,
		PFM_V2.manifest.length, 2);

	status |= mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash, 0,
		MOCK_ARG (manifest.addr + PFM_V2.manifest.sig_offset), MOCK_ARG_NOT_NULL,
		MOCK_ARG (PFM_V2.manifest.sig_len));
	status |= mock_expect_output (&manifest.flash.mock, 1, PFM_V2.manifest.signature,
		PFM_V2.manifest.sig_len, 2);

	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.start_sha256,
		&manifest.hash_mock, 0);
	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.update,
		&manifest.hash_mock, 0,
		MOCK_ARG_PTR_CONTAINS (PFM_V2.manifest.raw, MANIFEST_V2_HEADER_SIZE),
		MOCK_ARG (MANIFEST_V2_HEADER_SIZE));

	status |= mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash, 0,
		MOCK_ARG (manifest.addr + MANIFEST_V2_TOC_HDR_OFFSET), MOCK_ARG_NOT_NULL,
		MOCK_ARG (MANIFEST_V2_TOC_HEADER_SIZE));
	status |= mock_expect_output (&manifest.flash.mock, 1, &toc, sizeof (toc), 2);

	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.update,
		&manifest.hash_mock, 0,
		MOCK_ARG_PTR_CONTAINS (PFM_V2.manifest.toc, MANIFEST_V2_TOC_HEADER_SIZE),
		MOCK_ARG (MANIFEST_V2_TOC_HEADER_SIZE));

	for (i = 0; i <= PFM_V2.manifest.plat_id_entry;
		i++, validate_toc_start += MANIFEST_V2_TOC_ENTRY_SIZE) {
		status |= mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash,
			0, MOCK_ARG (manifest.addr + toc_entry_offset + (i * MANIFEST_V2_TOC_ENTRY_SIZE)),
			MOCK_ARG_NOT_NULL, MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));
		status |= mock_expect_output (&manifest.flash.mock, 1, &toc_entries[i],
			MANIFEST_V2_TOC_ENTRY_SIZE, 2);

		status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.update,
			&manifest.hash_mock, 0,
			MOCK_ARG_PTR_CONTAINS (&toc_entries[i], MANIFEST_V2_TOC_ENTRY_SIZE),
			MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));
	}

	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.cancel,
		&manifest.hash_mock, 0);

	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_verify (&manifest.test, &manifest.hash_mock.base,
		&manifest.verification.base, NULL, 0);
	CuAssertIntEquals (test, MANIFEST_NO_PLATFORM_ID, status);

	manifest_flash_v2_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_v2_test_verify_toc_header_read_error (CuTest *test)
{
	struct manifest_flash_v2_testing manifest;
	int status;

	TEST_START;

	manifest_flash_v2_testing_init (test, &manifest, 0x10000, PFM_MAGIC_NUM, PFM_V2_MAGIC_NUM);

	status = mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash, 0,
		MOCK_ARG (manifest.addr), MOCK_ARG_NOT_NULL, MOCK_ARG (MANIFEST_V2_HEADER_SIZE));
	status |= mock_expect_output (&manifest.flash.mock, 1, PFM_V2.manifest.raw,
		PFM_V2.manifest.length, 2);

	status |= mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash, 0,
		MOCK_ARG (manifest.addr + PFM_V2.manifest.sig_offset), MOCK_ARG_NOT_NULL,
		MOCK_ARG (PFM_V2.manifest.sig_len));
	status |= mock_expect_output (&manifest.flash.mock, 1, PFM_V2.manifest.signature,
		PFM_V2.manifest.sig_len, 2);

	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.start_sha256,
		&manifest.hash_mock, 0);
	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.update,
		&manifest.hash_mock, 0,
		MOCK_ARG_PTR_CONTAINS (PFM_V2.manifest.raw, MANIFEST_V2_HEADER_SIZE),
		MOCK_ARG (MANIFEST_V2_HEADER_SIZE));

	status |= mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash,
		FLASH_READ_FAILED, MOCK_ARG (manifest.addr + MANIFEST_V2_TOC_HDR_OFFSET), MOCK_ARG_NOT_NULL,
		MOCK_ARG (MANIFEST_V2_TOC_HEADER_SIZE));

	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.cancel,
		&manifest.hash_mock, 0);

	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_verify (&manifest.test, &manifest.hash_mock.base,
		&manifest.verification.base, NULL, 0);
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	manifest_flash_v2_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_v2_test_verify_toc_header_hash_error (CuTest *test)
{
	struct manifest_flash_v2_testing manifest;
	int status;

	TEST_START;

	manifest_flash_v2_testing_init (test, &manifest, 0x10000, PFM_MAGIC_NUM, PFM_V2_MAGIC_NUM);

	status = mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash, 0,
		MOCK_ARG (manifest.addr), MOCK_ARG_NOT_NULL, MOCK_ARG (MANIFEST_V2_HEADER_SIZE));
	status |= mock_expect_output (&manifest.flash.mock, 1, PFM_V2.manifest.raw,
		PFM_V2.manifest.length, 2);

	status |= mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash, 0,
		MOCK_ARG (manifest.addr + PFM_V2.manifest.sig_offset), MOCK_ARG_NOT_NULL,
		MOCK_ARG (PFM_V2.manifest.sig_len));
	status |= mock_expect_output (&manifest.flash.mock, 1, PFM_V2.manifest.signature,
		PFM_V2.manifest.sig_len, 2);

	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.start_sha256,
		&manifest.hash_mock, 0);
	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.update,
		&manifest.hash_mock, 0,
		MOCK_ARG_PTR_CONTAINS (PFM_V2.manifest.raw, MANIFEST_V2_HEADER_SIZE),
		MOCK_ARG (MANIFEST_V2_HEADER_SIZE));

	status |= mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash, 0,
		MOCK_ARG (manifest.addr + MANIFEST_V2_TOC_HDR_OFFSET), MOCK_ARG_NOT_NULL,
		MOCK_ARG (MANIFEST_V2_TOC_HEADER_SIZE));
	status |= mock_expect_output (&manifest.flash.mock, 1, PFM_V2.manifest.toc,
		PFM_V2.manifest.length - MANIFEST_V2_TOC_HDR_OFFSET, 2);

	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.update,
		&manifest.hash_mock, HASH_ENGINE_UPDATE_FAILED,
		MOCK_ARG_PTR_CONTAINS (PFM_V2.manifest.toc, MANIFEST_V2_TOC_HEADER_SIZE),
		MOCK_ARG (MANIFEST_V2_TOC_HEADER_SIZE));

	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.cancel,
		&manifest.hash_mock, 0);

	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_verify (&manifest.test, &manifest.hash_mock.base,
		&manifest.verification.base, NULL, 0);
	CuAssertIntEquals (test, HASH_ENGINE_UPDATE_FAILED, status);

	manifest_flash_v2_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_v2_test_verify_toc_element_read_error (CuTest *test)
{
	struct manifest_flash_v2_testing manifest;
	int status;

	TEST_START;

	manifest_flash_v2_testing_init (test, &manifest, 0x10000, PFM_MAGIC_NUM, PFM_V2_MAGIC_NUM);

	status = mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash, 0,
		MOCK_ARG (manifest.addr), MOCK_ARG_NOT_NULL, MOCK_ARG (MANIFEST_V2_HEADER_SIZE));
	status |= mock_expect_output (&manifest.flash.mock, 1, PFM_V2.manifest.raw,
		PFM_V2.manifest.length, 2);

	status |= mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash, 0,
		MOCK_ARG (manifest.addr + PFM_V2.manifest.sig_offset), MOCK_ARG_NOT_NULL,
		MOCK_ARG (PFM_V2.manifest.sig_len));
	status |= mock_expect_output (&manifest.flash.mock, 1, PFM_V2.manifest.signature,
		PFM_V2.manifest.sig_len, 2);

	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.start_sha256,
		&manifest.hash_mock, 0);
	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.update,
		&manifest.hash_mock, 0,
		MOCK_ARG_PTR_CONTAINS (PFM_V2.manifest.raw, MANIFEST_V2_HEADER_SIZE),
		MOCK_ARG (MANIFEST_V2_HEADER_SIZE));

	status |= mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash, 0,
		MOCK_ARG (manifest.addr + MANIFEST_V2_TOC_HDR_OFFSET), MOCK_ARG_NOT_NULL,
		MOCK_ARG (MANIFEST_V2_TOC_HEADER_SIZE));
	status |= mock_expect_output (&manifest.flash.mock, 1, PFM_V2.manifest.toc,
		PFM_V2.manifest.length - MANIFEST_V2_TOC_HDR_OFFSET, 2);

	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.update,
		&manifest.hash_mock, 0,
		MOCK_ARG_PTR_CONTAINS (PFM_V2.manifest.toc, MANIFEST_V2_TOC_HEADER_SIZE),
		MOCK_ARG (MANIFEST_V2_TOC_HEADER_SIZE));

	status |= mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash,
		FLASH_READ_FAILED,
		MOCK_ARG (manifest.addr + MANIFEST_V2_HEADER_SIZE + MANIFEST_V2_TOC_HEADER_SIZE),
		MOCK_ARG_NOT_NULL, MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));

	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.cancel,
		&manifest.hash_mock, 0);

	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_verify (&manifest.test, &manifest.hash_mock.base,
		&manifest.verification.base, NULL, 0);
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	manifest_flash_v2_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_v2_test_verify_toc_element_hash_error (CuTest *test)
{
	struct manifest_flash_v2_testing manifest;
	int status;
	const struct manifest_v2_testing_data *data = &PFM_V2.manifest;
	uint32_t toc_entry_offset = MANIFEST_V2_TOC_ENTRY_OFFSET;
	const struct manifest_toc_entry *toc_entries =
		(struct manifest_toc_entry*) (data->raw + toc_entry_offset);

	TEST_START;

	manifest_flash_v2_testing_init (test, &manifest, 0x10000, PFM_MAGIC_NUM, PFM_V2_MAGIC_NUM);

	status = mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash, 0,
		MOCK_ARG (manifest.addr), MOCK_ARG_NOT_NULL, MOCK_ARG (MANIFEST_V2_HEADER_SIZE));
	status |= mock_expect_output (&manifest.flash.mock, 1, data->raw, data->length, 2);

	status |= mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash, 0,
		MOCK_ARG (manifest.addr + data->sig_offset), MOCK_ARG_NOT_NULL, MOCK_ARG (data->sig_len));
	status |= mock_expect_output (&manifest.flash.mock, 1, data->signature, data->sig_len, 2);

	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.start_sha256,
		&manifest.hash_mock, 0);
	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.update,
		&manifest.hash_mock, 0, MOCK_ARG_PTR_CONTAINS (data->raw, MANIFEST_V2_HEADER_SIZE),
		MOCK_ARG (MANIFEST_V2_HEADER_SIZE));

	status |= mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash, 0,
		MOCK_ARG (manifest.addr + MANIFEST_V2_TOC_HDR_OFFSET), MOCK_ARG_NOT_NULL,
		MOCK_ARG (MANIFEST_V2_TOC_HEADER_SIZE));
	status |= mock_expect_output (&manifest.flash.mock, 1, data->toc,
		data->length - MANIFEST_V2_TOC_HDR_OFFSET, 2);

	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.update,
		&manifest.hash_mock, 0, MOCK_ARG_PTR_CONTAINS (data->toc, MANIFEST_V2_TOC_HEADER_SIZE),
		MOCK_ARG (MANIFEST_V2_TOC_HEADER_SIZE));

	status |= mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash,
		0, MOCK_ARG (manifest.addr + toc_entry_offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));
	status |= mock_expect_output (&manifest.flash.mock, 1, &toc_entries[0],
		MANIFEST_V2_TOC_ENTRY_SIZE, 2);

	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.update,
		&manifest.hash_mock, HASH_ENGINE_UPDATE_FAILED,
		MOCK_ARG_PTR_CONTAINS (&toc_entries[0], MANIFEST_V2_TOC_ENTRY_SIZE),
		MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));

	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.cancel,
		&manifest.hash_mock, 0);

	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_verify (&manifest.test, &manifest.hash_mock.base,
		&manifest.verification.base, NULL, 0);
	CuAssertIntEquals (test, HASH_ENGINE_UPDATE_FAILED, status);

	manifest_flash_v2_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_v2_test_verify_toc_read_error (CuTest *test)
{
	struct manifest_flash_v2_testing manifest;
	int status;
	const struct manifest_v2_testing_data *data = &PFM_V2.manifest;
	uint32_t toc_entry_offset = MANIFEST_V2_TOC_ENTRY_OFFSET;
	const struct manifest_toc_entry *toc_entries =
		(struct manifest_toc_entry*) (data->raw + toc_entry_offset);
	uint32_t validate_toc_start = toc_entry_offset;
	int i;

	TEST_START;

	manifest_flash_v2_testing_init (test, &manifest, 0x10000, PFM_MAGIC_NUM, PFM_V2_MAGIC_NUM);

	status = mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash, 0,
		MOCK_ARG (manifest.addr), MOCK_ARG_NOT_NULL, MOCK_ARG (MANIFEST_V2_HEADER_SIZE));
	status |= mock_expect_output (&manifest.flash.mock, 1, data->raw, data->length, 2);

	status |= mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash, 0,
		MOCK_ARG (manifest.addr + data->sig_offset), MOCK_ARG_NOT_NULL, MOCK_ARG (data->sig_len));
	status |= mock_expect_output (&manifest.flash.mock, 1, data->signature, data->sig_len, 2);

	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.start_sha256,
		&manifest.hash_mock, 0);
	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.update,
		&manifest.hash_mock, 0, MOCK_ARG_PTR_CONTAINS (data->raw, MANIFEST_V2_HEADER_SIZE),
		MOCK_ARG (MANIFEST_V2_HEADER_SIZE));

	status |= mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash, 0,
		MOCK_ARG (manifest.addr + MANIFEST_V2_TOC_HDR_OFFSET), MOCK_ARG_NOT_NULL,
		MOCK_ARG (MANIFEST_V2_TOC_HEADER_SIZE));
	status |= mock_expect_output (&manifest.flash.mock, 1, data->toc,
		data->length - MANIFEST_V2_TOC_HDR_OFFSET, 2);

	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.update,
		&manifest.hash_mock, 0, MOCK_ARG_PTR_CONTAINS (data->toc, MANIFEST_V2_TOC_HEADER_SIZE),
		MOCK_ARG (MANIFEST_V2_TOC_HEADER_SIZE));

	for (i = 0; i <= data->plat_id_entry; i++, validate_toc_start += MANIFEST_V2_TOC_ENTRY_SIZE) {
		status |= mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash,
			0, MOCK_ARG (manifest.addr + toc_entry_offset + (i * MANIFEST_V2_TOC_ENTRY_SIZE)),
			MOCK_ARG_NOT_NULL, MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));
		status |= mock_expect_output (&manifest.flash.mock, 1, &toc_entries[i],
			MANIFEST_V2_TOC_ENTRY_SIZE, 2);

		status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.update,
			&manifest.hash_mock, 0,
			MOCK_ARG_PTR_CONTAINS (&toc_entries[i], MANIFEST_V2_TOC_ENTRY_SIZE),
			MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));
	}

	status |= mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash,
		FLASH_READ_FAILED, MOCK_ARG (manifest.addr + validate_toc_start), MOCK_ARG_NOT_NULL,
		MOCK_ARG_ANY);

	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.cancel,
		&manifest.hash_mock, 0);

	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_verify (&manifest.test, &manifest.hash_mock.base,
		&manifest.verification.base, NULL, 0);
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	manifest_flash_v2_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_v2_test_verify_toc_hash_read_error (CuTest *test)
{
	struct manifest_flash_v2_testing manifest;
	int status;
	const struct manifest_v2_testing_data *data = &PFM_V2.manifest;
	uint32_t toc_entry_offset = MANIFEST_V2_TOC_ENTRY_OFFSET;
	const struct manifest_toc_entry *toc_entries =
		(struct manifest_toc_entry*) (data->raw + toc_entry_offset);
	uint32_t validate_toc_start = toc_entry_offset;
	int i;

	TEST_START;

	manifest_flash_v2_testing_init (test, &manifest, 0x10000, PFM_MAGIC_NUM, PFM_V2_MAGIC_NUM);

	status = mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash, 0,
		MOCK_ARG (manifest.addr), MOCK_ARG_NOT_NULL, MOCK_ARG (MANIFEST_V2_HEADER_SIZE));
	status |= mock_expect_output (&manifest.flash.mock, 1, data->raw, data->length, 2);

	status |= mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash, 0,
		MOCK_ARG (manifest.addr + data->sig_offset), MOCK_ARG_NOT_NULL, MOCK_ARG (data->sig_len));
	status |= mock_expect_output (&manifest.flash.mock, 1, data->signature, data->sig_len, 2);

	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.start_sha256,
		&manifest.hash_mock, 0);
	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.update,
		&manifest.hash_mock, 0, MOCK_ARG_PTR_CONTAINS (data->raw, MANIFEST_V2_HEADER_SIZE),
		MOCK_ARG (MANIFEST_V2_HEADER_SIZE));

	status |= mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash, 0,
		MOCK_ARG (manifest.addr + MANIFEST_V2_TOC_HDR_OFFSET), MOCK_ARG_NOT_NULL,
		MOCK_ARG (MANIFEST_V2_TOC_HEADER_SIZE));
	status |= mock_expect_output (&manifest.flash.mock, 1, data->toc,
		data->length - MANIFEST_V2_TOC_HDR_OFFSET, 2);

	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.update,
		&manifest.hash_mock, 0, MOCK_ARG_PTR_CONTAINS (data->toc, MANIFEST_V2_TOC_HEADER_SIZE),
		MOCK_ARG (MANIFEST_V2_TOC_HEADER_SIZE));

	for (i = 0; i <= data->plat_id_entry; i++, validate_toc_start += MANIFEST_V2_TOC_ENTRY_SIZE) {
		status |= mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash,
			0, MOCK_ARG (manifest.addr + toc_entry_offset + (i * MANIFEST_V2_TOC_ENTRY_SIZE)),
			MOCK_ARG_NOT_NULL, MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));
		status |= mock_expect_output (&manifest.flash.mock, 1, &toc_entries[i],
			MANIFEST_V2_TOC_ENTRY_SIZE, 2);

		status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.update,
			&manifest.hash_mock, 0,
			MOCK_ARG_PTR_CONTAINS (&toc_entries[i], MANIFEST_V2_TOC_ENTRY_SIZE),
			MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));
	}

	status |= flash_mock_expect_verify_flash_and_hash (&manifest.flash, &manifest.hash_mock,
		manifest.addr + validate_toc_start, data->raw + validate_toc_start,
		data->toc_hash_offset - validate_toc_start);

	status |= mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash,
		FLASH_READ_FAILED, MOCK_ARG (manifest.addr + data->toc_hash_offset), MOCK_ARG_NOT_NULL,
		MOCK_ARG (data->toc_hash_len));

	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.cancel,
		&manifest.hash_mock, 0);

	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_verify (&manifest.test, &manifest.hash_mock.base,
		&manifest.verification.base, NULL, 0);
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	manifest_flash_v2_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_v2_test_verify_toc_hash_hash_error (CuTest *test)
{
	struct manifest_flash_v2_testing manifest;
	int status;
	const struct manifest_v2_testing_data *data = &PFM_V2.manifest;
	uint32_t toc_entry_offset = MANIFEST_V2_TOC_ENTRY_OFFSET;
	const struct manifest_toc_entry *toc_entries =
		(struct manifest_toc_entry*) (data->raw + toc_entry_offset);
	uint32_t validate_toc_start = toc_entry_offset;
	int i;

	TEST_START;

	manifest_flash_v2_testing_init (test, &manifest, 0x10000, PFM_MAGIC_NUM, PFM_V2_MAGIC_NUM);

	status = mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash, 0,
		MOCK_ARG (manifest.addr), MOCK_ARG_NOT_NULL, MOCK_ARG (MANIFEST_V2_HEADER_SIZE));
	status |= mock_expect_output (&manifest.flash.mock, 1, data->raw, data->length, 2);

	status |= mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash, 0,
		MOCK_ARG (manifest.addr + data->sig_offset), MOCK_ARG_NOT_NULL, MOCK_ARG (data->sig_len));
	status |= mock_expect_output (&manifest.flash.mock, 1, data->signature, data->sig_len, 2);

	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.start_sha256,
		&manifest.hash_mock, 0);
	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.update,
		&manifest.hash_mock, 0, MOCK_ARG_PTR_CONTAINS (data->raw, MANIFEST_V2_HEADER_SIZE),
		MOCK_ARG (MANIFEST_V2_HEADER_SIZE));

	status |= mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash, 0,
		MOCK_ARG (manifest.addr + MANIFEST_V2_TOC_HDR_OFFSET), MOCK_ARG_NOT_NULL,
		MOCK_ARG (MANIFEST_V2_TOC_HEADER_SIZE));
	status |= mock_expect_output (&manifest.flash.mock, 1, data->toc,
		data->length - MANIFEST_V2_TOC_HDR_OFFSET, 2);

	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.update,
		&manifest.hash_mock, 0, MOCK_ARG_PTR_CONTAINS (data->toc, MANIFEST_V2_TOC_HEADER_SIZE),
		MOCK_ARG (MANIFEST_V2_TOC_HEADER_SIZE));

	for (i = 0; i <= data->plat_id_entry; i++, validate_toc_start += MANIFEST_V2_TOC_ENTRY_SIZE) {
		status |= mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash,
			0, MOCK_ARG (manifest.addr + toc_entry_offset + (i * MANIFEST_V2_TOC_ENTRY_SIZE)),
			MOCK_ARG_NOT_NULL, MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));
		status |= mock_expect_output (&manifest.flash.mock, 1, &toc_entries[i],
			MANIFEST_V2_TOC_ENTRY_SIZE, 2);

		status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.update,
			&manifest.hash_mock, 0,
			MOCK_ARG_PTR_CONTAINS (&toc_entries[i], MANIFEST_V2_TOC_ENTRY_SIZE),
			MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));
	}

	status |= flash_mock_expect_verify_flash_and_hash (&manifest.flash, &manifest.hash_mock,
		manifest.addr + validate_toc_start, data->raw + validate_toc_start,
		data->toc_hash_offset - validate_toc_start);

	status |= mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash, 0,
		MOCK_ARG (manifest.addr + data->toc_hash_offset), MOCK_ARG_NOT_NULL,
		MOCK_ARG (data->toc_hash_len));
	status |= mock_expect_output (&manifest.flash.mock, 1, data->toc_hash,
		data->length - data->toc_hash_offset, 2);

	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.update,
		&manifest.hash_mock, HASH_ENGINE_UPDATE_FAILED,
		MOCK_ARG_PTR_CONTAINS (data->toc_hash, data->toc_hash_len), MOCK_ARG (data->toc_hash_len));

	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.cancel,
		&manifest.hash_mock, 0);

	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_verify (&manifest.test, &manifest.hash_mock.base,
		&manifest.verification.base, NULL, 0);
	CuAssertIntEquals (test, HASH_ENGINE_UPDATE_FAILED, status);

	manifest_flash_v2_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_v2_test_verify_manifest_part1_read_error (CuTest *test)
{
	struct manifest_flash_v2_testing manifest;
	int status;
	const struct manifest_v2_testing_data *data = &PFM_V2.manifest;
	uint32_t toc_entry_offset = MANIFEST_V2_TOC_ENTRY_OFFSET;
	const struct manifest_toc_entry *toc_entries =
		(struct manifest_toc_entry*) (data->raw + toc_entry_offset);
	uint32_t validate_toc_start = toc_entry_offset;
	uint32_t validate_start = data->toc_hash_offset + data->toc_hash_len;
	int i;

	TEST_START;

	manifest_flash_v2_testing_init (test, &manifest, 0x10000, PFM_MAGIC_NUM, PFM_V2_MAGIC_NUM);

	status = mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash, 0,
		MOCK_ARG (manifest.addr), MOCK_ARG_NOT_NULL, MOCK_ARG (MANIFEST_V2_HEADER_SIZE));
	status |= mock_expect_output (&manifest.flash.mock, 1, data->raw, data->length, 2);

	status |= mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash, 0,
		MOCK_ARG (manifest.addr + data->sig_offset), MOCK_ARG_NOT_NULL, MOCK_ARG (data->sig_len));
	status |= mock_expect_output (&manifest.flash.mock, 1, data->signature, data->sig_len, 2);

	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.start_sha256,
		&manifest.hash_mock, 0);
	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.update,
		&manifest.hash_mock, 0, MOCK_ARG_PTR_CONTAINS (data->raw, MANIFEST_V2_HEADER_SIZE),
		MOCK_ARG (MANIFEST_V2_HEADER_SIZE));

	status |= mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash, 0,
		MOCK_ARG (manifest.addr + MANIFEST_V2_TOC_HDR_OFFSET), MOCK_ARG_NOT_NULL,
		MOCK_ARG (MANIFEST_V2_TOC_HEADER_SIZE));
	status |= mock_expect_output (&manifest.flash.mock, 1, data->toc,
		data->length - MANIFEST_V2_TOC_HDR_OFFSET, 2);

	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.update,
		&manifest.hash_mock, 0, MOCK_ARG_PTR_CONTAINS (data->toc, MANIFEST_V2_TOC_HEADER_SIZE),
		MOCK_ARG (MANIFEST_V2_TOC_HEADER_SIZE));

	for (i = 0; i <= data->plat_id_entry; i++, validate_toc_start += MANIFEST_V2_TOC_ENTRY_SIZE) {
		status |= mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash,
			0, MOCK_ARG (manifest.addr + toc_entry_offset + (i * MANIFEST_V2_TOC_ENTRY_SIZE)),
			MOCK_ARG_NOT_NULL, MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));
		status |= mock_expect_output (&manifest.flash.mock, 1, &toc_entries[i],
			MANIFEST_V2_TOC_ENTRY_SIZE, 2);

		status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.update,
			&manifest.hash_mock, 0,
			MOCK_ARG_PTR_CONTAINS (&toc_entries[i], MANIFEST_V2_TOC_ENTRY_SIZE),
			MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));
	}

	status |= flash_mock_expect_verify_flash_and_hash (&manifest.flash, &manifest.hash_mock,
		manifest.addr + validate_toc_start, data->raw + validate_toc_start,
		data->toc_hash_offset - validate_toc_start);

	status |= mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash, 0,
		MOCK_ARG (manifest.addr + data->toc_hash_offset), MOCK_ARG_NOT_NULL,
		MOCK_ARG (data->toc_hash_len));
	status |= mock_expect_output (&manifest.flash.mock, 1, data->toc_hash,
		data->length - data->toc_hash_offset, 2);

	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.update,
		&manifest.hash_mock, 0, MOCK_ARG_PTR_CONTAINS (data->toc_hash, data->toc_hash_len),
		MOCK_ARG (data->toc_hash_len));

	status |= mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash,
		FLASH_READ_FAILED, MOCK_ARG (manifest.addr + validate_start), MOCK_ARG_NOT_NULL,
		MOCK_ARG_ANY);

	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.cancel,
		&manifest.hash_mock, 0);

	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_verify (&manifest.test, &manifest.hash_mock.base,
		&manifest.verification.base, NULL, 0);
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	manifest_flash_v2_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_v2_test_verify_platform_id_too_long (CuTest *test)
{
	struct manifest_flash_v2_testing manifest;
	int status;
	const struct manifest_v2_testing_data *data = &PFM_V2.manifest;
	uint32_t toc_entry_offset = MANIFEST_V2_TOC_ENTRY_OFFSET;
	const struct manifest_toc_entry *toc_entries =
		(struct manifest_toc_entry*) (data->raw + toc_entry_offset);
	uint32_t validate_toc_start = toc_entry_offset;
	uint32_t validate_start = data->toc_hash_offset + data->toc_hash_len;
	uint32_t validate_end = data->plat_id_offset;
	int i;

	TEST_START;

	manifest_flash_v2_testing_init_dependencies (test, &manifest, 0x10000);
	manifest_flash_v2_testing_init_common (test, &manifest, 0x1000);

	status = manifest_flash_v2_init (&manifest.test, &manifest.flash.base, &manifest.hash.base,
		0x10000, PFM_MAGIC_NUM, PFM_V2_MAGIC_NUM, manifest.signature, sizeof (manifest.signature),
		manifest.platform_id, PFM_V2.manifest.plat_id_str_len);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash, 0,
		MOCK_ARG (manifest.addr), MOCK_ARG_NOT_NULL, MOCK_ARG (MANIFEST_V2_HEADER_SIZE));
	status |= mock_expect_output (&manifest.flash.mock, 1, data->raw, data->length, 2);

	status |= mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash, 0,
		MOCK_ARG (manifest.addr + data->sig_offset), MOCK_ARG_NOT_NULL, MOCK_ARG (data->sig_len));
	status |= mock_expect_output (&manifest.flash.mock, 1, data->signature, data->sig_len, 2);

	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.start_sha256,
		&manifest.hash_mock, 0);
	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.update,
		&manifest.hash_mock, 0, MOCK_ARG_PTR_CONTAINS (data->raw, MANIFEST_V2_HEADER_SIZE),
		MOCK_ARG (MANIFEST_V2_HEADER_SIZE));

	status |= mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash, 0,
		MOCK_ARG (manifest.addr + MANIFEST_V2_TOC_HDR_OFFSET), MOCK_ARG_NOT_NULL,
		MOCK_ARG (MANIFEST_V2_TOC_HEADER_SIZE));
	status |= mock_expect_output (&manifest.flash.mock, 1, data->toc,
		data->length - MANIFEST_V2_TOC_HDR_OFFSET, 2);

	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.update,
		&manifest.hash_mock, 0, MOCK_ARG_PTR_CONTAINS (data->toc, MANIFEST_V2_TOC_HEADER_SIZE),
		MOCK_ARG (MANIFEST_V2_TOC_HEADER_SIZE));

	for (i = 0; i <= data->plat_id_entry; i++, validate_toc_start += MANIFEST_V2_TOC_ENTRY_SIZE) {
		status |= mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash,
			0, MOCK_ARG (manifest.addr + toc_entry_offset + (i * MANIFEST_V2_TOC_ENTRY_SIZE)),
			MOCK_ARG_NOT_NULL, MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));
		status |= mock_expect_output (&manifest.flash.mock, 1, &toc_entries[i],
			MANIFEST_V2_TOC_ENTRY_SIZE, 2);

		status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.update,
			&manifest.hash_mock, 0,
			MOCK_ARG_PTR_CONTAINS (&toc_entries[i], MANIFEST_V2_TOC_ENTRY_SIZE),
			MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));
	}

	status |= flash_mock_expect_verify_flash_and_hash (&manifest.flash, &manifest.hash_mock,
		manifest.addr + validate_toc_start, data->raw + validate_toc_start,
		data->toc_hash_offset - validate_toc_start);

	status |= mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash, 0,
		MOCK_ARG (manifest.addr + data->toc_hash_offset), MOCK_ARG_NOT_NULL,
		MOCK_ARG (data->toc_hash_len));
	status |= mock_expect_output (&manifest.flash.mock, 1, data->toc_hash,
		data->length - data->toc_hash_offset, 2);

	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.update,
		&manifest.hash_mock, 0, MOCK_ARG_PTR_CONTAINS (data->toc_hash, data->toc_hash_len),
		MOCK_ARG (data->toc_hash_len));

	status |= flash_mock_expect_verify_flash_and_hash (&manifest.flash, &manifest.hash_mock,
		manifest.addr + validate_start, data->raw + validate_start, validate_end - validate_start);

	status |= mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash, 0,
		MOCK_ARG (manifest.addr + data->plat_id_offset), MOCK_ARG_NOT_NULL,
		MOCK_ARG (MANIFEST_V2_PLATFORM_HEADER_SIZE));
	status |= mock_expect_output (&manifest.flash.mock, 1, data->plat_id,
		data->length - data->plat_id_offset, 2);

	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.cancel,
		&manifest.hash_mock, 0);

	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_verify (&manifest.test, &manifest.hash_mock.base,
		&manifest.verification.base, NULL, 0);
	CuAssertIntEquals (test, MANIFEST_PLAT_ID_BUFFER_TOO_SMALL, status);

	manifest_flash_v2_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_v2_test_verify_platform_id_header_read_error (CuTest *test)
{
	struct manifest_flash_v2_testing manifest;
	int status;
	const struct manifest_v2_testing_data *data = &PFM_V2.manifest;
	uint32_t toc_entry_offset = MANIFEST_V2_TOC_ENTRY_OFFSET;
	const struct manifest_toc_entry *toc_entries =
		(struct manifest_toc_entry*) (data->raw + toc_entry_offset);
	uint32_t validate_toc_start = toc_entry_offset;
	uint32_t validate_start = data->toc_hash_offset + data->toc_hash_len;
	uint32_t validate_end = data->plat_id_offset;
	int i;

	TEST_START;

	manifest_flash_v2_testing_init (test, &manifest, 0x10000, PFM_MAGIC_NUM, PFM_V2_MAGIC_NUM);

	status = mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash, 0,
		MOCK_ARG (manifest.addr), MOCK_ARG_NOT_NULL, MOCK_ARG (MANIFEST_V2_HEADER_SIZE));
	status |= mock_expect_output (&manifest.flash.mock, 1, data->raw, data->length, 2);

	status |= mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash, 0,
		MOCK_ARG (manifest.addr + data->sig_offset), MOCK_ARG_NOT_NULL, MOCK_ARG (data->sig_len));
	status |= mock_expect_output (&manifest.flash.mock, 1, data->signature, data->sig_len, 2);

	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.start_sha256,
		&manifest.hash_mock, 0);
	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.update,
		&manifest.hash_mock, 0, MOCK_ARG_PTR_CONTAINS (data->raw, MANIFEST_V2_HEADER_SIZE),
		MOCK_ARG (MANIFEST_V2_HEADER_SIZE));

	status |= mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash, 0,
		MOCK_ARG (manifest.addr + MANIFEST_V2_TOC_HDR_OFFSET), MOCK_ARG_NOT_NULL,
		MOCK_ARG (MANIFEST_V2_TOC_HEADER_SIZE));
	status |= mock_expect_output (&manifest.flash.mock, 1, data->toc,
		data->length - MANIFEST_V2_TOC_HDR_OFFSET, 2);

	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.update,
		&manifest.hash_mock, 0, MOCK_ARG_PTR_CONTAINS (data->toc, MANIFEST_V2_TOC_HEADER_SIZE),
		MOCK_ARG (MANIFEST_V2_TOC_HEADER_SIZE));

	for (i = 0; i <= data->plat_id_entry; i++, validate_toc_start += MANIFEST_V2_TOC_ENTRY_SIZE) {
		status |= mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash,
			0, MOCK_ARG (manifest.addr + toc_entry_offset + (i * MANIFEST_V2_TOC_ENTRY_SIZE)),
			MOCK_ARG_NOT_NULL, MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));
		status |= mock_expect_output (&manifest.flash.mock, 1, &toc_entries[i],
			MANIFEST_V2_TOC_ENTRY_SIZE, 2);

		status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.update,
			&manifest.hash_mock, 0,
			MOCK_ARG_PTR_CONTAINS (&toc_entries[i], MANIFEST_V2_TOC_ENTRY_SIZE),
			MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));
	}

	status |= flash_mock_expect_verify_flash_and_hash (&manifest.flash, &manifest.hash_mock,
		manifest.addr + validate_toc_start, data->raw + validate_toc_start,
		data->toc_hash_offset - validate_toc_start);

	status |= mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash, 0,
		MOCK_ARG (manifest.addr + data->toc_hash_offset), MOCK_ARG_NOT_NULL,
		MOCK_ARG (data->toc_hash_len));
	status |= mock_expect_output (&manifest.flash.mock, 1, data->toc_hash,
		data->length - data->toc_hash_offset, 2);

	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.update,
		&manifest.hash_mock, 0, MOCK_ARG_PTR_CONTAINS (data->toc_hash, data->toc_hash_len),
		MOCK_ARG (data->toc_hash_len));

	status |= flash_mock_expect_verify_flash_and_hash (&manifest.flash, &manifest.hash_mock,
		manifest.addr + validate_start, data->raw + validate_start, validate_end - validate_start);

	status |= mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash,
		FLASH_READ_FAILED, MOCK_ARG (manifest.addr + data->plat_id_offset), MOCK_ARG_NOT_NULL,
		MOCK_ARG (MANIFEST_V2_PLATFORM_HEADER_SIZE));

	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.cancel,
		&manifest.hash_mock, 0);

	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_verify (&manifest.test, &manifest.hash_mock.base,
		&manifest.verification.base, NULL, 0);
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	manifest_flash_v2_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_v2_test_verify_platform_id_header_hash_error (CuTest *test)
{
	struct manifest_flash_v2_testing manifest;
	int status;
	const struct manifest_v2_testing_data *data = &PFM_V2.manifest;
	uint32_t toc_entry_offset = MANIFEST_V2_TOC_ENTRY_OFFSET;
	const struct manifest_toc_entry *toc_entries =
		(struct manifest_toc_entry*) (data->raw + toc_entry_offset);
	uint32_t validate_toc_start = toc_entry_offset;
	uint32_t validate_start = data->toc_hash_offset + data->toc_hash_len;
	uint32_t validate_end = data->plat_id_offset;
	int i;

	TEST_START;

	manifest_flash_v2_testing_init (test, &manifest, 0x10000, PFM_MAGIC_NUM, PFM_V2_MAGIC_NUM);

	status = mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash, 0,
		MOCK_ARG (manifest.addr), MOCK_ARG_NOT_NULL, MOCK_ARG (MANIFEST_V2_HEADER_SIZE));
	status |= mock_expect_output (&manifest.flash.mock, 1, data->raw, data->length, 2);

	status |= mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash, 0,
		MOCK_ARG (manifest.addr + data->sig_offset), MOCK_ARG_NOT_NULL, MOCK_ARG (data->sig_len));
	status |= mock_expect_output (&manifest.flash.mock, 1, data->signature, data->sig_len, 2);

	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.start_sha256,
		&manifest.hash_mock, 0);
	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.update,
		&manifest.hash_mock, 0, MOCK_ARG_PTR_CONTAINS (data->raw, MANIFEST_V2_HEADER_SIZE),
		MOCK_ARG (MANIFEST_V2_HEADER_SIZE));

	status |= mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash, 0,
		MOCK_ARG (manifest.addr + MANIFEST_V2_TOC_HDR_OFFSET), MOCK_ARG_NOT_NULL,
		MOCK_ARG (MANIFEST_V2_TOC_HEADER_SIZE));
	status |= mock_expect_output (&manifest.flash.mock, 1, data->toc,
		data->length - MANIFEST_V2_TOC_HDR_OFFSET, 2);

	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.update,
		&manifest.hash_mock, 0, MOCK_ARG_PTR_CONTAINS (data->toc, MANIFEST_V2_TOC_HEADER_SIZE),
		MOCK_ARG (MANIFEST_V2_TOC_HEADER_SIZE));

	for (i = 0; i <= data->plat_id_entry; i++, validate_toc_start += MANIFEST_V2_TOC_ENTRY_SIZE) {
		status |= mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash,
			0, MOCK_ARG (manifest.addr + toc_entry_offset + (i * MANIFEST_V2_TOC_ENTRY_SIZE)),
			MOCK_ARG_NOT_NULL, MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));
		status |= mock_expect_output (&manifest.flash.mock, 1, &toc_entries[i],
			MANIFEST_V2_TOC_ENTRY_SIZE, 2);

		status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.update,
			&manifest.hash_mock, 0,
			MOCK_ARG_PTR_CONTAINS (&toc_entries[i], MANIFEST_V2_TOC_ENTRY_SIZE),
			MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));
	}

	status |= flash_mock_expect_verify_flash_and_hash (&manifest.flash, &manifest.hash_mock,
		manifest.addr + validate_toc_start, data->raw + validate_toc_start,
		data->toc_hash_offset - validate_toc_start);

	status |= mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash, 0,
		MOCK_ARG (manifest.addr + data->toc_hash_offset), MOCK_ARG_NOT_NULL,
		MOCK_ARG (data->toc_hash_len));
	status |= mock_expect_output (&manifest.flash.mock, 1, data->toc_hash,
		data->length - data->toc_hash_offset, 2);

	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.update,
		&manifest.hash_mock, 0, MOCK_ARG_PTR_CONTAINS (data->toc_hash, data->toc_hash_len),
		MOCK_ARG (data->toc_hash_len));

	status |= flash_mock_expect_verify_flash_and_hash (&manifest.flash, &manifest.hash_mock,
		manifest.addr + validate_start, data->raw + validate_start, validate_end - validate_start);

	status |= mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash, 0,
		MOCK_ARG (manifest.addr + data->plat_id_offset), MOCK_ARG_NOT_NULL,
		MOCK_ARG (MANIFEST_V2_PLATFORM_HEADER_SIZE));
	status |= mock_expect_output (&manifest.flash.mock, 1, data->plat_id,
		data->length - data->plat_id_offset, 2);

	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.update,
		&manifest.hash_mock, HASH_ENGINE_UPDATE_FAILED,
		MOCK_ARG_PTR_CONTAINS (data->plat_id, MANIFEST_V2_PLATFORM_HEADER_SIZE),
		MOCK_ARG (MANIFEST_V2_PLATFORM_HEADER_SIZE));

	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.cancel,
		&manifest.hash_mock, 0);

	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_verify (&manifest.test, &manifest.hash_mock.base,
		&manifest.verification.base, NULL, 0);
	CuAssertIntEquals (test, HASH_ENGINE_UPDATE_FAILED, status);

	manifest_flash_v2_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_v2_test_verify_platform_id_read_error (CuTest *test)
{
	struct manifest_flash_v2_testing manifest;
	int status;
	const struct manifest_v2_testing_data *data = &PFM_V2.manifest;
	uint32_t toc_entry_offset = MANIFEST_V2_TOC_ENTRY_OFFSET;
	const struct manifest_toc_entry *toc_entries =
		(struct manifest_toc_entry*) (data->raw + toc_entry_offset);
	uint32_t validate_toc_start = toc_entry_offset;
	uint32_t validate_start = data->toc_hash_offset + data->toc_hash_len;
	uint32_t validate_end = data->plat_id_offset;
	int i;

	TEST_START;

	manifest_flash_v2_testing_init (test, &manifest, 0x10000, PFM_MAGIC_NUM, PFM_V2_MAGIC_NUM);

	status = mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash, 0,
		MOCK_ARG (manifest.addr), MOCK_ARG_NOT_NULL, MOCK_ARG (MANIFEST_V2_HEADER_SIZE));
	status |= mock_expect_output (&manifest.flash.mock, 1, data->raw, data->length, 2);

	status |= mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash, 0,
		MOCK_ARG (manifest.addr + data->sig_offset), MOCK_ARG_NOT_NULL, MOCK_ARG (data->sig_len));
	status |= mock_expect_output (&manifest.flash.mock, 1, data->signature, data->sig_len, 2);

	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.start_sha256,
		&manifest.hash_mock, 0);
	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.update,
		&manifest.hash_mock, 0, MOCK_ARG_PTR_CONTAINS (data->raw, MANIFEST_V2_HEADER_SIZE),
		MOCK_ARG (MANIFEST_V2_HEADER_SIZE));

	status |= mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash, 0,
		MOCK_ARG (manifest.addr + MANIFEST_V2_TOC_HDR_OFFSET), MOCK_ARG_NOT_NULL,
		MOCK_ARG (MANIFEST_V2_TOC_HEADER_SIZE));
	status |= mock_expect_output (&manifest.flash.mock, 1, data->toc,
		data->length - MANIFEST_V2_TOC_HDR_OFFSET, 2);

	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.update,
		&manifest.hash_mock, 0, MOCK_ARG_PTR_CONTAINS (data->toc, MANIFEST_V2_TOC_HEADER_SIZE),
		MOCK_ARG (MANIFEST_V2_TOC_HEADER_SIZE));

	for (i = 0; i <= data->plat_id_entry; i++, validate_toc_start += MANIFEST_V2_TOC_ENTRY_SIZE) {
		status |= mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash,
			0, MOCK_ARG (manifest.addr + toc_entry_offset + (i * MANIFEST_V2_TOC_ENTRY_SIZE)),
			MOCK_ARG_NOT_NULL, MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));
		status |= mock_expect_output (&manifest.flash.mock, 1, &toc_entries[i],
			MANIFEST_V2_TOC_ENTRY_SIZE, 2);

		status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.update,
			&manifest.hash_mock, 0,
			MOCK_ARG_PTR_CONTAINS (&toc_entries[i], MANIFEST_V2_TOC_ENTRY_SIZE),
			MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));
	}

	status |= flash_mock_expect_verify_flash_and_hash (&manifest.flash, &manifest.hash_mock,
		manifest.addr + validate_toc_start, data->raw + validate_toc_start,
		data->toc_hash_offset - validate_toc_start);

	status |= mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash, 0,
		MOCK_ARG (manifest.addr + data->toc_hash_offset), MOCK_ARG_NOT_NULL,
		MOCK_ARG (data->toc_hash_len));
	status |= mock_expect_output (&manifest.flash.mock, 1, data->toc_hash,
		data->length - data->toc_hash_offset, 2);

	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.update,
		&manifest.hash_mock, 0, MOCK_ARG_PTR_CONTAINS (data->toc_hash, data->toc_hash_len),
		MOCK_ARG (data->toc_hash_len));

	status |= flash_mock_expect_verify_flash_and_hash (&manifest.flash, &manifest.hash_mock,
		manifest.addr + validate_start, data->raw + validate_start, validate_end - validate_start);

	status |= mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash, 0,
		MOCK_ARG (manifest.addr + data->plat_id_offset), MOCK_ARG_NOT_NULL,
		MOCK_ARG (MANIFEST_V2_PLATFORM_HEADER_SIZE));
	status |= mock_expect_output (&manifest.flash.mock, 1, data->plat_id,
		data->length - data->plat_id_offset, 2);

	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.update,
		&manifest.hash_mock, 0,
		MOCK_ARG_PTR_CONTAINS (data->plat_id, MANIFEST_V2_PLATFORM_HEADER_SIZE),
		MOCK_ARG (MANIFEST_V2_PLATFORM_HEADER_SIZE));

	status |= mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash,
		FLASH_READ_FAILED,
		MOCK_ARG (manifest.addr + data->plat_id_offset + MANIFEST_V2_PLATFORM_HEADER_SIZE),
		MOCK_ARG_NOT_NULL, MOCK_ARG (data->plat_id_str_len));

	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.cancel,
		&manifest.hash_mock, 0);

	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_verify (&manifest.test, &manifest.hash_mock.base,
		&manifest.verification.base, NULL, 0);
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	manifest_flash_v2_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_v2_test_verify_platform_id_hash_error (CuTest *test)
{
	struct manifest_flash_v2_testing manifest;
	int status;
	const struct manifest_v2_testing_data *data = &PFM_V2_PLAT_FIRST.manifest;
	uint32_t toc_entry_offset = MANIFEST_V2_TOC_ENTRY_OFFSET;
	const struct manifest_toc_entry *toc_entries =
		(struct manifest_toc_entry*) (data->raw + toc_entry_offset);
	const uint8_t *plat_id = data->raw + data->plat_id_offset + MANIFEST_V2_PLATFORM_HEADER_SIZE;
	uint32_t validate_toc_start = toc_entry_offset;
	uint32_t validate_start = data->toc_hash_offset + data->toc_hash_len;
	uint32_t validate_end = data->plat_id_offset;
	int i;

	TEST_START;

	manifest_flash_v2_testing_init (test, &manifest, 0x10000, PFM_MAGIC_NUM, PFM_V2_MAGIC_NUM);

	status = mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash, 0,
		MOCK_ARG (manifest.addr), MOCK_ARG_NOT_NULL, MOCK_ARG (MANIFEST_V2_HEADER_SIZE));
	status |= mock_expect_output (&manifest.flash.mock, 1, data->raw, data->length, 2);

	status |= mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash, 0,
		MOCK_ARG (manifest.addr + data->sig_offset), MOCK_ARG_NOT_NULL, MOCK_ARG (data->sig_len));
	status |= mock_expect_output (&manifest.flash.mock, 1, data->signature, data->sig_len, 2);

	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.start_sha256,
		&manifest.hash_mock, 0);
	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.update,
		&manifest.hash_mock, 0, MOCK_ARG_PTR_CONTAINS (data->raw, MANIFEST_V2_HEADER_SIZE),
		MOCK_ARG (MANIFEST_V2_HEADER_SIZE));

	status |= mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash, 0,
		MOCK_ARG (manifest.addr + MANIFEST_V2_TOC_HDR_OFFSET), MOCK_ARG_NOT_NULL,
		MOCK_ARG (MANIFEST_V2_TOC_HEADER_SIZE));
	status |= mock_expect_output (&manifest.flash.mock, 1, data->toc,
		data->length - MANIFEST_V2_TOC_HDR_OFFSET, 2);

	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.update,
		&manifest.hash_mock, 0, MOCK_ARG_PTR_CONTAINS (data->toc, MANIFEST_V2_TOC_HEADER_SIZE),
		MOCK_ARG (MANIFEST_V2_TOC_HEADER_SIZE));

	for (i = 0; i <= data->plat_id_entry; i++, validate_toc_start += MANIFEST_V2_TOC_ENTRY_SIZE) {
		status |= mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash,
			0, MOCK_ARG (manifest.addr + toc_entry_offset + (i * MANIFEST_V2_TOC_ENTRY_SIZE)),
			MOCK_ARG_NOT_NULL, MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));
		status |= mock_expect_output (&manifest.flash.mock, 1, &toc_entries[i],
			MANIFEST_V2_TOC_ENTRY_SIZE, 2);

		status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.update,
			&manifest.hash_mock, 0,
			MOCK_ARG_PTR_CONTAINS (&toc_entries[i], MANIFEST_V2_TOC_ENTRY_SIZE),
			MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));
	}

	status |= flash_mock_expect_verify_flash_and_hash (&manifest.flash, &manifest.hash_mock,
		manifest.addr + validate_toc_start, data->raw + validate_toc_start,
		data->toc_hash_offset - validate_toc_start);

	status |= mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash, 0,
		MOCK_ARG (manifest.addr + data->toc_hash_offset), MOCK_ARG_NOT_NULL,
		MOCK_ARG (data->toc_hash_len));
	status |= mock_expect_output (&manifest.flash.mock, 1, data->toc_hash,
		data->length - data->toc_hash_offset, 2);

	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.update,
		&manifest.hash_mock, 0, MOCK_ARG_PTR_CONTAINS (data->toc_hash, data->toc_hash_len),
		MOCK_ARG (data->toc_hash_len));

	status |= flash_mock_expect_verify_flash_and_hash (&manifest.flash, &manifest.hash_mock,
		manifest.addr + validate_start, data->raw + validate_start, validate_end - validate_start);

	status |= mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash, 0,
		MOCK_ARG (manifest.addr + data->plat_id_offset), MOCK_ARG_NOT_NULL,
		MOCK_ARG (MANIFEST_V2_PLATFORM_HEADER_SIZE));
	status |= mock_expect_output (&manifest.flash.mock, 1, data->plat_id,
		data->length - data->plat_id_offset, 2);

	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.update,
		&manifest.hash_mock, 0,
		MOCK_ARG_PTR_CONTAINS (data->plat_id, MANIFEST_V2_PLATFORM_HEADER_SIZE),
		MOCK_ARG (MANIFEST_V2_PLATFORM_HEADER_SIZE));

	status |= mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash, 0,
		MOCK_ARG (manifest.addr + data->plat_id_offset + MANIFEST_V2_PLATFORM_HEADER_SIZE),
		MOCK_ARG_NOT_NULL, MOCK_ARG (data->plat_id_str_len));
	status |= mock_expect_output (&manifest.flash.mock, 1, plat_id,
		data->length - data->plat_id_offset + MANIFEST_V2_PLATFORM_HEADER_SIZE, 2);

	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.update,
		&manifest.hash_mock, HASH_ENGINE_UPDATE_FAILED,
		MOCK_ARG_PTR_CONTAINS (plat_id, data->plat_id_str_len), MOCK_ARG (data->plat_id_str_len));

	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.cancel,
		&manifest.hash_mock, 0);

	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_verify (&manifest.test, &manifest.hash_mock.base,
		&manifest.verification.base, NULL, 0);
	CuAssertIntEquals (test, HASH_ENGINE_UPDATE_FAILED, status);

	manifest_flash_v2_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_v2_test_verify_manifest_part2_read_error (CuTest *test)
{
	struct manifest_flash_v2_testing manifest;
	int status;
	const struct manifest_v2_testing_data *data = &PFM_V2_PLAT_FIRST.manifest;
	uint32_t toc_entry_offset = MANIFEST_V2_TOC_ENTRY_OFFSET;
	const struct manifest_toc_entry *toc_entries =
		(struct manifest_toc_entry*) (data->raw + toc_entry_offset);
	const uint8_t *plat_id = data->raw + data->plat_id_offset + MANIFEST_V2_PLATFORM_HEADER_SIZE;
	uint32_t validate_toc_start = toc_entry_offset;
	uint32_t validate_start = data->toc_hash_offset + data->toc_hash_len;
	uint32_t validate_end = data->plat_id_offset;
	uint32_t validate_resume =
		data->plat_id_offset + MANIFEST_V2_PLATFORM_HEADER_SIZE + data->plat_id_str_len;
	int i;

	TEST_START;

	manifest_flash_v2_testing_init (test, &manifest, 0x10000, PFM_MAGIC_NUM, PFM_V2_MAGIC_NUM);

	status = mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash, 0,
		MOCK_ARG (manifest.addr), MOCK_ARG_NOT_NULL, MOCK_ARG (MANIFEST_V2_HEADER_SIZE));
	status |= mock_expect_output (&manifest.flash.mock, 1, data->raw, data->length, 2);

	status |= mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash, 0,
		MOCK_ARG (manifest.addr + data->sig_offset), MOCK_ARG_NOT_NULL, MOCK_ARG (data->sig_len));
	status |= mock_expect_output (&manifest.flash.mock, 1, data->signature, data->sig_len, 2);

	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.start_sha256,
		&manifest.hash_mock, 0);
	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.update,
		&manifest.hash_mock, 0, MOCK_ARG_PTR_CONTAINS (data->raw, MANIFEST_V2_HEADER_SIZE),
		MOCK_ARG (MANIFEST_V2_HEADER_SIZE));

	status |= mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash, 0,
		MOCK_ARG (manifest.addr + MANIFEST_V2_TOC_HDR_OFFSET), MOCK_ARG_NOT_NULL,
		MOCK_ARG (MANIFEST_V2_TOC_HEADER_SIZE));
	status |= mock_expect_output (&manifest.flash.mock, 1, data->toc,
		data->length - MANIFEST_V2_TOC_HDR_OFFSET, 2);

	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.update,
		&manifest.hash_mock, 0, MOCK_ARG_PTR_CONTAINS (data->toc, MANIFEST_V2_TOC_HEADER_SIZE),
		MOCK_ARG (MANIFEST_V2_TOC_HEADER_SIZE));

	for (i = 0; i <= data->plat_id_entry; i++, validate_toc_start += MANIFEST_V2_TOC_ENTRY_SIZE) {
		status |= mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash,
			0, MOCK_ARG (manifest.addr + toc_entry_offset + (i * MANIFEST_V2_TOC_ENTRY_SIZE)),
			MOCK_ARG_NOT_NULL, MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));
		status |= mock_expect_output (&manifest.flash.mock, 1, &toc_entries[i],
			MANIFEST_V2_TOC_ENTRY_SIZE, 2);

		status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.update,
			&manifest.hash_mock, 0,
			MOCK_ARG_PTR_CONTAINS (&toc_entries[i], MANIFEST_V2_TOC_ENTRY_SIZE),
			MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));
	}

	status |= flash_mock_expect_verify_flash_and_hash (&manifest.flash, &manifest.hash_mock,
		manifest.addr + validate_toc_start, data->raw + validate_toc_start,
		data->toc_hash_offset - validate_toc_start);

	status |= mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash, 0,
		MOCK_ARG (manifest.addr + data->toc_hash_offset), MOCK_ARG_NOT_NULL,
		MOCK_ARG (data->toc_hash_len));
	status |= mock_expect_output (&manifest.flash.mock, 1, data->toc_hash,
		data->length - data->toc_hash_offset, 2);

	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.update,
		&manifest.hash_mock, 0, MOCK_ARG_PTR_CONTAINS (data->toc_hash, data->toc_hash_len),
		MOCK_ARG (data->toc_hash_len));

	status |= flash_mock_expect_verify_flash_and_hash (&manifest.flash, &manifest.hash_mock,
		manifest.addr + validate_start, data->raw + validate_start, validate_end - validate_start);

	status |= mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash, 0,
		MOCK_ARG (manifest.addr + data->plat_id_offset), MOCK_ARG_NOT_NULL,
		MOCK_ARG (MANIFEST_V2_PLATFORM_HEADER_SIZE));
	status |= mock_expect_output (&manifest.flash.mock, 1, data->plat_id,
		data->length - data->plat_id_offset, 2);

	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.update,
		&manifest.hash_mock, 0,
		MOCK_ARG_PTR_CONTAINS (data->plat_id, MANIFEST_V2_PLATFORM_HEADER_SIZE),
		MOCK_ARG (MANIFEST_V2_PLATFORM_HEADER_SIZE));

	status |= mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash, 0,
		MOCK_ARG (manifest.addr + data->plat_id_offset + MANIFEST_V2_PLATFORM_HEADER_SIZE),
		MOCK_ARG_NOT_NULL, MOCK_ARG (data->plat_id_str_len));
	status |= mock_expect_output (&manifest.flash.mock, 1, plat_id,
		data->length - data->plat_id_offset + MANIFEST_V2_PLATFORM_HEADER_SIZE, 2);

	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.update,
		&manifest.hash_mock, 0, MOCK_ARG_PTR_CONTAINS (plat_id, data->plat_id_str_len),
		MOCK_ARG (data->plat_id_str_len));

	status |= mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash,
		FLASH_READ_FAILED, MOCK_ARG (manifest.addr + validate_resume), MOCK_ARG_NOT_NULL,
		MOCK_ARG_ANY);

	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.cancel,
		&manifest.hash_mock, 0);

	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_verify (&manifest.test, &manifest.hash_mock.base,
		&manifest.verification.base, NULL, 0);
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	manifest_flash_v2_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_v2_test_verify_finish_hash_error (CuTest *test)
{
	struct manifest_flash_v2_testing manifest;
	int status;

	TEST_START;

	manifest_flash_v2_testing_init (test, &manifest, 0x10000, PFM_MAGIC_NUM, PFM_V2_MAGIC_NUM);

	manifest_flash_v2_testing_verify_manifest_mocked_hash (test, &manifest, &PFM_V2.manifest, 0,
		HASH_ENGINE_FINISH_FAILED);

	status = manifest_flash_verify (&manifest.test, &manifest.hash_mock.base,
		&manifest.verification.base, NULL, 0);
	CuAssertIntEquals (test, HASH_ENGINE_FINISH_FAILED, status);

	manifest_flash_v2_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_v2_test_verify_finish_hash_error_with_hash_out (CuTest *test)
{
	struct manifest_flash_v2_testing manifest;
	int status;
	uint8_t hash_out[SHA256_HASH_LENGTH];
	uint8_t empty[sizeof (hash_out)] = {0};

	TEST_START;

	memset (hash_out, 0xaa, sizeof (hash_out));

	manifest_flash_v2_testing_init (test, &manifest, 0x10000, PFM_MAGIC_NUM, PFM_V2_MAGIC_NUM);

	manifest_flash_v2_testing_verify_manifest_mocked_hash (test, &manifest, &PFM_V2.manifest, 0,
		HASH_ENGINE_FINISH_FAILED);

	status = manifest_flash_verify (&manifest.test, &manifest.hash_mock.base,
		&manifest.verification.base, hash_out, sizeof (hash_out));
	CuAssertIntEquals (test, HASH_ENGINE_FINISH_FAILED, status);

	status = testing_validate_array (empty, hash_out, sizeof (hash_out));
	CuAssertIntEquals (test, 0, status);

	manifest_flash_v2_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_v2_test_get_id (CuTest *test)
{
	struct manifest_flash_v2_testing manifest;
	int status;
	uint32_t id;

	TEST_START;

	manifest_flash_v2_testing_init_and_verify (test, &manifest, 0x10000, PFM_MAGIC_NUM,
		PFM_V2_MAGIC_NUM, &PFM_V2.manifest, 0, false, 0);

	status = manifest_flash_get_id (&manifest.test, &id);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, PFM_V2.manifest.id, id);

	manifest_flash_v2_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_v2_test_get_id_null (CuTest *test)
{
	struct manifest_flash_v2_testing manifest;
	int status;
	uint32_t id;

	TEST_START;

	manifest_flash_v2_testing_init_and_verify (test, &manifest, 0x10000, PFM_MAGIC_NUM,
		PFM_V2_MAGIC_NUM, &PFM_V2.manifest, 0, false, 0);

	status = manifest_flash_get_id (NULL, &id);
	CuAssertIntEquals (test, MANIFEST_INVALID_ARGUMENT, status);

	status = manifest_flash_get_id (&manifest.test, NULL);
	CuAssertIntEquals (test, MANIFEST_INVALID_ARGUMENT, status);

	manifest_flash_v2_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_v2_test_get_id_verify_never_run (CuTest *test)
{
	struct manifest_flash_v2_testing manifest;
	int status;
	uint32_t id;

	TEST_START;

	manifest_flash_v2_testing_init (test, &manifest, 0x10000, PFM_MAGIC_NUM, PFM_V2_MAGIC_NUM);

	status = manifest_flash_get_id (&manifest.test, &id);
	CuAssertIntEquals (test, MANIFEST_NO_MANIFEST, status);

	manifest_flash_v2_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_v2_test_get_id_after_verify_header_read_error (CuTest *test)
{
	struct manifest_flash_v2_testing manifest;
	int status;
	uint32_t id;

	TEST_START;

	manifest_flash_v2_testing_init_and_verify (test, &manifest, 0x10000, PFM_MAGIC_NUM,
		PFM_V2_MAGIC_NUM, &PFM_V2.manifest, 0, false, 0);

	status = mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash,
		FLASH_READ_FAILED, MOCK_ARG (manifest.addr), MOCK_ARG_NOT_NULL,
		MOCK_ARG (MANIFEST_V2_HEADER_SIZE));
	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_verify (&manifest.test, &manifest.hash.base,
		&manifest.verification.base, NULL, 0);
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	status = manifest_flash_get_id (&manifest.test, &id);
	CuAssertIntEquals (test, MANIFEST_NO_MANIFEST, status);

	manifest_flash_v2_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_v2_test_get_id_after_verify_bad_signature (CuTest *test)
{
	struct manifest_flash_v2_testing manifest;
	int status;
	uint32_t id;

	TEST_START;

	manifest_flash_v2_testing_init_and_verify (test, &manifest, 0x10000, PFM_MAGIC_NUM,
		PFM_V2_MAGIC_NUM, &PFM_V2.manifest, 0, false, 0);

	manifest_flash_v2_testing_verify_manifest (test, &manifest, &PFM_V2_PLAT_FIRST.manifest,
		RSA_ENGINE_BAD_SIGNATURE);

	status = manifest_flash_verify (&manifest.test, &manifest.hash.base,
		&manifest.verification.base, NULL, 0);
	CuAssertIntEquals (test, RSA_ENGINE_BAD_SIGNATURE, status);

	status = manifest_flash_get_id (&manifest.test, &id);
	CuAssertIntEquals (test, MANIFEST_NO_MANIFEST, status);

	manifest_flash_v2_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_v2_test_get_platform_id (CuTest *test)
{
	struct manifest_flash_v2_testing manifest;
	int status;
	char buffer[32];
	char *id = buffer;

	TEST_START;

	manifest_flash_v2_testing_init_and_verify (test, &manifest, 0x10000, PFM_MAGIC_NUM,
		PFM_V2_MAGIC_NUM, &PFM_V2.manifest, 0, false, 0);

	status = manifest_flash_get_platform_id (&manifest.test, &id, sizeof (buffer));
	CuAssertIntEquals (test, 0, status);
	CuAssertStrEquals (test, PFM_V2.manifest.plat_id_str, id);

	manifest_flash_v2_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_v2_test_get_platform_id_manifest_allocation (CuTest *test)
{
	struct manifest_flash_v2_testing manifest;
	int status;
	char *id = NULL;

	TEST_START;

	manifest_flash_v2_testing_init_and_verify (test, &manifest, 0x10000, PFM_MAGIC_NUM,
		PFM_V2_MAGIC_NUM, &PFM_V2.manifest, 0, false, 0);

	status = manifest_flash_get_platform_id (&manifest.test, &id, 0);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, id);
	CuAssertStrEquals (test, PFM_V2.manifest.plat_id_str, id);

	manifest_flash_v2_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_v2_test_get_platform_id_null (CuTest *test)
{
	struct manifest_flash_v2_testing manifest;
	int status;
	char buffer[32];
	char *id = buffer;

	TEST_START;

	manifest_flash_v2_testing_init_and_verify (test, &manifest, 0x10000, PFM_MAGIC_NUM,
		PFM_V2_MAGIC_NUM, &PFM_V2.manifest, 0, false, 0);

	status = manifest_flash_get_platform_id (NULL, &id, sizeof (buffer));
	CuAssertIntEquals (test, MANIFEST_INVALID_ARGUMENT, status);

	status = manifest_flash_get_platform_id (&manifest.test, NULL, sizeof (buffer));
	CuAssertIntEquals (test, MANIFEST_INVALID_ARGUMENT, status);

	manifest_flash_v2_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_v2_test_get_platform_id_small_buffer (CuTest *test)
{
	struct manifest_flash_v2_testing manifest;
	int status;
	char buffer[32];
	char *id = buffer;

	TEST_START;

	manifest_flash_v2_testing_init_and_verify (test, &manifest, 0x10000, PFM_MAGIC_NUM,
		PFM_V2_MAGIC_NUM, &PFM_V2.manifest, 0, false, 0);

	status = manifest_flash_get_platform_id (&manifest.test, &id, PFM_V2.manifest.plat_id_str_len);
	CuAssertIntEquals (test, MANIFEST_PLAT_ID_BUFFER_TOO_SMALL, status);

	manifest_flash_v2_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_v2_test_get_platform_id_verify_never_run (CuTest *test)
{
	struct manifest_flash_v2_testing manifest;
	int status;
	char buffer[32];
	char *id = buffer;

	TEST_START;

	manifest_flash_v2_testing_init (test, &manifest, 0x10000, PFM_MAGIC_NUM, PFM_V2_MAGIC_NUM);

	status = manifest_flash_get_platform_id (&manifest.test, &id, sizeof (buffer));
	CuAssertIntEquals (test, MANIFEST_NO_MANIFEST, status);

	manifest_flash_v2_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_v2_test_get_platform_id_after_verify_header_read_error (CuTest *test)
{
	struct manifest_flash_v2_testing manifest;
	int status;
	char buffer[32];
	char *id = buffer;

	TEST_START;

	manifest_flash_v2_testing_init_and_verify (test, &manifest, 0x10000, PFM_MAGIC_NUM,
		PFM_V2_MAGIC_NUM, &PFM_V2.manifest, 0, false, 0);

	status = mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash,
		FLASH_READ_FAILED, MOCK_ARG (manifest.addr), MOCK_ARG_NOT_NULL,
		MOCK_ARG (MANIFEST_V2_HEADER_SIZE));
	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_verify (&manifest.test, &manifest.hash.base,
		&manifest.verification.base, NULL, 0);
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	status = manifest_flash_get_platform_id (&manifest.test, &id, sizeof (buffer));
	CuAssertIntEquals (test, MANIFEST_NO_MANIFEST, status);

	manifest_flash_v2_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_v2_test_get_platform_id_after_verify_bad_signature (CuTest *test)
{
	struct manifest_flash_v2_testing manifest;
	int status;
	char buffer[32];
	char *id = buffer;

	TEST_START;

	manifest_flash_v2_testing_init_and_verify (test, &manifest, 0x10000, PFM_MAGIC_NUM,
		PFM_V2_MAGIC_NUM, &PFM_V2.manifest, 0, false, 0);

	manifest_flash_v2_testing_verify_manifest (test, &manifest, &PFM_V2_PLAT_FIRST.manifest,
		RSA_ENGINE_BAD_SIGNATURE);

	status = manifest_flash_verify (&manifest.test, &manifest.hash.base,
		&manifest.verification.base, NULL, 0);
	CuAssertIntEquals (test, RSA_ENGINE_BAD_SIGNATURE, status);

	status = manifest_flash_get_platform_id (&manifest.test, &id, sizeof (buffer));
	CuAssertIntEquals (test, MANIFEST_NO_MANIFEST, status);

	manifest_flash_v2_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_v2_test_get_hash_sha256 (CuTest *test)
{
	struct manifest_flash_v2_testing manifest;
	int status;
	uint8_t hash_out[SHA256_HASH_LENGTH];

	TEST_START;

	manifest_flash_v2_testing_init_and_verify (test, &manifest, 0x10000, PFM_MAGIC_NUM,
		PFM_V2_MAGIC_NUM, &PFM_V2.manifest, 0, false, 0);

	status = manifest_flash_get_hash (&manifest.test, &manifest.hash.base, hash_out,
		sizeof (hash_out));
	CuAssertIntEquals (test, PFM_V2.manifest.hash_len, status);

	status = testing_validate_array (PFM_V2.manifest.hash, hash_out, status);
	CuAssertIntEquals (test, 0, status);

	manifest_flash_v2_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_v2_test_get_hash_sha384 (CuTest *test)
{
	struct manifest_flash_v2_testing manifest;
	int status;
	uint8_t hash_out[SHA384_HASH_LENGTH];

	TEST_START;

	manifest_flash_v2_testing_init_and_verify (test, &manifest, 0x10000, PFM_MAGIC_NUM,
		PFM_V2_MAGIC_NUM, &PFM_V2_SHA384.manifest, 0, false, 0);

	status = manifest_flash_get_hash (&manifest.test, &manifest.hash.base, hash_out,
		sizeof (hash_out));
	CuAssertIntEquals (test, PFM_V2_SHA384.manifest.hash_len, status);

	status = testing_validate_array (PFM_V2_SHA384.manifest.hash, hash_out, status);
	CuAssertIntEquals (test, 0, status);

	manifest_flash_v2_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_v2_test_get_hash_sha512 (CuTest *test)
{
	struct manifest_flash_v2_testing manifest;
	int status;
	uint8_t hash_out[SHA512_HASH_LENGTH];

	TEST_START;

	manifest_flash_v2_testing_init_and_verify (test, &manifest, 0x10000, PFM_MAGIC_NUM,
		PFM_V2_MAGIC_NUM, &PFM_V2_SHA512.manifest, 0, false, 0);

	status = manifest_flash_get_hash (&manifest.test, &manifest.hash.base, hash_out,
		sizeof (hash_out));
	CuAssertIntEquals (test, PFM_V2_SHA512.manifest.hash_len, status);

	status = testing_validate_array (PFM_V2_SHA512.manifest.hash, hash_out, status);
	CuAssertIntEquals (test, 0, status);

	manifest_flash_v2_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_v2_test_get_hash_verify_never_run (CuTest *test)
{
	struct manifest_flash_v2_testing manifest;
	int status;
	uint8_t hash_out[SHA256_HASH_LENGTH];

	TEST_START;

	manifest_flash_v2_testing_init (test, &manifest, 0x10000, PFM_MAGIC_NUM, PFM_V2_MAGIC_NUM);

	status = mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash, 0,
		MOCK_ARG (manifest.addr), MOCK_ARG_NOT_NULL, MOCK_ARG (MANIFEST_V2_HEADER_SIZE));
	status |= mock_expect_output (&manifest.flash.mock, 1, PFM_V2.manifest.raw,
		PFM_V2.manifest.length, 2);

	status |= flash_mock_expect_verify_flash (&manifest.flash, manifest.addr,
		PFM_V2.manifest.raw, PFM_V2.manifest.length - PFM_V2.manifest.sig_len);

	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_get_hash (&manifest.test, &manifest.hash.base, hash_out,
		sizeof (hash_out));
	CuAssertIntEquals (test, PFM_V2.manifest.hash_len, status);

	status = testing_validate_array (PFM_V2.manifest.hash, hash_out, status);
	CuAssertIntEquals (test, 0, status);

	manifest_flash_v2_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_v2_test_get_hash_after_verify_header_read_error (CuTest *test)
{
	struct manifest_flash_v2_testing manifest;
	int status;
	uint8_t hash_out[SHA384_HASH_LENGTH];

	TEST_START;

	manifest_flash_v2_testing_init_and_verify (test, &manifest, 0x10000, PFM_MAGIC_NUM,
		PFM_V2_MAGIC_NUM, &PFM_V2_SHA384.manifest, 0, false, 0);

	status = mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash,
		FLASH_READ_FAILED, MOCK_ARG (manifest.addr), MOCK_ARG_NOT_NULL,
		MOCK_ARG (MANIFEST_V2_HEADER_SIZE));
	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_verify (&manifest.test, &manifest.hash.base,
		&manifest.verification.base, NULL, 0);
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	status = mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash, 0,
		MOCK_ARG (manifest.addr), MOCK_ARG_NOT_NULL, MOCK_ARG (MANIFEST_V2_HEADER_SIZE));
	status |= mock_expect_output (&manifest.flash.mock, 1, PFM_V2_SHA384.manifest.raw,
		PFM_V2_SHA384.manifest.length, 2);

	status |= flash_mock_expect_verify_flash (&manifest.flash, manifest.addr,
		PFM_V2_SHA384.manifest.raw, PFM_V2_SHA384.manifest.length - PFM_V2_SHA384.manifest.sig_len);

	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_get_hash (&manifest.test, &manifest.hash.base, hash_out,
		sizeof (hash_out));
	CuAssertIntEquals (test, PFM_V2_SHA384.manifest.hash_len, status);

	status = testing_validate_array (PFM_V2_SHA384.manifest.hash, hash_out, status);
	CuAssertIntEquals (test, 0, status);

	manifest_flash_v2_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_v2_test_get_hash_after_verify_finish_hash_error (CuTest *test)
{
	struct manifest_flash_v2_testing manifest;
	int status;
	uint8_t hash_out[SHA512_HASH_LENGTH];

	TEST_START;

	manifest_flash_v2_testing_init_and_verify (test, &manifest, 0x10000, PFM_MAGIC_NUM,
		PFM_V2_MAGIC_NUM, &PFM_V2.manifest, 0, false, 0);

	manifest_flash_v2_testing_verify_manifest_mocked_hash (test, &manifest, &PFM_V2.manifest, 0,
		HASH_ENGINE_FINISH_FAILED);

	status = manifest_flash_verify (&manifest.test, &manifest.hash_mock.base,
		&manifest.verification.base, NULL, 0);
	CuAssertIntEquals (test, HASH_ENGINE_FINISH_FAILED, status);

	status = mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash, 0,
		MOCK_ARG (manifest.addr), MOCK_ARG_NOT_NULL, MOCK_ARG (MANIFEST_V2_HEADER_SIZE));
	status |= mock_expect_output (&manifest.flash.mock, 1, PFM_V2_SHA512.manifest.raw,
		PFM_V2_SHA512.manifest.length, 2);

	status |= flash_mock_expect_verify_flash (&manifest.flash, manifest.addr,
		PFM_V2_SHA512.manifest.raw, PFM_V2_SHA512.manifest.length - PFM_V2_SHA512.manifest.sig_len);

	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_get_hash (&manifest.test, &manifest.hash.base, hash_out,
		sizeof (hash_out));
	CuAssertIntEquals (test, PFM_V2_SHA512.manifest.hash_len, status);

	status = testing_validate_array (PFM_V2_SHA512.manifest.hash, hash_out, status);
	CuAssertIntEquals (test, 0, status);

	manifest_flash_v2_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_v2_test_get_hash_after_verify_bad_signature (CuTest *test)
{
	struct manifest_flash_v2_testing manifest;
	int status;
	uint8_t hash_out[SHA512_HASH_LENGTH];

	TEST_START;

	manifest_flash_v2_testing_init_and_verify (test, &manifest, 0x10000, PFM_MAGIC_NUM,
		PFM_V2_MAGIC_NUM, &PFM_V2.manifest, 0, false, 0);

	manifest_flash_v2_testing_verify_manifest (test, &manifest, &PFM_V2_SHA512.manifest,
		RSA_ENGINE_BAD_SIGNATURE);

	status = manifest_flash_verify (&manifest.test, &manifest.hash.base,
		&manifest.verification.base, NULL, 0);
	CuAssertIntEquals (test, RSA_ENGINE_BAD_SIGNATURE, status);

	status = manifest_flash_get_hash (&manifest.test, &manifest.hash.base, hash_out,
		sizeof (hash_out));
	CuAssertIntEquals (test, PFM_V2_SHA512.manifest.hash_len, status);

	status = testing_validate_array (PFM_V2_SHA512.manifest.hash, hash_out, status);
	CuAssertIntEquals (test, 0, status);

	manifest_flash_v2_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_v2_test_get_hash_null (CuTest *test)
{
	struct manifest_flash_v2_testing manifest;
	int status;
	uint8_t hash_out[SHA256_HASH_LENGTH];

	TEST_START;

	manifest_flash_v2_testing_init_and_verify (test, &manifest, 0x10000, PFM_MAGIC_NUM,
		PFM_V2_MAGIC_NUM, &PFM_V2.manifest, 0, false, 0);

	status = manifest_flash_get_hash (NULL, &manifest.hash.base, hash_out,
		sizeof (hash_out));
	CuAssertIntEquals (test, MANIFEST_INVALID_ARGUMENT, status);

	status = manifest_flash_get_hash (&manifest.test, NULL, hash_out,
		sizeof (hash_out));
	CuAssertIntEquals (test, MANIFEST_INVALID_ARGUMENT, status);

	status = manifest_flash_get_hash (&manifest.test, &manifest.hash.base, NULL,
		sizeof (hash_out));
	CuAssertIntEquals (test, MANIFEST_INVALID_ARGUMENT, status);

	manifest_flash_v2_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_v2_test_get_hash_small_hash_buffer (CuTest *test)
{
	struct manifest_flash_v2_testing manifest;
	int status;
	uint8_t hash_out[SHA256_HASH_LENGTH - 1];

	TEST_START;

	manifest_flash_v2_testing_init_and_verify (test, &manifest, 0x10000, PFM_MAGIC_NUM,
		PFM_V2_MAGIC_NUM, &PFM_V2.manifest, 0, false, 0);

	status = manifest_flash_get_hash (&manifest.test, &manifest.hash.base, hash_out,
		sizeof (hash_out));
	CuAssertIntEquals (test, MANIFEST_HASH_BUFFER_TOO_SMALL, status);

	manifest_flash_v2_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_v2_test_get_hash_small_hash_buffer_sha384 (CuTest *test)
{
	struct manifest_flash_v2_testing manifest;
	int status;
	uint8_t hash_out[SHA384_HASH_LENGTH - 1];

	TEST_START;

	manifest_flash_v2_testing_init_and_verify (test, &manifest, 0x10000, PFM_MAGIC_NUM,
		PFM_V2_MAGIC_NUM, &PFM_V2_SHA384.manifest, 0, false, 0);

	status = manifest_flash_get_hash (&manifest.test, &manifest.hash.base, hash_out,
		sizeof (hash_out));
	CuAssertIntEquals (test, MANIFEST_HASH_BUFFER_TOO_SMALL, status);

	manifest_flash_v2_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_v2_test_get_hash_small_hash_buffer_sha512 (CuTest *test)
{
	struct manifest_flash_v2_testing manifest;
	int status;
	uint8_t hash_out[SHA512_HASH_LENGTH - 1];

	TEST_START;

	manifest_flash_v2_testing_init_and_verify (test, &manifest, 0x10000, PFM_MAGIC_NUM,
		PFM_V2_MAGIC_NUM, &PFM_V2_SHA512.manifest, 0, false, 0);

	status = manifest_flash_get_hash (&manifest.test, &manifest.hash.base, hash_out,
		sizeof (hash_out));
	CuAssertIntEquals (test, MANIFEST_HASH_BUFFER_TOO_SMALL, status);

	manifest_flash_v2_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_v2_test_get_hash_header_read_error (CuTest *test)
{
	struct manifest_flash_v2_testing manifest;
	int status;
	uint8_t hash_out[SHA256_HASH_LENGTH];

	TEST_START;

	manifest_flash_v2_testing_init (test, &manifest, 0x10000, PFM_MAGIC_NUM, PFM_V2_MAGIC_NUM);

	status = mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash,
		FLASH_READ_FAILED, MOCK_ARG (manifest.addr), MOCK_ARG_NOT_NULL,
		MOCK_ARG (MANIFEST_V2_HEADER_SIZE));

	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_get_hash (&manifest.test, &manifest.hash.base, hash_out,
		sizeof (hash_out));
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	manifest_flash_v2_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_v2_test_get_hash_bad_magic_number (CuTest *test)
{
	struct manifest_flash_v2_testing manifest;
	int status;
	struct manifest_header header;
	uint8_t hash_out[SHA256_HASH_LENGTH];

	TEST_START;

	memcpy (&header, PFM_V2.manifest.raw, sizeof (header));
	header.magic ^= 0x55;

	manifest_flash_v2_testing_init (test, &manifest, 0x10000, PFM_MAGIC_NUM, PFM_V2_MAGIC_NUM);

	status = mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash, 0,
		MOCK_ARG (manifest.addr), MOCK_ARG_NOT_NULL, MOCK_ARG (MANIFEST_V2_HEADER_SIZE));
	status |= mock_expect_output (&manifest.flash.mock, 1, &header, sizeof (header), 2);

	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_get_hash (&manifest.test, &manifest.hash.base, hash_out,
		sizeof (hash_out));
	CuAssertIntEquals (test, MANIFEST_BAD_MAGIC_NUMBER, status);

	manifest_flash_v2_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_v2_test_get_hash_bad_magic_number_v1_unsupported (CuTest *test)
{
	struct manifest_flash_v2_testing manifest;
	int status;
	struct manifest_header header;
	uint8_t hash_out[SHA256_HASH_LENGTH];

	TEST_START;

	memcpy (&header, PFM_V2.manifest.raw, sizeof (header));
	header.magic = MANIFEST_NOT_SUPPORTED;

	manifest_flash_v2_testing_init (test, &manifest, 0x10000, MANIFEST_NOT_SUPPORTED,
		PFM_V2_MAGIC_NUM);

	status = mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash, 0,
		MOCK_ARG (manifest.addr), MOCK_ARG_NOT_NULL, MOCK_ARG (MANIFEST_V2_HEADER_SIZE));
	status |= mock_expect_output (&manifest.flash.mock, 1, &header, sizeof (header), 2);

	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_get_hash (&manifest.test, &manifest.hash.base, hash_out,
		sizeof (hash_out));
	CuAssertIntEquals (test, MANIFEST_BAD_MAGIC_NUMBER, status);

	manifest_flash_v2_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_v2_test_get_hash_bad_magic_number_v2_unsupported (CuTest *test)
{
	struct manifest_flash_v2_testing manifest;
	int status;
	struct manifest_header header;
	uint8_t hash_out[SHA256_HASH_LENGTH];

	TEST_START;

	memcpy (&header, PFM_V2.manifest.raw, sizeof (header));
	header.magic = MANIFEST_NOT_SUPPORTED;

	manifest_flash_v2_testing_init (test, &manifest, 0x10000, PFM_MAGIC_NUM,
		MANIFEST_NOT_SUPPORTED);

	status = mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash, 0,
		MOCK_ARG (manifest.addr), MOCK_ARG_NOT_NULL, MOCK_ARG (MANIFEST_V2_HEADER_SIZE));
	status |= mock_expect_output (&manifest.flash.mock, 1, &header, sizeof (header), 2);

	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_get_hash (&manifest.test, &manifest.hash.base, hash_out,
		sizeof (hash_out));
	CuAssertIntEquals (test, MANIFEST_BAD_MAGIC_NUMBER, status);

	manifest_flash_v2_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_v2_test_get_hash_sig_longer_than_manifest (CuTest *test)
{
	struct manifest_flash_v2_testing manifest;
	int status;
	struct manifest_header header;
	uint8_t hash_out[SHA256_HASH_LENGTH];

	TEST_START;

	memcpy (&header, PFM_V2.manifest.raw, sizeof (header));
	header.sig_length = header.length + 1;

	manifest_flash_v2_testing_init (test, &manifest, 0x10000, PFM_MAGIC_NUM, PFM_V2_MAGIC_NUM);

	status = mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash, 0,
		MOCK_ARG (manifest.addr), MOCK_ARG_NOT_NULL, MOCK_ARG (MANIFEST_V2_HEADER_SIZE));
	status |= mock_expect_output (&manifest.flash.mock, 1, &header, sizeof (header), 2);

	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_get_hash (&manifest.test, &manifest.hash.base, hash_out,
		sizeof (hash_out));
	CuAssertIntEquals (test, MANIFEST_BAD_LENGTH, status);

	manifest_flash_v2_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_v2_test_get_hash_sig_same_length_as_manifest (CuTest *test)
{
	struct manifest_flash_v2_testing manifest;
	int status;
	struct manifest_header header;
	uint8_t hash_out[SHA256_HASH_LENGTH];

	TEST_START;

	memcpy (&header, PFM_V2.manifest.raw, sizeof (header));
	header.sig_length = header.length;

	manifest_flash_v2_testing_init (test, &manifest, 0x10000, PFM_MAGIC_NUM, PFM_V2_MAGIC_NUM);

	status = mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash, 0,
		MOCK_ARG (manifest.addr), MOCK_ARG_NOT_NULL, MOCK_ARG (MANIFEST_V2_HEADER_SIZE));
	status |= mock_expect_output (&manifest.flash.mock, 1, &header, sizeof (header), 2);

	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_get_hash (&manifest.test, &manifest.hash.base, hash_out,
		sizeof (hash_out));
	CuAssertIntEquals (test, MANIFEST_BAD_LENGTH, status);

	manifest_flash_v2_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_v2_test_get_hash_sig_length_into_header (CuTest *test)
{
	struct manifest_flash_v2_testing manifest;
	int status;
	struct manifest_header header;
	uint8_t hash_out[SHA256_HASH_LENGTH];

	TEST_START;

	memcpy (&header, PFM_V2.manifest.raw, sizeof (header));
	header.sig_length = (header.length - sizeof (header)) + 1;

	manifest_flash_v2_testing_init (test, &manifest, 0x10000, PFM_MAGIC_NUM, PFM_V2_MAGIC_NUM);

	status = mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash, 0,
		MOCK_ARG (manifest.addr), MOCK_ARG_NOT_NULL, MOCK_ARG (MANIFEST_V2_HEADER_SIZE));
	status |= mock_expect_output (&manifest.flash.mock, 1, &header, sizeof (header), 2);

	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_get_hash (&manifest.test, &manifest.hash.base, hash_out,
		sizeof (hash_out));
	CuAssertIntEquals (test, MANIFEST_BAD_LENGTH, status);

	manifest_flash_v2_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_v2_test_get_hash_verify_never_run_small_hash_buffer (CuTest *test)
{
	struct manifest_flash_v2_testing manifest;
	int status;
	uint8_t hash_out[SHA256_HASH_LENGTH - 1];

	TEST_START;

	manifest_flash_v2_testing_init (test, &manifest, 0x10000, PFM_MAGIC_NUM, PFM_V2_MAGIC_NUM);

	status = manifest_flash_get_hash (&manifest.test, &manifest.hash.base, hash_out,
		sizeof (hash_out));
	CuAssertIntEquals (test, MANIFEST_HASH_BUFFER_TOO_SMALL, status);

	manifest_flash_v2_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_v2_test_get_hash_verify_never_run_small_hash_buffer_sha384 (CuTest *test)
{
	struct manifest_flash_v2_testing manifest;
	int status;
	uint8_t hash_out[SHA384_HASH_LENGTH - 1];

	TEST_START;

	manifest_flash_v2_testing_init (test, &manifest, 0x10000, PFM_MAGIC_NUM, PFM_V2_MAGIC_NUM);

	status = mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash, 0,
		MOCK_ARG (manifest.addr), MOCK_ARG_NOT_NULL, MOCK_ARG (MANIFEST_V2_HEADER_SIZE));
	status |= mock_expect_output (&manifest.flash.mock, 1, PFM_V2_SHA384.manifest.raw,
		PFM_V2_SHA384.manifest.length, 2);

	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_get_hash (&manifest.test, &manifest.hash.base, hash_out,
		sizeof (hash_out));
	CuAssertIntEquals (test, MANIFEST_HASH_BUFFER_TOO_SMALL, status);

	manifest_flash_v2_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_v2_test_get_hash_verify_never_run_small_hash_buffer_sha512 (CuTest *test)
{
	struct manifest_flash_v2_testing manifest;
	int status;
	uint8_t hash_out[SHA512_HASH_LENGTH - 1];

	TEST_START;

	manifest_flash_v2_testing_init (test, &manifest, 0x10000, PFM_MAGIC_NUM, PFM_V2_MAGIC_NUM);

	status = mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash, 0,
		MOCK_ARG (manifest.addr), MOCK_ARG_NOT_NULL, MOCK_ARG (MANIFEST_V2_HEADER_SIZE));
	status |= mock_expect_output (&manifest.flash.mock, 1, PFM_V2_SHA512.manifest.raw,
		PFM_V2_SHA512.manifest.length, 2);

	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_get_hash (&manifest.test, &manifest.hash.base, hash_out,
		sizeof (hash_out));
	CuAssertIntEquals (test, MANIFEST_HASH_BUFFER_TOO_SMALL, status);

	manifest_flash_v2_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_v2_test_get_hash_unknown_hash_type (CuTest *test)
{
	struct manifest_flash_v2_testing manifest;
	int status;
	struct manifest_header header;
	uint8_t hash_out[SHA256_HASH_LENGTH];

	TEST_START;

	memcpy (&header, PFM_V2.manifest.raw, sizeof (header));
	header.sig_type = 0x03;

	manifest_flash_v2_testing_init (test, &manifest, 0x10000, PFM_MAGIC_NUM, PFM_V2_MAGIC_NUM);

	status = mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash, 0,
		MOCK_ARG (manifest.addr), MOCK_ARG_NOT_NULL, MOCK_ARG (MANIFEST_V2_HEADER_SIZE));
	status |= mock_expect_output (&manifest.flash.mock, 1, &header, sizeof (header), 2);

	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_get_hash (&manifest.test, &manifest.hash.base, hash_out,
		sizeof (hash_out));
	CuAssertIntEquals (test, MANIFEST_SIG_UNKNOWN_HASH_TYPE, status);

	manifest_flash_v2_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_v2_test_get_hash_read_error (CuTest *test)
{
	struct manifest_flash_v2_testing manifest;
	int status;
	uint8_t hash_out[SHA256_HASH_LENGTH];

	TEST_START;

	manifest_flash_v2_testing_init (test, &manifest, 0x10000, PFM_MAGIC_NUM, PFM_V2_MAGIC_NUM);

	status = mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash, 0,
		MOCK_ARG (manifest.addr), MOCK_ARG_NOT_NULL, MOCK_ARG (MANIFEST_V2_HEADER_SIZE));
	status |= mock_expect_output (&manifest.flash.mock, 1, PFM_V2.manifest.raw,
		PFM_V2.manifest.length, 2);

	status |= mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash,
		FLASH_READ_FAILED, MOCK_ARG (manifest.addr), MOCK_ARG_NOT_NULL, MOCK_ARG_ANY);

	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_get_hash (&manifest.test, &manifest.hash.base, hash_out,
		sizeof (hash_out));
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	manifest_flash_v2_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_v2_test_get_signature (CuTest *test)
{
	struct manifest_flash_v2_testing manifest;
	int status;
	uint8_t sig_out[PFM_V2.manifest.sig_len];

	TEST_START;

	manifest_flash_v2_testing_init_and_verify (test, &manifest, 0x10000, PFM_MAGIC_NUM,
		PFM_V2_MAGIC_NUM, &PFM_V2.manifest, 0, false, 0);

	status = manifest_flash_get_signature (&manifest.test, sig_out, sizeof (sig_out));
	CuAssertIntEquals (test, PFM_V2.manifest.sig_len, status);

	status = testing_validate_array (PFM_V2.manifest.signature, sig_out, status);
	CuAssertIntEquals (test, 0, status);

	manifest_flash_v2_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_v2_test_get_signature_verify_never_run (CuTest *test)
{
	struct manifest_flash_v2_testing manifest;
	int status;
	uint8_t sig_out[PFM_V2_SHA384.manifest.sig_len];

	TEST_START;

	manifest_flash_v2_testing_init (test, &manifest, 0x10000, PFM_MAGIC_NUM, PFM_V2_MAGIC_NUM);

	status = mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash, 0,
		MOCK_ARG (manifest.addr), MOCK_ARG_NOT_NULL, MOCK_ARG (MANIFEST_V2_HEADER_SIZE));
	status |= mock_expect_output (&manifest.flash.mock, 1, PFM_V2_SHA384.manifest.raw,
		PFM_V2_SHA384.manifest.length, 2);

	status |= mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash, 0,
		MOCK_ARG (manifest.addr + PFM_V2_SHA384.manifest.sig_offset), MOCK_ARG_NOT_NULL,
		MOCK_ARG (PFM_V2_SHA384.manifest.sig_len));
	status |= mock_expect_output (&manifest.flash.mock, 1, PFM_V2_SHA384.manifest.signature,
		PFM_V2_SHA384.manifest.sig_len, 2);

	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_get_signature (&manifest.test, sig_out, sizeof (sig_out));
	CuAssertIntEquals (test, PFM_V2_SHA384.manifest.sig_len, status);

	status = testing_validate_array (PFM_V2_SHA384.manifest.signature, sig_out, status);
	CuAssertIntEquals (test, 0, status);

	manifest_flash_v2_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_v2_test_get_signature_after_verify_header_read_error (CuTest *test)
{
	struct manifest_flash_v2_testing manifest;
	int status;
	uint8_t sig_out[PFM_V2.manifest.sig_len];

	TEST_START;

	manifest_flash_v2_testing_init_and_verify (test, &manifest, 0x10000, PFM_MAGIC_NUM,
		PFM_V2_MAGIC_NUM, &PFM_V2_SHA384.manifest, 0, false, 0);

	status = mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash,
		FLASH_READ_FAILED, MOCK_ARG (manifest.addr), MOCK_ARG_NOT_NULL,
		MOCK_ARG (MANIFEST_V2_HEADER_SIZE));
	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_verify (&manifest.test, &manifest.hash.base,
		&manifest.verification.base, NULL, 0);
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	status = mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash, 0,
		MOCK_ARG (manifest.addr), MOCK_ARG_NOT_NULL, MOCK_ARG (MANIFEST_V2_HEADER_SIZE));
	status |= mock_expect_output (&manifest.flash.mock, 1, PFM_V2.manifest.raw,
		PFM_V2.manifest.length, 2);

	status |= mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash, 0,
		MOCK_ARG (manifest.addr + PFM_V2.manifest.sig_offset), MOCK_ARG_NOT_NULL,
		MOCK_ARG (PFM_V2.manifest.sig_len));
	status |= mock_expect_output (&manifest.flash.mock, 1, PFM_V2.manifest.signature,
		PFM_V2.manifest.sig_len, 2);

	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_get_signature (&manifest.test, sig_out, sizeof (sig_out));
	CuAssertIntEquals (test, PFM_V2.manifest.sig_len, status);

	status = testing_validate_array (PFM_V2.manifest.signature, sig_out, status);
	CuAssertIntEquals (test, 0, status);

	manifest_flash_v2_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_v2_test_get_signature_after_verify_finish_hash_error (CuTest *test)
{
	struct manifest_flash_v2_testing manifest;
	int status;
	uint8_t sig_out[PFM_V2_SHA512.manifest.sig_len];

	TEST_START;

	manifest_flash_v2_testing_init_and_verify (test, &manifest, 0x10000, PFM_MAGIC_NUM,
		PFM_V2_MAGIC_NUM, &PFM_V2.manifest, 0, false, 0);

	manifest_flash_v2_testing_verify_manifest_mocked_hash (test, &manifest, &PFM_V2_SHA512.manifest,
		0, HASH_ENGINE_FINISH_FAILED);

	status = manifest_flash_verify (&manifest.test, &manifest.hash_mock.base,
		&manifest.verification.base, NULL, 0);
	CuAssertIntEquals (test, HASH_ENGINE_FINISH_FAILED, status);

	status = mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash, 0,
		MOCK_ARG (manifest.addr), MOCK_ARG_NOT_NULL, MOCK_ARG (MANIFEST_V2_HEADER_SIZE));
	status |= mock_expect_output (&manifest.flash.mock, 1, PFM_V2_SHA512.manifest.raw,
		PFM_V2_SHA512.manifest.length, 2);

	status |= mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash, 0,
		MOCK_ARG (manifest.addr + PFM_V2_SHA512.manifest.sig_offset), MOCK_ARG_NOT_NULL,
		MOCK_ARG (PFM_V2_SHA512.manifest.sig_len));
	status |= mock_expect_output (&manifest.flash.mock, 1, PFM_V2_SHA512.manifest.signature,
		PFM_V2_SHA512.manifest.sig_len, 2);

	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_get_signature (&manifest.test, sig_out, sizeof (sig_out));
	CuAssertIntEquals (test, PFM_V2_SHA512.manifest.sig_len, status);

	status = testing_validate_array (PFM_V2_SHA512.manifest.signature, sig_out, status);
	CuAssertIntEquals (test, 0, status);

	manifest_flash_v2_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_v2_test_get_signature_after_verify_bad_signature (CuTest *test)
{
	struct manifest_flash_v2_testing manifest;
	int status;
	uint8_t sig_out[PFM_V2_TWO_FW.manifest.sig_len];

	TEST_START;

	manifest_flash_v2_testing_init_and_verify (test, &manifest, 0x10000, PFM_MAGIC_NUM,
		PFM_V2_MAGIC_NUM, &PFM_V2.manifest, 0, false, 0);

	manifest_flash_v2_testing_verify_manifest (test, &manifest, &PFM_V2_TWO_FW.manifest,
		ECC_ENGINE_BAD_SIGNATURE);

	status = manifest_flash_verify (&manifest.test, &manifest.hash.base,
		&manifest.verification.base, NULL, 0);
	CuAssertIntEquals (test, ECC_ENGINE_BAD_SIGNATURE, status);

	status = mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash, 0,
		MOCK_ARG (manifest.addr), MOCK_ARG_NOT_NULL, MOCK_ARG (MANIFEST_V2_HEADER_SIZE));
	status |= mock_expect_output (&manifest.flash.mock, 1, PFM_V2_TWO_FW.manifest.raw,
		PFM_V2_TWO_FW.manifest.length, 2);

	status |= mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash, 0,
		MOCK_ARG (manifest.addr + PFM_V2_TWO_FW.manifest.sig_offset), MOCK_ARG_NOT_NULL,
		MOCK_ARG (PFM_V2_TWO_FW.manifest.sig_len));
	status |= mock_expect_output (&manifest.flash.mock, 1, PFM_V2_TWO_FW.manifest.signature,
		PFM_V2_TWO_FW.manifest.sig_len, 2);

	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_get_signature (&manifest.test, sig_out, sizeof (sig_out));
	CuAssertIntEquals (test, PFM_V2_TWO_FW.manifest.sig_len, status);

	status = testing_validate_array (PFM_V2_TWO_FW.manifest.signature, sig_out, status);
	CuAssertIntEquals (test, 0, status);

	manifest_flash_v2_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_v2_test_get_signature_null (CuTest *test)
{
	struct manifest_flash_v2_testing manifest;
	int status;
	uint8_t sig_out[PFM_V2.manifest.sig_len];

	TEST_START;

	manifest_flash_v2_testing_init_and_verify (test, &manifest, 0x10000, PFM_MAGIC_NUM,
		PFM_V2_MAGIC_NUM, &PFM_V2.manifest, 0, false, 0);

	status = manifest_flash_get_signature (NULL, sig_out, sizeof (sig_out));
	CuAssertIntEquals (test, MANIFEST_INVALID_ARGUMENT, status);

	status = manifest_flash_get_signature (&manifest.test, NULL, sizeof (sig_out));
	CuAssertIntEquals (test, MANIFEST_INVALID_ARGUMENT, status);

	manifest_flash_v2_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_v2_test_get_signature_small_sig_buffer (CuTest *test)
{
	struct manifest_flash_v2_testing manifest;
	int status;
	uint8_t sig_out[PFM_V2.manifest.sig_len - 1];

	TEST_START;

	manifest_flash_v2_testing_init_and_verify (test, &manifest, 0x10000, PFM_MAGIC_NUM,
		PFM_V2_MAGIC_NUM, &PFM_V2.manifest, 0, false, 0);

	status = manifest_flash_get_signature (&manifest.test, sig_out, sizeof (sig_out));
	CuAssertIntEquals (test, MANIFEST_SIG_BUFFER_TOO_SMALL, status);

	manifest_flash_v2_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_v2_test_get_signature_verify_never_run_small_sig_buffer (CuTest *test)
{
	struct manifest_flash_v2_testing manifest;
	int status;
	uint8_t sig_out[PFM_V2_SHA384.manifest.sig_len - 1];

	TEST_START;

	manifest_flash_v2_testing_init (test, &manifest, 0x10000, PFM_MAGIC_NUM, PFM_V2_MAGIC_NUM);

	status = mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash, 0,
		MOCK_ARG (manifest.addr), MOCK_ARG_NOT_NULL, MOCK_ARG (MANIFEST_V2_HEADER_SIZE));
	status |= mock_expect_output (&manifest.flash.mock, 1, PFM_V2_SHA384.manifest.raw,
		PFM_V2_SHA384.manifest.length, 2);

	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_get_signature (&manifest.test, sig_out, sizeof (sig_out));
	CuAssertIntEquals (test, MANIFEST_SIG_BUFFER_TOO_SMALL, status);

	manifest_flash_v2_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_v2_test_get_signature_header_read_error (CuTest *test)
{
	struct manifest_flash_v2_testing manifest;
	int status;
	uint8_t sig_out[PFM_V2.manifest.sig_len];

	TEST_START;

	manifest_flash_v2_testing_init (test, &manifest, 0x10000, PFM_MAGIC_NUM, PFM_V2_MAGIC_NUM);

	status = mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash,
		FLASH_READ_FAILED, MOCK_ARG (manifest.addr), MOCK_ARG_NOT_NULL,
		MOCK_ARG (MANIFEST_V2_HEADER_SIZE));

	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_get_signature (&manifest.test, sig_out, sizeof (sig_out));
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	manifest_flash_v2_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_v2_test_get_signature_bad_magic_number (CuTest *test)
{
	struct manifest_flash_v2_testing manifest;
	int status;
	struct manifest_header header;
	uint8_t sig_out[PFM_V2.manifest.sig_len];

	TEST_START;

	memcpy (&header, PFM_V2.manifest.raw, sizeof (header));
	header.magic ^= 0x55;

	manifest_flash_v2_testing_init (test, &manifest, 0x10000, PFM_MAGIC_NUM, PFM_V2_MAGIC_NUM);

	status = mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash, 0,
		MOCK_ARG (manifest.addr), MOCK_ARG_NOT_NULL, MOCK_ARG (MANIFEST_V2_HEADER_SIZE));
	status |= mock_expect_output (&manifest.flash.mock, 1, &header, sizeof (header), 2);

	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_get_signature (&manifest.test, sig_out, sizeof (sig_out));
	CuAssertIntEquals (test, MANIFEST_BAD_MAGIC_NUMBER, status);

	manifest_flash_v2_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_v2_test_get_signature_bad_magic_number_v1_unsupported (CuTest *test)
{
	struct manifest_flash_v2_testing manifest;
	int status;
	struct manifest_header header;
	uint8_t sig_out[PFM_V2.manifest.sig_len];

	TEST_START;

	memcpy (&header, PFM_V2.manifest.raw, sizeof (header));
	header.magic = MANIFEST_NOT_SUPPORTED;

	manifest_flash_v2_testing_init (test, &manifest, 0x10000, MANIFEST_NOT_SUPPORTED,
		PFM_V2_MAGIC_NUM);

	status = mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash, 0,
		MOCK_ARG (manifest.addr), MOCK_ARG_NOT_NULL, MOCK_ARG (MANIFEST_V2_HEADER_SIZE));
	status |= mock_expect_output (&manifest.flash.mock, 1, &header, sizeof (header), 2);

	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_get_signature (&manifest.test, sig_out, sizeof (sig_out));
	CuAssertIntEquals (test, MANIFEST_BAD_MAGIC_NUMBER, status);

	manifest_flash_v2_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_v2_test_get_signature_bad_magic_number_v2_unsupported (CuTest *test)
{
	struct manifest_flash_v2_testing manifest;
	int status;
	struct manifest_header header;
	uint8_t sig_out[PFM_V2.manifest.sig_len];

	TEST_START;

	memcpy (&header, PFM_V2.manifest.raw, sizeof (header));
	header.magic = MANIFEST_NOT_SUPPORTED;

	manifest_flash_v2_testing_init (test, &manifest, 0x10000, PFM_MAGIC_NUM,
		MANIFEST_NOT_SUPPORTED);

	status = mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash, 0,
		MOCK_ARG (manifest.addr), MOCK_ARG_NOT_NULL, MOCK_ARG (MANIFEST_V2_HEADER_SIZE));
	status |= mock_expect_output (&manifest.flash.mock, 1, &header, sizeof (header), 2);

	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_get_signature (&manifest.test, sig_out, sizeof (sig_out));
	CuAssertIntEquals (test, MANIFEST_BAD_MAGIC_NUMBER, status);

	manifest_flash_v2_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_v2_test_get_signature_sig_longer_than_manifest (CuTest *test)
{
	struct manifest_flash_v2_testing manifest;
	int status;
	struct manifest_header header;
	uint8_t sig_out[PFM_V2.manifest.sig_len];

	TEST_START;

	memcpy (&header, PFM_V2.manifest.raw, sizeof (header));
	header.sig_length = header.length + 1;

	manifest_flash_v2_testing_init (test, &manifest, 0x10000, PFM_MAGIC_NUM, PFM_V2_MAGIC_NUM);

	status = mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash, 0,
		MOCK_ARG (manifest.addr), MOCK_ARG_NOT_NULL, MOCK_ARG (MANIFEST_V2_HEADER_SIZE));
	status |= mock_expect_output (&manifest.flash.mock, 1, &header, sizeof (header), 2);

	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_get_signature (&manifest.test, sig_out, sizeof (sig_out));
	CuAssertIntEquals (test, MANIFEST_BAD_LENGTH, status);

	manifest_flash_v2_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_v2_test_get_signature_sig_same_length_as_manifest (CuTest *test)
{
	struct manifest_flash_v2_testing manifest;
	int status;
	struct manifest_header header;
	uint8_t sig_out[PFM_V2.manifest.sig_len];

	TEST_START;

	memcpy (&header, PFM_V2.manifest.raw, sizeof (header));
	header.sig_length = header.length;

	manifest_flash_v2_testing_init (test, &manifest, 0x10000, PFM_MAGIC_NUM, PFM_V2_MAGIC_NUM);

	status = mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash, 0,
		MOCK_ARG (manifest.addr), MOCK_ARG_NOT_NULL, MOCK_ARG (MANIFEST_V2_HEADER_SIZE));
	status |= mock_expect_output (&manifest.flash.mock, 1, &header, sizeof (header), 2);

	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_get_signature (&manifest.test, sig_out, sizeof (sig_out));
	CuAssertIntEquals (test, MANIFEST_BAD_LENGTH, status);

	manifest_flash_v2_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_v2_test_get_signature_sig_length_into_header (CuTest *test)
{
	struct manifest_flash_v2_testing manifest;
	int status;
	struct manifest_header header;
	uint8_t sig_out[PFM_V2.manifest.sig_len];

	TEST_START;

	memcpy (&header, PFM_V2.manifest.raw, sizeof (header));
	header.sig_length = (header.length - sizeof (header)) + 1;

	manifest_flash_v2_testing_init (test, &manifest, 0x10000, PFM_MAGIC_NUM, PFM_V2_MAGIC_NUM);

	status = mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash, 0,
		MOCK_ARG (manifest.addr), MOCK_ARG_NOT_NULL, MOCK_ARG (MANIFEST_V2_HEADER_SIZE));
	status |= mock_expect_output (&manifest.flash.mock, 1, &header, sizeof (header), 2);

	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_get_signature (&manifest.test, sig_out, sizeof (sig_out));
	CuAssertIntEquals (test, MANIFEST_BAD_LENGTH, status);

	manifest_flash_v2_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_v2_test_get_signature_read_error (CuTest *test)
{
	struct manifest_flash_v2_testing manifest;
	int status;
	uint8_t sig_out[PFM_V2_SHA384.manifest.sig_len];

	TEST_START;

	manifest_flash_v2_testing_init (test, &manifest, 0x10000, PFM_MAGIC_NUM, PFM_V2_MAGIC_NUM);

	status = mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash, 0,
		MOCK_ARG (manifest.addr), MOCK_ARG_NOT_NULL, MOCK_ARG (MANIFEST_V2_HEADER_SIZE));
	status |= mock_expect_output (&manifest.flash.mock, 1, PFM_V2_SHA384.manifest.raw,
		PFM_V2_SHA384.manifest.length, 2);

	status |= mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash,
		FLASH_READ_FAILED, MOCK_ARG (manifest.addr + PFM_V2_SHA384.manifest.sig_offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (PFM_V2_SHA384.manifest.sig_len));

	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_get_signature (&manifest.test, sig_out, sizeof (sig_out));
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	manifest_flash_v2_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_v2_test_read_element_data (CuTest *test)
{
	struct manifest_flash_v2_testing manifest;
	int status;
	uint8_t buffer[PFM_V2.manifest.plat_id_len];
	uint8_t *element = buffer;
	size_t total = 0;
	uint8_t format = 0xff;
	uint8_t found = 0xff;

	TEST_START;

	manifest_flash_v2_testing_init_and_verify (test, &manifest, 0x10000, PFM_MAGIC_NUM,
		PFM_V2_MAGIC_NUM, &PFM_V2.manifest, 0, false, 0);

	manifest_flash_v2_testing_read_element (test, &manifest, &PFM_V2.manifest,
		PFM_V2.manifest.plat_id_entry, 0, PFM_V2.manifest.plat_id_hash,
		PFM_V2.manifest.plat_id_offset, PFM_V2.manifest.plat_id_len, sizeof (buffer), 0);

	status = manifest_flash_read_element_data (&manifest.test, &manifest.hash.base,
		MANIFEST_PLATFORM_ID, 0, MANIFEST_NO_PARENT, 0, &found, &format, &total, &element,
		sizeof (buffer));
	CuAssertIntEquals (test, PFM_V2.manifest.plat_id_len, status);
	CuAssertIntEquals (test, PFM_V2.manifest.plat_id_entry, found);
	CuAssertIntEquals (test, 1, format);
	CuAssertIntEquals (test, PFM_V2.manifest.plat_id_len, total);

	status = testing_validate_array (PFM_V2.manifest.plat_id, buffer, status);
	CuAssertIntEquals (test, 0, status);

	manifest_flash_v2_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_v2_test_read_element_data_no_found_output (CuTest *test)
{
	struct manifest_flash_v2_testing manifest;
	int status;
	uint8_t buffer[PFM_V2.manifest.plat_id_len];
	uint8_t *element = buffer;
	size_t total = 0;
	uint8_t format = 0xff;

	TEST_START;

	manifest_flash_v2_testing_init_and_verify (test, &manifest, 0x10000, PFM_MAGIC_NUM,
		PFM_V2_MAGIC_NUM, &PFM_V2.manifest, 0, false, 0);

	manifest_flash_v2_testing_read_element (test, &manifest, &PFM_V2.manifest,
		PFM_V2.manifest.plat_id_entry, 0, PFM_V2.manifest.plat_id_hash,
		PFM_V2.manifest.plat_id_offset, PFM_V2.manifest.plat_id_len, sizeof (buffer), 0);

	status = manifest_flash_read_element_data (&manifest.test, &manifest.hash.base,
		MANIFEST_PLATFORM_ID, 0, MANIFEST_NO_PARENT, 0, NULL, &format, &total, &element,
		sizeof (buffer));
	CuAssertIntEquals (test, PFM_V2.manifest.plat_id_len, status);
	CuAssertIntEquals (test, 1, format);
	CuAssertIntEquals (test, PFM_V2.manifest.plat_id_len, total);

	status = testing_validate_array (PFM_V2.manifest.plat_id, buffer, status);
	CuAssertIntEquals (test, 0, status);

	manifest_flash_v2_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_v2_test_read_element_data_no_format_output (CuTest *test)
{
	struct manifest_flash_v2_testing manifest;
	int status;
	uint8_t buffer[PFM_V2.manifest.plat_id_len];
	uint8_t *element = buffer;
	size_t total = 0;
	uint8_t found = 0xff;

	TEST_START;

	manifest_flash_v2_testing_init_and_verify (test, &manifest, 0x10000, PFM_MAGIC_NUM,
		PFM_V2_MAGIC_NUM, &PFM_V2.manifest, 0, false, 0);

	manifest_flash_v2_testing_read_element (test, &manifest, &PFM_V2.manifest,
		PFM_V2.manifest.plat_id_entry, 0, PFM_V2.manifest.plat_id_hash,
		PFM_V2.manifest.plat_id_offset, PFM_V2.manifest.plat_id_len, sizeof (buffer), 0);

	status = manifest_flash_read_element_data (&manifest.test, &manifest.hash.base,
		MANIFEST_PLATFORM_ID, 0, MANIFEST_NO_PARENT, 0, &found, NULL, &total, &element,
		sizeof (buffer));
	CuAssertIntEquals (test, PFM_V2.manifest.plat_id_len, status);
	CuAssertIntEquals (test, PFM_V2.manifest.plat_id_entry, found);
	CuAssertIntEquals (test, PFM_V2.manifest.plat_id_len, total);

	status = testing_validate_array (PFM_V2.manifest.plat_id, buffer, status);
	CuAssertIntEquals (test, 0, status);

	manifest_flash_v2_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_v2_test_read_element_data_no_total_length_output (CuTest *test)
{
	struct manifest_flash_v2_testing manifest;
	int status;
	uint8_t buffer[PFM_V2.manifest.plat_id_len];
	uint8_t *element = buffer;
	uint8_t format = 0xff;
	uint8_t found = 0xff;

	TEST_START;

	manifest_flash_v2_testing_init_and_verify (test, &manifest, 0x10000, PFM_MAGIC_NUM,
		PFM_V2_MAGIC_NUM, &PFM_V2.manifest, 0, false, 0);

	manifest_flash_v2_testing_read_element (test, &manifest, &PFM_V2.manifest,
		PFM_V2.manifest.plat_id_entry, 0, PFM_V2.manifest.plat_id_hash,
		PFM_V2.manifest.plat_id_offset, PFM_V2.manifest.plat_id_len, sizeof (buffer), 0);

	status = manifest_flash_read_element_data (&manifest.test, &manifest.hash.base,
		MANIFEST_PLATFORM_ID, 0, MANIFEST_NO_PARENT, 0, &found, &format, NULL, &element,
		sizeof (buffer));
	CuAssertIntEquals (test, PFM_V2.manifest.plat_id_len, status);
	CuAssertIntEquals (test, PFM_V2.manifest.plat_id_entry, found);
	CuAssertIntEquals (test, 1, format);

	status = testing_validate_array (PFM_V2.manifest.plat_id, buffer, status);
	CuAssertIntEquals (test, 0, status);

	manifest_flash_v2_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_v2_test_read_element_data_dynamic_allocation (CuTest *test)
{
	struct manifest_flash_v2_testing manifest;
	int status;
	uint8_t *element = NULL;
	size_t total = 0;
	uint8_t format = 0xff;
	uint8_t found = 0xff;

	TEST_START;

	manifest_flash_v2_testing_init_and_verify (test, &manifest, 0x10000, PFM_MAGIC_NUM,
		PFM_V2_MAGIC_NUM, &PFM_V2.manifest, 0, false, 0);

	manifest_flash_v2_testing_read_element (test, &manifest, &PFM_V2.manifest,
		PFM_V2.manifest.plat_id_entry, 0, PFM_V2.manifest.plat_id_hash,
		PFM_V2.manifest.plat_id_offset, PFM_V2.manifest.plat_id_len, PFM_V2.manifest.plat_id_len,
		0);

	status = manifest_flash_read_element_data (&manifest.test, &manifest.hash.base,
		MANIFEST_PLATFORM_ID, 0, MANIFEST_NO_PARENT, 0, &found, &format, &total, &element, 0);
	CuAssertIntEquals (test, PFM_V2.manifest.plat_id_len, status);
	CuAssertIntEquals (test, PFM_V2.manifest.plat_id_entry, found);
	CuAssertIntEquals (test, 1, format);
	CuAssertIntEquals (test, PFM_V2.manifest.plat_id_len, total);
	CuAssertPtrNotNull (test, element);

	status = testing_validate_array (PFM_V2.manifest.plat_id, element, status);
	CuAssertIntEquals (test, 0, status);

	platform_free (element);

	manifest_flash_v2_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_v2_test_read_element_data_with_mock_hash (CuTest *test)
{
	struct manifest_flash_v2_testing manifest;
	int status;
	uint8_t buffer[PFM_V2.manifest.plat_id_len];
	uint8_t *element = buffer;
	size_t total = 0;
	uint8_t format = 0xff;
	uint8_t found = 0xff;

	TEST_START;

	manifest_flash_v2_testing_init_and_verify (test, &manifest, 0x10000, PFM_MAGIC_NUM,
		PFM_V2_MAGIC_NUM, &PFM_V2.manifest, 0, false, 0);

	manifest_flash_v2_testing_read_element_mocked_hash (test, &manifest, &PFM_V2.manifest,
		PFM_V2.manifest.plat_id_entry, 0, PFM_V2.manifest.plat_id_hash,
		PFM_V2.manifest.plat_id_offset, PFM_V2.manifest.plat_id_len, sizeof (buffer), 0);

	status = manifest_flash_read_element_data (&manifest.test, &manifest.hash_mock.base,
		MANIFEST_PLATFORM_ID, 0, MANIFEST_NO_PARENT, 0, &found, &format, &total, &element,
		sizeof (buffer));
	CuAssertIntEquals (test, PFM_V2.manifest.plat_id_len, status);
	CuAssertIntEquals (test, PFM_V2.manifest.plat_id_entry, found);
	CuAssertIntEquals (test, 1, format);
	CuAssertIntEquals (test, PFM_V2.manifest.plat_id_len, total);

	status = testing_validate_array (PFM_V2.manifest.plat_id, buffer, status);
	CuAssertIntEquals (test, 0, status);

	manifest_flash_v2_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_v2_test_read_element_data_first_element (CuTest *test)
{
	struct manifest_flash_v2_testing manifest;
	int status;
	uint8_t buffer[PFM_V2_PLAT_FIRST.manifest.plat_id_len];
	uint8_t *element = buffer;
	size_t total = 0;
	uint8_t format = 0xff;
	uint8_t found = 0xff;

	TEST_START;

	manifest_flash_v2_testing_init_and_verify (test, &manifest, 0x10000, PFM_MAGIC_NUM,
		PFM_V2_MAGIC_NUM, &PFM_V2_PLAT_FIRST.manifest, 0, false, 0);

	manifest_flash_v2_testing_read_element (test, &manifest, &PFM_V2_PLAT_FIRST.manifest,
		PFM_V2_PLAT_FIRST.manifest.plat_id_entry, 0, PFM_V2_PLAT_FIRST.manifest.plat_id_hash,
		PFM_V2_PLAT_FIRST.manifest.plat_id_offset, PFM_V2_PLAT_FIRST.manifest.plat_id_len,
		sizeof (buffer), 0);

	status = manifest_flash_read_element_data (&manifest.test, &manifest.hash.base,
		MANIFEST_PLATFORM_ID, 0, MANIFEST_NO_PARENT, 0, &found, &format, &total, &element,
		sizeof (buffer));
	CuAssertIntEquals (test, PFM_V2_PLAT_FIRST.manifest.plat_id_len, status);
	CuAssertIntEquals (test, PFM_V2_PLAT_FIRST.manifest.plat_id_entry, found);
	CuAssertIntEquals (test, 1, format);
	CuAssertIntEquals (test, PFM_V2_PLAT_FIRST.manifest.plat_id_len, total);

	status = testing_validate_array (PFM_V2_PLAT_FIRST.manifest.plat_id, buffer, status);
	CuAssertIntEquals (test, 0, status);

	manifest_flash_v2_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_v2_test_read_element_data_first_element_hash (CuTest *test)
{
	struct manifest_flash_v2_testing manifest;
	int status;
	uint8_t buffer[PFM_V2_PLAT_FIRST.flash_dev_len];
	uint8_t *element = buffer;
	size_t total = 0;
	uint8_t format = 0xff;
	uint8_t found = 0xff;

	TEST_START;

	manifest_flash_v2_testing_init_and_verify (test, &manifest, 0x10000, PFM_MAGIC_NUM,
		PFM_V2_MAGIC_NUM, &PFM_V2_PLAT_FIRST.manifest, 0, false, 0);

	manifest_flash_v2_testing_read_element (test, &manifest, &PFM_V2_PLAT_FIRST.manifest,
		PFM_V2_PLAT_FIRST.flash_dev_entry, 0, PFM_V2_PLAT_FIRST.flash_dev_hash,
		PFM_V2_PLAT_FIRST.flash_dev_offset, PFM_V2_PLAT_FIRST.flash_dev_len, sizeof (buffer), 0);

	status = manifest_flash_read_element_data (&manifest.test, &manifest.hash.base,
		PFM_FLASH_DEVICE, 0, MANIFEST_NO_PARENT, 0, &found, &format, &total, &element,
		sizeof (buffer));
	CuAssertIntEquals (test, PFM_V2_PLAT_FIRST.flash_dev_len, status);
	CuAssertIntEquals (test, PFM_V2_PLAT_FIRST.flash_dev_entry, found);
	CuAssertIntEquals (test, 0, format);
	CuAssertIntEquals (test, PFM_V2_PLAT_FIRST.flash_dev_len, total);

	status = testing_validate_array (PFM_V2_PLAT_FIRST.flash_dev, buffer, status);
	CuAssertIntEquals (test, 0, status);

	manifest_flash_v2_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_v2_test_read_element_data_with_start_offset (CuTest *test)
{
	struct manifest_flash_v2_testing manifest;
	int status;
	uint8_t buffer[PFM_V2_TWO_FW.manifest.plat_id_len];
	uint8_t *element = buffer;
	size_t total = 0;
	uint8_t format = 0xff;
	uint8_t found = 0xff;

	TEST_START;

	manifest_flash_v2_testing_init_and_verify (test, &manifest, 0x10000, PFM_MAGIC_NUM,
		PFM_V2_MAGIC_NUM, &PFM_V2_TWO_FW.manifest, 0, false, 0);

	manifest_flash_v2_testing_read_element (test, &manifest, &PFM_V2_TWO_FW.manifest,
		PFM_V2_TWO_FW.manifest.plat_id_entry, PFM_V2_TWO_FW.manifest.plat_id_entry,
		PFM_V2_TWO_FW.manifest.plat_id_hash, PFM_V2_TWO_FW.manifest.plat_id_offset,
		PFM_V2_TWO_FW.manifest.plat_id_len, sizeof (buffer), 0);

	status = manifest_flash_read_element_data (&manifest.test, &manifest.hash.base,
		MANIFEST_PLATFORM_ID, PFM_V2_TWO_FW.manifest.plat_id_entry, MANIFEST_NO_PARENT, 0, &found,
		&format, &total, &element, sizeof (buffer));
	CuAssertIntEquals (test, PFM_V2_TWO_FW.manifest.plat_id_len, status);
	CuAssertIntEquals (test, PFM_V2_TWO_FW.manifest.plat_id_entry, found);
	CuAssertIntEquals (test, 1, format);
	CuAssertIntEquals (test, PFM_V2_TWO_FW.manifest.plat_id_len, total);

	status = testing_validate_array (PFM_V2_TWO_FW.manifest.plat_id, buffer, status);
	CuAssertIntEquals (test, 0, status);

	manifest_flash_v2_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_v2_test_read_element_data_no_hash (CuTest *test)
{
	struct manifest_flash_v2_testing manifest;
	int status;
	uint8_t buffer[PFM_V2_NO_TOC_HASHES.manifest.plat_id_len];
	uint8_t *element = buffer;
	size_t total = 0;
	uint8_t format = 0xff;
	uint8_t found = 0xff;

	TEST_START;

	manifest_flash_v2_testing_init_and_verify (test, &manifest, 0x10000, PFM_MAGIC_NUM,
		PFM_V2_MAGIC_NUM, &PFM_V2_NO_TOC_HASHES.manifest, 0, false, 0);

	manifest_flash_v2_testing_read_element (test, &manifest, &PFM_V2_NO_TOC_HASHES.manifest,
		PFM_V2_NO_TOC_HASHES.manifest.plat_id_entry, 0, PFM_V2_NO_TOC_HASHES.manifest.plat_id_hash,
		PFM_V2_NO_TOC_HASHES.manifest.plat_id_offset, PFM_V2_NO_TOC_HASHES.manifest.plat_id_len,
		sizeof (buffer), 0);

	status = manifest_flash_read_element_data (&manifest.test, &manifest.hash.base,
		MANIFEST_PLATFORM_ID, 0, MANIFEST_NO_PARENT, 0, &found, &format, &total, &element,
		sizeof (buffer));
	CuAssertIntEquals (test, PFM_V2_NO_TOC_HASHES.manifest.plat_id_len, status);
	CuAssertIntEquals (test, PFM_V2_NO_TOC_HASHES.manifest.plat_id_entry, found);
	CuAssertIntEquals (test, 1, format);
	CuAssertIntEquals (test, PFM_V2_NO_TOC_HASHES.manifest.plat_id_len, total);

	status = testing_validate_array (PFM_V2_NO_TOC_HASHES.manifest.plat_id, buffer, status);
	CuAssertIntEquals (test, 0, status);

	manifest_flash_v2_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_v2_test_read_element_data_no_hash_invalid_id (CuTest *test)
{
	struct manifest_flash_v2_testing manifest;
	int status;
	uint8_t buffer[PFM_V2_NO_FW_HASHES.fw[0].fw_len];
	uint8_t *element = buffer;
	size_t total = 0;
	uint8_t format = 0xff;
	uint8_t found = 0xff;

	TEST_START;

	manifest_flash_v2_testing_init_and_verify (test, &manifest, 0x10000, PFM_MAGIC_NUM,
		PFM_V2_MAGIC_NUM, &PFM_V2_NO_FW_HASHES.manifest, 0, false, 0);

	manifest_flash_v2_testing_read_element (test, &manifest, &PFM_V2_NO_FW_HASHES.manifest,
		PFM_V2_NO_FW_HASHES.fw[0].fw_entry, 0, PFM_V2_NO_FW_HASHES.fw[0].fw_hash,
		PFM_V2_NO_FW_HASHES.fw[0].fw_offset, PFM_V2_NO_FW_HASHES.fw[0].fw_len, sizeof (buffer), 0);

	status = manifest_flash_read_element_data (&manifest.test, &manifest.hash.base,
		PFM_FIRMWARE, 0, MANIFEST_NO_PARENT, 0, &found, &format, &total, &element, sizeof (buffer));
	CuAssertIntEquals (test, PFM_V2_NO_FW_HASHES.fw[0].fw_len, status);
	CuAssertIntEquals (test, PFM_V2_NO_FW_HASHES.fw[0].fw_entry, found);
	CuAssertIntEquals (test, 1, format);
	CuAssertIntEquals (test, PFM_V2_NO_FW_HASHES.fw[0].fw_len, total);

	status = testing_validate_array (PFM_V2_NO_FW_HASHES.fw[0].fw, buffer, status);
	CuAssertIntEquals (test, 0, status);

	manifest_flash_v2_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_v2_test_read_element_data_with_parent (CuTest *test)
{
	struct manifest_flash_v2_testing manifest;
	int status;
	uint8_t buffer[PFM_V2.fw[0].version[0].fw_version_len];
	uint8_t *element = buffer;
	size_t total = 0;
	uint8_t format = 0xff;
	uint8_t found = 0xff;

	TEST_START;

	manifest_flash_v2_testing_init_and_verify (test, &manifest, 0x10000, PFM_MAGIC_NUM,
		PFM_V2_MAGIC_NUM, &PFM_V2.manifest, 0, false, 0);

	manifest_flash_v2_testing_read_element (test, &manifest, &PFM_V2.manifest,
		PFM_V2.fw[0].version[0].fw_version_entry, PFM_V2.fw[0].version[0].fw_version_entry,
		PFM_V2.fw[0].version[0].fw_version_hash, PFM_V2.fw[0].version[0].fw_version_offset,
		PFM_V2.fw[0].version[0].fw_version_len, sizeof (buffer), 0);

	status = manifest_flash_read_element_data (&manifest.test, &manifest.hash.base,
		PFM_FIRMWARE_VERSION, PFM_V2.fw[0].version[0].fw_version_entry, PFM_FIRMWARE, 0, &found,
		&format, &total, &element, sizeof (buffer));
	CuAssertIntEquals (test, PFM_V2.fw[0].version[0].fw_version_len, status);
	CuAssertIntEquals (test, PFM_V2.fw[0].version[0].fw_version_entry, found);
	CuAssertIntEquals (test, 1, format);
	CuAssertIntEquals (test, PFM_V2.fw[0].version[0].fw_version_len, total);

	status = testing_validate_array (PFM_V2.fw[0].version[0].fw_version, buffer, status);
	CuAssertIntEquals (test, 0, status);

	manifest_flash_v2_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_v2_test_read_element_data_second_element_instance (CuTest *test)
{
	struct manifest_flash_v2_testing manifest;
	int status;
	uint8_t buffer[PFM_V2_TWO_FW.fw[1].fw_len];
	uint8_t *element = buffer;
	size_t total = 0;
	uint8_t format = 0xff;
	uint8_t found = 0xff;

	TEST_START;

	manifest_flash_v2_testing_init_and_verify (test, &manifest, 0x10000, PFM_MAGIC_NUM,
		PFM_V2_MAGIC_NUM, &PFM_V2_TWO_FW.manifest, 0, false, 0);

	manifest_flash_v2_testing_read_element (test, &manifest, &PFM_V2_TWO_FW.manifest,
		PFM_V2_TWO_FW.fw[1].fw_entry, PFM_V2_TWO_FW.fw[0].fw_entry + 1, PFM_V2_TWO_FW.fw[1].fw_hash,
		PFM_V2_TWO_FW.fw[1].fw_offset, PFM_V2_TWO_FW.fw[1].fw_len, sizeof (buffer), 0);

	status = manifest_flash_read_element_data (&manifest.test, &manifest.hash.base,
		PFM_FIRMWARE, PFM_V2_TWO_FW.fw[0].fw_entry + 1, MANIFEST_NO_PARENT, 0, &found, &format,
		&total, &element, sizeof (buffer));
	CuAssertIntEquals (test, PFM_V2_TWO_FW.fw[1].fw_len, status);
	CuAssertIntEquals (test, PFM_V2_TWO_FW.fw[1].fw_entry, found);
	CuAssertIntEquals (test, 1, format);
	CuAssertIntEquals (test, PFM_V2_TWO_FW.fw[1].fw_len, total);

	status = testing_validate_array (PFM_V2_TWO_FW.fw[1].fw, buffer, status);
	CuAssertIntEquals (test, 0, status);

	manifest_flash_v2_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_v2_test_read_element_data_partial_element (CuTest *test)
{
	struct manifest_flash_v2_testing manifest;
	int status;
	uint8_t buffer[PFM_V2.manifest.plat_id_len - 1];
	uint8_t *element = buffer;
	size_t total = 0;
	uint8_t format = 0xff;
	uint8_t found = 0xff;

	TEST_START;

	manifest_flash_v2_testing_init_and_verify (test, &manifest, 0x10000, PFM_MAGIC_NUM,
		PFM_V2_MAGIC_NUM, &PFM_V2.manifest, 0, false, 0);

	manifest_flash_v2_testing_read_element (test, &manifest, &PFM_V2.manifest,
		PFM_V2.manifest.plat_id_entry, 0, PFM_V2.manifest.plat_id_hash,
		PFM_V2.manifest.plat_id_offset, PFM_V2.manifest.plat_id_len, sizeof (buffer), 0);

	status = manifest_flash_read_element_data (&manifest.test, &manifest.hash.base,
		MANIFEST_PLATFORM_ID, 0, MANIFEST_NO_PARENT, 0, &found, &format, &total, &element,
		sizeof (buffer));
	CuAssertIntEquals (test, sizeof (buffer), status);
	CuAssertIntEquals (test, PFM_V2.manifest.plat_id_entry, found);
	CuAssertIntEquals (test, 1, format);
	CuAssertIntEquals (test, PFM_V2.manifest.plat_id_len, total);

	status = testing_validate_array (PFM_V2.manifest.plat_id, buffer, status);
	CuAssertIntEquals (test, 0, status);

	manifest_flash_v2_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_v2_test_read_element_data_partial_element_no_hash (CuTest *test)
{
	struct manifest_flash_v2_testing manifest;
	int status;
	uint8_t buffer[PFM_V2_NO_TOC_HASHES.manifest.plat_id_len - 1];
	uint8_t *element = buffer;
	size_t total = 0;
	uint8_t format = 0xff;
	uint8_t found = 0xff;

	TEST_START;

	manifest_flash_v2_testing_init_and_verify (test, &manifest, 0x10000, PFM_MAGIC_NUM,
		PFM_V2_MAGIC_NUM, &PFM_V2_NO_TOC_HASHES.manifest, 0, false, 0);

	manifest_flash_v2_testing_read_element (test, &manifest, &PFM_V2_NO_TOC_HASHES.manifest,
		PFM_V2_NO_TOC_HASHES.manifest.plat_id_entry, 0, PFM_V2_NO_TOC_HASHES.manifest.plat_id_hash,
		PFM_V2_NO_TOC_HASHES.manifest.plat_id_offset, PFM_V2_NO_TOC_HASHES.manifest.plat_id_len,
		sizeof (buffer), 0);

	status = manifest_flash_read_element_data (&manifest.test, &manifest.hash.base,
		MANIFEST_PLATFORM_ID, 0, MANIFEST_NO_PARENT, 0, &found, &format, &total, &element,
		sizeof (buffer));
	CuAssertIntEquals (test, sizeof (buffer), status);
	CuAssertIntEquals (test, PFM_V2_NO_TOC_HASHES.manifest.plat_id_entry, found);
	CuAssertIntEquals (test, 1, format);
	CuAssertIntEquals (test, PFM_V2_NO_TOC_HASHES.manifest.plat_id_len, total);

	status = testing_validate_array (PFM_V2_NO_TOC_HASHES.manifest.plat_id, buffer, status);
	CuAssertIntEquals (test, 0, status);

	manifest_flash_v2_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_v2_test_read_element_data_large_buffer (CuTest *test)
{
	struct manifest_flash_v2_testing manifest;
	int status;
	uint8_t buffer[PFM_V2.manifest.plat_id_len + 1];
	uint8_t *element = buffer;
	size_t total = 0;
	uint8_t format = 0xff;
	uint8_t found = 0xff;

	TEST_START;

	manifest_flash_v2_testing_init_and_verify (test, &manifest, 0x10000, PFM_MAGIC_NUM,
		PFM_V2_MAGIC_NUM, &PFM_V2.manifest, 0, false, 0);

	manifest_flash_v2_testing_read_element (test, &manifest, &PFM_V2.manifest,
		PFM_V2.manifest.plat_id_entry, 0, PFM_V2.manifest.plat_id_hash,
		PFM_V2.manifest.plat_id_offset, PFM_V2.manifest.plat_id_len, PFM_V2.manifest.plat_id_len,
		0);

	status = manifest_flash_read_element_data (&manifest.test, &manifest.hash.base,
		MANIFEST_PLATFORM_ID, 0, MANIFEST_NO_PARENT, 0, &found, &format, &total, &element,
		sizeof (buffer));
	CuAssertIntEquals (test, PFM_V2.manifest.plat_id_len, status);
	CuAssertIntEquals (test, PFM_V2.manifest.plat_id_entry, found);
	CuAssertIntEquals (test, 1, format);
	CuAssertIntEquals (test, PFM_V2.manifest.plat_id_len, total);

	status = testing_validate_array (PFM_V2.manifest.plat_id, buffer, status);
	CuAssertIntEquals (test, 0, status);

	manifest_flash_v2_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_v2_test_read_element_data_max_entry_and_hash (CuTest *test)
{
	struct manifest_flash_v2_testing manifest;
	int status;
	uint8_t buffer[PFM_V2.manifest.plat_id_len + 1];
	uint8_t *element = buffer;
	size_t total = 0;
	uint8_t format = 0xff;
	uint8_t found = 0xff;
	union {
		struct {
			struct manifest_toc_entry entries[0xff];
			uint8_t hashes[0xff][SHA256_HASH_LENGTH];
		} data;
		uint8_t raw[(MANIFEST_V2_TOC_ENTRY_SIZE + SHA256_HASH_LENGTH) * 0xff];
	} toc;
	uint8_t data[PFM_V2.manifest.plat_id_len + PFM_V2.flash_dev_len];
	size_t toc_len = MANIFEST_V2_TOC_HEADER_SIZE + sizeof (toc) + SHA256_HASH_LENGTH;
	size_t sig_len = RSA_KEY_LENGTH_2K;
	uint32_t sig_offset = MANIFEST_V2_HEADER_SIZE + toc_len + sizeof (data);
	struct manifest_header header = {
		.length = sig_offset + sig_len,
		.magic = PFM_V2_MAGIC_NUM,
		.id = 100,
		.sig_length = sig_len,
		.sig_type = 0,
		.reserved = 0
	};
	struct manifest_toc_header toc_header = {
		.entry_count = 0xff,
		.hash_count = 0xff,
		.hash_type = 0,
		.reserved = 0,
	};
	uint32_t toc_entry_offset = MANIFEST_V2_TOC_ENTRY_OFFSET;
	const uint8_t *plat_id = data + MANIFEST_V2_PLATFORM_HEADER_SIZE;
	uint32_t validate_toc_start = toc_entry_offset;
	uint32_t toc_hash_offset = MANIFEST_V2_HEADER_SIZE + toc_len - SHA256_HASH_LENGTH;
	uint32_t plat_id_offset = MANIFEST_V2_HEADER_SIZE + toc_len;
	uint32_t fw_offset = plat_id_offset + PFM_V2.manifest.plat_id_len;
	uint32_t validate_resume =
		plat_id_offset + MANIFEST_V2_PLATFORM_HEADER_SIZE + PFM_V2.manifest.plat_id_str_len;
	uint32_t last_entry = toc_entry_offset + (MANIFEST_V2_TOC_ENTRY_SIZE * 0xff);
	uint32_t hash_offset = last_entry + (SHA256_HASH_LENGTH * 0xfe);
	int i;

	TEST_START;

	/* Fill the manifest data. */
	memcpy (data, PFM_V2.manifest.plat_id, PFM_V2.manifest.plat_id_len);
	memcpy (&data[PFM_V2.manifest.plat_id_len], PFM_V2.flash_dev, PFM_V2.flash_dev_len);

	/* Fill the TOC with entries and hashes. */
	for (i = 0; i < 0xff; i++) {
		if (i == 0xfe) {
			memcpy (&toc.data.entries[i],
				PFM_V2.manifest.raw + toc_entry_offset +
					(MANIFEST_V2_TOC_ENTRY_SIZE * PFM_V2.manifest.plat_id_entry),
				MANIFEST_V2_TOC_ENTRY_SIZE);
			toc.data.entries[i].offset = plat_id_offset;
			toc.data.entries[i].format = 0xaa;
		}
		else {
			memcpy (&toc.data.entries[i], &PFM_V2.manifest.raw[toc_entry_offset],
				MANIFEST_V2_TOC_ENTRY_SIZE);
			toc.data.entries[i].offset = fw_offset;
			toc.data.entries[i].format = 0x60;
		}
		toc.data.entries[i].hash_id = i;

		memcpy (toc.data.hashes[i], &PFM_V2.manifest.toc_hash, SHA256_HASH_LENGTH);
		toc.data.hashes[i][0] ^= 0x55;
		toc.data.hashes[i][1] = i;
	}

	manifest_flash_v2_testing_init (test, &manifest, 0x10000, PFM_MAGIC_NUM, PFM_V2_MAGIC_NUM);

	/* Manifest verification. */
	status = mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash, 0,
		MOCK_ARG (manifest.addr), MOCK_ARG_NOT_NULL, MOCK_ARG (MANIFEST_V2_HEADER_SIZE));
	status |= mock_expect_output (&manifest.flash.mock, 1, &header, sizeof (header), 2);

	status |= mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash, 0,
		MOCK_ARG (manifest.addr + sig_offset), MOCK_ARG_NOT_NULL, MOCK_ARG (sig_len));
	status |= mock_expect_output (&manifest.flash.mock, 1, PFM_V2.manifest.signature, sig_len, 2);

	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.start_sha256,
		&manifest.hash_mock, 0);

	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.update,
		&manifest.hash_mock, 0, MOCK_ARG_PTR_CONTAINS (&header, MANIFEST_V2_HEADER_SIZE),
		MOCK_ARG (MANIFEST_V2_HEADER_SIZE));

	status |= mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash, 0,
		MOCK_ARG (manifest.addr + MANIFEST_V2_TOC_HDR_OFFSET), MOCK_ARG_NOT_NULL,
		MOCK_ARG (MANIFEST_V2_TOC_HEADER_SIZE));
	status |= mock_expect_output (&manifest.flash.mock, 1, &toc_header, sizeof (toc_header), 2);

	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.update,
		&manifest.hash_mock, 0, MOCK_ARG_PTR_CONTAINS (&toc_header, MANIFEST_V2_TOC_HEADER_SIZE),
		MOCK_ARG (MANIFEST_V2_TOC_HEADER_SIZE));

	for (i = 0; i <= 0xfe; i++, validate_toc_start += MANIFEST_V2_TOC_ENTRY_SIZE) {
		status |= mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash,
			0, MOCK_ARG (manifest.addr + toc_entry_offset + (i * MANIFEST_V2_TOC_ENTRY_SIZE)),
			MOCK_ARG_NOT_NULL, MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));
		status |= mock_expect_output (&manifest.flash.mock, 1, &toc.data.entries[i],
			MANIFEST_V2_TOC_ENTRY_SIZE, 2);

		status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.update,
			&manifest.hash_mock, 0,
			MOCK_ARG_PTR_CONTAINS (&toc.data.entries[i], MANIFEST_V2_TOC_ENTRY_SIZE),
			MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));
	}

	status |= flash_mock_expect_verify_flash_and_hash (&manifest.flash, &manifest.hash_mock,
		manifest.addr + validate_toc_start, toc.raw + (validate_toc_start - toc_entry_offset),
		toc_hash_offset - validate_toc_start);

	status |= mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash, 0,
		MOCK_ARG (manifest.addr + toc_hash_offset), MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&manifest.flash.mock, 1, PFM_V2.manifest.toc_hash,
		SHA256_HASH_LENGTH, 2);

	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.update,
		&manifest.hash_mock, 0,
		MOCK_ARG_PTR_CONTAINS (PFM_V2.manifest.toc_hash, SHA256_HASH_LENGTH),
		MOCK_ARG (SHA256_HASH_LENGTH));

	status |= mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash, 0,
		MOCK_ARG (manifest.addr + plat_id_offset), MOCK_ARG_NOT_NULL,
		MOCK_ARG (MANIFEST_V2_PLATFORM_HEADER_SIZE));
	status |= mock_expect_output (&manifest.flash.mock, 1, data, sizeof (data), 2);

	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.update,
		&manifest.hash_mock, 0, MOCK_ARG_PTR_CONTAINS (data, MANIFEST_V2_PLATFORM_HEADER_SIZE),
		MOCK_ARG (MANIFEST_V2_PLATFORM_HEADER_SIZE));

	status |= mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash, 0,
		MOCK_ARG (manifest.addr + plat_id_offset + MANIFEST_V2_PLATFORM_HEADER_SIZE),
		MOCK_ARG_NOT_NULL, MOCK_ARG (PFM_V2.manifest.plat_id_str_len));
	status |= mock_expect_output (&manifest.flash.mock, 1, plat_id, PFM_V2.manifest.plat_id_len, 2);

	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.update,
		&manifest.hash_mock, 0, MOCK_ARG_PTR_CONTAINS (plat_id, PFM_V2.manifest.plat_id_str_len),
		MOCK_ARG (PFM_V2.manifest.plat_id_str_len));

	status |= flash_mock_expect_verify_flash_and_hash (&manifest.flash, &manifest.hash_mock,
		manifest.addr + validate_resume, data + validate_resume - plat_id_offset,
		sig_offset - validate_resume);

	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.finish,
		&manifest.hash_mock, 0, MOCK_ARG_NOT_NULL, MOCK_ARG_ANY);
	status |= mock_expect_output (&manifest.hash_mock.mock, 0, PFM_V2.manifest.hash,
		SHA256_HASH_LENGTH, 1);

	status |= mock_expect (&manifest.verification.mock,
		manifest.verification.base.verify_signature, &manifest.verification, 0,
		MOCK_ARG_PTR_CONTAINS (PFM_V2.manifest.hash, SHA256_HASH_LENGTH),
		MOCK_ARG (SHA256_HASH_LENGTH),
		MOCK_ARG_PTR_CONTAINS (PFM_V2.manifest.signature, sig_len), MOCK_ARG (sig_len));

	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_verify (&manifest.test, &manifest.hash_mock.base,
		&manifest.verification.base, NULL, 0);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&manifest.flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&manifest.hash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&manifest.verification.mock);
	CuAssertIntEquals (test, 0, status);

	/* Start hashing the table of contents data. */
	status = mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.start_sha256,
		&manifest.hash_mock, 0);

	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.update,
		&manifest.hash_mock, 0, MOCK_ARG_PTR_CONTAINS (&toc_header, MANIFEST_V2_TOC_HEADER_SIZE),
		MOCK_ARG (MANIFEST_V2_TOC_HEADER_SIZE));

	/* Find the desired TOC entry. */
	for (i = 0; i <= 0xfe; i++) {
		status |= mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash,
			0, MOCK_ARG (manifest.addr + toc_entry_offset + (i * MANIFEST_V2_TOC_ENTRY_SIZE)),
			MOCK_ARG_NOT_NULL, MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));
		status |= mock_expect_output (&manifest.flash.mock, 1, &toc.data.entries[i],
			MANIFEST_V2_TOC_ENTRY_SIZE, 2);

		status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.update,
			&manifest.hash_mock, 0,
			MOCK_ARG_PTR_CONTAINS (&toc.data.entries[i], MANIFEST_V2_TOC_ENTRY_SIZE),
			MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));
	}

	/* Hash TOC data until element hash. */
	status |= flash_mock_expect_verify_flash_and_hash (&manifest.flash, &manifest.hash_mock,
		manifest.addr + last_entry, toc.raw + last_entry, hash_offset - last_entry);

	/* Read element hash. */
	status |= mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash,
		0, MOCK_ARG (manifest.addr + hash_offset), MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA256_HASH_LENGTH));
	/* For some reason valgrind throws an uninitialized memory warning if &toc.raw[hash_offset] is
	 * used as the output data here.  There is no such error if it is used later on with
	 * hash_mock.finish, and it is not clear what exactly is left uninitialized.  Since the actual
	 * value is irrelevent, just use a static hash value that avoids the error. */
	status |= mock_expect_output (&manifest.flash.mock, 1, PFM_V2.manifest.hash, SHA256_HASH_LENGTH,
		2);

	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.update,
		&manifest.hash_mock, 0,
		MOCK_ARG_PTR_CONTAINS (PFM_V2.manifest.hash, SHA256_HASH_LENGTH),
		MOCK_ARG (SHA256_HASH_LENGTH));

	/* TOC hash */
	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.finish,
		&manifest.hash_mock, 0, MOCK_ARG_NOT_NULL, MOCK_ARG (SHA512_HASH_LENGTH));
	status |= mock_expect_output (&manifest.hash_mock.mock, 0, PFM_V2.manifest.toc_hash,
		SHA256_HASH_LENGTH, 1);

	/* Read element data */
	status |= mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash, 0,
		MOCK_ARG (manifest.addr + plat_id_offset), MOCK_ARG_NOT_NULL,
		MOCK_ARG (PFM_V2.manifest.plat_id_len));
	status |= mock_expect_output (&manifest.flash.mock, 1, data, sizeof (data), 2);

	/* Element hash */
	status |= mock_expect (&manifest.hash_mock.mock,
		manifest.hash_mock.base.start_sha256, &manifest.hash_mock, 0);

	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.update,
		&manifest.hash_mock, 0, MOCK_ARG_PTR_CONTAINS (data, PFM_V2.manifest.plat_id_len),
		MOCK_ARG (PFM_V2.manifest.plat_id_len));

	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.finish,
		&manifest.hash_mock, 0, MOCK_ARG_NOT_NULL, MOCK_ARG (SHA512_HASH_LENGTH));
	status |= mock_expect_output (&manifest.hash_mock.mock, 0, PFM_V2.manifest.hash,
		SHA256_HASH_LENGTH, 1);

	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_read_element_data (&manifest.test, &manifest.hash_mock.base,
		MANIFEST_PLATFORM_ID, 0, MANIFEST_NO_PARENT, 0, &found, &format, &total, &element,
		sizeof (buffer));
	CuAssertIntEquals (test, PFM_V2.manifest.plat_id_len, status);
	CuAssertIntEquals (test, 0xfe, found);
	CuAssertIntEquals (test, 0xaa, format);
	CuAssertIntEquals (test, PFM_V2.manifest.plat_id_len, total);

	status = testing_validate_array (PFM_V2.manifest.plat_id, buffer, status);
	CuAssertIntEquals (test, 0, status);

	manifest_flash_v2_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_v2_test_read_element_data_with_read_offset (CuTest *test)
{
	struct manifest_flash_v2_testing manifest;
	int status;
	uint8_t buffer[PFM_V2.manifest.plat_id_len];
	uint8_t *element = buffer;
	size_t total = 0;
	uint8_t format = 0xff;
	uint8_t found = 0xff;

	TEST_START;

	manifest_flash_v2_testing_init_and_verify (test, &manifest, 0x10000, PFM_MAGIC_NUM,
		PFM_V2_MAGIC_NUM, &PFM_V2.manifest, 0, false, 0);

	manifest_flash_v2_testing_read_element (test, &manifest, &PFM_V2.manifest,
		PFM_V2.manifest.plat_id_entry, 0, PFM_V2.manifest.plat_id_hash,
		PFM_V2.manifest.plat_id_offset, PFM_V2.manifest.plat_id_len, sizeof (buffer), 4);

	status = manifest_flash_read_element_data (&manifest.test, &manifest.hash.base,
		MANIFEST_PLATFORM_ID, 0, MANIFEST_NO_PARENT, 4, &found, &format, &total, &element,
		sizeof (buffer));
	CuAssertIntEquals (test, PFM_V2.manifest.plat_id_len - 4, status);
	CuAssertIntEquals (test, PFM_V2.manifest.plat_id_entry, found);
	CuAssertIntEquals (test, 1, format);
	CuAssertIntEquals (test, PFM_V2.manifest.plat_id_len, total);

	status = testing_validate_array (PFM_V2.manifest.plat_id + 4, buffer, status);
	CuAssertIntEquals (test, 0, status);

	manifest_flash_v2_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_v2_test_read_element_data_with_read_offset_no_hash (CuTest *test)
{
	struct manifest_flash_v2_testing manifest;
	int status;
	uint8_t buffer[PFM_V2_NO_TOC_HASHES.manifest.plat_id_len];
	uint8_t *element = buffer;
	size_t total = 0;
	uint8_t format = 0xff;
	uint8_t found = 0xff;

	TEST_START;

	manifest_flash_v2_testing_init_and_verify (test, &manifest, 0x10000, PFM_MAGIC_NUM,
		PFM_V2_MAGIC_NUM, &PFM_V2_NO_TOC_HASHES.manifest, 0, false, 0);

	manifest_flash_v2_testing_read_element (test, &manifest, &PFM_V2_NO_TOC_HASHES.manifest,
		PFM_V2_NO_TOC_HASHES.manifest.plat_id_entry, 0, PFM_V2_NO_TOC_HASHES.manifest.plat_id_hash,
		PFM_V2_NO_TOC_HASHES.manifest.plat_id_offset, PFM_V2_NO_TOC_HASHES.manifest.plat_id_len,
		sizeof (buffer), 4);

	status = manifest_flash_read_element_data (&manifest.test, &manifest.hash.base,
		MANIFEST_PLATFORM_ID, 0, MANIFEST_NO_PARENT, 4, &found, &format, &total, &element,
		sizeof (buffer));
	CuAssertIntEquals (test, PFM_V2_NO_TOC_HASHES.manifest.plat_id_len - 4, status);
	CuAssertIntEquals (test, PFM_V2_NO_TOC_HASHES.manifest.plat_id_entry, found);
	CuAssertIntEquals (test, 1, format);
	CuAssertIntEquals (test, PFM_V2_NO_TOC_HASHES.manifest.plat_id_len, total);

	status = testing_validate_array (PFM_V2_NO_TOC_HASHES.manifest.plat_id + 4, buffer, status);
	CuAssertIntEquals (test, 0, status);

	manifest_flash_v2_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_v2_test_read_element_data_with_read_offset_dynamic_allocation (
	CuTest *test)
{
	struct manifest_flash_v2_testing manifest;
	int status;
	uint8_t *element = NULL;
	size_t total = 0;
	uint8_t format = 0xff;
	uint8_t found = 0xff;

	TEST_START;

	manifest_flash_v2_testing_init_and_verify (test, &manifest, 0x10000, PFM_MAGIC_NUM,
		PFM_V2_MAGIC_NUM, &PFM_V2.manifest, 0, false, 0);

	manifest_flash_v2_testing_read_element (test, &manifest, &PFM_V2.manifest,
		PFM_V2.manifest.plat_id_entry, 0, PFM_V2.manifest.plat_id_hash,
		PFM_V2.manifest.plat_id_offset, PFM_V2.manifest.plat_id_len,
		PFM_V2.manifest.plat_id_len - 4, 4);

	status = manifest_flash_read_element_data (&manifest.test, &manifest.hash.base,
		MANIFEST_PLATFORM_ID, 0, MANIFEST_NO_PARENT, 4, &found, &format, &total, &element, 0);
	CuAssertIntEquals (test, PFM_V2.manifest.plat_id_len - 4, status);
	CuAssertIntEquals (test, PFM_V2.manifest.plat_id_entry, found);
	CuAssertIntEquals (test, 1, format);
	CuAssertIntEquals (test, PFM_V2.manifest.plat_id_len, total);
	CuAssertPtrNotNull (test, element);

	status = testing_validate_array (PFM_V2.manifest.plat_id + 4, element, status);
	CuAssertIntEquals (test, 0, status);

	platform_free (element);

	manifest_flash_v2_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_v2_test_read_element_data_partial_element_with_read_offset (CuTest *test)
{
	struct manifest_flash_v2_testing manifest;
	int status;
	uint8_t buffer[PFM_V2.manifest.plat_id_len - 4 - 1];
	uint8_t *element = buffer;
	size_t total = 0;
	uint8_t format = 0xff;
	uint8_t found = 0xff;

	TEST_START;

	manifest_flash_v2_testing_init_and_verify (test, &manifest, 0x10000, PFM_MAGIC_NUM,
		PFM_V2_MAGIC_NUM, &PFM_V2.manifest, 0, false, 0);

	manifest_flash_v2_testing_read_element (test, &manifest, &PFM_V2.manifest,
		PFM_V2.manifest.plat_id_entry, 0, PFM_V2.manifest.plat_id_hash,
		PFM_V2.manifest.plat_id_offset, PFM_V2.manifest.plat_id_len, sizeof (buffer), 4);

	status = manifest_flash_read_element_data (&manifest.test, &manifest.hash.base,
		MANIFEST_PLATFORM_ID, 0, MANIFEST_NO_PARENT, 4, &found, &format, &total, &element,
		sizeof (buffer));
	CuAssertIntEquals (test, sizeof (buffer), status);
	CuAssertIntEquals (test, PFM_V2.manifest.plat_id_entry, found);
	CuAssertIntEquals (test, 1, format);
	CuAssertIntEquals (test, PFM_V2.manifest.plat_id_len, total);

	status = testing_validate_array (PFM_V2.manifest.plat_id + 4, buffer, status);
	CuAssertIntEquals (test, 0, status);

	manifest_flash_v2_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_v2_test_read_element_data_partial_element_with_read_offset_no_hash (
	CuTest *test)
{
	struct manifest_flash_v2_testing manifest;
	int status;
	uint8_t buffer[PFM_V2_NO_TOC_HASHES.manifest.plat_id_len - 4 - 1];
	uint8_t *element = buffer;
	size_t total = 0;
	uint8_t format = 0xff;
	uint8_t found = 0xff;

	TEST_START;

	manifest_flash_v2_testing_init_and_verify (test, &manifest, 0x10000, PFM_MAGIC_NUM,
		PFM_V2_MAGIC_NUM, &PFM_V2_NO_TOC_HASHES.manifest, 0, false, 0);

	manifest_flash_v2_testing_read_element (test, &manifest, &PFM_V2_NO_TOC_HASHES.manifest,
		PFM_V2_NO_TOC_HASHES.manifest.plat_id_entry, 0, PFM_V2_NO_TOC_HASHES.manifest.plat_id_hash,
		PFM_V2_NO_TOC_HASHES.manifest.plat_id_offset, PFM_V2_NO_TOC_HASHES.manifest.plat_id_len,
		sizeof (buffer), 4);

	status = manifest_flash_read_element_data (&manifest.test, &manifest.hash.base,
		MANIFEST_PLATFORM_ID, 0, MANIFEST_NO_PARENT, 4, &found, &format, &total, &element,
		sizeof (buffer));
	CuAssertIntEquals (test, sizeof (buffer), status);
	CuAssertIntEquals (test, PFM_V2_NO_TOC_HASHES.manifest.plat_id_entry, found);
	CuAssertIntEquals (test, 1, format);
	CuAssertIntEquals (test, PFM_V2_NO_TOC_HASHES.manifest.plat_id_len, total);

	status = testing_validate_array (PFM_V2_NO_TOC_HASHES.manifest.plat_id + 4, buffer, status);
	CuAssertIntEquals (test, 0, status);

	manifest_flash_v2_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_v2_test_read_element_data_with_read_offset_larger_than_element (
	CuTest *test)
{
	struct manifest_flash_v2_testing manifest;
	int status;
	uint8_t buffer[PFM_V2.manifest.plat_id_len];
	uint8_t *element = buffer;
	size_t total = 0;
	uint8_t format = 0xff;
	uint8_t found = 0xff;

	TEST_START;

	manifest_flash_v2_testing_init_and_verify (test, &manifest, 0x10000, PFM_MAGIC_NUM,
		PFM_V2_MAGIC_NUM, &PFM_V2.manifest, 0, false, 0);

	manifest_flash_v2_testing_read_element (test, &manifest, &PFM_V2.manifest,
		PFM_V2.manifest.plat_id_entry, 0, PFM_V2.manifest.plat_id_hash,
		PFM_V2.manifest.plat_id_offset, PFM_V2.manifest.plat_id_len, sizeof (buffer),
		PFM_V2.manifest.plat_id_len + 1);

	status = manifest_flash_read_element_data (&manifest.test, &manifest.hash.base,
		MANIFEST_PLATFORM_ID, 0, MANIFEST_NO_PARENT, PFM_V2.manifest.plat_id_len + 1, &found,
		&format, &total, &element, sizeof (buffer));
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, PFM_V2.manifest.plat_id_entry, found);
	CuAssertIntEquals (test, 1, format);
	CuAssertIntEquals (test, PFM_V2.manifest.plat_id_len, total);

	manifest_flash_v2_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_v2_test_read_element_data_with_read_offset_larger_than_element_dynamic_allocation (
	CuTest *test)
{
	struct manifest_flash_v2_testing manifest;
	int status;
	uint8_t *element = NULL;
	size_t total = 0;
	uint8_t format = 0xff;
	uint8_t found = 0xff;

	TEST_START;

	manifest_flash_v2_testing_init_and_verify (test, &manifest, 0x10000, PFM_MAGIC_NUM,
		PFM_V2_MAGIC_NUM, &PFM_V2.manifest, 0, false, 0);

	manifest_flash_v2_testing_read_element (test, &manifest, &PFM_V2.manifest,
		PFM_V2.manifest.plat_id_entry, 0, PFM_V2.manifest.plat_id_hash,
		PFM_V2.manifest.plat_id_offset, PFM_V2.manifest.plat_id_len, 0,
		PFM_V2.manifest.plat_id_len + 1);

	status = manifest_flash_read_element_data (&manifest.test, &manifest.hash.base,
		MANIFEST_PLATFORM_ID, 0, MANIFEST_NO_PARENT, PFM_V2.manifest.plat_id_len + 1, &found,
		&format, &total, &element, 0);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, PFM_V2.manifest.plat_id_entry, found);
	CuAssertIntEquals (test, 1, format);
	CuAssertIntEquals (test, PFM_V2.manifest.plat_id_len, total);
	CuAssertPtrEquals (test, NULL, element);

	manifest_flash_v2_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_v2_test_read_element_data_with_read_offset_equal_to_element_length (
	CuTest *test)
{
	struct manifest_flash_v2_testing manifest;
	int status;
	uint8_t buffer[PFM_V2.manifest.plat_id_len];
	uint8_t *element = buffer;
	size_t total = 0;
	uint8_t format = 0xff;
	uint8_t found = 0xff;

	TEST_START;

	manifest_flash_v2_testing_init_and_verify (test, &manifest, 0x10000, PFM_MAGIC_NUM,
		PFM_V2_MAGIC_NUM, &PFM_V2.manifest, 0, false, 0);

	manifest_flash_v2_testing_read_element (test, &manifest, &PFM_V2.manifest,
		PFM_V2.manifest.plat_id_entry, 0, PFM_V2.manifest.plat_id_hash,
		PFM_V2.manifest.plat_id_offset, PFM_V2.manifest.plat_id_len, sizeof (buffer),
		PFM_V2.manifest.plat_id_len);

	status = manifest_flash_read_element_data (&manifest.test, &manifest.hash.base,
		MANIFEST_PLATFORM_ID, 0, MANIFEST_NO_PARENT, PFM_V2.manifest.plat_id_len, &found,
		&format, &total, &element, sizeof (buffer));
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, PFM_V2.manifest.plat_id_entry, found);
	CuAssertIntEquals (test, 1, format);
	CuAssertIntEquals (test, PFM_V2.manifest.plat_id_len, total);

	manifest_flash_v2_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_v2_test_read_element_data_read_zero_length (CuTest *test)
{
	struct manifest_flash_v2_testing manifest;
	int status;
	uint8_t buffer[PFM_V2.manifest.plat_id_len];
	uint8_t *element = buffer;
	size_t total = 0;
	uint8_t format = 0xff;
	uint8_t found = 0xff;

	TEST_START;

	manifest_flash_v2_testing_init_and_verify (test, &manifest, 0x10000, PFM_MAGIC_NUM,
		PFM_V2_MAGIC_NUM, &PFM_V2.manifest, 0, false, 0);

	manifest_flash_v2_testing_read_element (test, &manifest, &PFM_V2.manifest,
		PFM_V2.manifest.plat_id_entry, 0, PFM_V2.manifest.plat_id_hash,
		PFM_V2.manifest.plat_id_offset, PFM_V2.manifest.plat_id_len, 0, 0);

	status = manifest_flash_read_element_data (&manifest.test, &manifest.hash.base,
		MANIFEST_PLATFORM_ID, 0, MANIFEST_NO_PARENT, 0, &found, &format, &total, &element, 0);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, PFM_V2.manifest.plat_id_entry, found);
	CuAssertIntEquals (test, 1, format);
	CuAssertIntEquals (test, PFM_V2.manifest.plat_id_len, total);

	manifest_flash_v2_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_v2_test_read_element_data_read_null_element (CuTest *test)
{
	struct manifest_flash_v2_testing manifest;
	int status;
	size_t total = 0;
	uint8_t format = 0xff;
	uint8_t found = 0xff;

	TEST_START;

	manifest_flash_v2_testing_init_and_verify (test, &manifest, 0x10000, PFM_MAGIC_NUM,
		PFM_V2_MAGIC_NUM, &PFM_V2.manifest, 0, false, 0);

	manifest_flash_v2_testing_read_element (test, &manifest, &PFM_V2.manifest,
		PFM_V2.manifest.plat_id_entry, 0, PFM_V2.manifest.plat_id_hash,
		PFM_V2.manifest.plat_id_offset, PFM_V2.manifest.plat_id_len, 0, 0);

	status = manifest_flash_read_element_data (&manifest.test, &manifest.hash.base,
		MANIFEST_PLATFORM_ID, 0, MANIFEST_NO_PARENT, 0, &found, &format, &total, NULL, 1);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, PFM_V2.manifest.plat_id_entry, found);
	CuAssertIntEquals (test, 1, format);
	CuAssertIntEquals (test, PFM_V2.manifest.plat_id_len, total);

	manifest_flash_v2_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_v2_test_read_element_data_null (CuTest *test)
{
	struct manifest_flash_v2_testing manifest;
	int status;
	uint8_t buffer[PFM_V2.manifest.plat_id_len];
	uint8_t *element = buffer;
	size_t total = 0;
	uint8_t format = 0xff;
	uint8_t found = 0xff;

	TEST_START;

	manifest_flash_v2_testing_init_and_verify (test, &manifest, 0x10000, PFM_MAGIC_NUM,
		PFM_V2_MAGIC_NUM, &PFM_V2.manifest, 0, false, 0);

	status = manifest_flash_read_element_data (NULL, &manifest.hash.base,
		MANIFEST_PLATFORM_ID, 0, MANIFEST_NO_PARENT, 0, &found, &format, &total, &element,
		sizeof (buffer));
	CuAssertIntEquals (test, MANIFEST_INVALID_ARGUMENT, status);

	status = manifest_flash_read_element_data (&manifest.test, NULL,
		MANIFEST_PLATFORM_ID, 0, MANIFEST_NO_PARENT, 0, &found, &format, &total, &element,
		sizeof (buffer));
	CuAssertIntEquals (test, MANIFEST_INVALID_ARGUMENT, status);

	manifest_flash_v2_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_v2_test_read_element_data_verify_never_run (CuTest *test)
{
	struct manifest_flash_v2_testing manifest;
	int status;
	uint8_t buffer[PFM_V2.manifest.plat_id_len];
	uint8_t *element = buffer;
	size_t total = 0;
	uint8_t format = 0xff;
	uint8_t found = 0xff;

	TEST_START;

	manifest_flash_v2_testing_init (test, &manifest, 0x10000, PFM_MAGIC_NUM, PFM_V2_MAGIC_NUM);

	status = manifest_flash_read_element_data (&manifest.test, &manifest.hash.base,
		MANIFEST_PLATFORM_ID, 0, MANIFEST_NO_PARENT, 0, &found, &format, &total, &element,
		sizeof (buffer));
	CuAssertIntEquals (test, MANIFEST_NO_MANIFEST, status);

	manifest_flash_v2_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_v2_test_read_element_data_after_verify_header_read_error (CuTest *test)
{
	struct manifest_flash_v2_testing manifest;
	int status;
	uint8_t buffer[PFM_V2.manifest.plat_id_len];
	uint8_t *element = buffer;
	size_t total = 0;
	uint8_t format = 0xff;
	uint8_t found = 0xff;

	TEST_START;

	manifest_flash_v2_testing_init_and_verify (test, &manifest, 0x10000, PFM_MAGIC_NUM,
		PFM_V2_MAGIC_NUM, &PFM_V2.manifest, 0, false, 0);

	status = mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash,
		FLASH_READ_FAILED, MOCK_ARG (manifest.addr), MOCK_ARG_NOT_NULL,
		MOCK_ARG (MANIFEST_V2_HEADER_SIZE));
	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_verify (&manifest.test, &manifest.hash.base,
		&manifest.verification.base, NULL, 0);
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	status = manifest_flash_read_element_data (&manifest.test, &manifest.hash.base,
		MANIFEST_PLATFORM_ID, 0, MANIFEST_NO_PARENT, 0, &found, &format, &total, &element,
		sizeof (buffer));
	CuAssertIntEquals (test, MANIFEST_NO_MANIFEST, status);

	manifest_flash_v2_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_v2_test_read_element_data_after_verify_bad_signature (CuTest *test)
{
	struct manifest_flash_v2_testing manifest;
	int status;
	uint8_t buffer[PFM_V2.manifest.plat_id_len];
	uint8_t *element = buffer;
	size_t total = 0;
	uint8_t format = 0xff;
	uint8_t found = 0xff;

	TEST_START;

	manifest_flash_v2_testing_init_and_verify (test, &manifest, 0x10000, PFM_MAGIC_NUM,
		PFM_V2_MAGIC_NUM, &PFM_V2.manifest, 0, false, 0);

	manifest_flash_v2_testing_verify_manifest (test, &manifest, &PFM_V2_PLAT_FIRST.manifest,
		RSA_ENGINE_BAD_SIGNATURE);

	status = manifest_flash_verify (&manifest.test, &manifest.hash.base,
		&manifest.verification.base, NULL, 0);
	CuAssertIntEquals (test, RSA_ENGINE_BAD_SIGNATURE, status);

	status = mock_validate (&manifest.flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&manifest.verification.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&manifest.hash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_read_element_data (&manifest.test, &manifest.hash.base,
		MANIFEST_PLATFORM_ID, 0, MANIFEST_NO_PARENT, 0, &found, &format, &total, &element,
		sizeof (buffer));
	CuAssertIntEquals (test, MANIFEST_NO_MANIFEST, status);

	manifest_flash_v2_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_v2_test_read_element_data_element_not_found_not_present (CuTest *test)
{
	struct manifest_flash_v2_testing manifest;
	int status;
	uint8_t buffer[PFM_V2.manifest.plat_id_len];
	uint8_t *element = buffer;
	size_t total = 0;
	uint8_t format = 0xff;
	uint8_t found = 0xff;

	TEST_START;

	manifest_flash_v2_testing_init_and_verify (test, &manifest, 0x10000, PFM_MAGIC_NUM,
		PFM_V2_MAGIC_NUM, &PFM_V2.manifest, 0, false, 0);

	manifest_flash_v2_testing_read_element_mocked_hash (test, &manifest, &PFM_V2.manifest, -1, 0,
		-1, 0, 0, 0, 0);

	status = manifest_flash_read_element_data (&manifest.test, &manifest.hash_mock.base, 0x55, 0,
		MANIFEST_NO_PARENT, 0, &found, &format, &total, &element, sizeof (buffer));
	CuAssertIntEquals (test, MANIFEST_ELEMENT_NOT_FOUND, status);

	manifest_flash_v2_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_v2_test_read_element_data_element_not_found_start_after_element (
	CuTest *test)
{
	struct manifest_flash_v2_testing manifest;
	int status;
	uint8_t buffer[PFM_V2_PLAT_FIRST.manifest.plat_id_len];
	uint8_t *element = buffer;
	size_t total = 0;
	uint8_t format = 0xff;
	uint8_t found = 0xff;

	TEST_START;

	manifest_flash_v2_testing_init_and_verify (test, &manifest, 0x10000, PFM_MAGIC_NUM,
		PFM_V2_MAGIC_NUM, &PFM_V2_PLAT_FIRST.manifest, 0, false, 0);

	manifest_flash_v2_testing_read_element (test, &manifest, &PFM_V2_PLAT_FIRST.manifest,
		PFM_V2_PLAT_FIRST.manifest.plat_id_entry, PFM_V2_PLAT_FIRST.manifest.plat_id_entry + 1, -1,
		0, 0, 0, 0);

	status = manifest_flash_read_element_data (&manifest.test, &manifest.hash.base,
		MANIFEST_PLATFORM_ID, PFM_V2_PLAT_FIRST.manifest.plat_id_entry + 1, MANIFEST_NO_PARENT, 0,
		&found, &format, &total, &element, sizeof (buffer));
	CuAssertIntEquals (test, MANIFEST_ELEMENT_NOT_FOUND, status);

	manifest_flash_v2_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_v2_test_read_element_data_element_not_found_bad_start_entry (
	CuTest *test)
{
	struct manifest_flash_v2_testing manifest;
	int status;
	uint8_t buffer[PFM_V2.manifest.plat_id_len];
	uint8_t *element = buffer;
	size_t total = 0;
	uint8_t format = 0xff;
	uint8_t found = 0xff;

	TEST_START;

	manifest_flash_v2_testing_init_and_verify (test, &manifest, 0x10000, PFM_MAGIC_NUM,
		PFM_V2_MAGIC_NUM, &PFM_V2.manifest, 0, false, 0);

	status = manifest_flash_read_element_data (&manifest.test, &manifest.hash.base,
		MANIFEST_PLATFORM_ID, PFM_V2.manifest.toc_entries, MANIFEST_NO_PARENT, 0, &found, &format,
		&total, &element, sizeof (buffer));
	CuAssertIntEquals (test, MANIFEST_ELEMENT_NOT_FOUND, status);

	manifest_flash_v2_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_v2_test_read_element_data_with_parent_wrong_type (CuTest *test)
{
	struct manifest_flash_v2_testing manifest;
	int status;
	uint8_t buffer[PFM_V2.fw[0].version[0].fw_version_len];
	uint8_t *element = buffer;
	size_t total = 0;
	uint8_t format = 0xff;
	uint8_t found = 0xff;
	const struct manifest_v2_testing_data *data = &PFM_V2.manifest;
	int start = PFM_V2.fw[0].version[0].fw_version_entry;
	int entry = PFM_V2.fw[0].version[0].fw_version_entry;
	int hash_id = PFM_V2.fw[0].version[0].fw_version_hash;
	uint32_t toc_entry_offset = MANIFEST_V2_TOC_ENTRY_OFFSET;
	uint32_t first_entry = toc_entry_offset + (MANIFEST_V2_TOC_ENTRY_SIZE * start);
	uint32_t last_entry = toc_entry_offset + (MANIFEST_V2_TOC_ENTRY_SIZE * (entry + 1));
	uint32_t hash_offset;
	uint32_t after_hash;
	const struct manifest_toc_entry *toc_entries =
		(struct manifest_toc_entry*) (data->raw + toc_entry_offset);
	int i;

	TEST_START;

	manifest_flash_v2_testing_init_and_verify (test, &manifest, 0x10000, PFM_MAGIC_NUM,
		PFM_V2_MAGIC_NUM, &PFM_V2.manifest, 0, false, 0);

	hash_offset = toc_entry_offset + (MANIFEST_V2_TOC_ENTRY_SIZE * data->toc_entries) +
		(data->toc_hash_len * hash_id);
	after_hash = hash_offset + data->toc_hash_len;

	status = mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.start_sha256,
		&manifest.hash_mock, 0);
	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.update,
		&manifest.hash_mock, 0, MOCK_ARG_PTR_CONTAINS (data->toc, MANIFEST_V2_TOC_HEADER_SIZE),
		MOCK_ARG (MANIFEST_V2_TOC_HEADER_SIZE));

	status = flash_mock_expect_verify_flash_and_hash (&manifest.flash, &manifest.hash_mock,
		manifest.addr + toc_entry_offset, data->raw + toc_entry_offset,
		first_entry - toc_entry_offset);

	for (i = start; i <= entry; i++) {
		status |= mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash,
			0, MOCK_ARG (manifest.addr + toc_entry_offset + (i * MANIFEST_V2_TOC_ENTRY_SIZE)),
			MOCK_ARG_NOT_NULL, MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));
		status |= mock_expect_output (&manifest.flash.mock, 1, &toc_entries[i],
			MANIFEST_V2_TOC_ENTRY_SIZE, 2);

		status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.update,
			&manifest.hash_mock, 0,
			MOCK_ARG_PTR_CONTAINS (&toc_entries[i], MANIFEST_V2_TOC_ENTRY_SIZE),
			MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));
	}

	status |= flash_mock_expect_verify_flash_and_hash (&manifest.flash, &manifest.hash_mock,
		manifest.addr + last_entry, data->raw + last_entry, hash_offset - last_entry);

	status |= mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash,
		0, MOCK_ARG (manifest.addr + hash_offset), MOCK_ARG_NOT_NULL,
		MOCK_ARG (data->toc_hash_len));
	status |= mock_expect_output (&manifest.flash.mock, 1, data->raw + hash_offset,
		data->length - hash_offset, 2);

	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.update,
		&manifest.hash_mock, 0,
		MOCK_ARG_PTR_CONTAINS (&data->raw[hash_offset], data->toc_hash_len),
		MOCK_ARG (data->toc_hash_len));

	status |= flash_mock_expect_verify_flash_and_hash (&manifest.flash, &manifest.hash_mock,
		manifest.addr + after_hash, data->raw + after_hash, data->toc_hash_offset - after_hash);

	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.finish,
		&manifest.hash_mock, 0, MOCK_ARG_NOT_NULL, MOCK_ARG (SHA512_HASH_LENGTH));
	status |= mock_expect_output (&manifest.hash_mock.mock, 0, data->toc_hash, data->toc_hash_len,
		1);

	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_read_element_data (&manifest.test, &manifest.hash_mock.base,
		PFM_FIRMWARE_VERSION, PFM_V2.fw[0].version[0].fw_version_entry, PFM_FLASH_DEVICE, 0, &found,
		&format, &total, &element, sizeof (buffer));
	CuAssertIntEquals (test, MANIFEST_WRONG_PARENT, status);

	manifest_flash_v2_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_v2_test_read_element_data_with_parent_wrong_type_no_hash (CuTest *test)
{
	struct manifest_flash_v2_testing manifest;
	int status;
	uint8_t buffer[PFM_V2_NO_TOC_HASHES.fw[0].version[0].fw_version_len];
	uint8_t *element = buffer;
	size_t total = 0;
	uint8_t format = 0xff;
	uint8_t found = 0xff;
	const struct manifest_v2_testing_data *data = &PFM_V2_NO_TOC_HASHES.manifest;
	int start = PFM_V2_NO_TOC_HASHES.fw[0].version[0].fw_version_entry;
	int entry = PFM_V2_NO_TOC_HASHES.fw[0].version[0].fw_version_entry;
	uint32_t toc_entry_offset = MANIFEST_V2_TOC_ENTRY_OFFSET;
	uint32_t first_entry = toc_entry_offset + (MANIFEST_V2_TOC_ENTRY_SIZE * start);
	uint32_t last_entry = toc_entry_offset + (MANIFEST_V2_TOC_ENTRY_SIZE * (entry + 1));
	const struct manifest_toc_entry *toc_entries =
		(struct manifest_toc_entry*) (data->raw + toc_entry_offset);
	int i;

	TEST_START;

	manifest_flash_v2_testing_init_and_verify (test, &manifest, 0x10000, PFM_MAGIC_NUM,
		PFM_V2_MAGIC_NUM, &PFM_V2_NO_TOC_HASHES.manifest, 0, false, 0);

	status = mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.start_sha512,
		&manifest.hash_mock, 0);
	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.update,
		&manifest.hash_mock, 0, MOCK_ARG_PTR_CONTAINS (data->toc, MANIFEST_V2_TOC_HEADER_SIZE),
		MOCK_ARG (MANIFEST_V2_TOC_HEADER_SIZE));

	status = flash_mock_expect_verify_flash_and_hash (&manifest.flash, &manifest.hash_mock,
		manifest.addr + toc_entry_offset, data->raw + toc_entry_offset,
		first_entry - toc_entry_offset);

	for (i = start; i <= entry; i++) {
		status |= mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash,
			0, MOCK_ARG (manifest.addr + toc_entry_offset + (i * MANIFEST_V2_TOC_ENTRY_SIZE)),
			MOCK_ARG_NOT_NULL, MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));
		status |= mock_expect_output (&manifest.flash.mock, 1, &toc_entries[i],
			MANIFEST_V2_TOC_ENTRY_SIZE, 2);

		status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.update,
			&manifest.hash_mock, 0,
			MOCK_ARG_PTR_CONTAINS (&toc_entries[i], MANIFEST_V2_TOC_ENTRY_SIZE),
			MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));
	}

	status |= flash_mock_expect_verify_flash_and_hash (&manifest.flash, &manifest.hash_mock,
		manifest.addr + last_entry, data->raw + last_entry, data->toc_hash_offset - last_entry);

	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.finish,
		&manifest.hash_mock, 0, MOCK_ARG_NOT_NULL, MOCK_ARG (SHA512_HASH_LENGTH));
	status |= mock_expect_output (&manifest.hash_mock.mock, 0, data->toc_hash, data->toc_hash_len,
		1);

	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_read_element_data (&manifest.test, &manifest.hash_mock.base,
		PFM_FIRMWARE_VERSION, PFM_V2_NO_TOC_HASHES.fw[0].version[0].fw_version_entry,
		PFM_FLASH_DEVICE, 0, &found, &format, &total, &element, sizeof (buffer));
	CuAssertIntEquals (test, MANIFEST_WRONG_PARENT, status);

	manifest_flash_v2_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_v2_test_read_element_data_with_parent_child_not_found (CuTest *test)
{
	struct manifest_flash_v2_testing manifest;
	int status;
	uint8_t buffer[PFM_V2.manifest.plat_id_len];
	uint8_t *element = buffer;
	size_t total = 0;
	uint8_t format = 0xff;
	uint8_t found = 0xff;
	const struct manifest_v2_testing_data *data = &PFM_V2.manifest;
	int start = 0;
	uint32_t toc_entry_offset = MANIFEST_V2_TOC_ENTRY_OFFSET;
	uint32_t first_entry = toc_entry_offset + (MANIFEST_V2_TOC_ENTRY_SIZE * start);
	const struct manifest_toc_entry *toc_entries =
		(struct manifest_toc_entry*) (data->raw + toc_entry_offset);

	TEST_START;

	manifest_flash_v2_testing_init_and_verify (test, &manifest, 0x10000, PFM_MAGIC_NUM,
		PFM_V2_MAGIC_NUM, &PFM_V2.manifest, 0, false, 0);

	status = mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.start_sha256,
		&manifest.hash_mock, 0);
	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.update,
		&manifest.hash_mock, 0, MOCK_ARG_PTR_CONTAINS (data->toc, MANIFEST_V2_TOC_HEADER_SIZE),
		MOCK_ARG (MANIFEST_V2_TOC_HEADER_SIZE));

	status = flash_mock_expect_verify_flash_and_hash (&manifest.flash, &manifest.hash_mock,
		manifest.addr + toc_entry_offset, data->raw + toc_entry_offset,
		first_entry - toc_entry_offset);

	status |= mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash,
		0, MOCK_ARG (manifest.addr + toc_entry_offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));
	status |= mock_expect_output (&manifest.flash.mock, 1, toc_entries, MANIFEST_V2_TOC_ENTRY_SIZE,
		2);

	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.cancel,
		&manifest.hash_mock, 0);

	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_read_element_data (&manifest.test, &manifest.hash_mock.base,
		MANIFEST_PLATFORM_ID, 0, PFM_FIRMWARE, 0, &found, &format, &total, &element,
		sizeof (buffer));
	CuAssertIntEquals (test, MANIFEST_CHILD_NOT_FOUND, status);

	manifest_flash_v2_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_v2_test_read_element_data_with_parent_child_not_found_last_element (
	CuTest *test)
{
	struct manifest_flash_v2_testing manifest;
	int status;
	uint8_t buffer[PFM_V2_TWO_FW.fw[1].version[0].fw_version_len];
	uint8_t *element = buffer;
	size_t total = 0;
	uint8_t format = 0xff;
	uint8_t found = 0xff;
	const struct manifest_v2_testing_data *data = &PFM_V2_TWO_FW.manifest;
	int start = PFM_V2_TWO_FW.fw[1].version[0].fw_version_entry;
	uint32_t toc_entry_offset = MANIFEST_V2_TOC_ENTRY_OFFSET;
	uint32_t first_entry = toc_entry_offset + (MANIFEST_V2_TOC_ENTRY_SIZE * start);
	const struct manifest_toc_entry *toc_entries =
		(struct manifest_toc_entry*) (data->raw + toc_entry_offset);

	TEST_START;

	manifest_flash_v2_testing_init_and_verify (test, &manifest, 0x10000, PFM_MAGIC_NUM,
		PFM_V2_MAGIC_NUM, &PFM_V2_TWO_FW.manifest, 0, false, 0);

	status = mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.start_sha256,
		&manifest.hash_mock, 0);
	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.update,
		&manifest.hash_mock, 0, MOCK_ARG_PTR_CONTAINS (data->toc, MANIFEST_V2_TOC_HEADER_SIZE),
		MOCK_ARG (MANIFEST_V2_TOC_HEADER_SIZE));

	status = flash_mock_expect_verify_flash_and_hash (&manifest.flash, &manifest.hash_mock,
		manifest.addr + toc_entry_offset, data->raw + toc_entry_offset,
		first_entry - toc_entry_offset);

	status |= mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash,
		0, MOCK_ARG (manifest.addr + first_entry),
		MOCK_ARG_NOT_NULL, MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));
	status |= mock_expect_output (&manifest.flash.mock, 1, &toc_entries[start],
		MANIFEST_V2_TOC_ENTRY_SIZE, 2);

	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.update,
		&manifest.hash_mock, 0,
		MOCK_ARG_PTR_CONTAINS (&toc_entries[start], MANIFEST_V2_TOC_ENTRY_SIZE),
		MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));

	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.cancel,
		&manifest.hash_mock, 0);

	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_read_element_data (&manifest.test, &manifest.hash_mock.base, 0x55,
		start, PFM_FIRMWARE, 0, &found, &format, &total, &element, sizeof (buffer));
	CuAssertIntEquals (test, MANIFEST_CHILD_NOT_FOUND, status);

	manifest_flash_v2_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_v2_test_read_element_data_with_parent_bad_start_entry (CuTest *test)
{
	struct manifest_flash_v2_testing manifest;
	int status;
	uint8_t buffer[PFM_V2.manifest.plat_id_len];
	uint8_t *element = buffer;
	size_t total = 0;
	uint8_t format = 0xff;
	uint8_t found = 0xff;
	int start = PFM_V2.manifest.toc_entries;

	TEST_START;

	manifest_flash_v2_testing_init_and_verify (test, &manifest, 0x10000, PFM_MAGIC_NUM,
		PFM_V2_MAGIC_NUM, &PFM_V2.manifest, 0, false, 0);

	status = manifest_flash_read_element_data (&manifest.test, &manifest.hash_mock.base,
		PFM_FIRMWARE_VERSION, start, PFM_FIRMWARE, 0, &found, &format, &total, &element,
		sizeof (buffer));
	CuAssertIntEquals (test, MANIFEST_CHILD_NOT_FOUND, status);

	manifest_flash_v2_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_v2_test_read_element_data_child_no_parent_specified (CuTest *test)
{
	struct manifest_flash_v2_testing manifest;
	int status;
	uint8_t buffer[PFM_V2.fw[0].version[0].fw_version_len];
	uint8_t *element = buffer;
	size_t total = 0;
	uint8_t format = 0xff;
	uint8_t found = 0xff;
	const struct manifest_v2_testing_data *data = &PFM_V2.manifest;
	int start = 0;
	int entry = PFM_V2.fw[0].version[0].fw_version_entry;
	int hash_id = PFM_V2.fw[0].version[0].fw_version_hash;
	uint32_t toc_entry_offset = MANIFEST_V2_TOC_ENTRY_OFFSET;
	uint32_t first_entry = toc_entry_offset + (MANIFEST_V2_TOC_ENTRY_SIZE * start);
	uint32_t last_entry = toc_entry_offset + (MANIFEST_V2_TOC_ENTRY_SIZE * (entry + 1));
	uint32_t hash_offset;
	uint32_t after_hash;
	const struct manifest_toc_entry *toc_entries =
		(struct manifest_toc_entry*) (data->raw + toc_entry_offset);
	int i;

	TEST_START;

	manifest_flash_v2_testing_init_and_verify (test, &manifest, 0x10000, PFM_MAGIC_NUM,
		PFM_V2_MAGIC_NUM, &PFM_V2.manifest, 0, false, 0);

	hash_offset = toc_entry_offset + (MANIFEST_V2_TOC_ENTRY_SIZE * data->toc_entries) +
		(data->toc_hash_len * hash_id);
	after_hash = hash_offset + data->toc_hash_len;

	status = mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.start_sha256,
		&manifest.hash_mock, 0);
	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.update,
		&manifest.hash_mock, 0, MOCK_ARG_PTR_CONTAINS (data->toc, MANIFEST_V2_TOC_HEADER_SIZE),
		MOCK_ARG (MANIFEST_V2_TOC_HEADER_SIZE));

	status = flash_mock_expect_verify_flash_and_hash (&manifest.flash, &manifest.hash_mock,
		manifest.addr + toc_entry_offset, data->raw + toc_entry_offset,
		first_entry - toc_entry_offset);

	for (i = start; i <= entry; i++) {
		status |= mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash,
			0, MOCK_ARG (manifest.addr + toc_entry_offset + (i * MANIFEST_V2_TOC_ENTRY_SIZE)),
			MOCK_ARG_NOT_NULL, MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));
		status |= mock_expect_output (&manifest.flash.mock, 1, &toc_entries[i],
			MANIFEST_V2_TOC_ENTRY_SIZE, 2);

		status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.update,
			&manifest.hash_mock, 0,
			MOCK_ARG_PTR_CONTAINS (&toc_entries[i], MANIFEST_V2_TOC_ENTRY_SIZE),
			MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));
	}

	status |= flash_mock_expect_verify_flash_and_hash (&manifest.flash, &manifest.hash_mock,
		manifest.addr + last_entry, data->raw + last_entry, hash_offset - last_entry);

	status |= mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash,
		0, MOCK_ARG (manifest.addr + hash_offset), MOCK_ARG_NOT_NULL,
		MOCK_ARG (data->toc_hash_len));
	status |= mock_expect_output (&manifest.flash.mock, 1, data->raw + hash_offset,
		data->length - hash_offset, 2);

	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.update,
		&manifest.hash_mock, 0,
		MOCK_ARG_PTR_CONTAINS (&data->raw[hash_offset], data->toc_hash_len),
		MOCK_ARG (data->toc_hash_len));

	status |= flash_mock_expect_verify_flash_and_hash (&manifest.flash, &manifest.hash_mock,
		manifest.addr + after_hash, data->raw + after_hash, data->toc_hash_offset - after_hash);

	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.finish,
		&manifest.hash_mock, 0, MOCK_ARG_NOT_NULL, MOCK_ARG (SHA512_HASH_LENGTH));
	status |= mock_expect_output (&manifest.hash_mock.mock, 0, data->toc_hash, data->toc_hash_len,
		1);

	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_read_element_data (&manifest.test, &manifest.hash_mock.base,
		PFM_FIRMWARE_VERSION, 0, MANIFEST_NO_PARENT, 0, &found, &format, &total, &element,
		sizeof (buffer));
	CuAssertIntEquals (test, MANIFEST_WRONG_PARENT, status);

	manifest_flash_v2_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_v2_test_read_element_data_bad_toc_hash (CuTest *test)
{
	struct manifest_flash_v2_testing manifest;
	int status;
	uint8_t buffer[PFM_V2.manifest.plat_id_len];
	uint8_t *element = buffer;
	size_t total = 0;
	uint8_t format = 0xff;
	uint8_t found = 0xff;
	const struct manifest_v2_testing_data *data = &PFM_V2.manifest;
	int start = 0;
	int entry = data->plat_id_entry;
	int hash_id = data->plat_id_hash;
	uint32_t toc_entry_offset = MANIFEST_V2_TOC_ENTRY_OFFSET;
	uint32_t first_entry = toc_entry_offset + (MANIFEST_V2_TOC_ENTRY_SIZE * start);
	uint32_t last_entry = toc_entry_offset + (MANIFEST_V2_TOC_ENTRY_SIZE * (entry + 1));
	uint32_t hash_offset;
	uint32_t after_hash;
	const struct manifest_toc_entry *toc_entries =
		(struct manifest_toc_entry*) (data->raw + toc_entry_offset);
	int i;
	uint8_t bad_hash[data->toc_hash_len];

	TEST_START;

	manifest_flash_v2_testing_init_and_verify (test, &manifest, 0x10000, PFM_MAGIC_NUM,
		PFM_V2_MAGIC_NUM, &PFM_V2.manifest, 0, false, 0);

	hash_offset = toc_entry_offset + (MANIFEST_V2_TOC_ENTRY_SIZE * data->toc_entries) +
		(data->toc_hash_len * hash_id);
	after_hash = hash_offset + data->toc_hash_len;

	memcpy (bad_hash, data->raw + hash_offset, data->toc_hash_len);
	bad_hash[0] ^= 0x55;

	status = flash_mock_expect_verify_flash (&manifest.flash, manifest.addr + toc_entry_offset,
		data->raw + toc_entry_offset, first_entry - toc_entry_offset);

	for (i = start; i <= entry; i++) {
		status |= mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash,
			0, MOCK_ARG (manifest.addr + toc_entry_offset + (i * MANIFEST_V2_TOC_ENTRY_SIZE)),
			MOCK_ARG_NOT_NULL, MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));
		status |= mock_expect_output (&manifest.flash.mock, 1, &toc_entries[i],
			MANIFEST_V2_TOC_ENTRY_SIZE, 2);
	}

	status |= flash_mock_expect_verify_flash (&manifest.flash, manifest.addr + last_entry,
		data->raw + last_entry, hash_offset - last_entry);

	status |= mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash,
		0, MOCK_ARG (manifest.addr + hash_offset), MOCK_ARG_NOT_NULL,
		MOCK_ARG (data->toc_hash_len));
	status |= mock_expect_output (&manifest.flash.mock, 1, bad_hash, sizeof (bad_hash), 2);

	status |= flash_mock_expect_verify_flash (&manifest.flash, manifest.addr + after_hash,
		data->raw + after_hash, data->toc_hash_offset - after_hash);

	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_read_element_data (&manifest.test, &manifest.hash.base,
		MANIFEST_PLATFORM_ID, 0, MANIFEST_NO_PARENT, 0, &found, &format, &total, &element,
		sizeof (buffer));
	CuAssertIntEquals (test, MANIFEST_TOC_INVALID, status);

	manifest_flash_v2_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_v2_test_read_element_data_bad_element_hash (CuTest *test)
{
	struct manifest_flash_v2_testing manifest;
	int status;
	uint8_t buffer[PFM_V2.manifest.plat_id_len];
	uint8_t *element = buffer;
	size_t total = 0;
	uint8_t format = 0xff;
	uint8_t found = 0xff;
	const struct manifest_v2_testing_data *data = &PFM_V2.manifest;
	int start = 0;
	int entry = data->plat_id_entry;
	int hash_id = data->plat_id_hash;
	size_t length = data->plat_id_len;
	uint32_t offset = data->plat_id_offset;
	uint32_t toc_entry_offset = MANIFEST_V2_TOC_ENTRY_OFFSET;
	uint32_t first_entry = toc_entry_offset + (MANIFEST_V2_TOC_ENTRY_SIZE * start);
	uint32_t last_entry = toc_entry_offset + (MANIFEST_V2_TOC_ENTRY_SIZE * (entry + 1));
	uint32_t hash_offset;
	uint32_t after_hash;
	const struct manifest_toc_entry *toc_entries =
		(struct manifest_toc_entry*) (data->raw + toc_entry_offset);
	int i;
	uint8_t bad_element[data->plat_id_len];

	TEST_START;

	manifest_flash_v2_testing_init_and_verify (test, &manifest, 0x10000, PFM_MAGIC_NUM,
		PFM_V2_MAGIC_NUM, &PFM_V2.manifest, 0, false, 0);

	hash_offset = toc_entry_offset + (MANIFEST_V2_TOC_ENTRY_SIZE * data->toc_entries) +
		(data->toc_hash_len * hash_id);
	after_hash = hash_offset + data->toc_hash_len;

	memcpy (bad_element, data->plat_id, data->plat_id_len);
	bad_element[0] ^= 0x55;

	status = flash_mock_expect_verify_flash (&manifest.flash, manifest.addr + toc_entry_offset,
		data->raw + toc_entry_offset, first_entry - toc_entry_offset);

	for (i = start; i <= entry; i++) {
		status |= mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash,
			0, MOCK_ARG (manifest.addr + toc_entry_offset + (i * MANIFEST_V2_TOC_ENTRY_SIZE)),
			MOCK_ARG_NOT_NULL, MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));
		status |= mock_expect_output (&manifest.flash.mock, 1, &toc_entries[i],
			MANIFEST_V2_TOC_ENTRY_SIZE, 2);
	}

	status |= flash_mock_expect_verify_flash (&manifest.flash, manifest.addr + last_entry,
		data->raw + last_entry, hash_offset - last_entry);

	status |= mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash,
		0, MOCK_ARG (manifest.addr + hash_offset), MOCK_ARG_NOT_NULL,
		MOCK_ARG (data->toc_hash_len));
	status |= mock_expect_output (&manifest.flash.mock, 1, data->raw + hash_offset,
		data->length - hash_offset, 2);

	status |= flash_mock_expect_verify_flash (&manifest.flash, manifest.addr + after_hash,
		data->raw + after_hash, data->toc_hash_offset - after_hash);

	status |= mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash, 0,
		MOCK_ARG (manifest.addr + offset), MOCK_ARG_NOT_NULL, MOCK_ARG (length));
	status |= mock_expect_output (&manifest.flash.mock, 1, bad_element, sizeof (bad_element), 2);

	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_read_element_data (&manifest.test, &manifest.hash.base,
		MANIFEST_PLATFORM_ID, 0, MANIFEST_NO_PARENT, 0, &found, &format, &total, &element,
		sizeof (buffer));
	CuAssertIntEquals (test, MANIFEST_ELEMENT_INVALID, status);

	manifest_flash_v2_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_v2_test_read_element_data_start_toc_hash_error (CuTest *test)
{
	struct manifest_flash_v2_testing manifest;
	int status;
	uint8_t buffer[PFM_V2.manifest.plat_id_len];
	uint8_t *element = buffer;
	size_t total = 0;
	uint8_t format = 0xff;
	uint8_t found = 0xff;

	TEST_START;

	manifest_flash_v2_testing_init_and_verify (test, &manifest, 0x10000, PFM_MAGIC_NUM,
		PFM_V2_MAGIC_NUM, &PFM_V2.manifest, 0, false, 0);

	status = mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.start_sha256,
		&manifest.hash_mock, HASH_ENGINE_START_SHA256_FAILED);

	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_read_element_data (&manifest.test, &manifest.hash_mock.base,
		MANIFEST_PLATFORM_ID, 0, MANIFEST_NO_PARENT, 0, &found, &format, &total, &element,
		sizeof (buffer));
	CuAssertIntEquals (test, HASH_ENGINE_START_SHA256_FAILED, status);

	manifest_flash_v2_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_v2_test_read_element_data_toc_header_hash_error (CuTest *test)
{
	struct manifest_flash_v2_testing manifest;
	int status;
	uint8_t buffer[PFM_V2.manifest.plat_id_len];
	uint8_t *element = buffer;
	size_t total = 0;
	uint8_t format = 0xff;
	uint8_t found = 0xff;
	const struct manifest_v2_testing_data *data = &PFM_V2.manifest;

	TEST_START;

	manifest_flash_v2_testing_init_and_verify (test, &manifest, 0x10000, PFM_MAGIC_NUM,
		PFM_V2_MAGIC_NUM, &PFM_V2.manifest, 0, false, 0);

	status = mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.start_sha256,
		&manifest.hash_mock, 0);
	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.update,
		&manifest.hash_mock, HASH_ENGINE_UPDATE_FAILED,
		MOCK_ARG_PTR_CONTAINS (data->toc, MANIFEST_V2_TOC_HEADER_SIZE),
		MOCK_ARG (MANIFEST_V2_TOC_HEADER_SIZE));

	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.cancel,
		&manifest.hash_mock, 0);

	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_read_element_data (&manifest.test, &manifest.hash_mock.base,
		MANIFEST_PLATFORM_ID, 0, MANIFEST_NO_PARENT, 0, &found, &format, &total, &element,
		sizeof (buffer));
	CuAssertIntEquals (test, HASH_ENGINE_UPDATE_FAILED, status);

	manifest_flash_v2_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_v2_test_read_element_data_toc_beginning_read_error (CuTest *test)
{
	struct manifest_flash_v2_testing manifest;
	int status;
	uint8_t buffer[PFM_V2.manifest.plat_id_len];
	uint8_t *element = buffer;
	size_t total = 0;
	uint8_t format = 0xff;
	uint8_t found = 0xff;
	const struct manifest_v2_testing_data *data = &PFM_V2.manifest;
	int start = 1;
	uint32_t toc_entry_offset = MANIFEST_V2_TOC_ENTRY_OFFSET;
	uint32_t first_entry = toc_entry_offset + (MANIFEST_V2_TOC_ENTRY_SIZE * start);

	TEST_START;

	manifest_flash_v2_testing_init_and_verify (test, &manifest, 0x10000, PFM_MAGIC_NUM,
		PFM_V2_MAGIC_NUM, &PFM_V2.manifest, 0, false, 0);

	status = mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.start_sha256,
		&manifest.hash_mock, 0);
	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.update,
		&manifest.hash_mock, 0, MOCK_ARG_PTR_CONTAINS (data->toc, MANIFEST_V2_TOC_HEADER_SIZE),
		MOCK_ARG (MANIFEST_V2_TOC_HEADER_SIZE));

	status = mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash,
		FLASH_READ_FAILED, MOCK_ARG (manifest.addr + toc_entry_offset), MOCK_ARG_NOT_NULL,
		MOCK_ARG (first_entry - toc_entry_offset));

	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.cancel,
		&manifest.hash_mock, 0);

	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_read_element_data (&manifest.test, &manifest.hash_mock.base,
		MANIFEST_PLATFORM_ID, 1, MANIFEST_NO_PARENT, 0, &found, &format, &total, &element,
		sizeof (buffer));
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	manifest_flash_v2_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_v2_test_read_element_data_toc_entry_read_error (CuTest *test)
{
	struct manifest_flash_v2_testing manifest;
	int status;
	uint8_t buffer[PFM_V2.manifest.plat_id_len];
	uint8_t *element = buffer;
	size_t total = 0;
	uint8_t format = 0xff;
	uint8_t found = 0xff;
	const struct manifest_v2_testing_data *data = &PFM_V2.manifest;
	int start = 0;
	uint32_t toc_entry_offset = MANIFEST_V2_TOC_ENTRY_OFFSET;
	uint32_t first_entry = toc_entry_offset + (MANIFEST_V2_TOC_ENTRY_SIZE * start);

	TEST_START;

	manifest_flash_v2_testing_init_and_verify (test, &manifest, 0x10000, PFM_MAGIC_NUM,
		PFM_V2_MAGIC_NUM, &PFM_V2.manifest, 0, false, 0);

	status = mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.start_sha256,
		&manifest.hash_mock, 0);
	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.update,
		&manifest.hash_mock, 0, MOCK_ARG_PTR_CONTAINS (data->toc, MANIFEST_V2_TOC_HEADER_SIZE),
		MOCK_ARG (MANIFEST_V2_TOC_HEADER_SIZE));

	status = flash_mock_expect_verify_flash_and_hash (&manifest.flash, &manifest.hash_mock,
		manifest.addr + toc_entry_offset, data->raw + toc_entry_offset,
		first_entry - toc_entry_offset);

	status |= mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash,
		FLASH_READ_FAILED, MOCK_ARG (manifest.addr + toc_entry_offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));

	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.cancel,
		&manifest.hash_mock, 0);

	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_read_element_data (&manifest.test, &manifest.hash_mock.base,
		MANIFEST_PLATFORM_ID, 0, MANIFEST_NO_PARENT, 0, &found, &format, &total, &element,
		sizeof (buffer));
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	manifest_flash_v2_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_v2_test_read_element_data_toc_entry_hash_error (CuTest *test)
{
	struct manifest_flash_v2_testing manifest;
	int status;
	uint8_t buffer[PFM_V2.manifest.plat_id_len];
	uint8_t *element = buffer;
	size_t total = 0;
	uint8_t format = 0xff;
	uint8_t found = 0xff;
	const struct manifest_v2_testing_data *data = &PFM_V2.manifest;
	int start = 0;
	uint32_t toc_entry_offset = MANIFEST_V2_TOC_ENTRY_OFFSET;
	uint32_t first_entry = toc_entry_offset + (MANIFEST_V2_TOC_ENTRY_SIZE * start);
	const struct manifest_toc_entry *toc_entries =
		(struct manifest_toc_entry*) (data->raw + toc_entry_offset);

	TEST_START;

	manifest_flash_v2_testing_init_and_verify (test, &manifest, 0x10000, PFM_MAGIC_NUM,
		PFM_V2_MAGIC_NUM, &PFM_V2.manifest, 0, false, 0);

	status = mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.start_sha256,
		&manifest.hash_mock, 0);
	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.update,
		&manifest.hash_mock, 0, MOCK_ARG_PTR_CONTAINS (data->toc, MANIFEST_V2_TOC_HEADER_SIZE),
		MOCK_ARG (MANIFEST_V2_TOC_HEADER_SIZE));

	status = flash_mock_expect_verify_flash_and_hash (&manifest.flash, &manifest.hash_mock,
		manifest.addr + toc_entry_offset, data->raw + toc_entry_offset,
		first_entry - toc_entry_offset);

	status |= mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash,
		0, MOCK_ARG (manifest.addr + toc_entry_offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));
	status |= mock_expect_output (&manifest.flash.mock, 1, toc_entries, MANIFEST_V2_TOC_ENTRY_SIZE,
		2);

	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.update,
		&manifest.hash_mock, HASH_ENGINE_UPDATE_FAILED,
		MOCK_ARG_PTR_CONTAINS (toc_entries, MANIFEST_V2_TOC_ENTRY_SIZE),
		MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));

	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.cancel,
		&manifest.hash_mock, 0);

	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_read_element_data (&manifest.test, &manifest.hash_mock.base,
		MANIFEST_PLATFORM_ID, 0, MANIFEST_NO_PARENT, 0, &found, &format, &total, &element,
		sizeof (buffer));
	CuAssertIntEquals (test, HASH_ENGINE_UPDATE_FAILED, status);

	manifest_flash_v2_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_v2_test_read_element_data_toc_middle_read_error (CuTest *test)
{
	struct manifest_flash_v2_testing manifest;
	int status;
	uint8_t buffer[PFM_V2.manifest.plat_id_len];
	uint8_t *element = buffer;
	size_t total = 0;
	uint8_t format = 0xff;
	uint8_t found = 0xff;
	const struct manifest_v2_testing_data *data = &PFM_V2.manifest;
	int start = 0;
	int entry = PFM_V2.manifest.plat_id_entry;
	int hash_id = PFM_V2.manifest.plat_id_hash;
	uint32_t toc_entry_offset = MANIFEST_V2_TOC_ENTRY_OFFSET;
	uint32_t first_entry = toc_entry_offset + (MANIFEST_V2_TOC_ENTRY_SIZE * start);
	uint32_t last_entry = toc_entry_offset + (MANIFEST_V2_TOC_ENTRY_SIZE * (entry + 1));
	uint32_t hash_offset;
	const struct manifest_toc_entry *toc_entries =
		(struct manifest_toc_entry*) (data->raw + toc_entry_offset);
	int i;

	TEST_START;

	manifest_flash_v2_testing_init_and_verify (test, &manifest, 0x10000, PFM_MAGIC_NUM,
		PFM_V2_MAGIC_NUM, &PFM_V2.manifest, 0, false, 0);

	hash_offset = toc_entry_offset + (MANIFEST_V2_TOC_ENTRY_SIZE * data->toc_entries) +
		(data->toc_hash_len * hash_id);

	status = mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.start_sha256,
		&manifest.hash_mock, 0);
	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.update,
		&manifest.hash_mock, 0, MOCK_ARG_PTR_CONTAINS (data->toc, MANIFEST_V2_TOC_HEADER_SIZE),
		MOCK_ARG (MANIFEST_V2_TOC_HEADER_SIZE));

	status = flash_mock_expect_verify_flash_and_hash (&manifest.flash, &manifest.hash_mock,
		manifest.addr + toc_entry_offset, data->raw + toc_entry_offset,
		first_entry - toc_entry_offset);

	for (i = start; i <= entry; i++) {
		status |= mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash,
			0, MOCK_ARG (manifest.addr + toc_entry_offset + (i * MANIFEST_V2_TOC_ENTRY_SIZE)),
			MOCK_ARG_NOT_NULL, MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));
		status |= mock_expect_output (&manifest.flash.mock, 1, &toc_entries[i],
			MANIFEST_V2_TOC_ENTRY_SIZE, 2);

		status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.update,
			&manifest.hash_mock, 0,
			MOCK_ARG_PTR_CONTAINS (&toc_entries[i], MANIFEST_V2_TOC_ENTRY_SIZE),
			MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));
	}

	status |= mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash,
		FLASH_READ_FAILED, MOCK_ARG (manifest.addr + last_entry), MOCK_ARG_NOT_NULL,
		MOCK_ARG (hash_offset - last_entry));

	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.cancel,
		&manifest.hash_mock, 0);

	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_read_element_data (&manifest.test, &manifest.hash_mock.base,
		MANIFEST_PLATFORM_ID, 0, MANIFEST_NO_PARENT, 0, &found, &format, &total, &element,
		sizeof (buffer));
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	manifest_flash_v2_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_v2_test_read_element_data_toc_element_hash_read_error (CuTest *test)
{
	struct manifest_flash_v2_testing manifest;
	int status;
	uint8_t buffer[PFM_V2.manifest.plat_id_len];
	uint8_t *element = buffer;
	size_t total = 0;
	uint8_t format = 0xff;
	uint8_t found = 0xff;
	const struct manifest_v2_testing_data *data = &PFM_V2.manifest;
	int start = 0;
	int entry = PFM_V2.manifest.plat_id_entry;
	int hash_id = PFM_V2.manifest.plat_id_hash;
	uint32_t toc_entry_offset = MANIFEST_V2_TOC_ENTRY_OFFSET;
	uint32_t first_entry = toc_entry_offset + (MANIFEST_V2_TOC_ENTRY_SIZE * start);
	uint32_t last_entry = toc_entry_offset + (MANIFEST_V2_TOC_ENTRY_SIZE * (entry + 1));
	uint32_t hash_offset;
	const struct manifest_toc_entry *toc_entries =
		(struct manifest_toc_entry*) (data->raw + toc_entry_offset);
	int i;

	TEST_START;

	manifest_flash_v2_testing_init_and_verify (test, &manifest, 0x10000, PFM_MAGIC_NUM,
		PFM_V2_MAGIC_NUM, &PFM_V2.manifest, 0, false, 0);

	hash_offset = toc_entry_offset + (MANIFEST_V2_TOC_ENTRY_SIZE * data->toc_entries) +
		(data->toc_hash_len * hash_id);

	status = mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.start_sha256,
		&manifest.hash_mock, 0);
	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.update,
		&manifest.hash_mock, 0, MOCK_ARG_PTR_CONTAINS (data->toc, MANIFEST_V2_TOC_HEADER_SIZE),
		MOCK_ARG (MANIFEST_V2_TOC_HEADER_SIZE));

	status = flash_mock_expect_verify_flash_and_hash (&manifest.flash, &manifest.hash_mock,
		manifest.addr + toc_entry_offset, data->raw + toc_entry_offset,
		first_entry - toc_entry_offset);

	for (i = start; i <= entry; i++) {
		status |= mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash,
			0, MOCK_ARG (manifest.addr + toc_entry_offset + (i * MANIFEST_V2_TOC_ENTRY_SIZE)),
			MOCK_ARG_NOT_NULL, MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));
		status |= mock_expect_output (&manifest.flash.mock, 1, &toc_entries[i],
			MANIFEST_V2_TOC_ENTRY_SIZE, 2);

		status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.update,
			&manifest.hash_mock, 0,
			MOCK_ARG_PTR_CONTAINS (&toc_entries[i], MANIFEST_V2_TOC_ENTRY_SIZE),
			MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));
	}

	status |= flash_mock_expect_verify_flash_and_hash (&manifest.flash, &manifest.hash_mock,
			manifest.addr + last_entry, data->raw + last_entry, hash_offset - last_entry);

	status |= mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash,
		FLASH_READ_FAILED, MOCK_ARG (manifest.addr + hash_offset), MOCK_ARG_NOT_NULL,
		MOCK_ARG (data->toc_hash_len));

	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.cancel,
		&manifest.hash_mock, 0);

	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_read_element_data (&manifest.test, &manifest.hash_mock.base,
		MANIFEST_PLATFORM_ID, 0, MANIFEST_NO_PARENT, 0, &found, &format, &total, &element,
		sizeof (buffer));
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	manifest_flash_v2_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_v2_test_read_element_data_toc_element_hash_hash_error (CuTest *test)
{
	struct manifest_flash_v2_testing manifest;
	int status;
	uint8_t buffer[PFM_V2.manifest.plat_id_len];
	uint8_t *element = buffer;
	size_t total = 0;
	uint8_t format = 0xff;
	uint8_t found = 0xff;
	const struct manifest_v2_testing_data *data = &PFM_V2.manifest;
	int start = 0;
	int entry = PFM_V2.manifest.plat_id_entry;
	int hash_id = PFM_V2.manifest.plat_id_hash;
	uint32_t toc_entry_offset = MANIFEST_V2_TOC_ENTRY_OFFSET;
	uint32_t first_entry = toc_entry_offset + (MANIFEST_V2_TOC_ENTRY_SIZE * start);
	uint32_t last_entry = toc_entry_offset + (MANIFEST_V2_TOC_ENTRY_SIZE * (entry + 1));
	uint32_t hash_offset;
	const struct manifest_toc_entry *toc_entries =
		(struct manifest_toc_entry*) (data->raw + toc_entry_offset);
	int i;

	TEST_START;

	manifest_flash_v2_testing_init_and_verify (test, &manifest, 0x10000, PFM_MAGIC_NUM,
		PFM_V2_MAGIC_NUM, &PFM_V2.manifest, 0, false, 0);

	hash_offset = toc_entry_offset + (MANIFEST_V2_TOC_ENTRY_SIZE * data->toc_entries) +
		(data->toc_hash_len * hash_id);

	status = mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.start_sha256,
		&manifest.hash_mock, 0);
	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.update,
		&manifest.hash_mock, 0, MOCK_ARG_PTR_CONTAINS (data->toc, MANIFEST_V2_TOC_HEADER_SIZE),
		MOCK_ARG (MANIFEST_V2_TOC_HEADER_SIZE));

	status = flash_mock_expect_verify_flash_and_hash (&manifest.flash, &manifest.hash_mock,
		manifest.addr + toc_entry_offset, data->raw + toc_entry_offset,
		first_entry - toc_entry_offset);

	for (i = start; i <= entry; i++) {
		status |= mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash,
			0, MOCK_ARG (manifest.addr + toc_entry_offset + (i * MANIFEST_V2_TOC_ENTRY_SIZE)),
			MOCK_ARG_NOT_NULL, MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));
		status |= mock_expect_output (&manifest.flash.mock, 1, &toc_entries[i],
			MANIFEST_V2_TOC_ENTRY_SIZE, 2);

		status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.update,
			&manifest.hash_mock, 0,
			MOCK_ARG_PTR_CONTAINS (&toc_entries[i], MANIFEST_V2_TOC_ENTRY_SIZE),
			MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));
	}

	status |= flash_mock_expect_verify_flash_and_hash (&manifest.flash, &manifest.hash_mock,
			manifest.addr + last_entry, data->raw + last_entry, hash_offset - last_entry);

	status |= mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash, 0,
		MOCK_ARG (manifest.addr + hash_offset), MOCK_ARG_NOT_NULL, MOCK_ARG (data->toc_hash_len));
	status |= mock_expect_output (&manifest.flash.mock, 1, data->raw + hash_offset,
		data->length - hash_offset, 2);

	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.update,
		&manifest.hash_mock, HASH_ENGINE_UPDATE_FAILED,
		MOCK_ARG_PTR_CONTAINS (&data->raw[hash_offset], data->toc_hash_len),
		MOCK_ARG (data->toc_hash_len));

	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.cancel,
		&manifest.hash_mock, 0);

	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_read_element_data (&manifest.test, &manifest.hash_mock.base,
		MANIFEST_PLATFORM_ID, 0, MANIFEST_NO_PARENT, 0, &found, &format, &total, &element,
		sizeof (buffer));
	CuAssertIntEquals (test, HASH_ENGINE_UPDATE_FAILED, status);

	manifest_flash_v2_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_v2_test_read_element_data_toc_end_read_error (CuTest *test)
{
	struct manifest_flash_v2_testing manifest;
	int status;
	uint8_t buffer[PFM_V2.flash_dev_len];
	uint8_t *element = buffer;
	size_t total = 0;
	uint8_t format = 0xff;
	uint8_t found = 0xff;
	const struct manifest_v2_testing_data *data = &PFM_V2.manifest;
	int start = 0;
	int entry = PFM_V2.flash_dev_entry;
	int hash_id = PFM_V2.flash_dev_hash;
	uint32_t toc_entry_offset = MANIFEST_V2_TOC_ENTRY_OFFSET;
	uint32_t first_entry = toc_entry_offset + (MANIFEST_V2_TOC_ENTRY_SIZE * start);
	uint32_t last_entry = toc_entry_offset + (MANIFEST_V2_TOC_ENTRY_SIZE * (entry + 1));
	uint32_t hash_offset;
	uint32_t after_hash;
	const struct manifest_toc_entry *toc_entries =
		(struct manifest_toc_entry*) (data->raw + toc_entry_offset);
	int i;

	TEST_START;

	manifest_flash_v2_testing_init_and_verify (test, &manifest, 0x10000, PFM_MAGIC_NUM,
		PFM_V2_MAGIC_NUM, &PFM_V2.manifest, 0, false, 0);

	hash_offset = toc_entry_offset + (MANIFEST_V2_TOC_ENTRY_SIZE * data->toc_entries) +
		(data->toc_hash_len * hash_id);
	after_hash = hash_offset + data->toc_hash_len;

	status = mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.start_sha256,
		&manifest.hash_mock, 0);
	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.update,
		&manifest.hash_mock, 0, MOCK_ARG_PTR_CONTAINS (data->toc, MANIFEST_V2_TOC_HEADER_SIZE),
		MOCK_ARG (MANIFEST_V2_TOC_HEADER_SIZE));

	status = flash_mock_expect_verify_flash_and_hash (&manifest.flash, &manifest.hash_mock,
		manifest.addr + toc_entry_offset, data->raw + toc_entry_offset,
		first_entry - toc_entry_offset);

	for (i = start; i <= entry; i++) {
		status |= mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash,
			0, MOCK_ARG (manifest.addr + toc_entry_offset + (i * MANIFEST_V2_TOC_ENTRY_SIZE)),
			MOCK_ARG_NOT_NULL, MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));
		status |= mock_expect_output (&manifest.flash.mock, 1, &toc_entries[i],
			MANIFEST_V2_TOC_ENTRY_SIZE, 2);

		status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.update,
			&manifest.hash_mock, 0,
			MOCK_ARG_PTR_CONTAINS (&toc_entries[i], MANIFEST_V2_TOC_ENTRY_SIZE),
			MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));
	}

	status |= flash_mock_expect_verify_flash_and_hash (&manifest.flash, &manifest.hash_mock,
			manifest.addr + last_entry, data->raw + last_entry, hash_offset - last_entry);

	status |= mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash, 0,
		MOCK_ARG (manifest.addr + hash_offset), MOCK_ARG_NOT_NULL, MOCK_ARG (data->toc_hash_len));
	status |= mock_expect_output (&manifest.flash.mock, 1, data->raw + hash_offset,
		data->length - hash_offset, 2);

	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.update,
		&manifest.hash_mock, 0,
		MOCK_ARG_PTR_CONTAINS (&data->raw[hash_offset], data->toc_hash_len),
		MOCK_ARG (data->toc_hash_len));

	status |= mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash,
		FLASH_READ_FAILED, MOCK_ARG (manifest.addr + after_hash), MOCK_ARG_NOT_NULL,
		MOCK_ARG (data->toc_hash_offset - after_hash));

	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.cancel,
		&manifest.hash_mock, 0);

	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_read_element_data (&manifest.test, &manifest.hash_mock.base,
		PFM_FLASH_DEVICE, 0, MANIFEST_NO_PARENT, 0, &found, &format, &total, &element,
		sizeof (buffer));
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	manifest_flash_v2_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_v2_test_read_element_data_toc_end_no_element_hash_read_error (
	CuTest *test)
{
	struct manifest_flash_v2_testing manifest;
	int status;
	uint8_t buffer[PFM_V2_NO_FW_HASHES.fw[0].fw_len];
	uint8_t *element = buffer;
	size_t total = 0;
	uint8_t format = 0xff;
	uint8_t found = 0xff;
	const struct manifest_v2_testing_data *data = &PFM_V2_NO_FW_HASHES.manifest;
	int start = 0;
	int entry = PFM_V2_NO_FW_HASHES.fw[0].fw_entry;
	uint32_t toc_entry_offset = MANIFEST_V2_TOC_ENTRY_OFFSET;
	uint32_t first_entry = toc_entry_offset + (MANIFEST_V2_TOC_ENTRY_SIZE * start);
	uint32_t last_entry = toc_entry_offset + (MANIFEST_V2_TOC_ENTRY_SIZE * (entry + 1));
	const struct manifest_toc_entry *toc_entries =
		(struct manifest_toc_entry*) (data->raw + toc_entry_offset);
	int i;

	TEST_START;

	manifest_flash_v2_testing_init_and_verify (test, &manifest, 0x10000, PFM_MAGIC_NUM,
		PFM_V2_MAGIC_NUM, &PFM_V2_NO_FW_HASHES.manifest, 0, false, 0);

	status = mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.start_sha256,
		&manifest.hash_mock, 0);
	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.update,
		&manifest.hash_mock, 0, MOCK_ARG_PTR_CONTAINS (data->toc, MANIFEST_V2_TOC_HEADER_SIZE),
		MOCK_ARG (MANIFEST_V2_TOC_HEADER_SIZE));

	status = flash_mock_expect_verify_flash_and_hash (&manifest.flash, &manifest.hash_mock,
		manifest.addr + toc_entry_offset, data->raw + toc_entry_offset,
		first_entry - toc_entry_offset);

	for (i = start; i <= entry; i++) {
		status |= mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash,
			0, MOCK_ARG (manifest.addr + toc_entry_offset + (i * MANIFEST_V2_TOC_ENTRY_SIZE)),
			MOCK_ARG_NOT_NULL, MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));
		status |= mock_expect_output (&manifest.flash.mock, 1, &toc_entries[i],
			MANIFEST_V2_TOC_ENTRY_SIZE, 2);

		status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.update,
			&manifest.hash_mock, 0,
			MOCK_ARG_PTR_CONTAINS (&toc_entries[i], MANIFEST_V2_TOC_ENTRY_SIZE),
			MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));
	}

	status |= mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash,
		FLASH_READ_FAILED, MOCK_ARG (manifest.addr + last_entry), MOCK_ARG_NOT_NULL,
		MOCK_ARG (data->toc_hash_offset - last_entry));

	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.cancel,
		&manifest.hash_mock, 0);

	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_read_element_data (&manifest.test, &manifest.hash_mock.base,
		PFM_FIRMWARE, 0, MANIFEST_NO_PARENT, 0, &found, &format, &total, &element, sizeof (buffer));
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	manifest_flash_v2_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_v2_test_read_element_data_finish_toc_hash_error (CuTest *test)
{
	struct manifest_flash_v2_testing manifest;
	int status;
	uint8_t buffer[PFM_V2.manifest.plat_id_len];
	uint8_t *element = buffer;
	size_t total = 0;
	uint8_t format = 0xff;
	uint8_t found = 0xff;
	const struct manifest_v2_testing_data *data = &PFM_V2.manifest;
	int start = 0;
	int entry = PFM_V2.manifest.plat_id_entry;
	int hash_id = PFM_V2.manifest.plat_id_hash;
	uint32_t toc_entry_offset = MANIFEST_V2_TOC_ENTRY_OFFSET;
	uint32_t first_entry = toc_entry_offset + (MANIFEST_V2_TOC_ENTRY_SIZE * start);
	uint32_t last_entry = toc_entry_offset + (MANIFEST_V2_TOC_ENTRY_SIZE * (entry + 1));
	uint32_t hash_offset;
	uint32_t after_hash;
	const struct manifest_toc_entry *toc_entries =
		(struct manifest_toc_entry*) (data->raw + toc_entry_offset);
	int i;

	TEST_START;

	manifest_flash_v2_testing_init_and_verify (test, &manifest, 0x10000, PFM_MAGIC_NUM,
		PFM_V2_MAGIC_NUM, &PFM_V2.manifest, 0, false, 0);

	hash_offset = toc_entry_offset + (MANIFEST_V2_TOC_ENTRY_SIZE * data->toc_entries) +
		(data->toc_hash_len * hash_id);
	after_hash = hash_offset + data->toc_hash_len;

	status = mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.start_sha256,
		&manifest.hash_mock, 0);
	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.update,
		&manifest.hash_mock, 0, MOCK_ARG_PTR_CONTAINS (data->toc, MANIFEST_V2_TOC_HEADER_SIZE),
		MOCK_ARG (MANIFEST_V2_TOC_HEADER_SIZE));

	status = flash_mock_expect_verify_flash_and_hash (&manifest.flash, &manifest.hash_mock,
		manifest.addr + toc_entry_offset, data->raw + toc_entry_offset,
		first_entry - toc_entry_offset);

	for (i = start; i <= entry; i++) {
		status |= mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash,
			0, MOCK_ARG (manifest.addr + toc_entry_offset + (i * MANIFEST_V2_TOC_ENTRY_SIZE)),
			MOCK_ARG_NOT_NULL, MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));
		status |= mock_expect_output (&manifest.flash.mock, 1, &toc_entries[i],
			MANIFEST_V2_TOC_ENTRY_SIZE, 2);

		status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.update,
			&manifest.hash_mock, 0,
			MOCK_ARG_PTR_CONTAINS (&toc_entries[i], MANIFEST_V2_TOC_ENTRY_SIZE),
			MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));
	}

	status |= flash_mock_expect_verify_flash_and_hash (&manifest.flash, &manifest.hash_mock,
			manifest.addr + last_entry, data->raw + last_entry, hash_offset - last_entry);

	status |= mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash, 0,
		MOCK_ARG (manifest.addr + hash_offset), MOCK_ARG_NOT_NULL, MOCK_ARG (data->toc_hash_len));
	status |= mock_expect_output (&manifest.flash.mock, 1, data->raw + hash_offset,
		data->length - hash_offset, 2);

	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.update,
		&manifest.hash_mock, 0,
		MOCK_ARG_PTR_CONTAINS (&data->raw[hash_offset], data->toc_hash_len),
		MOCK_ARG (data->toc_hash_len));

	status |= flash_mock_expect_verify_flash_and_hash (&manifest.flash, &manifest.hash_mock,
		manifest.addr + after_hash, data->raw + after_hash, data->toc_hash_offset - after_hash);

	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.finish,
		&manifest.hash_mock, HASH_ENGINE_FINISH_FAILED, MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA512_HASH_LENGTH));

	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.cancel,
		&manifest.hash_mock, 0);

	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_read_element_data (&manifest.test, &manifest.hash_mock.base,
		MANIFEST_PLATFORM_ID, 0, MANIFEST_NO_PARENT, 0, &found, &format, &total, &element,
		sizeof (buffer));
	CuAssertIntEquals (test, HASH_ENGINE_FINISH_FAILED, status);

	manifest_flash_v2_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_v2_test_read_element_data_start_element_hash_error (CuTest *test)
{
	struct manifest_flash_v2_testing manifest;
	int status;
	uint8_t buffer[PFM_V2.manifest.plat_id_len];
	uint8_t *element = buffer;
	size_t total = 0;
	uint8_t format = 0xff;
	uint8_t found = 0xff;
	const struct manifest_v2_testing_data *data = &PFM_V2.manifest;
	int start = 0;
	int entry = PFM_V2.manifest.plat_id_entry;
	int hash_id = PFM_V2.manifest.plat_id_hash;
	uint32_t toc_entry_offset = MANIFEST_V2_TOC_ENTRY_OFFSET;
	uint32_t first_entry = toc_entry_offset + (MANIFEST_V2_TOC_ENTRY_SIZE * start);
	uint32_t last_entry = toc_entry_offset + (MANIFEST_V2_TOC_ENTRY_SIZE * (entry + 1));
	uint32_t hash_offset;
	uint32_t after_hash;
	const struct manifest_toc_entry *toc_entries =
		(struct manifest_toc_entry*) (data->raw + toc_entry_offset);
	int i;

	TEST_START;

	manifest_flash_v2_testing_init_and_verify (test, &manifest, 0x10000, PFM_MAGIC_NUM,
		PFM_V2_MAGIC_NUM, &PFM_V2.manifest, 0, false, 0);

	hash_offset = toc_entry_offset + (MANIFEST_V2_TOC_ENTRY_SIZE * data->toc_entries) +
		(data->toc_hash_len * hash_id);
	after_hash = hash_offset + data->toc_hash_len;

	status = mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.start_sha256,
		&manifest.hash_mock, 0);
	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.update,
		&manifest.hash_mock, 0, MOCK_ARG_PTR_CONTAINS (data->toc, MANIFEST_V2_TOC_HEADER_SIZE),
		MOCK_ARG (MANIFEST_V2_TOC_HEADER_SIZE));

	status = flash_mock_expect_verify_flash_and_hash (&manifest.flash, &manifest.hash_mock,
		manifest.addr + toc_entry_offset, data->raw + toc_entry_offset,
		first_entry - toc_entry_offset);

	for (i = start; i <= entry; i++) {
		status |= mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash,
			0, MOCK_ARG (manifest.addr + toc_entry_offset + (i * MANIFEST_V2_TOC_ENTRY_SIZE)),
			MOCK_ARG_NOT_NULL, MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));
		status |= mock_expect_output (&manifest.flash.mock, 1, &toc_entries[i],
			MANIFEST_V2_TOC_ENTRY_SIZE, 2);

		status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.update,
			&manifest.hash_mock, 0,
			MOCK_ARG_PTR_CONTAINS (&toc_entries[i], MANIFEST_V2_TOC_ENTRY_SIZE),
			MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));
	}

	status |= flash_mock_expect_verify_flash_and_hash (&manifest.flash, &manifest.hash_mock,
			manifest.addr + last_entry, data->raw + last_entry, hash_offset - last_entry);

	status |= mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash, 0,
		MOCK_ARG (manifest.addr + hash_offset), MOCK_ARG_NOT_NULL, MOCK_ARG (data->toc_hash_len));
	status |= mock_expect_output (&manifest.flash.mock, 1, data->raw + hash_offset,
		data->length - hash_offset, 2);

	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.update,
		&manifest.hash_mock, 0,
		MOCK_ARG_PTR_CONTAINS (&data->raw[hash_offset], data->toc_hash_len),
		MOCK_ARG (data->toc_hash_len));

	status |= flash_mock_expect_verify_flash_and_hash (&manifest.flash, &manifest.hash_mock,
		manifest.addr + after_hash, data->raw + after_hash, data->toc_hash_offset - after_hash);

	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.finish,
		&manifest.hash_mock, 0, MOCK_ARG_NOT_NULL, MOCK_ARG (SHA512_HASH_LENGTH));
	status |= mock_expect_output (&manifest.hash_mock.mock, 0, data->toc_hash, data->toc_hash_len,
		1);

	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.start_sha256,
		&manifest.hash_mock, HASH_ENGINE_START_SHA256_FAILED);

	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_read_element_data (&manifest.test, &manifest.hash_mock.base,
		MANIFEST_PLATFORM_ID, 0, MANIFEST_NO_PARENT, 0, &found, &format, &total, &element,
		sizeof (buffer));
	CuAssertIntEquals (test, HASH_ENGINE_START_SHA256_FAILED, status);

	manifest_flash_v2_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_v2_test_read_element_data_element_offset_data_read_error (CuTest *test)
{
	struct manifest_flash_v2_testing manifest;
	int status;
	uint8_t buffer[PFM_V2.manifest.plat_id_len];
	uint8_t *element = buffer;
	size_t total = 0;
	uint8_t format = 0xff;
	uint8_t found = 0xff;
	const struct manifest_v2_testing_data *data = &PFM_V2.manifest;
	int start = 0;
	int entry = PFM_V2.manifest.plat_id_entry;
	int hash_id = PFM_V2.manifest.plat_id_hash;
	uint32_t offset = PFM_V2.manifest.plat_id_offset;
	uint32_t read_offset = 4;
	uint32_t toc_entry_offset = MANIFEST_V2_TOC_ENTRY_OFFSET;
	uint32_t first_entry = toc_entry_offset + (MANIFEST_V2_TOC_ENTRY_SIZE * start);
	uint32_t last_entry = toc_entry_offset + (MANIFEST_V2_TOC_ENTRY_SIZE * (entry + 1));
	uint32_t hash_offset;
	uint32_t after_hash;
	const struct manifest_toc_entry *toc_entries =
		(struct manifest_toc_entry*) (data->raw + toc_entry_offset);
	int i;

	TEST_START;

	manifest_flash_v2_testing_init_and_verify (test, &manifest, 0x10000, PFM_MAGIC_NUM,
		PFM_V2_MAGIC_NUM, &PFM_V2.manifest, 0, false, 0);

	hash_offset = toc_entry_offset + (MANIFEST_V2_TOC_ENTRY_SIZE * data->toc_entries) +
		(data->toc_hash_len * hash_id);
	after_hash = hash_offset + data->toc_hash_len;

	status = mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.start_sha256,
		&manifest.hash_mock, 0);
	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.update,
		&manifest.hash_mock, 0, MOCK_ARG_PTR_CONTAINS (data->toc, MANIFEST_V2_TOC_HEADER_SIZE),
		MOCK_ARG (MANIFEST_V2_TOC_HEADER_SIZE));

	status = flash_mock_expect_verify_flash_and_hash (&manifest.flash, &manifest.hash_mock,
		manifest.addr + toc_entry_offset, data->raw + toc_entry_offset,
		first_entry - toc_entry_offset);

	for (i = start; i <= entry; i++) {
		status |= mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash,
			0, MOCK_ARG (manifest.addr + toc_entry_offset + (i * MANIFEST_V2_TOC_ENTRY_SIZE)),
			MOCK_ARG_NOT_NULL, MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));
		status |= mock_expect_output (&manifest.flash.mock, 1, &toc_entries[i],
			MANIFEST_V2_TOC_ENTRY_SIZE, 2);

		status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.update,
			&manifest.hash_mock, 0,
			MOCK_ARG_PTR_CONTAINS (&toc_entries[i], MANIFEST_V2_TOC_ENTRY_SIZE),
			MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));
	}

	status |= flash_mock_expect_verify_flash_and_hash (&manifest.flash, &manifest.hash_mock,
			manifest.addr + last_entry, data->raw + last_entry, hash_offset - last_entry);

	status |= mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash, 0,
		MOCK_ARG (manifest.addr + hash_offset), MOCK_ARG_NOT_NULL, MOCK_ARG (data->toc_hash_len));
	status |= mock_expect_output (&manifest.flash.mock, 1, data->raw + hash_offset,
		data->length - hash_offset, 2);

	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.update,
		&manifest.hash_mock, 0,
		MOCK_ARG_PTR_CONTAINS (&data->raw[hash_offset], data->toc_hash_len),
		MOCK_ARG (data->toc_hash_len));

	status |= flash_mock_expect_verify_flash_and_hash (&manifest.flash, &manifest.hash_mock,
		manifest.addr + after_hash, data->raw + after_hash, data->toc_hash_offset - after_hash);

	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.finish,
		&manifest.hash_mock, 0, MOCK_ARG_NOT_NULL, MOCK_ARG (SHA512_HASH_LENGTH));
	status |= mock_expect_output (&manifest.hash_mock.mock, 0, data->toc_hash, data->toc_hash_len,
		1);

	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.start_sha256,
		&manifest.hash_mock, 0);

	status |= mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash,
		FLASH_READ_FAILED, MOCK_ARG (manifest.addr + offset), MOCK_ARG_NOT_NULL,
		MOCK_ARG (read_offset));

	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.cancel,
		&manifest.hash_mock, 0);

	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_read_element_data (&manifest.test, &manifest.hash_mock.base,
		MANIFEST_PLATFORM_ID, 0, MANIFEST_NO_PARENT, read_offset, &found, &format, &total, &element,
		sizeof (buffer));
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	manifest_flash_v2_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_v2_test_read_element_data_element_read_error (CuTest *test)
{
	struct manifest_flash_v2_testing manifest;
	int status;
	uint8_t buffer[PFM_V2.manifest.plat_id_len];
	uint8_t *element = buffer;
	size_t total = 0;
	uint8_t format = 0xff;
	uint8_t found = 0xff;
	const struct manifest_v2_testing_data *data = &PFM_V2.manifest;
	int start = 0;
	int entry = PFM_V2.manifest.plat_id_entry;
	int hash_id = PFM_V2.manifest.plat_id_hash;
	uint32_t offset = PFM_V2.manifest.plat_id_offset;
	size_t read_len = sizeof (buffer);
	uint32_t toc_entry_offset = MANIFEST_V2_TOC_ENTRY_OFFSET;
	uint32_t first_entry = toc_entry_offset + (MANIFEST_V2_TOC_ENTRY_SIZE * start);
	uint32_t last_entry = toc_entry_offset + (MANIFEST_V2_TOC_ENTRY_SIZE * (entry + 1));
	uint32_t hash_offset;
	uint32_t after_hash;
	const struct manifest_toc_entry *toc_entries =
		(struct manifest_toc_entry*) (data->raw + toc_entry_offset);
	int i;

	TEST_START;

	manifest_flash_v2_testing_init_and_verify (test, &manifest, 0x10000, PFM_MAGIC_NUM,
		PFM_V2_MAGIC_NUM, &PFM_V2.manifest, 0, false, 0);

	hash_offset = toc_entry_offset + (MANIFEST_V2_TOC_ENTRY_SIZE * data->toc_entries) +
		(data->toc_hash_len * hash_id);
	after_hash = hash_offset + data->toc_hash_len;

	status = mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.start_sha256,
		&manifest.hash_mock, 0);
	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.update,
		&manifest.hash_mock, 0, MOCK_ARG_PTR_CONTAINS (data->toc, MANIFEST_V2_TOC_HEADER_SIZE),
		MOCK_ARG (MANIFEST_V2_TOC_HEADER_SIZE));

	status = flash_mock_expect_verify_flash_and_hash (&manifest.flash, &manifest.hash_mock,
		manifest.addr + toc_entry_offset, data->raw + toc_entry_offset,
		first_entry - toc_entry_offset);

	for (i = start; i <= entry; i++) {
		status |= mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash,
			0, MOCK_ARG (manifest.addr + toc_entry_offset + (i * MANIFEST_V2_TOC_ENTRY_SIZE)),
			MOCK_ARG_NOT_NULL, MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));
		status |= mock_expect_output (&manifest.flash.mock, 1, &toc_entries[i],
			MANIFEST_V2_TOC_ENTRY_SIZE, 2);

		status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.update,
			&manifest.hash_mock, 0,
			MOCK_ARG_PTR_CONTAINS (&toc_entries[i], MANIFEST_V2_TOC_ENTRY_SIZE),
			MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));
	}

	status |= flash_mock_expect_verify_flash_and_hash (&manifest.flash, &manifest.hash_mock,
			manifest.addr + last_entry, data->raw + last_entry, hash_offset - last_entry);

	status |= mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash, 0,
		MOCK_ARG (manifest.addr + hash_offset), MOCK_ARG_NOT_NULL, MOCK_ARG (data->toc_hash_len));
	status |= mock_expect_output (&manifest.flash.mock, 1, data->raw + hash_offset,
		data->length - hash_offset, 2);

	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.update,
		&manifest.hash_mock, 0,
		MOCK_ARG_PTR_CONTAINS (&data->raw[hash_offset], data->toc_hash_len),
		MOCK_ARG (data->toc_hash_len));

	status |= flash_mock_expect_verify_flash_and_hash (&manifest.flash, &manifest.hash_mock,
		manifest.addr + after_hash, data->raw + after_hash, data->toc_hash_offset - after_hash);

	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.finish,
		&manifest.hash_mock, 0, MOCK_ARG_NOT_NULL, MOCK_ARG (SHA512_HASH_LENGTH));
	status |= mock_expect_output (&manifest.hash_mock.mock, 0, data->toc_hash, data->toc_hash_len,
		1);

	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.start_sha256,
		&manifest.hash_mock, 0);

	status |= mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash,
		FLASH_READ_FAILED, MOCK_ARG (manifest.addr + offset), MOCK_ARG_NOT_NULL,
		MOCK_ARG (read_len));

	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.cancel,
		&manifest.hash_mock, 0);

	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_read_element_data (&manifest.test, &manifest.hash_mock.base,
		MANIFEST_PLATFORM_ID, 0, MANIFEST_NO_PARENT, 0, &found, &format, &total, &element,
		sizeof (buffer));
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	manifest_flash_v2_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_v2_test_read_element_data_element_hash_error (CuTest *test)
{
	struct manifest_flash_v2_testing manifest;
	int status;
	uint8_t buffer[PFM_V2.manifest.plat_id_len];
	uint8_t *element = buffer;
	size_t total = 0;
	uint8_t format = 0xff;
	uint8_t found = 0xff;
	const struct manifest_v2_testing_data *data = &PFM_V2.manifest;
	int start = 0;
	int entry = PFM_V2.manifest.plat_id_entry;
	int hash_id = PFM_V2.manifest.plat_id_hash;
	uint32_t offset = PFM_V2.manifest.plat_id_offset;
	size_t read_len = sizeof (buffer);
	uint32_t toc_entry_offset = MANIFEST_V2_TOC_ENTRY_OFFSET;
	uint32_t first_entry = toc_entry_offset + (MANIFEST_V2_TOC_ENTRY_SIZE * start);
	uint32_t last_entry = toc_entry_offset + (MANIFEST_V2_TOC_ENTRY_SIZE * (entry + 1));
	uint32_t hash_offset;
	uint32_t after_hash;
	const struct manifest_toc_entry *toc_entries =
		(struct manifest_toc_entry*) (data->raw + toc_entry_offset);
	int i;

	TEST_START;

	manifest_flash_v2_testing_init_and_verify (test, &manifest, 0x10000, PFM_MAGIC_NUM,
		PFM_V2_MAGIC_NUM, &PFM_V2.manifest, 0, false, 0);

	hash_offset = toc_entry_offset + (MANIFEST_V2_TOC_ENTRY_SIZE * data->toc_entries) +
		(data->toc_hash_len * hash_id);
	after_hash = hash_offset + data->toc_hash_len;

	status = mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.start_sha256,
		&manifest.hash_mock, 0);
	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.update,
		&manifest.hash_mock, 0, MOCK_ARG_PTR_CONTAINS (data->toc, MANIFEST_V2_TOC_HEADER_SIZE),
		MOCK_ARG (MANIFEST_V2_TOC_HEADER_SIZE));

	status = flash_mock_expect_verify_flash_and_hash (&manifest.flash, &manifest.hash_mock,
		manifest.addr + toc_entry_offset, data->raw + toc_entry_offset,
		first_entry - toc_entry_offset);

	for (i = start; i <= entry; i++) {
		status |= mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash,
			0, MOCK_ARG (manifest.addr + toc_entry_offset + (i * MANIFEST_V2_TOC_ENTRY_SIZE)),
			MOCK_ARG_NOT_NULL, MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));
		status |= mock_expect_output (&manifest.flash.mock, 1, &toc_entries[i],
			MANIFEST_V2_TOC_ENTRY_SIZE, 2);

		status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.update,
			&manifest.hash_mock, 0,
			MOCK_ARG_PTR_CONTAINS (&toc_entries[i], MANIFEST_V2_TOC_ENTRY_SIZE),
			MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));
	}

	status |= flash_mock_expect_verify_flash_and_hash (&manifest.flash, &manifest.hash_mock,
			manifest.addr + last_entry, data->raw + last_entry, hash_offset - last_entry);

	status |= mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash, 0,
		MOCK_ARG (manifest.addr + hash_offset), MOCK_ARG_NOT_NULL, MOCK_ARG (data->toc_hash_len));
	status |= mock_expect_output (&manifest.flash.mock, 1, data->raw + hash_offset,
		data->length - hash_offset, 2);

	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.update,
		&manifest.hash_mock, 0,
		MOCK_ARG_PTR_CONTAINS (&data->raw[hash_offset], data->toc_hash_len),
		MOCK_ARG (data->toc_hash_len));

	status |= flash_mock_expect_verify_flash_and_hash (&manifest.flash, &manifest.hash_mock,
		manifest.addr + after_hash, data->raw + after_hash, data->toc_hash_offset - after_hash);

	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.finish,
		&manifest.hash_mock, 0, MOCK_ARG_NOT_NULL, MOCK_ARG (SHA512_HASH_LENGTH));
	status |= mock_expect_output (&manifest.hash_mock.mock, 0, data->toc_hash, data->toc_hash_len,
		1);

	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.start_sha256,
		&manifest.hash_mock, 0);

	status |= mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash, 0,
		MOCK_ARG (manifest.addr + offset), MOCK_ARG_NOT_NULL, MOCK_ARG (read_len));
	status |= mock_expect_output (&manifest.flash.mock, 1, data->raw + offset,
		data->length - offset, 2);

	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.update,
		&manifest.hash_mock, HASH_ENGINE_UPDATE_FAILED,
		MOCK_ARG_PTR_CONTAINS (data->raw + offset, read_len), MOCK_ARG (read_len));

	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.cancel,
		&manifest.hash_mock, 0);

	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_read_element_data (&manifest.test, &manifest.hash_mock.base,
		MANIFEST_PLATFORM_ID, 0, MANIFEST_NO_PARENT, 0, &found, &format, &total, &element,
		sizeof (buffer));
	CuAssertIntEquals (test, HASH_ENGINE_UPDATE_FAILED, status);

	manifest_flash_v2_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_v2_test_read_element_data_extra_element_data_read_error (CuTest *test)
{
	struct manifest_flash_v2_testing manifest;
	int status;
	uint8_t buffer[PFM_V2.manifest.plat_id_len - 1];
	uint8_t *element = buffer;
	size_t total = 0;
	uint8_t format = 0xff;
	uint8_t found = 0xff;
	const struct manifest_v2_testing_data *data = &PFM_V2.manifest;
	int start = 0;
	int entry = PFM_V2.manifest.plat_id_entry;
	int hash_id = PFM_V2.manifest.plat_id_hash;
	uint32_t offset = PFM_V2.manifest.plat_id_offset;
	size_t read_len = sizeof (buffer);
	uint32_t toc_entry_offset = MANIFEST_V2_TOC_ENTRY_OFFSET;
	uint32_t first_entry = toc_entry_offset + (MANIFEST_V2_TOC_ENTRY_SIZE * start);
	uint32_t last_entry = toc_entry_offset + (MANIFEST_V2_TOC_ENTRY_SIZE * (entry + 1));
	uint32_t hash_offset;
	uint32_t after_hash;
	const struct manifest_toc_entry *toc_entries =
		(struct manifest_toc_entry*) (data->raw + toc_entry_offset);
	int i;

	TEST_START;

	manifest_flash_v2_testing_init_and_verify (test, &manifest, 0x10000, PFM_MAGIC_NUM,
		PFM_V2_MAGIC_NUM, &PFM_V2.manifest, 0, false, 0);

	hash_offset = toc_entry_offset + (MANIFEST_V2_TOC_ENTRY_SIZE * data->toc_entries) +
		(data->toc_hash_len * hash_id);
	after_hash = hash_offset + data->toc_hash_len;

	status = mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.start_sha256,
		&manifest.hash_mock, 0);
	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.update,
		&manifest.hash_mock, 0, MOCK_ARG_PTR_CONTAINS (data->toc, MANIFEST_V2_TOC_HEADER_SIZE),
		MOCK_ARG (MANIFEST_V2_TOC_HEADER_SIZE));

	status = flash_mock_expect_verify_flash_and_hash (&manifest.flash, &manifest.hash_mock,
		manifest.addr + toc_entry_offset, data->raw + toc_entry_offset,
		first_entry - toc_entry_offset);

	for (i = start; i <= entry; i++) {
		status |= mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash,
			0, MOCK_ARG (manifest.addr + toc_entry_offset + (i * MANIFEST_V2_TOC_ENTRY_SIZE)),
			MOCK_ARG_NOT_NULL, MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));
		status |= mock_expect_output (&manifest.flash.mock, 1, &toc_entries[i],
			MANIFEST_V2_TOC_ENTRY_SIZE, 2);

		status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.update,
			&manifest.hash_mock, 0,
			MOCK_ARG_PTR_CONTAINS (&toc_entries[i], MANIFEST_V2_TOC_ENTRY_SIZE),
			MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));
	}

	status |= flash_mock_expect_verify_flash_and_hash (&manifest.flash, &manifest.hash_mock,
			manifest.addr + last_entry, data->raw + last_entry, hash_offset - last_entry);

	status |= mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash, 0,
		MOCK_ARG (manifest.addr + hash_offset), MOCK_ARG_NOT_NULL, MOCK_ARG (data->toc_hash_len));
	status |= mock_expect_output (&manifest.flash.mock, 1, data->raw + hash_offset,
		data->length - hash_offset, 2);

	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.update,
		&manifest.hash_mock, 0,
		MOCK_ARG_PTR_CONTAINS (&data->raw[hash_offset], data->toc_hash_len),
		MOCK_ARG (data->toc_hash_len));

	status |= flash_mock_expect_verify_flash_and_hash (&manifest.flash, &manifest.hash_mock,
		manifest.addr + after_hash, data->raw + after_hash, data->toc_hash_offset - after_hash);

	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.finish,
		&manifest.hash_mock, 0, MOCK_ARG_NOT_NULL, MOCK_ARG (SHA512_HASH_LENGTH));
	status |= mock_expect_output (&manifest.hash_mock.mock, 0, data->toc_hash, data->toc_hash_len,
		1);

	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.start_sha256,
		&manifest.hash_mock, 0);

	status |= mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash, 0,
		MOCK_ARG (manifest.addr + offset), MOCK_ARG_NOT_NULL, MOCK_ARG (read_len));
	status |= mock_expect_output (&manifest.flash.mock, 1, data->raw + offset,
		data->length - offset, 2);

	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.update,
		&manifest.hash_mock, 0, MOCK_ARG_PTR_CONTAINS (data->raw + offset, read_len),
		MOCK_ARG (read_len));

	status |= mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash,
		FLASH_READ_FAILED, MOCK_ARG (manifest.addr + offset + read_len), MOCK_ARG_NOT_NULL,
		MOCK_ARG (PFM_V2.manifest.plat_id_len - read_len));

	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.cancel,
		&manifest.hash_mock, 0);

	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_read_element_data (&manifest.test, &manifest.hash_mock.base,
		MANIFEST_PLATFORM_ID, 0, MANIFEST_NO_PARENT, 0, &found, &format, &total, &element,
		sizeof (buffer));
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	manifest_flash_v2_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_v2_test_read_element_data_finish_element_hash_error (CuTest *test)
{
	struct manifest_flash_v2_testing manifest;
	int status;
	uint8_t buffer[PFM_V2.manifest.plat_id_len];
	uint8_t *element = buffer;
	size_t total = 0;
	uint8_t format = 0xff;
	uint8_t found = 0xff;
	const struct manifest_v2_testing_data *data = &PFM_V2.manifest;
	int start = 0;
	int entry = PFM_V2.manifest.plat_id_entry;
	int hash_id = PFM_V2.manifest.plat_id_hash;
	uint32_t offset = PFM_V2.manifest.plat_id_offset;
	size_t read_len = sizeof (buffer);
	uint32_t toc_entry_offset = MANIFEST_V2_TOC_ENTRY_OFFSET;
	uint32_t first_entry = toc_entry_offset + (MANIFEST_V2_TOC_ENTRY_SIZE * start);
	uint32_t last_entry = toc_entry_offset + (MANIFEST_V2_TOC_ENTRY_SIZE * (entry + 1));
	uint32_t hash_offset;
	uint32_t after_hash;
	const struct manifest_toc_entry *toc_entries =
		(struct manifest_toc_entry*) (data->raw + toc_entry_offset);
	int i;

	TEST_START;

	manifest_flash_v2_testing_init_and_verify (test, &manifest, 0x10000, PFM_MAGIC_NUM,
		PFM_V2_MAGIC_NUM, &PFM_V2.manifest, 0, false, 0);

	hash_offset = toc_entry_offset + (MANIFEST_V2_TOC_ENTRY_SIZE * data->toc_entries) +
		(data->toc_hash_len * hash_id);
	after_hash = hash_offset + data->toc_hash_len;

	status = mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.start_sha256,
		&manifest.hash_mock, 0);
	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.update,
		&manifest.hash_mock, 0, MOCK_ARG_PTR_CONTAINS (data->toc, MANIFEST_V2_TOC_HEADER_SIZE),
		MOCK_ARG (MANIFEST_V2_TOC_HEADER_SIZE));

	status = flash_mock_expect_verify_flash_and_hash (&manifest.flash, &manifest.hash_mock,
		manifest.addr + toc_entry_offset, data->raw + toc_entry_offset,
		first_entry - toc_entry_offset);

	for (i = start; i <= entry; i++) {
		status |= mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash,
			0, MOCK_ARG (manifest.addr + toc_entry_offset + (i * MANIFEST_V2_TOC_ENTRY_SIZE)),
			MOCK_ARG_NOT_NULL, MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));
		status |= mock_expect_output (&manifest.flash.mock, 1, &toc_entries[i],
			MANIFEST_V2_TOC_ENTRY_SIZE, 2);

		status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.update,
			&manifest.hash_mock, 0,
			MOCK_ARG_PTR_CONTAINS (&toc_entries[i], MANIFEST_V2_TOC_ENTRY_SIZE),
			MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));
	}

	status |= flash_mock_expect_verify_flash_and_hash (&manifest.flash, &manifest.hash_mock,
			manifest.addr + last_entry, data->raw + last_entry, hash_offset - last_entry);

	status |= mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash, 0,
		MOCK_ARG (manifest.addr + hash_offset), MOCK_ARG_NOT_NULL, MOCK_ARG (data->toc_hash_len));
	status |= mock_expect_output (&manifest.flash.mock, 1, data->raw + hash_offset,
		data->length - hash_offset, 2);

	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.update,
		&manifest.hash_mock, 0,
		MOCK_ARG_PTR_CONTAINS (&data->raw[hash_offset], data->toc_hash_len),
		MOCK_ARG (data->toc_hash_len));

	status |= flash_mock_expect_verify_flash_and_hash (&manifest.flash, &manifest.hash_mock,
		manifest.addr + after_hash, data->raw + after_hash, data->toc_hash_offset - after_hash);

	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.finish,
		&manifest.hash_mock, 0, MOCK_ARG_NOT_NULL, MOCK_ARG (SHA512_HASH_LENGTH));
	status |= mock_expect_output (&manifest.hash_mock.mock, 0, data->toc_hash, data->toc_hash_len,
		1);

	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.start_sha256,
		&manifest.hash_mock, 0);

	status |= mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash, 0,
		MOCK_ARG (manifest.addr + offset), MOCK_ARG_NOT_NULL, MOCK_ARG (read_len));
	status |= mock_expect_output (&manifest.flash.mock, 1, data->raw + offset,
		data->length - offset, 2);

	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.update,
		&manifest.hash_mock, 0, MOCK_ARG_PTR_CONTAINS (data->raw + offset, read_len),
		MOCK_ARG (read_len));

	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.finish,
		&manifest.hash_mock, HASH_ENGINE_FINISH_FAILED, MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA512_HASH_LENGTH));

	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.cancel,
		&manifest.hash_mock, 0);

	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_read_element_data (&manifest.test, &manifest.hash_mock.base,
		MANIFEST_PLATFORM_ID, 0, MANIFEST_NO_PARENT, 0, &found, &format, &total, &element,
		sizeof (buffer));
	CuAssertIntEquals (test, HASH_ENGINE_FINISH_FAILED, status);

	manifest_flash_v2_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_v2_test_compare_platform_id_equal (CuTest *test)
{
	struct manifest_flash_v2_testing manifest1;
	struct manifest_flash_v2_testing manifest2;
	int status;

	TEST_START;

	manifest_flash_v2_testing_init_and_verify (test, &manifest1, 0x10000, PFM_MAGIC_NUM,
		PFM_V2_MAGIC_NUM, &PFM_V2.manifest, 0, false, 0);
	manifest_flash_v2_testing_init_and_verify (test, &manifest2, 0x20000, PFM_MAGIC_NUM,
		PFM_V2_MAGIC_NUM, &PFM_V2_PLAT_FIRST.manifest, 0, false, 0);

	status = manifest_flash_compare_platform_id (&manifest1.test, &manifest2.test, false);
	CuAssertIntEquals (test, 0, status);

	manifest_flash_v2_testing_validate_and_release (test, &manifest1);
	manifest_flash_v2_testing_validate_and_release (test, &manifest2);
}

static void manifest_flash_v2_test_compare_platform_id_sku_upgrade (CuTest *test)
{
	struct manifest_flash_v2_testing manifest1;
	struct manifest_flash_v2_testing manifest2;
	int status;

	TEST_START;

	manifest_flash_v2_testing_init_and_verify (test, &manifest1, 0x10000, PCD_MAGIC_NUM,
		PCD_V2_MAGIC_NUM, &PCD_TESTING.manifest, 0, false, 0);
	manifest_flash_v2_testing_init_and_verify (test, &manifest2, 0x20000, PCD_MAGIC_NUM,
		PCD_V2_MAGIC_NUM, &PCD_SKU_SPECIFIC_TESTING.manifest, 0, false, 0);

	status = manifest_flash_compare_platform_id (&manifest1.test, &manifest2.test, true);
	CuAssertIntEquals (test, 0, status);

	manifest_flash_v2_testing_validate_and_release (test, &manifest1);
	manifest_flash_v2_testing_validate_and_release (test, &manifest2);
}

static void manifest_flash_v2_test_compare_platform_id_sku_upgrade_not_permitted (CuTest *test)
{
	struct manifest_flash_v2_testing manifest1;
	struct manifest_flash_v2_testing manifest2;
	int status;

	TEST_START;

	manifest_flash_v2_testing_init_and_verify (test, &manifest1, 0x10000, PCD_MAGIC_NUM,
		PCD_V2_MAGIC_NUM, &PCD_TESTING.manifest, 0, false, 0);
	manifest_flash_v2_testing_init_and_verify (test, &manifest2, 0x20000, PCD_MAGIC_NUM,
		PCD_V2_MAGIC_NUM, &PCD_SKU_SPECIFIC_TESTING.manifest, 0, false, 0);

	status = manifest_flash_compare_platform_id (&manifest1.test, &manifest2.test, false);
	CuAssertIntEquals (test, 1, status);

	manifest_flash_v2_testing_validate_and_release (test, &manifest1);
	manifest_flash_v2_testing_validate_and_release (test, &manifest2);
}

static void manifest_flash_v2_test_compare_platform_id_sku_downgrade (CuTest *test)
{
	struct manifest_flash_v2_testing manifest1;
	struct manifest_flash_v2_testing manifest2;
	int status;

	TEST_START;

	manifest_flash_v2_testing_init_and_verify (test, &manifest1, 0x10000, PCD_MAGIC_NUM,
		PCD_V2_MAGIC_NUM, &PCD_SKU_SPECIFIC_TESTING.manifest, 0, false, 0);
	manifest_flash_v2_testing_init_and_verify (test, &manifest2, 0x20000, PCD_MAGIC_NUM,
		PCD_V2_MAGIC_NUM, &PCD_TESTING.manifest, 0, false, 0);

	status = manifest_flash_compare_platform_id (&manifest1.test, &manifest2.test, true);
	CuAssertIntEquals (test, 1, status);

	manifest_flash_v2_testing_validate_and_release (test, &manifest1);
	manifest_flash_v2_testing_validate_and_release (test, &manifest2);
}

static void manifest_flash_v2_test_compare_platform_id_different (CuTest *test)
{
	struct manifest_flash_v2_testing manifest1;
	struct manifest_flash_v2_testing manifest2;
	int status;

	TEST_START;

	manifest_flash_v2_testing_init_and_verify (test, &manifest1, 0x10000, PFM_MAGIC_NUM,
		PFM_V2_MAGIC_NUM, &PFM_V2.manifest, 0, false, 0);
	manifest_flash_v2_testing_init_and_verify (test, &manifest2, 0x20000, PFM_MAGIC_NUM,
		PFM_V2_MAGIC_NUM, &PFM_V2_TWO_FW.manifest, 0, false, 0);

	status = manifest_flash_compare_platform_id (&manifest2.test, &manifest1.test, false);
	CuAssertIntEquals (test, 1, status);

	manifest_flash_v2_testing_validate_and_release (test, &manifest1);
	manifest_flash_v2_testing_validate_and_release (test, &manifest2);
}

static void manifest_flash_v2_test_compare_platform_id_no_manifest1 (CuTest *test)
{
	struct manifest_flash_v2_testing manifest1;
	struct manifest_flash_v2_testing manifest2;
	int status;

	TEST_START;

	manifest_flash_v2_testing_init (test, &manifest1, 0x10000, PFM_MAGIC_NUM,
		PFM_V2_MAGIC_NUM);
	manifest_flash_v2_testing_init_and_verify (test, &manifest2, 0x20000, PFM_MAGIC_NUM,
		PFM_V2_MAGIC_NUM, &PFM_V2_PLAT_FIRST.manifest, 0, false, 0);

	status = manifest_flash_compare_platform_id (&manifest1.test, &manifest2.test, false);
	CuAssertIntEquals (test, MANIFEST_NO_MANIFEST, status);

	manifest_flash_v2_testing_validate_and_release (test, &manifest1);
	manifest_flash_v2_testing_validate_and_release (test, &manifest2);
}

static void manifest_flash_v2_test_compare_platform_id_no_manifest2 (CuTest *test)
{
	struct manifest_flash_v2_testing manifest1;
	struct manifest_flash_v2_testing manifest2;
	int status;

	TEST_START;

	manifest_flash_v2_testing_init_and_verify (test, &manifest1, 0x10000, PFM_MAGIC_NUM,
		PFM_V2_MAGIC_NUM, &PFM_V2.manifest, 0, false, 0);
	manifest_flash_v2_testing_init (test, &manifest2, 0x20000, PFM_MAGIC_NUM,
		PFM_V2_MAGIC_NUM);

	status = manifest_flash_compare_platform_id (&manifest1.test, &manifest2.test, false);
	CuAssertIntEquals (test, MANIFEST_NO_MANIFEST, status);

	manifest_flash_v2_testing_validate_and_release (test, &manifest1);
	manifest_flash_v2_testing_validate_and_release (test, &manifest2);
}

static void manifest_flash_v2_test_compare_platform_id_no_manifests (CuTest *test)
{
	struct manifest_flash_v2_testing manifest1;
	struct manifest_flash_v2_testing manifest2;
	int status;

	TEST_START;

	manifest_flash_v2_testing_init (test, &manifest1, 0x10000, PFM_MAGIC_NUM,
		PFM_V2_MAGIC_NUM);
	manifest_flash_v2_testing_init (test, &manifest2, 0x20000, PFM_MAGIC_NUM,
		PFM_V2_MAGIC_NUM);

	status = manifest_flash_compare_platform_id (&manifest1.test, &manifest2.test, false);
	CuAssertIntEquals (test, MANIFEST_NO_MANIFEST, status);

	manifest_flash_v2_testing_validate_and_release (test, &manifest1);
	manifest_flash_v2_testing_validate_and_release (test, &manifest2);
}

static void manifest_flash_v2_test_compare_platform_id_null_manifest1 (CuTest *test)
{
	struct manifest_flash_v2_testing manifest2;
	int status;

	TEST_START;

	manifest_flash_v2_testing_init_and_verify (test, &manifest2, 0x20000, PFM_MAGIC_NUM,
		PFM_V2_MAGIC_NUM, &PFM_V2_PLAT_FIRST.manifest, 0, false, 0);

	status = manifest_flash_compare_platform_id (NULL, &manifest2.test, false);
	CuAssertIntEquals (test, MANIFEST_INVALID_ARGUMENT, status);

	manifest_flash_v2_testing_validate_and_release (test, &manifest2);
}

static void manifest_flash_v2_test_compare_platform_id_null_manifest2 (CuTest *test)
{
	struct manifest_flash_v2_testing manifest1;
	int status;

	TEST_START;

	manifest_flash_v2_testing_init_and_verify (test, &manifest1, 0x10000, PFM_MAGIC_NUM,
		PFM_V2_MAGIC_NUM, &PFM_V2.manifest, 0, false, 0);

	status = manifest_flash_compare_platform_id (&manifest1.test, NULL, false);
	CuAssertIntEquals (test, MANIFEST_INVALID_ARGUMENT, status);

	manifest_flash_v2_testing_validate_and_release (test, &manifest1);
}

static void manifest_flash_v2_test_compare_platform_id_both_null (CuTest *test)
{
	int status;

	TEST_START;

	status = manifest_flash_compare_platform_id (NULL, NULL, false);
	CuAssertIntEquals (test, MANIFEST_INVALID_ARGUMENT, status);
}

static void manifest_flash_v2_test_get_num_child_elements_no_child_len (CuTest *test)
{
	struct manifest_flash_v2_testing manifest;
	int status = 0;

	TEST_START;

	manifest_flash_v2_testing_init_and_verify (test, &manifest, 0x10000, CFM_MAGIC_NUM,
		CFM_V2_MAGIC_NUM, &CFM_TESTING.manifest, 0, false, 0);

	manifest_flash_v2_testing_get_num_child_elements (test, &manifest, &CFM_TESTING.manifest, 2,
		26);

	status = manifest_flash_get_num_child_elements (&manifest.test, &manifest.hash.base, 2,
		CFM_COMPONENT_DEVICE, MANIFEST_NO_PARENT, CFM_ROOT_CA, NULL);
	CuAssertIntEquals (test, 1, status);

	manifest_flash_v2_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_v2_test_get_num_child_elements_first_child (CuTest *test)
{
	struct manifest_flash_v2_testing manifest;
	size_t child_len;
	int status = 0;

	TEST_START;

	manifest_flash_v2_testing_init_and_verify (test, &manifest, 0x10000, CFM_MAGIC_NUM,
		CFM_V2_MAGIC_NUM, &CFM_TESTING.manifest, 0, false, 0);

	manifest_flash_v2_testing_get_num_child_elements (test, &manifest, &CFM_TESTING.manifest, 2,
		26);

	status = manifest_flash_get_num_child_elements (&manifest.test, &manifest.hash.base, 2,
		CFM_COMPONENT_DEVICE, MANIFEST_NO_PARENT, CFM_ROOT_CA, &child_len);
	CuAssertIntEquals (test, 1, status);
	CuAssertIntEquals (test, 0x44, child_len);

	manifest_flash_v2_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_v2_test_get_num_child_elements_not_first_child (CuTest *test)
{
	struct manifest_flash_v2_testing manifest;
	size_t child_len;
	int status = 0;

	TEST_START;

	manifest_flash_v2_testing_init_and_verify (test, &manifest, 0x10000, CFM_MAGIC_NUM,
		CFM_V2_MAGIC_NUM, &CFM_TESTING.manifest, 0, false, 0);

	manifest_flash_v2_testing_get_num_child_elements (test, &manifest, &CFM_TESTING.manifest, 2,
		26);

	status = manifest_flash_get_num_child_elements (&manifest.test, &manifest.hash.base, 2,
		CFM_COMPONENT_DEVICE, MANIFEST_NO_PARENT, CFM_PMR_DIGEST, &child_len);
	CuAssertIntEquals (test, 2, status);
	CuAssertIntEquals (test, 0x88, child_len);

	manifest_flash_v2_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_v2_test_get_num_child_elements_entry_with_nested_child (CuTest *test)
{
	struct manifest_flash_v2_testing manifest;
	size_t child_len;
	int status = 0;

	TEST_START;

	manifest_flash_v2_testing_init_and_verify (test, &manifest, 0x10000, CFM_MAGIC_NUM,
		CFM_V2_MAGIC_NUM, &CFM_TESTING.manifest, 0, false, 0);

	manifest_flash_v2_testing_get_num_child_elements (test, &manifest, &CFM_TESTING.manifest, 2,
		26);

	status = manifest_flash_get_num_child_elements (&manifest.test, &manifest.hash.base, 2,
		CFM_COMPONENT_DEVICE, MANIFEST_NO_PARENT, CFM_MEASUREMENT_DATA, &child_len);
	CuAssertIntEquals (test, 2, status);
	CuAssertIntEquals (test, 0x8, child_len);

	manifest_flash_v2_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_v2_test_get_num_child_elements_get_nested_child_count (CuTest *test)
{
	struct manifest_flash_v2_testing manifest;
	size_t child_len;
	int status = 0;

	TEST_START;

	manifest_flash_v2_testing_init_and_verify (test, &manifest, 0x10000, CFM_MAGIC_NUM,
		CFM_V2_MAGIC_NUM, &CFM_TESTING.manifest, 0, false, 0);

	manifest_flash_v2_testing_get_num_child_elements (test, &manifest, &CFM_TESTING.manifest, 10,
		12);

	status = manifest_flash_get_num_child_elements (&manifest.test, &manifest.hash.base, 10,
		CFM_MEASUREMENT_DATA, CFM_COMPONENT_DEVICE, CFM_ALLOWABLE_DATA, &child_len);
	CuAssertIntEquals (test, 2, status);
	CuAssertIntEquals (test, 0x34, child_len);

	manifest_flash_v2_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_v2_test_get_num_child_elements_terminate_at_parent (CuTest *test)
{
	struct manifest_flash_v2_testing manifest;
	size_t child_len;
	int status;

	TEST_START;

	manifest_flash_v2_testing_init_and_verify (test, &manifest, 0x10000, CFM_MAGIC_NUM,
		CFM_V2_MAGIC_NUM, &CFM_TESTING.manifest, 0, false, 0);

	manifest_flash_v2_testing_get_num_child_elements (test, &manifest, &CFM_TESTING.manifest, 21,
		22);

	status = manifest_flash_get_num_child_elements (&manifest.test, &manifest.hash.base, 21,
		CFM_ALLOWABLE_CFM, CFM_COMPONENT_DEVICE, CFM_ALLOWABLE_ID, &child_len);
	CuAssertIntEquals (test, 1, status);
	CuAssertIntEquals (test, 0x8, child_len);

	manifest_flash_v2_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_v2_test_get_num_child_elements_terminate_same_as_entry (
	CuTest *test)
{
	struct manifest_flash_v2_testing manifest;
	size_t child_len;
	int status;

	TEST_START;

	manifest_flash_v2_testing_init_and_verify (test, &manifest, 0x10000, CFM_MAGIC_NUM,
		CFM_V2_MAGIC_NUM, &CFM_TESTING.manifest, 0, false, 0);

	manifest_flash_v2_testing_get_num_child_elements (test, &manifest, &CFM_TESTING.manifest, 25,
		26);

	status = manifest_flash_get_num_child_elements (&manifest.test, &manifest.hash.base, 25,
		CFM_ALLOWABLE_PCD, CFM_COMPONENT_DEVICE, CFM_ALLOWABLE_ID, &child_len);
	CuAssertIntEquals (test, 1, status);
	CuAssertIntEquals (test, 0x8, child_len);

	manifest_flash_v2_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_v2_test_get_num_child_elements_entry_has_no_child_elements (CuTest *test)
{
	struct manifest_flash_v2_testing manifest;
	size_t child_len;
	int status;

	TEST_START;

	manifest_flash_v2_testing_init_and_verify (test, &manifest, 0x10000, CFM_MAGIC_NUM,
		CFM_V2_MAGIC_NUM, &CFM_TESTING.manifest, 0, false, 0);

	manifest_flash_v2_testing_get_num_child_elements (test, &manifest, &CFM_TESTING.manifest, 3, 3);

	status = manifest_flash_get_num_child_elements (&manifest.test, &manifest.hash.base, 3,
		CFM_ROOT_CA, CFM_COMPONENT_DEVICE, CFM_ALLOWABLE_DATA, &child_len);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0, child_len);

	manifest_flash_v2_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_v2_test_get_num_child_elements_null (CuTest *test)
{
	struct manifest_flash_v2_testing manifest;
	size_t child_len;
	int status;

	TEST_START;

	manifest_flash_v2_testing_init_and_verify (test, &manifest, 0x10000, PFM_MAGIC_NUM,
		PFM_V2_MAGIC_NUM, &PFM_V2.manifest, 0, false, 0);

	status = manifest_flash_get_num_child_elements (NULL, &manifest.hash.base, 0, 0, 0, 0,
		&child_len);
	CuAssertIntEquals (test, MANIFEST_INVALID_ARGUMENT, status);

	status = manifest_flash_get_num_child_elements (&manifest.test, NULL, 0, 0, 0, 0, &child_len);
	CuAssertIntEquals (test, MANIFEST_INVALID_ARGUMENT, status);

	manifest_flash_v2_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_v2_test_get_num_child_elements_verify_never_run (CuTest *test)
{
	struct manifest_flash_v2_testing manifest;
	int status;

	TEST_START;

	manifest_flash_v2_testing_init (test, &manifest, 0x10000, CFM_MAGIC_NUM, CFM_V2_MAGIC_NUM);

	status = manifest_flash_get_num_child_elements (&manifest.test, &manifest.hash.base, 0, 0, 0, 0,
		NULL);
	CuAssertIntEquals (test, MANIFEST_NO_MANIFEST, status);

	manifest_flash_v2_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_v2_test_get_num_child_elements_entry_invalid (CuTest *test)
{
	struct manifest_flash_v2_testing manifest;
	size_t child_len;
	int status;

	TEST_START;

	manifest_flash_v2_testing_init_and_verify (test, &manifest, 0x10000, CFM_MAGIC_NUM,
		CFM_V2_MAGIC_NUM, &CFM_TESTING.manifest, 0, false, 0);

	status = manifest_flash_get_num_child_elements (&manifest.test, &manifest.hash.base, 39,
		CFM_MEASUREMENT_DATA, CFM_COMPONENT_DEVICE, CFM_ALLOWABLE_DATA, &child_len);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0, child_len);

	manifest_flash_v2_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_v2_test_get_num_child_elements_entry_last (CuTest *test)
{
	struct manifest_flash_v2_testing manifest;
	size_t child_len;
	int status;

	TEST_START;

	manifest_flash_v2_testing_init_and_verify (test, &manifest, 0x10000, CFM_MAGIC_NUM,
		CFM_V2_MAGIC_NUM, &CFM_TESTING.manifest, 0, false, 0);

	manifest_flash_v2_testing_get_num_child_elements (test, &manifest, &CFM_TESTING.manifest, 38,
		38);

	status = manifest_flash_get_num_child_elements (&manifest.test, &manifest.hash.base, 38,
		CFM_ALLOWABLE_ID, CFM_ALLOWABLE_PCD, CFM_ALLOWABLE_DATA, &child_len);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0, child_len);

	manifest_flash_v2_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_v2_test_get_num_child_elements_start_hash_fail (CuTest *test)
{
	struct manifest_flash_v2_testing manifest;
	size_t child_len;
	int status;

	TEST_START;

	manifest_flash_v2_testing_init_and_verify (test, &manifest, 0x10000, CFM_MAGIC_NUM,
		CFM_V2_MAGIC_NUM, &CFM_TESTING.manifest, 0, true, 0);

	status = mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.start_sha256,
		&manifest.hash_mock, HASH_ENGINE_NO_MEMORY);
	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_get_num_child_elements (&manifest.test, &manifest.hash_mock.base, 2,
		CFM_COMPONENT_DEVICE, MANIFEST_NO_PARENT, CFM_ALLOWABLE_PFM, &child_len);
	CuAssertIntEquals (test, HASH_ENGINE_NO_MEMORY, status);

	manifest_flash_v2_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_v2_test_get_num_child_elements_toc_header_hash_update_fail (CuTest *test)
{
	struct manifest_flash_v2_testing manifest;
	size_t child_len;
	int status;

	TEST_START;

	manifest_flash_v2_testing_init_and_verify (test, &manifest, 0x10000, CFM_MAGIC_NUM,
		CFM_V2_MAGIC_NUM, &CFM_TESTING.manifest, 0, true, 0);

	status = mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.start_sha256,
		&manifest.hash_mock, 0);
	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.update,
		&manifest.hash_mock, HASH_ENGINE_NO_MEMORY,
		MOCK_ARG_PTR_CONTAINS (CFM_TESTING.manifest.toc, sizeof (struct manifest_toc_header)),
		MOCK_ARG (sizeof (struct manifest_toc_header)));
	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.cancel,
		&manifest.hash_mock, 0);
	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_get_num_child_elements (&manifest.test, &manifest.hash_mock.base, 2,
		CFM_COMPONENT_DEVICE, MANIFEST_NO_PARENT, CFM_ALLOWABLE_PFM, &child_len);
	CuAssertIntEquals (test, HASH_ENGINE_NO_MEMORY, status);

	manifest_flash_v2_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_v2_test_get_num_child_elements_toc_before_entry_hash_update_fail (
	CuTest *test)
{
	struct manifest_flash_v2_testing manifest;
	size_t child_len;
	int status;

	TEST_START;

	manifest_flash_v2_testing_init_and_verify (test, &manifest, 0x10000, CFM_MAGIC_NUM,
		CFM_V2_MAGIC_NUM, &CFM_TESTING.manifest, 0, true, 0);

	status = mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash,
		FLASH_NO_MEMORY, MOCK_ARG (manifest.addr + MANIFEST_V2_TOC_ENTRY_OFFSET),
		MOCK_ARG_NOT_NULL, MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE * 2));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.start_sha256,
		&manifest.hash_mock, 0);
	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.update,
		&manifest.hash_mock, 0,
		MOCK_ARG_PTR_CONTAINS (CFM_TESTING.manifest.toc, sizeof (struct manifest_toc_header)),
		MOCK_ARG (sizeof (struct manifest_toc_header)));

	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.cancel,
		&manifest.hash_mock, 0);
	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_get_num_child_elements (&manifest.test, &manifest.hash_mock.base, 2,
		CFM_COMPONENT_DEVICE, MANIFEST_NO_PARENT, CFM_ALLOWABLE_PFM, &child_len);
	CuAssertIntEquals (test, FLASH_NO_MEMORY, status);

	manifest_flash_v2_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_v2_test_get_num_child_elements_read_fail (CuTest *test)
{
	struct manifest_flash_v2_testing manifest;
	size_t child_len;
	int status;

	TEST_START;

	manifest_flash_v2_testing_init_and_verify (test, &manifest, 0x10000, CFM_MAGIC_NUM,
		CFM_V2_MAGIC_NUM, &CFM_TESTING.manifest, 0, false, 0);

	status = flash_mock_expect_verify_flash (&manifest.flash,
		manifest.addr + MANIFEST_V2_TOC_ENTRY_OFFSET,
		CFM_TESTING.manifest.raw + MANIFEST_V2_TOC_ENTRY_OFFSET, MANIFEST_V2_TOC_ENTRY_SIZE * 2);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash,
		FLASH_NO_MEMORY, MOCK_ARG (manifest.addr + MANIFEST_V2_TOC_ENTRY_OFFSET +
			2 * MANIFEST_V2_TOC_ENTRY_SIZE), MOCK_ARG_NOT_NULL,
		MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));
	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_get_num_child_elements (&manifest.test, &manifest.hash.base, 2,
		CFM_COMPONENT_DEVICE, MANIFEST_NO_PARENT, CFM_ALLOWABLE_PFM, &child_len);
	CuAssertIntEquals (test, FLASH_NO_MEMORY, status);

	manifest_flash_v2_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_v2_test_get_num_child_elements_hash_update_entry_fail (CuTest *test)
{
	struct manifest_flash_v2_testing manifest;
	size_t child_len;
	int status;

	TEST_START;

	manifest_flash_v2_testing_init_and_verify (test, &manifest, 0x10000, CFM_MAGIC_NUM,
		CFM_V2_MAGIC_NUM, &CFM_TESTING.manifest, 0, true, 0);

	status = mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash,
		0, MOCK_ARG (manifest.addr + MANIFEST_V2_TOC_ENTRY_OFFSET), MOCK_ARG_NOT_NULL,
		MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE * 2));
	status |= mock_expect_output (&manifest.flash.mock, 1,
		CFM_TESTING.manifest.toc + MANIFEST_V2_TOC_ENTRY_OFFSET, MANIFEST_V2_TOC_ENTRY_SIZE * 2,
		-1);
	status |= mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash,
		0, MOCK_ARG (manifest.addr + MANIFEST_V2_TOC_ENTRY_OFFSET + MANIFEST_V2_TOC_ENTRY_SIZE * 2),
		MOCK_ARG_NOT_NULL, MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));
	status |= mock_expect_output (&manifest.flash.mock, 1,
		CFM_TESTING.manifest.toc + MANIFEST_V2_TOC_ENTRY_OFFSET + MANIFEST_V2_TOC_ENTRY_SIZE * 2,
		MANIFEST_V2_TOC_ENTRY_SIZE, -1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.start_sha256,
		&manifest.hash_mock, 0);
	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.update,
		&manifest.hash_mock, 0,
		MOCK_ARG_PTR_CONTAINS (CFM_TESTING.manifest.toc, sizeof (struct manifest_toc_header)),
		MOCK_ARG (sizeof (struct manifest_toc_header)));
	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.update,
		&manifest.hash_mock, 0,
		MOCK_ARG_PTR_CONTAINS (CFM_TESTING.manifest.toc + MANIFEST_V2_TOC_ENTRY_OFFSET,
			MANIFEST_V2_TOC_ENTRY_SIZE * 2), MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE * 2));
	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.update,
		&manifest.hash_mock, HASH_ENGINE_NO_MEMORY,
		MOCK_ARG_PTR_CONTAINS (CFM_TESTING.manifest.toc + MANIFEST_V2_TOC_ENTRY_OFFSET +
			MANIFEST_V2_TOC_ENTRY_SIZE * 2, MANIFEST_V2_TOC_ENTRY_SIZE),
		MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));
	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.cancel,
		&manifest.hash_mock, 0);
	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_get_num_child_elements (&manifest.test, &manifest.hash_mock.base, 2,
		CFM_COMPONENT_DEVICE, MANIFEST_NO_PARENT, CFM_ALLOWABLE_PFM, &child_len);
	CuAssertIntEquals (test, HASH_ENGINE_NO_MEMORY, status);

	manifest_flash_v2_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_v2_test_get_num_child_elements_toc_after_last_entry_hash_update_fail (
	CuTest *test)
{
	struct manifest_flash_v2_testing manifest;
	uint32_t offset = MANIFEST_V2_TOC_ENTRY_OFFSET;
	size_t child_len;
	int status;

	TEST_START;

	manifest_flash_v2_testing_init_and_verify (test, &manifest, 0x10000, CFM_MAGIC_NUM,
		CFM_V2_MAGIC_NUM, &CFM_TESTING.manifest, 0, true, 0);

	status = mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.start_sha256,
		&manifest.hash_mock, 0);
	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.update,
		&manifest.hash_mock, 0,
		MOCK_ARG_PTR_CONTAINS (CFM_TESTING.manifest.toc, sizeof (struct manifest_toc_header)),
		MOCK_ARG (sizeof (struct manifest_toc_header)));
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_expect_verify_flash_and_hash (&manifest.flash, &manifest.hash_mock,
		manifest.addr + MANIFEST_V2_TOC_ENTRY_OFFSET,
		CFM_TESTING.manifest.raw + MANIFEST_V2_TOC_ENTRY_OFFSET,
		MANIFEST_V2_TOC_ENTRY_SIZE * 2);
	CuAssertIntEquals (test, 0, status);

	offset += MANIFEST_V2_TOC_ENTRY_SIZE * 2;

	for (int i = 2; i <= 26; ++i) {
		status |= mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash,
			0, MOCK_ARG (manifest.addr + offset), MOCK_ARG_NOT_NULL,
			MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));
		status |= mock_expect_output (&manifest.flash.mock, 1, CFM_TESTING.manifest.raw + offset,
			MANIFEST_V2_TOC_ENTRY_SIZE, 2);
		status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.update,
			&manifest.hash_mock, 0,
			MOCK_ARG_PTR_CONTAINS (CFM_TESTING.manifest.raw + offset, MANIFEST_V2_TOC_ENTRY_SIZE),
			MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));

		offset += MANIFEST_V2_TOC_ENTRY_SIZE;
	}
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash,
		FLASH_NO_MEMORY, MOCK_ARG (manifest.addr + offset), MOCK_ARG_NOT_NULL, MOCK_ARG (0x100));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.cancel,
		&manifest.hash_mock, 0);
	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_get_num_child_elements (&manifest.test, &manifest.hash_mock.base, 2,
		CFM_COMPONENT_DEVICE, MANIFEST_NO_PARENT, CFM_ALLOWABLE_PFM, &child_len);
	CuAssertIntEquals (test, FLASH_NO_MEMORY, status);

	manifest_flash_v2_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_v2_test_get_num_child_elements_hash_finish_fail (CuTest *test)
{
	struct manifest_flash_v2_testing manifest;
	uint32_t offset = MANIFEST_V2_TOC_ENTRY_OFFSET;
	size_t child_len;
	int status;

	TEST_START;

	manifest_flash_v2_testing_init_and_verify (test, &manifest, 0x10000, CFM_MAGIC_NUM,
		CFM_V2_MAGIC_NUM, &CFM_TESTING.manifest, 0, true, 0);

	status = mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.start_sha256,
		&manifest.hash_mock, 0);
	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.update,
		&manifest.hash_mock, 0,
		MOCK_ARG_PTR_CONTAINS (CFM_TESTING.manifest.toc, sizeof (struct manifest_toc_header)),
		MOCK_ARG (sizeof (struct manifest_toc_header)));
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_expect_verify_flash_and_hash (&manifest.flash, &manifest.hash_mock,
		manifest.addr + MANIFEST_V2_TOC_ENTRY_OFFSET,
		CFM_TESTING.manifest.raw + MANIFEST_V2_TOC_ENTRY_OFFSET,
		MANIFEST_V2_TOC_ENTRY_SIZE * 2);
	CuAssertIntEquals (test, 0, status);

	offset += MANIFEST_V2_TOC_ENTRY_SIZE * 2;

	for (int i = 2; i <= 26; ++i) {
		status |= mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash,
			0, MOCK_ARG (manifest.addr + offset), MOCK_ARG_NOT_NULL,
			MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));
		status |= mock_expect_output (&manifest.flash.mock, 1, CFM_TESTING.manifest.raw + offset,
			MANIFEST_V2_TOC_ENTRY_SIZE, 2);
		status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.update,
			&manifest.hash_mock, 0,
			MOCK_ARG_PTR_CONTAINS (CFM_TESTING.manifest.raw + offset, MANIFEST_V2_TOC_ENTRY_SIZE),
			MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));

		offset += MANIFEST_V2_TOC_ENTRY_SIZE;
	}
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_expect_verify_flash_and_hash (&manifest.flash, &manifest.hash_mock,
		manifest.addr + offset, CFM_TESTING.manifest.raw + offset, MANIFEST_V2_TOC_ENTRY_SIZE * 12 +
		CFM_TESTING.manifest.toc_hash_len * 39);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.finish,
		&manifest.hash_mock, HASH_ENGINE_NO_MEMORY, MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA512_HASH_LENGTH));
	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.cancel,
		&manifest.hash_mock, 0);
	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_get_num_child_elements (&manifest.test, &manifest.hash_mock.base, 2,
		CFM_COMPONENT_DEVICE, MANIFEST_NO_PARENT, CFM_ALLOWABLE_PFM, &child_len);
	CuAssertIntEquals (test, HASH_ENGINE_NO_MEMORY, status);

	manifest_flash_v2_testing_validate_and_release (test, &manifest);
}

static void manifest_flash_v2_test_get_num_child_elements_toc_invalid (CuTest *test)
{
	struct manifest_flash_v2_testing manifest;
	uint8_t validate_hash[SHA512_HASH_LENGTH] = {0};
	uint32_t offset = MANIFEST_V2_TOC_ENTRY_OFFSET;
	size_t child_len;
	int status;

	TEST_START;

	manifest_flash_v2_testing_init_and_verify (test, &manifest, 0x10000, CFM_MAGIC_NUM,
		CFM_V2_MAGIC_NUM, &CFM_TESTING.manifest, 0, true, 0);

	status = mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.start_sha256,
		&manifest.hash_mock, 0);
	status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.update,
		&manifest.hash_mock, 0,
		MOCK_ARG_PTR_CONTAINS (CFM_TESTING.manifest.toc, sizeof (struct manifest_toc_header)),
		MOCK_ARG (sizeof (struct manifest_toc_header)));
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_expect_verify_flash_and_hash (&manifest.flash, &manifest.hash_mock,
		manifest.addr + MANIFEST_V2_TOC_ENTRY_OFFSET,
		CFM_TESTING.manifest.raw + MANIFEST_V2_TOC_ENTRY_OFFSET,
		MANIFEST_V2_TOC_ENTRY_SIZE * 2);
	CuAssertIntEquals (test, 0, status);

	offset += MANIFEST_V2_TOC_ENTRY_SIZE * 2;

	for (int i = 2; i <= 26; ++i) {
		status |= mock_expect (&manifest.flash.mock, manifest.flash.base.read, &manifest.flash,
			0, MOCK_ARG (manifest.addr + offset), MOCK_ARG_NOT_NULL,
			MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));
		status |= mock_expect_output (&manifest.flash.mock, 1, CFM_TESTING.manifest.raw + offset,
			MANIFEST_V2_TOC_ENTRY_SIZE, 2);
		status |= mock_expect (&manifest.hash_mock.mock, manifest.hash_mock.base.update,
			&manifest.hash_mock, 0,
			MOCK_ARG_PTR_CONTAINS (CFM_TESTING.manifest.raw + offset, MANIFEST_V2_TOC_ENTRY_SIZE),
			MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));

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
		sizeof (validate_hash),	-1);
	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_get_num_child_elements (&manifest.test, &manifest.hash_mock.base, 2,
		CFM_COMPONENT_DEVICE, MANIFEST_NO_PARENT, CFM_ALLOWABLE_PFM, &child_len);
	CuAssertIntEquals (test, MANIFEST_TOC_INVALID, status);

	manifest_flash_v2_testing_validate_and_release (test, &manifest);
}

TEST_SUITE_START (manifest_flash_v2);

TEST (manifest_flash_v2_test_init);
TEST (manifest_flash_v2_test_init_null);
TEST (manifest_flash_v2_test_init_not_aligned);
TEST (manifest_flash_v2_test_init_block_size_error);
TEST (manifest_flash_v2_test_verify);
TEST (manifest_flash_v2_test_verify_with_mock_hash);
TEST (manifest_flash_v2_test_verify_platform_id_first);
TEST (manifest_flash_v2_test_verify_ecc_signature);
TEST (manifest_flash_v2_test_verify_sha384);
TEST (manifest_flash_v2_test_verify_sha512);
TEST (manifest_flash_v2_test_verify_different_hash_types);
TEST (manifest_flash_v2_test_verify_no_element_hashes);
TEST (manifest_flash_v2_test_verify_partial_element_hashes);
TEST (manifest_flash_v2_test_verify_max_entries_and_hashes);
TEST (manifest_flash_v2_test_verify_minimum_platform_id_buffer_length);
TEST (manifest_flash_v2_test_verify_with_hash_out);
TEST (manifest_flash_v2_test_verify_with_hash_out_sha384);
TEST (manifest_flash_v2_test_verify_with_hash_out_sha512);
TEST (manifest_flash_v2_test_verify_null);
TEST (manifest_flash_v2_test_verify_small_hash_buffer);
TEST (manifest_flash_v2_test_verify_small_hash_buffer_sha384);
TEST (manifest_flash_v2_test_verify_small_hash_buffer_sha512);
TEST (manifest_flash_v2_test_verify_header_read_error);
TEST (manifest_flash_v2_test_verify_header_read_error_with_hash_out);
TEST (manifest_flash_v2_test_verify_bad_magic_number);
TEST (manifest_flash_v2_test_verify_bad_magic_number_v1_unsupported);
TEST (manifest_flash_v2_test_verify_bad_magic_number_v2_unsupported);
TEST (manifest_flash_v2_test_verify_sig_unknown_hash_type);
TEST (manifest_flash_v2_test_verify_sig_longer_than_manifest);
TEST (manifest_flash_v2_test_verify_sig_same_length_as_manifest);
TEST (manifest_flash_v2_test_verify_sig_length_into_header);
TEST (manifest_flash_v2_test_verify_sig_too_long);
TEST (manifest_flash_v2_test_verify_sig_read_error);
TEST (manifest_flash_v2_test_verify_bad_signature);
TEST (manifest_flash_v2_test_verify_bad_signature_with_hash_out);
TEST (manifest_flash_v2_test_verify_bad_signature_ecc_with_hash_out);
TEST (manifest_flash_v2_test_verify_start_hash_error);
TEST (manifest_flash_v2_test_verify_header_hash_error);
TEST (manifest_flash_v2_test_verify_toc_unknown_hash_type);
TEST (manifest_flash_v2_test_verify_toc_no_platform_id_element);
TEST (manifest_flash_v2_test_verify_toc_header_read_error);
TEST (manifest_flash_v2_test_verify_toc_header_hash_error);
TEST (manifest_flash_v2_test_verify_toc_element_read_error);
TEST (manifest_flash_v2_test_verify_toc_element_hash_error);
TEST (manifest_flash_v2_test_verify_toc_read_error);
TEST (manifest_flash_v2_test_verify_toc_hash_read_error);
TEST (manifest_flash_v2_test_verify_toc_hash_hash_error);
TEST (manifest_flash_v2_test_verify_manifest_part1_read_error);
TEST (manifest_flash_v2_test_verify_platform_id_too_long);
TEST (manifest_flash_v2_test_verify_platform_id_header_read_error);
TEST (manifest_flash_v2_test_verify_platform_id_header_hash_error);
TEST (manifest_flash_v2_test_verify_platform_id_read_error);
TEST (manifest_flash_v2_test_verify_platform_id_hash_error);
TEST (manifest_flash_v2_test_verify_manifest_part2_read_error);
TEST (manifest_flash_v2_test_verify_finish_hash_error);
TEST (manifest_flash_v2_test_verify_finish_hash_error_with_hash_out);
TEST (manifest_flash_v2_test_get_id);
TEST (manifest_flash_v2_test_get_id_null);
TEST (manifest_flash_v2_test_get_id_verify_never_run);
TEST (manifest_flash_v2_test_get_id_after_verify_header_read_error);
TEST (manifest_flash_v2_test_get_id_after_verify_bad_signature);
TEST (manifest_flash_v2_test_get_platform_id);
TEST (manifest_flash_v2_test_get_platform_id_manifest_allocation);
TEST (manifest_flash_v2_test_get_platform_id_null);
TEST (manifest_flash_v2_test_get_platform_id_small_buffer);
TEST (manifest_flash_v2_test_get_platform_id_verify_never_run);
TEST (manifest_flash_v2_test_get_platform_id_after_verify_header_read_error);
TEST (manifest_flash_v2_test_get_platform_id_after_verify_bad_signature);
TEST (manifest_flash_v2_test_get_hash_sha256);
TEST (manifest_flash_v2_test_get_hash_sha384);
TEST (manifest_flash_v2_test_get_hash_sha512);
TEST (manifest_flash_v2_test_get_hash_verify_never_run);
TEST (manifest_flash_v2_test_get_hash_after_verify_header_read_error);
TEST (manifest_flash_v2_test_get_hash_after_verify_finish_hash_error);
TEST (manifest_flash_v2_test_get_hash_after_verify_bad_signature);
TEST (manifest_flash_v2_test_get_hash_null);
TEST (manifest_flash_v2_test_get_hash_small_hash_buffer);
TEST (manifest_flash_v2_test_get_hash_small_hash_buffer_sha384);
TEST (manifest_flash_v2_test_get_hash_small_hash_buffer_sha512);
TEST (manifest_flash_v2_test_get_hash_header_read_error);
TEST (manifest_flash_v2_test_get_hash_bad_magic_number);
TEST (manifest_flash_v2_test_get_hash_bad_magic_number_v1_unsupported);
TEST (manifest_flash_v2_test_get_hash_bad_magic_number_v2_unsupported);
TEST (manifest_flash_v2_test_get_hash_sig_longer_than_manifest);
TEST (manifest_flash_v2_test_get_hash_sig_same_length_as_manifest);
TEST (manifest_flash_v2_test_get_hash_sig_length_into_header);
TEST (manifest_flash_v2_test_get_hash_verify_never_run_small_hash_buffer);
TEST (manifest_flash_v2_test_get_hash_verify_never_run_small_hash_buffer_sha384);
TEST (manifest_flash_v2_test_get_hash_verify_never_run_small_hash_buffer_sha512);
TEST (manifest_flash_v2_test_get_hash_unknown_hash_type);
TEST (manifest_flash_v2_test_get_hash_read_error);
TEST (manifest_flash_v2_test_get_signature);
TEST (manifest_flash_v2_test_get_signature_verify_never_run);
TEST (manifest_flash_v2_test_get_signature_after_verify_header_read_error);
TEST (manifest_flash_v2_test_get_signature_after_verify_finish_hash_error);
TEST (manifest_flash_v2_test_get_signature_after_verify_bad_signature);
TEST (manifest_flash_v2_test_get_signature_null);
TEST (manifest_flash_v2_test_get_signature_small_sig_buffer);
TEST (manifest_flash_v2_test_get_signature_verify_never_run_small_sig_buffer);
TEST (manifest_flash_v2_test_get_signature_header_read_error);
TEST (manifest_flash_v2_test_get_signature_bad_magic_number);
TEST (manifest_flash_v2_test_get_signature_bad_magic_number_v1_unsupported);
TEST (manifest_flash_v2_test_get_signature_bad_magic_number_v2_unsupported);
TEST (manifest_flash_v2_test_get_signature_sig_longer_than_manifest);
TEST (manifest_flash_v2_test_get_signature_sig_same_length_as_manifest);
TEST (manifest_flash_v2_test_get_signature_sig_length_into_header);
TEST (manifest_flash_v2_test_get_signature_read_error);
TEST (manifest_flash_v2_test_read_element_data);
TEST (manifest_flash_v2_test_read_element_data_no_found_output);
TEST (manifest_flash_v2_test_read_element_data_no_format_output);
TEST (manifest_flash_v2_test_read_element_data_no_total_length_output);
TEST (manifest_flash_v2_test_read_element_data_dynamic_allocation);
TEST (manifest_flash_v2_test_read_element_data_with_mock_hash);
TEST (manifest_flash_v2_test_read_element_data_first_element);
TEST (manifest_flash_v2_test_read_element_data_first_element_hash);
TEST (manifest_flash_v2_test_read_element_data_with_start_offset);
TEST (manifest_flash_v2_test_read_element_data_no_hash);
TEST (manifest_flash_v2_test_read_element_data_no_hash_invalid_id);
TEST (manifest_flash_v2_test_read_element_data_with_parent);
TEST (manifest_flash_v2_test_read_element_data_second_element_instance);
TEST (manifest_flash_v2_test_read_element_data_partial_element);
TEST (manifest_flash_v2_test_read_element_data_partial_element_no_hash);
TEST (manifest_flash_v2_test_read_element_data_large_buffer);
TEST (manifest_flash_v2_test_read_element_data_max_entry_and_hash);
TEST (manifest_flash_v2_test_read_element_data_with_read_offset);
TEST (manifest_flash_v2_test_read_element_data_with_read_offset_no_hash);
TEST (manifest_flash_v2_test_read_element_data_with_read_offset_dynamic_allocation);
TEST (manifest_flash_v2_test_read_element_data_partial_element_with_read_offset);
TEST (manifest_flash_v2_test_read_element_data_partial_element_with_read_offset_no_hash);
TEST (manifest_flash_v2_test_read_element_data_with_read_offset_larger_than_element);
TEST (manifest_flash_v2_test_read_element_data_with_read_offset_larger_than_element_dynamic_allocation);
TEST (manifest_flash_v2_test_read_element_data_with_read_offset_equal_to_element_length);
TEST (manifest_flash_v2_test_read_element_data_read_zero_length);
TEST (manifest_flash_v2_test_read_element_data_read_null_element);
TEST (manifest_flash_v2_test_read_element_data_null);
TEST (manifest_flash_v2_test_read_element_data_verify_never_run);
TEST (manifest_flash_v2_test_read_element_data_after_verify_header_read_error);
TEST (manifest_flash_v2_test_read_element_data_after_verify_bad_signature);
TEST (manifest_flash_v2_test_read_element_data_element_not_found_not_present);
TEST (manifest_flash_v2_test_read_element_data_element_not_found_start_after_element);
TEST (manifest_flash_v2_test_read_element_data_element_not_found_bad_start_entry);
TEST (manifest_flash_v2_test_read_element_data_with_parent_wrong_type);
TEST (manifest_flash_v2_test_read_element_data_with_parent_wrong_type_no_hash);
TEST (manifest_flash_v2_test_read_element_data_with_parent_child_not_found);
TEST (manifest_flash_v2_test_read_element_data_with_parent_child_not_found_last_element);
TEST (manifest_flash_v2_test_read_element_data_with_parent_bad_start_entry);
TEST (manifest_flash_v2_test_read_element_data_child_no_parent_specified);
TEST (manifest_flash_v2_test_read_element_data_bad_toc_hash);
TEST (manifest_flash_v2_test_read_element_data_bad_element_hash);
TEST (manifest_flash_v2_test_read_element_data_start_toc_hash_error);
TEST (manifest_flash_v2_test_read_element_data_toc_header_hash_error);
TEST (manifest_flash_v2_test_read_element_data_toc_beginning_read_error);
TEST (manifest_flash_v2_test_read_element_data_toc_entry_read_error);
TEST (manifest_flash_v2_test_read_element_data_toc_entry_hash_error);
TEST (manifest_flash_v2_test_read_element_data_toc_middle_read_error);
TEST (manifest_flash_v2_test_read_element_data_toc_element_hash_read_error);
TEST (manifest_flash_v2_test_read_element_data_toc_element_hash_hash_error);
TEST (manifest_flash_v2_test_read_element_data_toc_end_read_error);
TEST (manifest_flash_v2_test_read_element_data_toc_end_no_element_hash_read_error);
TEST (manifest_flash_v2_test_read_element_data_finish_toc_hash_error);
TEST (manifest_flash_v2_test_read_element_data_start_element_hash_error);
TEST (manifest_flash_v2_test_read_element_data_element_offset_data_read_error);
TEST (manifest_flash_v2_test_read_element_data_element_read_error);
TEST (manifest_flash_v2_test_read_element_data_element_hash_error);
TEST (manifest_flash_v2_test_read_element_data_extra_element_data_read_error);
TEST (manifest_flash_v2_test_read_element_data_finish_element_hash_error);
TEST (manifest_flash_v2_test_compare_platform_id_equal);
TEST (manifest_flash_v2_test_compare_platform_id_sku_upgrade);
TEST (manifest_flash_v2_test_compare_platform_id_sku_upgrade_not_permitted);
TEST (manifest_flash_v2_test_compare_platform_id_sku_downgrade);
TEST (manifest_flash_v2_test_compare_platform_id_different);
TEST (manifest_flash_v2_test_compare_platform_id_no_manifest1);
TEST (manifest_flash_v2_test_compare_platform_id_no_manifest2);
TEST (manifest_flash_v2_test_compare_platform_id_no_manifests);
TEST (manifest_flash_v2_test_compare_platform_id_null_manifest1);
TEST (manifest_flash_v2_test_compare_platform_id_null_manifest2);
TEST (manifest_flash_v2_test_compare_platform_id_both_null);
TEST (manifest_flash_v2_test_get_num_child_elements_no_child_len);
TEST (manifest_flash_v2_test_get_num_child_elements_first_child);
TEST (manifest_flash_v2_test_get_num_child_elements_not_first_child);
TEST (manifest_flash_v2_test_get_num_child_elements_entry_with_nested_child);
TEST (manifest_flash_v2_test_get_num_child_elements_get_nested_child_count);
TEST (manifest_flash_v2_test_get_num_child_elements_terminate_at_parent);
TEST (manifest_flash_v2_test_get_num_child_elements_terminate_same_as_entry);
TEST (manifest_flash_v2_test_get_num_child_elements_entry_has_no_child_elements);
TEST (manifest_flash_v2_test_get_num_child_elements_null);
TEST (manifest_flash_v2_test_get_num_child_elements_verify_never_run);
TEST (manifest_flash_v2_test_get_num_child_elements_entry_invalid);
TEST (manifest_flash_v2_test_get_num_child_elements_entry_last);
TEST (manifest_flash_v2_test_get_num_child_elements_start_hash_fail);
TEST (manifest_flash_v2_test_get_num_child_elements_toc_header_hash_update_fail);
TEST (manifest_flash_v2_test_get_num_child_elements_toc_before_entry_hash_update_fail);
TEST (manifest_flash_v2_test_get_num_child_elements_read_fail);
TEST (manifest_flash_v2_test_get_num_child_elements_hash_update_entry_fail);
TEST (manifest_flash_v2_test_get_num_child_elements_toc_after_last_entry_hash_update_fail);
TEST (manifest_flash_v2_test_get_num_child_elements_hash_finish_fail);
TEST (manifest_flash_v2_test_get_num_child_elements_toc_invalid);

TEST_SUITE_END;
