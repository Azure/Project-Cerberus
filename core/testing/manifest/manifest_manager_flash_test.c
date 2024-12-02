// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "testing.h"
#include "flash/flash_common.h"
#include "manifest/cfm/cfm.h"
#include "manifest/manifest_manager_flash.h"
#include "manifest/pcd/pcd.h"
#include "testing/engines/hash_testing_engine.h"
#include "testing/mock/crypto/signature_verification_mock.h"
#include "testing/mock/flash/flash_mock.h"
#include "testing/mock/manifest/manifest_mock.h"
#include "testing/mock/state_manager/state_manager_mock.h"


TEST_SUITE_LABEL ("manifest_manager_flash");


/**
 * Dependencies for testing the common manager for manifests on flash.
 */
struct manifest_manager_flash_testing {
	HASH_TESTING_ENGINE (hash);							/**< Hashing engine for validation. */
	struct signature_verification_mock verification;	/**< PFM signature verification. */
	struct flash_mock flash;							/**< Mock for flash storage. */
	struct state_manager_mock state_mgr;				/**< Mock for state management. */
	struct manifest_mock manifest1;						/**< Mock for the first manifest. */
	struct manifest_flash manifest1_flash;				/**< Common flash handler for the first manifest. */
	uint32_t manifest1_addr;							/**< Base address of the first manifest. */
	struct manifest_mock manifest2;						/**< Mock for the second manifest. */
	struct manifest_flash manifest2_flash;				/**< Common flash handler for the second manifest. */
	uint32_t manifest2_addr;							/**< Base address of the second manifest. */
	struct manifest_manager mgr_base;					/**< Common manifest manager handling. */
	struct manifest_manager_flash test;					/**< Manager instance under test. */
};


/**
 * Initialize common manifest manager testing dependencies.
 *
 * @param test The testing framework.
 * @param manager The testing components to initialize.
 * @param addr1 Base address of the first manifest.
 * @param addr2 Base address of the second manifest.
 */
static void manifest_manager_flash_testing_init_dependencies (CuTest *test,
	struct manifest_manager_flash_testing *manager, uint32_t addr1, uint32_t addr2)
{
	uint32_t block_size = FLASH_BLOCK_SIZE;
	int status;

	status = HASH_TESTING_ENGINE_INIT (&manager->hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&manager->verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&manager->flash);
	CuAssertIntEquals (test, 0, status);

	status = state_manager_mock_init (&manager->state_mgr);
	CuAssertIntEquals (test, 0, status);

	status = manifest_mock_init (&manager->manifest1);
	CuAssertIntEquals (test, 0, status);

	manager->manifest1_addr = addr1;
	mock_set_name (&manager->manifest1.mock, "manifest1");

	status = manifest_mock_init (&manager->manifest2);
	CuAssertIntEquals (test, 0, status);

	manager->manifest2_addr = addr2;
	mock_set_name (&manager->manifest2.mock, "manifest2");

	status = manifest_manager_init (&manager->mgr_base, &manager->hash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager->flash.mock, manager->flash.base.get_block_size,	&manager->flash,
		0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output_tmp (&manager->flash.mock, 0, &block_size, sizeof (block_size),
		-1);

	status |= mock_expect (&manager->flash.mock, manager->flash.base.get_block_size,
		&manager->flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output_tmp (&manager->flash.mock, 0, &block_size, sizeof (block_size),
		-1);

	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_init (&manager->manifest1_flash, &manager->flash.base, addr1, 0x1234);
	CuAssertIntEquals (test, 0, status);

	status = manifest_flash_init (&manager->manifest2_flash, &manager->flash.base, addr2, 0x1234);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Release test dependencies and validate all mocks.
 *
 * @param test The testing framework.
 * @param manager The testing components to release.
 */
void manifest_manager_flash_testing_release_dependencies (CuTest *test,
	struct manifest_manager_flash_testing *manager)
{
	int status;

	status = flash_mock_validate_and_release (&manager->flash);
	status |= signature_verification_mock_validate_and_release (&manager->verification);
	status |= state_manager_mock_validate_and_release (&manager->state_mgr);
	status |= manifest_mock_validate_and_release (&manager->manifest1);
	status |= manifest_mock_validate_and_release (&manager->manifest2);

	CuAssertIntEquals (test, 0, status);

	manifest_flash_release (&manager->manifest1_flash);
	manifest_flash_release (&manager->manifest2_flash);
	HASH_TESTING_ENGINE_RELEASE (&manager->hash);
}

/**
 * Release a test instance and validate all mocks.
 *
 * @param test The testing framework.
 * @param manager The testing components to release.
 */
static void manifest_manager_flash_testing_release (CuTest *test,
	struct manifest_manager_flash_testing *manager)
{
	manifest_manager_flash_release (&manager->test);

	manifest_manager_flash_testing_release_dependencies (test, manager);
}

/*******************
 * Test cases
 *******************/

static void manifest_manager_flash_test_init_cfm_verify_error (CuTest *test)
{
	struct manifest_manager_flash_testing manager;
	int status;
	int i;

	TEST_START;

	manifest_manager_flash_testing_init_dependencies (test, &manager, 0x10000, 0x20000);

	status = mock_expect (&manager.state_mgr.mock, manager.state_mgr.base.is_manifest_valid,
		&manager.state_mgr, 0, MOCK_ARG (0));

	/* The state manager is queried multiple times to determine active/pending regions. */
	for (i = 0; i < 7; i++) {
		status |= mock_expect (&manager.state_mgr.mock, manager.state_mgr.base.get_active_manifest,
			&manager.state_mgr, 0, MOCK_ARG (0));
	}

	status |= mock_expect (&manager.manifest1.mock, manager.manifest1.base.verify,
		&manager.manifest1, CFM_ENTRY_NOT_FOUND, MOCK_ARG_PTR (&manager.hash),
		MOCK_ARG_PTR (&manager.verification), MOCK_ARG_ANY, MOCK_ARG_ANY);

	status |= mock_expect (&manager.manifest2.mock, manager.manifest2.base.verify,
		&manager.manifest2, CFM_MALFORMED_COMPONENT_DEVICE_ENTRY, MOCK_ARG_PTR (&manager.hash),
		MOCK_ARG_PTR (&manager.verification), MOCK_ARG_ANY, MOCK_ARG_ANY);

	CuAssertIntEquals (test, 0, status);

	status = manifest_manager_flash_init (&manager.test, &manager.mgr_base,	&manager.manifest1.base,
		&manager.manifest2.base, &manager.manifest1_flash, &manager.manifest2_flash,
		&manager.state_mgr.base, &manager.hash.base, &manager.verification.base, 0, 0, false);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL,
		manifest_manager_flash_get_manifest_region (&manager.test, true));
	CuAssertPtrEquals (test, NULL,
		manifest_manager_flash_get_manifest_region (&manager.test, false));

	manifest_manager_flash_testing_release (test, &manager);
}

static void manifest_manager_flash_test_init_pcd_verify_error (CuTest *test)
{
	struct manifest_manager_flash_testing manager;
	int status;
	int i;

	TEST_START;

	manifest_manager_flash_testing_init_dependencies (test, &manager, 0x10000, 0x20000);

	status = mock_expect (&manager.state_mgr.mock, manager.state_mgr.base.is_manifest_valid,
		&manager.state_mgr, 0, MOCK_ARG (0));

	/* The state manager is queried multiple times to determine active/pending regions. */
	for (i = 0; i < 7; i++) {
		status |= mock_expect (&manager.state_mgr.mock, manager.state_mgr.base.get_active_manifest,
			&manager.state_mgr, 0, MOCK_ARG (0));
	}

	status |= mock_expect (&manager.manifest1.mock, manager.manifest1.base.verify,
		&manager.manifest1, PCD_INVALID_PORT, MOCK_ARG_PTR (&manager.hash),
		MOCK_ARG_PTR (&manager.verification), MOCK_ARG_ANY, MOCK_ARG_ANY);

	status |= mock_expect (&manager.manifest2.mock, manager.manifest2.base.verify,
		&manager.manifest2, PCD_MALFORMED_ROT_ELEMENT, MOCK_ARG_PTR (&manager.hash),
		MOCK_ARG_PTR (&manager.verification), MOCK_ARG_ANY, MOCK_ARG_ANY);

	CuAssertIntEquals (test, 0, status);

	status = manifest_manager_flash_init (&manager.test, &manager.mgr_base,	&manager.manifest1.base,
		&manager.manifest2.base, &manager.manifest1_flash, &manager.manifest2_flash,
		&manager.state_mgr.base, &manager.hash.base, &manager.verification.base, 0, 0, false);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL,
		manifest_manager_flash_get_manifest_region (&manager.test, true));
	CuAssertPtrEquals (test, NULL,
		manifest_manager_flash_get_manifest_region (&manager.test, false));

	manifest_manager_flash_testing_release (test, &manager);
}


// *INDENT-OFF*
TEST_SUITE_START (manifest_manager_flash);

/* TODO:  Consolidate many of the generic manifest_manager_flash workflows in this test suite rather
 * than duplicating them across PFM, CFM, and PCD manager test suites. */
TEST (manifest_manager_flash_test_init_cfm_verify_error);
TEST (manifest_manager_flash_test_init_pcd_verify_error);

TEST_SUITE_END;
// *INDENT-ON*
