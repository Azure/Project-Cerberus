// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "testing.h"
#include "attestation/pcr_store.h"
#include "common/array_size.h"
#include "firmware/firmware_pfm_verify.h"
#include "firmware/firmware_pfm_verify_static.h"
#include "manifest/manifest_logging.h"
#include "manifest/manifest_manager.h"
#include "testing/crypto/hash_testing.h"
#include "testing/engines/hash_testing_engine.h"
#include "testing/logging/debug_log_testing.h"
#include "testing/manifest/pfm/pfm_flash_v2_testing.h"
#include "testing/mock/crypto/hash_mock.h"
#include "testing/mock/crypto/signature_verification_mock.h"
#include "testing/mock/flash/flash_mock.h"
#include "testing/mock/logging/logging_mock.h"
#include "testing/mock/manifest/pfm/pfm_mock.h"


TEST_SUITE_LABEL ("firmware_pfm_verify");


/**
 * Measurement event ID to use for the verification result.
 */
#define	FIRMWARE_PFM_VERIFY_TESTING_EVENT_ID_RESULT			0x11112222

/**
 * Measurement digest for a successful verification result (i.e. 0).
 */
const uint8_t FIRMWARE_PFM_VERIFY_TESTING_RESULT_SUCCESS_MEASUREMENT[] = {
	0x72, 0x8e, 0x27, 0xea, 0x05, 0x55, 0xb3, 0xe0, 0x5b, 0xa5, 0xd0, 0x32, 0x20, 0x2c, 0xde, 0x48,
	0x7e, 0x12, 0x16, 0xd3, 0x0c, 0x50, 0xcc, 0xbe, 0x27, 0x51, 0xca, 0x90, 0x17, 0x9e, 0xc8, 0xfc
};

/**
 * Measurement digest for verification not having been run (i.e. FIRMWARE_PFM_VERIFY_NOT_VERIFIED).
 */
const uint8_t FIRMWARE_PFM_VERIFY_TESTING_RESULT_NOT_RUN_MEASUREMENT[] = {
	0x34, 0xe8, 0xc3, 0x9b, 0xb3, 0x90, 0xf3, 0x36, 0x54, 0x19, 0xfb, 0x7b, 0xc7, 0x62, 0xfc, 0xe2,
	0xdb, 0xf3, 0x74, 0x0f, 0xb4, 0x39, 0xb5, 0xf9, 0x0d, 0xbc, 0x4e, 0x7e, 0xfc, 0xe1, 0xeb, 0x4f
};

/**
 * Measurement digest for a verification failure (FIRMWARE_PFM_VERIFY_PFM_MULTI_FW).
 */
const uint8_t FIRMWARE_PFM_VERIFY_TESTING_RESULT_MULTI_FW_MEASUREMENT[] = {
	0x5d, 0xc6, 0x92, 0x66, 0x05, 0x40, 0x78, 0x52, 0x26, 0x8c, 0x26, 0x37, 0xe6, 0xc8, 0x6e, 0x2c,
	0xac, 0x1c, 0x62, 0xee, 0xfa, 0x34, 0x94, 0x4b, 0xe6, 0x37, 0x10, 0xbd, 0xd0, 0xcb, 0x70, 0x3e
};

/**
 * Measurement digest for a verification failure (FIRMWARE_PFM_VERIFY_EMPTY_PFM).
 */
const uint8_t FIRMWARE_PFM_VERIFY_TESTING_RESULT_EMPTY_PFM_MEASUREMENT[] = {
	0x46, 0xe3, 0x99, 0xc0, 0x14, 0xc5, 0x5e, 0x25, 0x78, 0x20, 0x85, 0xb5, 0xf7, 0x41, 0x28, 0xd8,
	0xb1, 0x66, 0x92, 0xfa, 0xb8, 0xb8, 0x9a, 0xd5, 0x3d, 0xe5, 0xbd, 0x26, 0x93, 0x9b, 0xc6, 0x82
};

/**
 * Measurement digest for a verification failure (FIRMWARE_PFM_VERIFY_PFM_MULTI_VERSION).
 */
const uint8_t FIRMWARE_PFM_VERIFY_TESTING_RESULT_MULTI_VERSION_MEASUREMENT[] = {
	0x0b, 0xd7, 0xb6, 0x26, 0xb9, 0x5a, 0xf1, 0x45, 0x3e, 0x51, 0xc2, 0x48, 0x1e, 0x8f, 0x88, 0x75,
	0xe8, 0xe5, 0x54, 0xff, 0x6d, 0x2c, 0x7e, 0x3e, 0xd6, 0x6f, 0x28, 0x85, 0x53, 0x5b, 0x33, 0x05
};

/**
 * Measurement digest for a verification failure (FIRMWARE_PFM_VERIFY_PFM_NO_VERSION).
 */
const uint8_t FIRMWARE_PFM_VERIFY_TESTING_RESULT_NO_VERSION_MEASUREMENT[] = {
	0xd5, 0xbd, 0xd1, 0x44, 0xae, 0xc6, 0xae, 0x84, 0xc4, 0xaa, 0x84, 0x1e, 0xaf, 0xcb, 0xd5, 0xa5,
	0x8c, 0xdd, 0xcc, 0x6d, 0xdc, 0xe8, 0x3f, 0x52, 0x12, 0x14, 0xc3, 0xbb, 0xe8, 0x7f, 0x1a, 0x51
};

/**
 * Measurement digest for a verification failure (FIRMWARE_PFM_VERIFY_PFM_NO_IMAGE).
 */
const uint8_t FIRMWARE_PFM_VERIFY_TESTING_RESULT_NO_IMAGE_MEASUREMENT[] = {
	0x99, 0x66, 0xe9, 0x22, 0x5d, 0x92, 0x18, 0x82, 0xb2, 0x23, 0xa9, 0x97, 0x0d, 0xfa, 0x66, 0xb2,
	0x16, 0x93, 0x89, 0x49, 0xa3, 0x4f, 0xab, 0x47, 0x93, 0x0e, 0xa3, 0xaf, 0xc9, 0x5d, 0x3c, 0x31
};

/**
 * Measurement digest for a verification failure (MANIFEST_VERIFY_FAILED).
 */
const uint8_t FIRMWARE_PFM_VERIFY_TESTING_RESULT_PFM_VERIFY_FAILED_MEASUREMENT[] = {
	0x38, 0x4e, 0x06, 0x36, 0xce, 0xbe, 0x3a, 0xd2, 0x50, 0x15, 0x60, 0x5f, 0x24, 0x56, 0x36, 0xb9,
	0x44, 0xe2, 0x92, 0x98, 0x63, 0x44, 0x6f, 0xdd, 0x7c, 0xcb, 0x28, 0xe5, 0xe3, 0xe0, 0xc1, 0xd0
};

/**
 * Measurement digest for a verification failure (MANIFEST_CHECK_EMPTY_FAILED).
 */
const uint8_t FIRMWARE_PFM_VERIFY_TESTING_RESULT_PFM_EMPTY_FAILED_MEASUREMENT[] = {
	0xae, 0x66, 0xf5, 0xda, 0x94, 0x99, 0x16, 0x97, 0x75, 0x0e, 0xcd, 0x48, 0x75, 0x17, 0x56, 0x66,
	0x4b, 0xf5, 0x98, 0x4d, 0xeb, 0x69, 0x0b, 0x30, 0xc0, 0x80, 0x98, 0xcb, 0x3e, 0x0d, 0x49, 0xea
};

/**
 * Measurement digest for a verification failure (PFM_GET_FW_FAILED).
 */
const uint8_t FIRMWARE_PFM_VERIFY_TESTING_RESULT_PFM_GET_FW_FAILED_MEASUREMENT[] = {
	0x17, 0xde, 0xc8, 0x6c, 0xc8, 0xe7, 0x08, 0x85, 0xc2, 0xf9, 0xc9, 0x3d, 0xd6, 0x70, 0xb6, 0xf0,
	0x87, 0x09, 0xd4, 0x8c, 0x2a, 0x6c, 0x4b, 0x65, 0x06, 0x00, 0x33, 0x15, 0x66, 0xb5, 0x80, 0xa4
};

/**
 * Measurement digest for a verification failure (PFM_GET_VERSIONS_FAILED).
 */
const uint8_t FIRMWARE_PFM_VERIFY_TESTING_RESULT_PFM_GET_VERSIONS_FAILED_MEASUREMENT[] = {
	0x22, 0xad, 0x89, 0xe9, 0x78, 0x0c, 0xe3, 0x5d, 0x8c, 0xe8, 0xfe, 0x33, 0x18, 0x90, 0xb2, 0x51,
	0x28, 0xe7, 0x40, 0x8e, 0x25, 0x7d, 0x5b, 0xed, 0x73, 0x20, 0x38, 0xeb, 0x14, 0x61, 0x0c, 0x70
};

/**
 * Measurement digest for a verification failure (PFM_GET_FW_IMAGES_FAILED).
 */
const uint8_t FIRMWARE_PFM_VERIFY_TESTING_RESULT_PFM_GET_IMAGES_FAILED_MEASUREMENT[] = {
	0x41, 0x69, 0xaa, 0x60, 0xa2, 0xca, 0xf5, 0xf1, 0x55, 0xf7, 0x4a, 0x97, 0x4a, 0x28, 0xbe, 0xcd,
	0xee, 0x21, 0x80, 0x61, 0xcb, 0x26, 0x68, 0xed, 0x7d, 0x9c, 0xf0, 0xd4, 0x85, 0x4d, 0xf6, 0xd5
};

/**
 * Measurement digest for a verification failure (FLASH_READ_FAILED).
 */
const uint8_t FIRMWARE_PFM_VERIFY_TESTING_RESULT_FLASH_FAILED_MEASUREMENT[] = {
	0xee, 0x5a, 0x7e, 0x80, 0xd1, 0xf8, 0x54, 0xbb, 0xd3, 0xbf, 0x9c, 0x42, 0x33, 0xb4, 0x6b, 0x74,
	0xce, 0x27, 0x95, 0x05, 0xd2, 0xb2, 0xfe, 0x1f, 0x40, 0xd5, 0xee, 0xc6, 0x9c, 0x14, 0x82, 0x8b
};

/**
 * Measurement digest for a verification failure (FIRMWARE_PFM_VERIFY_UNSUPPORTED_ID).
 */
const uint8_t FIRMWARE_PFM_VERIFY_TESTING_RESULT_PFM_UNSUPPORTED_ID_MEASUREMENT[] = {
	0xe8, 0x15, 0x45, 0x84, 0x73, 0x01, 0xb7, 0x2f, 0x89, 0x8c, 0x67, 0x0a, 0x95, 0x47, 0xf2, 0x47,
	0xcc, 0x60, 0xe3, 0x62, 0xb1, 0x25, 0x27, 0x58, 0xac, 0x45, 0xa0, 0x66, 0x80, 0xed, 0xdb, 0xcb
};

/**
 * Measurement digest for a verification failure (MANIFEST_NO_MANIFEST).
 */
const uint8_t FIRMWARE_PFM_VERIFY_TESTING_RESULT_PFM_GET_ID_FAILED_MEASUREMENT[] = {
	0x70, 0xeb, 0xea, 0x90, 0xf0, 0x21, 0x85, 0x1a, 0x17, 0x99, 0xe8, 0x8e, 0x44, 0x52, 0xa5, 0x67,
	0xf8, 0x5a, 0xcd, 0x6a, 0xfa, 0x16, 0x47, 0xcd, 0xa1, 0xd6, 0xac, 0x4b, 0x7e, 0x7d, 0x78, 0xb9
};

/**
 * Measurement event ID to use for the firmware version string.
 */
#define	FIRMWARE_PFM_VERIFY_TESTING_EVENT_ID_VERSION		0x33334444

/**
 * Version string that is measured during verification.
 */
const char *FIRMWARE_PFM_VERIFY_TESTING_VERSION_STR = "1234";

/**
 * Measurement digest for the firmware version string of "1234", which includes the null terminator.
 */
const uint8_t FIRMWARE_PFM_VERIFY_TESTING_VERSION_MEASUREMENT[] = {
	0x24, 0x42, 0xf0, 0x8f, 0xf3, 0x46, 0xed, 0x18, 0xb1, 0xef, 0x7b, 0x88, 0x73, 0x93, 0xa8, 0x89,
	0xad, 0xf3, 0x91, 0x79, 0x73, 0x10, 0x47, 0x75, 0x4a, 0x4d, 0xac, 0xc5, 0x79, 0xf5, 0x6a, 0x50
};

/**
 * Measurement digest for an empty firmware version string (i.e. just a null character).
 */
const uint8_t FIRMWARE_PFM_VERIFY_TESTING_VERSION_EMPTY_MEASUREMENT[] = {
	0x90, 0xba, 0x32, 0x95, 0xc3, 0x34, 0x72, 0xd7, 0x8c, 0xa7, 0x44, 0xa2, 0xe0, 0x7b, 0xb2, 0x1b,
	0xc7, 0x04, 0xc9, 0xe8, 0x46, 0x01, 0x5d, 0x90, 0xab, 0xae, 0x3d, 0x7e, 0x6a, 0xe3, 0x88, 0x55
};

/**
 * Measurement event ID to use for the PFM digest.
 */
#define	FIRMWARE_PFM_VERIFY_TESTING_EVENT_ID_PFM			0x55556666

/**
 * Measurement digest for the PFM digest using PFM_V2.manifest.hash and PFM_V2.manifest.hash_len.
 */
const uint8_t FIRMWARE_PFM_VERIFY_TESTING_PFM_PFM_V2_MEASUREMENT[] = {
	0xca, 0x97, 0xe9, 0x7a, 0xdb, 0xa4, 0xd5, 0xab, 0xf3, 0x50, 0xad, 0x2b, 0xc1, 0x40, 0x60, 0x54,
	0xa7, 0xf2, 0xf9, 0x0f, 0xe2, 0x7f, 0xfa, 0x03, 0xf9, 0x2a, 0x30, 0x0b, 0x7b, 0xaf, 0xb1, 0x6b
};

/**
 * Measurement digest for no PFM (32 bytes of zero).
 */
const uint8_t FIRMWARE_PFM_VERIFY_TESTING_PFM_NONE_MEASUREMENT[] = {
	0x37, 0x96, 0x1e, 0x68, 0x23, 0x7f, 0x4a, 0xd6, 0xb3, 0x44, 0xda, 0xc1, 0x34, 0x4d, 0x38, 0x77,
	0x4e, 0xa5, 0x54, 0x21, 0xff, 0xf3, 0x76, 0xa2, 0xaa, 0x81, 0xb5, 0xda, 0x54, 0xc1, 0x88, 0x9e
};

/**
 * Measurement event ID to use for the PFM ID.
 */
#define	FIRMWARE_PFM_VERIFY_TESTING_EVENT_ID_PFM_ID			0x77778888

/**
 * Measurement digest for the PFM ID using PFM_V2.manifest.id.
 */
const uint8_t FIRMWARE_PFM_VERIFY_TESTING_PFM_ID_PFM_V2_MEASUREMENT[] = {
	0xda, 0x48, 0x81, 0x00, 0x1b, 0x5f, 0xbe, 0xda, 0xd0, 0x5a, 0x75, 0x08, 0x62, 0xaa, 0x12, 0xb2,
	0x4d, 0x04, 0x69, 0xc6, 0x42, 0x2c, 0x73, 0xc8, 0x3c, 0x59, 0x5b, 0xfa, 0x48, 0xab, 0x93, 0xfe
};

/**
 * Measurement digest for the PFM ID with no valid PFM.
 */
const uint8_t FIRMWARE_PFM_VERIFY_TESTING_PFM_ID_NONE_MEASUREMENT[] = {
	0x88, 0x95, 0x0a, 0x39, 0xb1, 0x29, 0xf4, 0xb4, 0xd0, 0x45, 0xa9, 0x1d, 0x89, 0xce, 0xc9, 0x7e,
	0x8f, 0x33, 0xae, 0xb1, 0xa9, 0xe7, 0x72, 0xa6, 0x2a, 0x57, 0x70, 0x04, 0x1b, 0x16, 0x19, 0x39
};

/**
 * Measurement event ID to use for the PFM platform ID.
 */
#define	FIRMWARE_PFM_VERIFY_TESTING_EVENT_ID_PLATFORM_ID	0x9999aaaa

/**
 * Measurement digest for the PFM platform ID using PFM_V2.manifest.plat_id_str and
 * PFM_V2.manifest.plat_id_str_len + 1.
 */
const uint8_t FIRMWARE_PFM_VERIFY_TESTING_PLATFORM_ID_PFM_V2_MEASUREMENT[] = {
	0x27, 0x64, 0x3f, 0x54, 0xac, 0x3e, 0x55, 0x08, 0xe9, 0x57, 0xb7, 0x6b, 0xf2, 0x9c, 0x73, 0xa3,
	0x40, 0xb5, 0xac, 0xac, 0x61, 0x7b, 0x1a, 0xfe, 0x5f, 0xd7, 0x21, 0x0c, 0x32, 0x37, 0x21, 0x72
};

/**
 * Measurement digest for the PFM platform ID with no valid PFM.
 */
const uint8_t FIRMWARE_PFM_VERIFY_TESTING_PLATFORM_ID_NONE_MEASUREMENT[] = {
	0x65, 0x49, 0x87, 0x5d, 0x38, 0x4f, 0x4b, 0x9e, 0x0d, 0xa8, 0x2e, 0x74, 0xc3, 0x65, 0x22, 0x04,
	0x40, 0x09, 0xdf, 0x3e, 0xe3, 0xd6, 0xeb, 0xec, 0x87, 0x36, 0xd7, 0xcb, 0xe7, 0xb3, 0x60, 0x7f
};


/**
 * Dependencies for testing.
 */
struct firmware_pfm_verify_testing {
	struct flash_mock flash;						/**< Mock for the flash device. */
	struct pfm_mock pfm;							/**< Mock for the PFM used for verification. */
	HASH_TESTING_ENGINE (hash);						/**< Hash engine for verification. */
	struct hash_engine_mock hash_mock;				/**< Mock for hash operations. */
	struct signature_verification_mock sig_verify;	/**< Mock for signature verification. */
	char version[256];								/**< Buffer the firmware version string. */
	struct pcr_store pcr;							/**< Measurement management. */
	struct logging_mock log;						/**< Mock for the debug log. */
	struct firmware_pfm_verify_state state;			/**< Context for the verification manager. */
	struct firmware_pfm_verify test;				/**< Verification manager under test. */
};


/**
 * Initialize testing dependencies.
 *
 * @param test The testing framework.
 * @param fw_verify The testing components to initialize.
 * @param measurement_result Measurement ID for the verification result.
 * @param measurement_version Measurement ID for the firmware version.
 * @param measurement_pfm Measurement ID for the PFM digest.
 * @param measurement_pfm_id Measurement ID for the PFM ID.
 * @param measurement_platform_id Measurement ID for the PFM platform ID.
 */
static void firmware_pfm_verify_testing_init_dependencies (CuTest *test,
	struct firmware_pfm_verify_testing *fw_verify, uint16_t measurement_result,
	uint16_t measurement_version, uint16_t measurement_pfm, uint16_t measurement_pfm_id,
	uint16_t measurement_platform_id)
{
	const struct pcr_config pcr_config[] = {
		{
			.num_measurements = 6,
			.measurement_algo = HASH_TYPE_SHA256
		}
	};
	int status;

	status = flash_mock_init (&fw_verify->flash);
	CuAssertIntEquals (test, 0, status);

	status = pfm_mock_init (&fw_verify->pfm);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_INIT (&fw_verify->hash);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_init (&fw_verify->hash_mock);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&fw_verify->sig_verify);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_init (&fw_verify->pcr, pcr_config, ARRAY_SIZE (pcr_config));
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_set_tcg_event_type (&fw_verify->pcr, measurement_result,
		FIRMWARE_PFM_VERIFY_TESTING_EVENT_ID_RESULT);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_set_tcg_event_type (&fw_verify->pcr, measurement_version,
		FIRMWARE_PFM_VERIFY_TESTING_EVENT_ID_VERSION);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_set_tcg_event_type (&fw_verify->pcr, measurement_pfm,
		FIRMWARE_PFM_VERIFY_TESTING_EVENT_ID_PFM);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_set_tcg_event_type (&fw_verify->pcr, measurement_pfm_id,
		FIRMWARE_PFM_VERIFY_TESTING_EVENT_ID_PFM_ID);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_set_tcg_event_type (&fw_verify->pcr, measurement_platform_id,
		FIRMWARE_PFM_VERIFY_TESTING_EVENT_ID_PLATFORM_ID);
	CuAssertIntEquals (test, 0, status);

	status = logging_mock_init (&fw_verify->log);
	CuAssertIntEquals (test, 0, status);

	debug_log = &fw_verify->log.base;
}

/**
 * Release all testing dependencies and validate all mocks.
 *
 * @param test The testing framework.
 * @param fw_verify The testing dependencies to release.
 */
static void firmware_pfm_verify_testing_release_dependencies (CuTest *test,
	struct firmware_pfm_verify_testing *fw_verify)
{
	int status;

	debug_log = NULL;

	status = flash_mock_validate_and_release (&fw_verify->flash);
	status |= pfm_mock_validate_and_release (&fw_verify->pfm);
	status |= hash_mock_validate_and_release (&fw_verify->hash_mock);
	status |= signature_verification_mock_validate_and_release (&fw_verify->sig_verify);
	status |= logging_mock_validate_and_release (&fw_verify->log);

	CuAssertIntEquals (test, 0, status);

	pcr_store_release (&fw_verify->pcr);
	HASH_TESTING_ENGINE_RELEASE (&fw_verify->hash);
}

/**
 * Set up expectations to mock measurement updates to a PCR.
 *
 * @param fw_verify The testing components to use.
 * @param count The number of measurement updates to mock.
 *
 * @return 0 if the expectations were set successfully or non-zero if not.
 */
static int firmware_pfm_verify_testing_mock_pcr_update (
	struct firmware_pfm_verify_testing *fw_verify, size_t count)
{
	int status = 0;
	size_t i;

	/* Mock PCR store operations for successful measurements.  In this case, the details of the
	 * operations are not meaningful, since they are not happening in the module being tested. */
	for (i = 0; i < count; i++) {
		status |= mock_expect (&fw_verify->hash_mock.mock, fw_verify->hash_mock.base.start_sha256,
			&fw_verify->hash_mock, 0);

		status |= mock_expect (&fw_verify->hash_mock.mock, fw_verify->hash_mock.base.update,
			&fw_verify->hash_mock, 0, MOCK_ARG_NOT_NULL, MOCK_ARG_ANY);
		status |= mock_expect (&fw_verify->hash_mock.mock, fw_verify->hash_mock.base.update,
			&fw_verify->hash_mock, 0, MOCK_ARG_NOT_NULL, MOCK_ARG_ANY);
		status |= mock_expect (&fw_verify->hash_mock.mock, fw_verify->hash_mock.base.update,
			&fw_verify->hash_mock, 0, MOCK_ARG_NOT_NULL, MOCK_ARG_ANY);

		status |= mock_expect (&fw_verify->hash_mock.mock, fw_verify->hash_mock.base.finish,
			&fw_verify->hash_mock, 0, MOCK_ARG_NOT_NULL, MOCK_ARG_ANY);
	}

	return status;
}

/**
 * Initialize an instance for testing.
 *
 * @param test The testing framework.
 * @param fw_verify The testing components to initialize.
 * @param version_length Length of the version buffer.  0 for max length.
 * @param measurement_result Measurement ID for the verification result.
 * @param measurement_version Measurement ID for the firmware version.
 * @param measurement_pfm Measurement ID for the PFM digest.
 * @param measurement_pfm_id Measurement ID for the PFM ID.
 * @param measurement_platform_id Measurement ID for the PFM platform ID.
 */
static void firmware_pfm_verify_testing_init (CuTest *test,
	struct firmware_pfm_verify_testing *fw_verify, size_t version_length,
	uint16_t measurement_result, uint16_t measurement_version, uint16_t measurement_pfm,
	uint16_t measurement_pfm_id, uint16_t measurement_platform_id)
{
	int status;
	size_t length = (version_length) ? version_length : sizeof (fw_verify->version);

	firmware_pfm_verify_testing_init_dependencies (test, fw_verify, measurement_result,
		measurement_version, measurement_pfm, measurement_pfm_id, measurement_platform_id);

	status = firmware_pfm_verify_init (&fw_verify->test, &fw_verify->state, &fw_verify->flash.base,
		&fw_verify->pfm.base, &fw_verify->hash.base, &fw_verify->sig_verify.base, &fw_verify->pcr,
		fw_verify->version, length, measurement_result, measurement_version, measurement_pfm,
		measurement_pfm_id, measurement_platform_id);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Initialize an instance for testing using a mock for hashing.
 *
 * @param test The testing framework.
 * @param fw_verify The testing components to initialize.
 * @param version_length Length of the version buffer.  0 for max length.
 * @param measurement_result Measurement ID for the verification result.
 * @param measurement_version Measurement ID for the firmware version.
 * @param measurement_pfm Measurement ID for the PFM digest.
 * @param measurement_pfm_id Measurement ID for the PFM ID.
 * @param measurement_platform_id Measurement ID for the PFM platform ID.
 */
static void firmware_pfm_verify_testing_init_mocked_hash (CuTest *test,
	struct firmware_pfm_verify_testing *fw_verify, size_t version_length,
	uint16_t measurement_result, uint16_t measurement_version, uint16_t measurement_pfm,
	uint16_t measurement_pfm_id, uint16_t measurement_platform_id)
{
	int status;
	size_t length = (version_length) ? version_length : sizeof (fw_verify->version);

	firmware_pfm_verify_testing_init_dependencies (test, fw_verify, measurement_result,
		measurement_version, measurement_pfm, measurement_pfm_id, measurement_platform_id);

	status = firmware_pfm_verify_testing_mock_pcr_update (fw_verify, 5);
	CuAssertIntEquals (test, 0, status);

	status = firmware_pfm_verify_init (&fw_verify->test, &fw_verify->state, &fw_verify->flash.base,
		&fw_verify->pfm.base, &fw_verify->hash_mock.base, &fw_verify->sig_verify.base,
		&fw_verify->pcr, fw_verify->version, length, measurement_result, measurement_version,
		measurement_pfm, measurement_pfm_id, measurement_platform_id);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Initialize a static instance for testing.
 *
 * @param test The testing framework.
 * @param fw_verify The testing components to initialize.
 * @param measurement_result Measurement ID for the verification result.
 * @param measurement_version Measurement ID for the firmware version.
 * @param measurement_pfm Measurement ID for the PFM digest.
 * @param measurement_pfm_id Measurement ID for the PFM ID.
 * @param measurement_platform_id Measurement ID for the PFM platform ID.
 */
static void firmware_pfm_verify_testing_init_static (CuTest *test,
	struct firmware_pfm_verify_testing *fw_verify, uint16_t measurement_result,
	uint16_t measurement_version, uint16_t measurement_pfm, uint16_t measurement_pfm_id,
	uint16_t measurement_platform_id)
{
	int status;

	firmware_pfm_verify_testing_init_dependencies (test, fw_verify, measurement_result,
		measurement_version, measurement_pfm, measurement_pfm_id, measurement_platform_id);

	status = firmware_pfm_verify_init_state (&fw_verify->test);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Release a test instance and validate all mocks.
 *
 * @param test The testing framework.
 * @param fw_verify The testing components to release.
 */
static void firmware_pfm_verify_testing_release (CuTest *test,
	struct firmware_pfm_verify_testing *fw_verify)
{
	firmware_pfm_verify_release (&fw_verify->test);
	firmware_pfm_verify_testing_release_dependencies (test, fw_verify);
}

/**
 * Execute a successful firmware verification using the PFM, which includes updating internal state
 * and PCR measurements.
 *
 * @param test The testing framework.
 * @param fw_verify The testing components to use for verification.
 */
static void firmware_pfm_verify_testing_run_successful_verification (CuTest *test,
	struct firmware_pfm_verify_testing *fw_verify)
{
	struct pfm_firmware fw_list;
	const char *fw_exp = {"fw1"};
	struct pfm_firmware_version version;
	struct pfm_firmware_versions version_list;
	const char *version_exp = FIRMWARE_PFM_VERIFY_TESTING_VERSION_STR;
	struct flash_region img_region;
	struct pfm_image_hash img_hash;
	struct pfm_image_list img_list;
	int status;

	/* Since the mocks will consume this information within the context of this function call, it's
	 * fine that these are stack allocations without using _tmp variants for expectation outputs. */
	fw_list.ids = &fw_exp;
	fw_list.count = 1;

	version.fw_version_id = version_exp;
	version.version_addr = 0x123;

	version_list.versions = &version;
	version_list.count = 1;

	img_region.start_addr = 0x10000;
	img_region.length = HASH_TESTING_FULL_BLOCK_4096_LEN;

	img_hash.regions = &img_region;
	img_hash.count = 1;
	memcpy (img_hash.hash, SHA256_FULL_BLOCK_4096_HASH, SHA256_HASH_LENGTH);
	img_hash.hash_length = SHA256_HASH_LENGTH;
	img_hash.hash_type = HASH_TYPE_SHA256;
	img_hash.always_validate = 1;

	img_list.images_hash = &img_hash;
	img_list.images_sig = NULL;
	img_list.count = 1;

	/* Verify the PFM. */
	status = mock_expect (&fw_verify->pfm.mock, fw_verify->pfm.base.base.verify, &fw_verify->pfm, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL, MOCK_ARG_PTR (NULL), MOCK_ARG (0));

	status |= mock_expect (&fw_verify->pfm.mock, fw_verify->pfm.base.base.is_empty, &fw_verify->pfm,
		0);

	/* Check that there is only one firmware component in the PFM. */
	status |= mock_expect (&fw_verify->pfm.mock, fw_verify->pfm.base.get_firmware, &fw_verify->pfm,
		0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&fw_verify->pfm.mock, 0, &fw_list, sizeof (fw_list), -1);
	status |= mock_expect_save_arg (&fw_verify->pfm.mock, 0, 0);

	status |= mock_expect (&fw_verify->pfm.mock, fw_verify->pfm.base.free_firmware, &fw_verify->pfm,
		0, MOCK_ARG_SAVED_ARG (0));

	/* Get the firmware version from the PFM. */
	status |= mock_expect (&fw_verify->pfm.mock, fw_verify->pfm.base.get_supported_versions,
		&fw_verify->pfm, 0, MOCK_ARG_PTR (NULL), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&fw_verify->pfm.mock, 1, &version_list, sizeof (version_list),
		-1);
	status |= mock_expect_save_arg (&fw_verify->pfm.mock, 1, 1);

	/* Get the image verification details. */
	status |= mock_expect (&fw_verify->pfm.mock, fw_verify->pfm.base.get_firmware_images,
		&fw_verify->pfm, 0, MOCK_ARG_PTR (NULL),
		MOCK_ARG_PTR_CONTAINS_TMP (version_exp, strlen (version_exp) + 1), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&fw_verify->pfm.mock, 2, &img_list, sizeof (img_list), -1);
	status |= mock_expect_save_arg (&fw_verify->pfm.mock, 2, 2);

	/* Run flash verification. */
	status |= flash_mock_expect_verify_flash (&fw_verify->flash, 0x10000,
		HASH_TESTING_FULL_BLOCK_4096, HASH_TESTING_FULL_BLOCK_4096_LEN);

	status |= mock_expect (&fw_verify->pfm.mock, fw_verify->pfm.base.free_firmware_images,
		&fw_verify->pfm, 0, MOCK_ARG_SAVED_ARG (2));
	status |= mock_expect (&fw_verify->pfm.mock, fw_verify->pfm.base.free_fw_versions,
		&fw_verify->pfm, 0, MOCK_ARG_SAVED_ARG (1));

	/* Measure PFM details. */
	status |= mock_expect (&fw_verify->pfm.mock, fw_verify->pfm.base.base.get_hash, &fw_verify->pfm,
		PFM_V2.manifest.hash_len, MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (PFM_V2.manifest.hash_len));
	status |= mock_expect_output (&fw_verify->pfm.mock, 1, PFM_V2.manifest.hash,
		PFM_V2.manifest.hash_len, 2);

	status |= mock_expect (&fw_verify->pfm.mock, fw_verify->pfm.base.base.get_id, &fw_verify->pfm,
		0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&fw_verify->pfm.mock, 0, &PFM_V2.manifest.id,
		sizeof (PFM_V2.manifest.id), -1);

	status |= mock_expect (&fw_verify->pfm.mock, fw_verify->pfm.base.base.get_platform_id,
		&fw_verify->pfm, 0, MOCK_ARG_PTR_PTR (NULL), MOCK_ARG (0));
	status |= mock_expect_output (&fw_verify->pfm.mock, 0, &PFM_V2.manifest.plat_id_str,
		sizeof (void*), -1);

	status |= mock_expect (&fw_verify->pfm.mock, fw_verify->pfm.base.base.free_platform_id,
		&fw_verify->pfm, 0, MOCK_ARG_PTR (PFM_V2.manifest.plat_id_str));

	CuAssertIntEquals (test, 0, status);

	status = firmware_pfm_verify_run_verification (&fw_verify->test, NULL);
	CuAssertIntEquals (test, 0, status);
}


/*******************
 * Test cases
 *******************/

static void firmware_pfm_verify_test_init (CuTest *test)
{
	uint16_t measurement_result = PCR_MEASUREMENT (0, 0);
	uint16_t measurement_version = PCR_MEASUREMENT (0, 1);
	uint16_t measurement_pfm = PCR_MEASUREMENT (0, 2);
	uint16_t measurement_pfm_id = PCR_MEASUREMENT (0, 3);
	uint16_t measurement_plat_id = PCR_MEASUREMENT (0, 4);
	struct firmware_pfm_verify_testing fw_verify;
	int status;
	struct pcr_measurement measurement;

	TEST_START;

	firmware_pfm_verify_testing_init_dependencies (test, &fw_verify, measurement_result,
		measurement_version, measurement_pfm, measurement_pfm_id, measurement_plat_id);

	status = firmware_pfm_verify_init (&fw_verify.test, &fw_verify.state, &fw_verify.flash.base,
		&fw_verify.pfm.base, &fw_verify.hash.base, &fw_verify.sig_verify.base, &fw_verify.pcr,
		fw_verify.version, sizeof (fw_verify.version), measurement_result, measurement_version,
		measurement_pfm, measurement_pfm_id, measurement_plat_id);
	CuAssertIntEquals (test, 0, status);

	/* Check verification result measurement. */
	status = pcr_store_get_measurement (&fw_verify.pcr, measurement_result, &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (FIRMWARE_PFM_VERIFY_TESTING_RESULT_NOT_RUN_MEASUREMENT,
		measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	/* Check firmware version measurement. */
	status = pcr_store_get_measurement (&fw_verify.pcr, measurement_version, &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (FIRMWARE_PFM_VERIFY_TESTING_VERSION_EMPTY_MEASUREMENT,
		measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	/* Check PFM digest measurement. */
	status = pcr_store_get_measurement (&fw_verify.pcr, measurement_pfm, &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (FIRMWARE_PFM_VERIFY_TESTING_PFM_NONE_MEASUREMENT,
		measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	/* Check PFM ID measurement. */
	status = pcr_store_get_measurement (&fw_verify.pcr, measurement_pfm_id, &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (FIRMWARE_PFM_VERIFY_TESTING_PFM_ID_NONE_MEASUREMENT,
		measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	/* Check PFM platform ID measurement. */
	status = pcr_store_get_measurement (&fw_verify.pcr, measurement_plat_id, &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (FIRMWARE_PFM_VERIFY_TESTING_PLATFORM_ID_NONE_MEASUREMENT,
		measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	firmware_pfm_verify_testing_release (test, &fw_verify);
}

static void firmware_pfm_verify_test_init_null (CuTest *test)
{
	uint16_t measurement_result = PCR_MEASUREMENT (0, 0);
	uint16_t measurement_version = PCR_MEASUREMENT (0, 1);
	uint16_t measurement_pfm = PCR_MEASUREMENT (0, 2);
	uint16_t measurement_pfm_id = PCR_MEASUREMENT (0, 3);
	uint16_t measurement_plat_id = PCR_MEASUREMENT (0, 4);
	struct firmware_pfm_verify_testing fw_verify;
	int status;

	TEST_START;

	firmware_pfm_verify_testing_init_dependencies (test, &fw_verify, measurement_result,
		measurement_version, measurement_pfm, measurement_pfm_id, measurement_plat_id);

	status = firmware_pfm_verify_init (NULL, &fw_verify.state, &fw_verify.flash.base,
		&fw_verify.pfm.base, &fw_verify.hash.base, &fw_verify.sig_verify.base, &fw_verify.pcr,
		fw_verify.version, sizeof (fw_verify.version), measurement_result, measurement_version,
		measurement_pfm, measurement_pfm_id, measurement_plat_id);
	CuAssertIntEquals (test, FIRMWARE_PFM_VERIFY_INVALID_ARGUMENT, status);

	status = firmware_pfm_verify_init (&fw_verify.test, NULL, &fw_verify.flash.base,
		&fw_verify.pfm.base, &fw_verify.hash.base, &fw_verify.sig_verify.base, &fw_verify.pcr,
		fw_verify.version, sizeof (fw_verify.version), measurement_result, measurement_version,
		measurement_pfm, measurement_pfm_id, measurement_plat_id);
	CuAssertIntEquals (test, FIRMWARE_PFM_VERIFY_INVALID_ARGUMENT, status);

	status = firmware_pfm_verify_init (&fw_verify.test, &fw_verify.state, NULL, &fw_verify.pfm.base,
		&fw_verify.hash.base, &fw_verify.sig_verify.base, &fw_verify.pcr, fw_verify.version,
		sizeof (fw_verify.version), measurement_result, measurement_version, measurement_pfm,
		measurement_pfm_id, measurement_plat_id);
	CuAssertIntEquals (test, FIRMWARE_PFM_VERIFY_INVALID_ARGUMENT, status);

	status = firmware_pfm_verify_init (&fw_verify.test, &fw_verify.state, &fw_verify.flash.base,
		NULL, &fw_verify.hash.base, &fw_verify.sig_verify.base, &fw_verify.pcr, fw_verify.version,
		sizeof (fw_verify.version), measurement_result, measurement_version, measurement_pfm,
		measurement_pfm_id, measurement_plat_id);
	CuAssertIntEquals (test, FIRMWARE_PFM_VERIFY_INVALID_ARGUMENT, status);

	status = firmware_pfm_verify_init (&fw_verify.test, &fw_verify.state, &fw_verify.flash.base,
		&fw_verify.pfm.base, NULL, &fw_verify.sig_verify.base, &fw_verify.pcr, fw_verify.version,
		sizeof (fw_verify.version), measurement_result, measurement_version, measurement_pfm,
		measurement_pfm_id, measurement_plat_id);
	CuAssertIntEquals (test, FIRMWARE_PFM_VERIFY_INVALID_ARGUMENT, status);

	status = firmware_pfm_verify_init (&fw_verify.test, &fw_verify.state, &fw_verify.flash.base,
		&fw_verify.pfm.base, &fw_verify.hash.base, NULL, &fw_verify.pcr, fw_verify.version,
		sizeof (fw_verify.version), measurement_result, measurement_version, measurement_pfm,
		measurement_pfm_id, measurement_plat_id);
	CuAssertIntEquals (test, FIRMWARE_PFM_VERIFY_INVALID_ARGUMENT, status);

	status = firmware_pfm_verify_init (&fw_verify.test, &fw_verify.state, &fw_verify.flash.base,
		&fw_verify.pfm.base, &fw_verify.hash.base, &fw_verify.sig_verify.base, NULL,
		fw_verify.version, sizeof (fw_verify.version), measurement_result, measurement_version,
		measurement_pfm, measurement_pfm_id, measurement_plat_id);
	CuAssertIntEquals (test, FIRMWARE_PFM_VERIFY_INVALID_ARGUMENT, status);

	status = firmware_pfm_verify_init (&fw_verify.test, &fw_verify.state, &fw_verify.flash.base,
		&fw_verify.pfm.base, &fw_verify.hash.base, &fw_verify.sig_verify.base, &fw_verify.pcr, NULL,
		sizeof (fw_verify.version), measurement_result, measurement_version, measurement_pfm,
		measurement_pfm_id, measurement_plat_id);
	CuAssertIntEquals (test, FIRMWARE_PFM_VERIFY_INVALID_ARGUMENT, status);

	status = firmware_pfm_verify_init (&fw_verify.test, &fw_verify.state, &fw_verify.flash.base,
		&fw_verify.pfm.base, &fw_verify.hash.base, &fw_verify.sig_verify.base, &fw_verify.pcr,
		fw_verify.version, 0, measurement_result, measurement_version, measurement_pfm,
		measurement_pfm_id, measurement_plat_id);
	CuAssertIntEquals (test, FIRMWARE_PFM_VERIFY_INVALID_ARGUMENT, status);

	firmware_pfm_verify_testing_release (test, &fw_verify);
}

static void firmware_pfm_verify_test_init_measurement_result_error (CuTest *test)
{
	uint16_t measurement_result = PCR_MEASUREMENT (0, 0);
	uint16_t measurement_version = PCR_MEASUREMENT (0, 1);
	uint16_t measurement_pfm = PCR_MEASUREMENT (0, 2);
	uint16_t measurement_pfm_id = PCR_MEASUREMENT (0, 3);
	uint16_t measurement_plat_id = PCR_MEASUREMENT (0, 4);
	struct firmware_pfm_verify_testing fw_verify;
	int status;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_MANIFEST,
		.msg_index = MANIFEST_LOGGING_RECORD_MEASUREMENT_FAIL,
		.arg1 = measurement_result,
		.arg2 = HASH_ENGINE_START_SHA256_FAILED
	};

	TEST_START;

	firmware_pfm_verify_testing_init_dependencies (test, &fw_verify, measurement_result,
		measurement_version, measurement_pfm, measurement_pfm_id, measurement_plat_id);

	status = mock_expect (&fw_verify.hash_mock.mock, fw_verify.hash_mock.base.start_sha256,
		&fw_verify.hash_mock, HASH_ENGINE_START_SHA256_FAILED);

	status |= mock_expect (&fw_verify.log.mock, fw_verify.log.base.create_entry, &fw_verify.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));

	CuAssertIntEquals (test, 0, status);

	status = firmware_pfm_verify_init (&fw_verify.test, &fw_verify.state, &fw_verify.flash.base,
		&fw_verify.pfm.base, &fw_verify.hash_mock.base, &fw_verify.sig_verify.base, &fw_verify.pcr,
		fw_verify.version, sizeof (fw_verify.version), measurement_result, measurement_version,
		measurement_pfm, measurement_pfm_id, measurement_plat_id);
	CuAssertIntEquals (test, HASH_ENGINE_START_SHA256_FAILED, status);

	firmware_pfm_verify_testing_release (test, &fw_verify);
}

static void firmware_pfm_verify_test_init_measurement_version_error (CuTest *test)
{
	uint16_t measurement_result = PCR_MEASUREMENT (0, 0);
	uint16_t measurement_version = PCR_MEASUREMENT (0, 1);
	uint16_t measurement_pfm = PCR_MEASUREMENT (0, 2);
	uint16_t measurement_pfm_id = PCR_MEASUREMENT (0, 3);
	uint16_t measurement_plat_id = PCR_MEASUREMENT (0, 4);
	struct firmware_pfm_verify_testing fw_verify;
	int status;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_MANIFEST,
		.msg_index = MANIFEST_LOGGING_RECORD_MEASUREMENT_FAIL,
		.arg1 = measurement_version,
		.arg2 = HASH_ENGINE_START_SHA256_FAILED
	};

	TEST_START;

	firmware_pfm_verify_testing_init_dependencies (test, &fw_verify, measurement_result,
		measurement_version, measurement_pfm, measurement_pfm_id, measurement_plat_id);

	status = firmware_pfm_verify_testing_mock_pcr_update (&fw_verify, 1);

	status |= mock_expect (&fw_verify.hash_mock.mock, fw_verify.hash_mock.base.start_sha256,
		&fw_verify.hash_mock, HASH_ENGINE_START_SHA256_FAILED);

	status |= mock_expect (&fw_verify.log.mock, fw_verify.log.base.create_entry, &fw_verify.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));

	CuAssertIntEquals (test, 0, status);

	status = firmware_pfm_verify_init (&fw_verify.test, &fw_verify.state, &fw_verify.flash.base,
		&fw_verify.pfm.base, &fw_verify.hash_mock.base, &fw_verify.sig_verify.base, &fw_verify.pcr,
		fw_verify.version, sizeof (fw_verify.version), measurement_result, measurement_version,
		measurement_pfm, measurement_pfm_id, measurement_plat_id);
	CuAssertIntEquals (test, HASH_ENGINE_START_SHA256_FAILED, status);

	firmware_pfm_verify_testing_release (test, &fw_verify);
}

static void firmware_pfm_verify_test_init_measurement_pfm_error (CuTest *test)
{
	uint16_t measurement_result = PCR_MEASUREMENT (0, 0);
	uint16_t measurement_version = PCR_MEASUREMENT (0, 1);
	uint16_t measurement_pfm = PCR_MEASUREMENT (0, 2);
	uint16_t measurement_pfm_id = PCR_MEASUREMENT (0, 3);
	uint16_t measurement_plat_id = PCR_MEASUREMENT (0, 4);
	struct firmware_pfm_verify_testing fw_verify;
	int status;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_MANIFEST,
		.msg_index = MANIFEST_LOGGING_RECORD_MEASUREMENT_FAIL,
		.arg1 = measurement_pfm,
		.arg2 = HASH_ENGINE_START_SHA256_FAILED
	};

	TEST_START;

	firmware_pfm_verify_testing_init_dependencies (test, &fw_verify, measurement_result,
		measurement_version, measurement_pfm, measurement_pfm_id, measurement_plat_id);

	status = firmware_pfm_verify_testing_mock_pcr_update (&fw_verify, 2);

	status |= mock_expect (&fw_verify.hash_mock.mock, fw_verify.hash_mock.base.start_sha256,
		&fw_verify.hash_mock, HASH_ENGINE_START_SHA256_FAILED);

	status |= mock_expect (&fw_verify.log.mock, fw_verify.log.base.create_entry, &fw_verify.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));

	CuAssertIntEquals (test, 0, status);

	status = firmware_pfm_verify_init (&fw_verify.test, &fw_verify.state, &fw_verify.flash.base,
		&fw_verify.pfm.base, &fw_verify.hash_mock.base, &fw_verify.sig_verify.base, &fw_verify.pcr,
		fw_verify.version, sizeof (fw_verify.version), measurement_result, measurement_version,
		measurement_pfm, measurement_pfm_id, measurement_plat_id);
	CuAssertIntEquals (test, HASH_ENGINE_START_SHA256_FAILED, status);

	firmware_pfm_verify_testing_release (test, &fw_verify);
}

static void firmware_pfm_verify_test_init_measurement_pfm_id_error (CuTest *test)
{
	uint16_t measurement_result = PCR_MEASUREMENT (0, 0);
	uint16_t measurement_version = PCR_MEASUREMENT (0, 1);
	uint16_t measurement_pfm = PCR_MEASUREMENT (0, 2);
	uint16_t measurement_pfm_id = PCR_MEASUREMENT (0, 3);
	uint16_t measurement_plat_id = PCR_MEASUREMENT (0, 4);
	struct firmware_pfm_verify_testing fw_verify;
	int status;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_MANIFEST,
		.msg_index = MANIFEST_LOGGING_RECORD_MEASUREMENT_FAIL,
		.arg1 = measurement_pfm_id,
		.arg2 = HASH_ENGINE_START_SHA256_FAILED
	};

	TEST_START;

	firmware_pfm_verify_testing_init_dependencies (test, &fw_verify, measurement_result,
		measurement_version, measurement_pfm, measurement_pfm_id, measurement_plat_id);

	status = firmware_pfm_verify_testing_mock_pcr_update (&fw_verify, 3);

	status |= mock_expect (&fw_verify.hash_mock.mock, fw_verify.hash_mock.base.start_sha256,
		&fw_verify.hash_mock, HASH_ENGINE_START_SHA256_FAILED);

	status |= mock_expect (&fw_verify.log.mock, fw_verify.log.base.create_entry, &fw_verify.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));

	CuAssertIntEquals (test, 0, status);

	status = firmware_pfm_verify_init (&fw_verify.test, &fw_verify.state, &fw_verify.flash.base,
		&fw_verify.pfm.base, &fw_verify.hash_mock.base, &fw_verify.sig_verify.base, &fw_verify.pcr,
		fw_verify.version, sizeof (fw_verify.version), measurement_result, measurement_version,
		measurement_pfm, measurement_pfm_id, measurement_plat_id);
	CuAssertIntEquals (test, HASH_ENGINE_START_SHA256_FAILED, status);

	firmware_pfm_verify_testing_release (test, &fw_verify);
}

static void firmware_pfm_verify_test_init_measurement_platform_id_error (CuTest *test)
{
	uint16_t measurement_result = PCR_MEASUREMENT (0, 0);
	uint16_t measurement_version = PCR_MEASUREMENT (0, 1);
	uint16_t measurement_pfm = PCR_MEASUREMENT (0, 2);
	uint16_t measurement_pfm_id = PCR_MEASUREMENT (0, 3);
	uint16_t measurement_plat_id = PCR_MEASUREMENT (0, 4);
	struct firmware_pfm_verify_testing fw_verify;
	int status;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_MANIFEST,
		.msg_index = MANIFEST_LOGGING_RECORD_MEASUREMENT_FAIL,
		.arg1 = measurement_plat_id,
		.arg2 = HASH_ENGINE_START_SHA256_FAILED
	};

	TEST_START;

	firmware_pfm_verify_testing_init_dependencies (test, &fw_verify, measurement_result,
		measurement_version, measurement_pfm, measurement_pfm_id, measurement_plat_id);

	status = firmware_pfm_verify_testing_mock_pcr_update (&fw_verify, 4);

	status |= mock_expect (&fw_verify.hash_mock.mock, fw_verify.hash_mock.base.start_sha256,
		&fw_verify.hash_mock, HASH_ENGINE_START_SHA256_FAILED);

	status |= mock_expect (&fw_verify.log.mock, fw_verify.log.base.create_entry, &fw_verify.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));

	CuAssertIntEquals (test, 0, status);

	status = firmware_pfm_verify_init (&fw_verify.test, &fw_verify.state, &fw_verify.flash.base,
		&fw_verify.pfm.base, &fw_verify.hash_mock.base, &fw_verify.sig_verify.base, &fw_verify.pcr,
		fw_verify.version, sizeof (fw_verify.version), measurement_result, measurement_version,
		measurement_pfm, measurement_pfm_id, measurement_plat_id);
	CuAssertIntEquals (test, HASH_ENGINE_START_SHA256_FAILED, status);

	firmware_pfm_verify_testing_release (test, &fw_verify);
}

static void firmware_pfm_verify_test_static_init (CuTest *test)
{
	uint16_t measurement_result = PCR_MEASUREMENT (0, 1);
	uint16_t measurement_version = PCR_MEASUREMENT (0, 3);
	uint16_t measurement_pfm = PCR_MEASUREMENT (0, 5);
	uint16_t measurement_pfm_id = PCR_MEASUREMENT (0, 4);
	uint16_t measurement_plat_id = PCR_MEASUREMENT (0, 2);
	struct firmware_pfm_verify_testing fw_verify = {
		.test = firmware_pfm_verify_static_init (&fw_verify.state, &fw_verify.flash.base,
			&fw_verify.pfm.base, &fw_verify.hash.base, &fw_verify.sig_verify.base, &fw_verify.pcr,
			fw_verify.version, sizeof (fw_verify.version), measurement_result, measurement_version,
			measurement_pfm, measurement_pfm_id, measurement_plat_id)
	};
	int status;
	struct pcr_measurement measurement;

	TEST_START;

	firmware_pfm_verify_testing_init_dependencies (test, &fw_verify, measurement_result,
		measurement_version, measurement_pfm, measurement_pfm_id, measurement_plat_id);

	status = firmware_pfm_verify_init_state (&fw_verify.test);
	CuAssertIntEquals (test, 0, status);

	/* Check verification result measurement. */
	status = pcr_store_get_measurement (&fw_verify.pcr, measurement_result, &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (FIRMWARE_PFM_VERIFY_TESTING_RESULT_NOT_RUN_MEASUREMENT,
		measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	/* Check firmware version measurement. */
	status = pcr_store_get_measurement (&fw_verify.pcr, measurement_version, &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (FIRMWARE_PFM_VERIFY_TESTING_VERSION_EMPTY_MEASUREMENT,
		measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	/* Check PFM digest measurement. */
	status = pcr_store_get_measurement (&fw_verify.pcr, measurement_pfm, &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (FIRMWARE_PFM_VERIFY_TESTING_PFM_NONE_MEASUREMENT,
		measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	/* Check PFM ID measurement. */
	status = pcr_store_get_measurement (&fw_verify.pcr, measurement_pfm_id, &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (FIRMWARE_PFM_VERIFY_TESTING_PFM_ID_NONE_MEASUREMENT,
		measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	/* Check PFM platform ID measurement. */
	status = pcr_store_get_measurement (&fw_verify.pcr, measurement_plat_id, &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (FIRMWARE_PFM_VERIFY_TESTING_PLATFORM_ID_NONE_MEASUREMENT,
		measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	firmware_pfm_verify_testing_release (test, &fw_verify);
}

static void firmware_pfm_verify_test_static_init_null (CuTest *test)
{
	uint16_t measurement_result = PCR_MEASUREMENT (0, 1);
	uint16_t measurement_version = PCR_MEASUREMENT (0, 3);
	uint16_t measurement_pfm = PCR_MEASUREMENT (0, 5);
	uint16_t measurement_pfm_id = PCR_MEASUREMENT (0, 4);
	uint16_t measurement_plat_id = PCR_MEASUREMENT (0, 2);
	struct firmware_pfm_verify_testing fw_verify = {
		.test = firmware_pfm_verify_static_init (&fw_verify.state, &fw_verify.flash.base,
			&fw_verify.pfm.base, &fw_verify.hash.base, &fw_verify.sig_verify.base, &fw_verify.pcr,
			fw_verify.version, sizeof (fw_verify.version), measurement_result, measurement_version,
			measurement_pfm, measurement_pfm_id, measurement_plat_id)
	};

	struct firmware_pfm_verify null_state = firmware_pfm_verify_static_init (NULL,
		&fw_verify.flash.base, &fw_verify.pfm.base, &fw_verify.hash.base,
		&fw_verify.sig_verify.base, &fw_verify.pcr, fw_verify.version, sizeof (fw_verify.version),
		measurement_result, measurement_version, measurement_pfm, measurement_pfm_id,
		measurement_plat_id);

	struct firmware_pfm_verify null_flash = firmware_pfm_verify_static_init (&fw_verify.state, NULL,
		&fw_verify.pfm.base, &fw_verify.hash.base, &fw_verify.sig_verify.base, &fw_verify.pcr,
		fw_verify.version, sizeof (fw_verify.version), measurement_result, measurement_version,
		measurement_pfm, measurement_pfm_id, measurement_plat_id);

	struct firmware_pfm_verify null_pfm = firmware_pfm_verify_static_init (&fw_verify.state,
		&fw_verify.flash.base, NULL, &fw_verify.hash.base, &fw_verify.sig_verify.base,
		&fw_verify.pcr, fw_verify.version, sizeof (fw_verify.version), measurement_result,
		measurement_version, measurement_pfm, measurement_pfm_id, measurement_plat_id);

	struct firmware_pfm_verify null_hash = firmware_pfm_verify_static_init (&fw_verify.state,
		&fw_verify.flash.base, &fw_verify.pfm.base, NULL, &fw_verify.sig_verify.base,
		&fw_verify.pcr, fw_verify.version, sizeof (fw_verify.version), measurement_result,
		measurement_version, measurement_pfm, measurement_pfm_id, measurement_plat_id);

	struct firmware_pfm_verify null_verify = firmware_pfm_verify_static_init (&fw_verify.state,
		&fw_verify.flash.base, &fw_verify.pfm.base, &fw_verify.hash.base, NULL, &fw_verify.pcr,
		fw_verify.version, sizeof (fw_verify.version), measurement_result, measurement_version,
		measurement_pfm, measurement_pfm_id, measurement_plat_id);

	struct firmware_pfm_verify null_pcr = firmware_pfm_verify_static_init (&fw_verify.state,
		&fw_verify.flash.base, &fw_verify.pfm.base, &fw_verify.hash.base,
		&fw_verify.sig_verify.base, NULL, fw_verify.version, sizeof (fw_verify.version),
		measurement_result, measurement_version, measurement_pfm, measurement_pfm_id,
		measurement_plat_id);

	struct firmware_pfm_verify null_version = firmware_pfm_verify_static_init (&fw_verify.state,
		&fw_verify.flash.base, &fw_verify.pfm.base, &fw_verify.hash.base,
		&fw_verify.sig_verify.base, &fw_verify.pcr, NULL, sizeof (fw_verify.version),
		measurement_result, measurement_version, measurement_pfm, measurement_pfm_id,
		measurement_plat_id);

	struct firmware_pfm_verify zero_version_len = firmware_pfm_verify_static_init (&fw_verify.state,
		&fw_verify.flash.base, &fw_verify.pfm.base, &fw_verify.hash.base,
		&fw_verify.sig_verify.base, &fw_verify.pcr, fw_verify.version, 0, measurement_result,
		measurement_version, measurement_pfm, measurement_pfm_id, measurement_plat_id);
	int status;

	TEST_START;

	firmware_pfm_verify_testing_init_dependencies (test, &fw_verify, measurement_result,
		measurement_version, measurement_pfm, measurement_pfm_id, measurement_plat_id);

	status = firmware_pfm_verify_init_state (NULL);
	CuAssertIntEquals (test, FIRMWARE_PFM_VERIFY_INVALID_ARGUMENT, status);

	status = firmware_pfm_verify_init_state (&null_state);
	CuAssertIntEquals (test, FIRMWARE_PFM_VERIFY_INVALID_ARGUMENT, status);

	status = firmware_pfm_verify_init_state (&null_flash);
	CuAssertIntEquals (test, FIRMWARE_PFM_VERIFY_INVALID_ARGUMENT, status);

	status = firmware_pfm_verify_init_state (&null_pfm);
	CuAssertIntEquals (test, FIRMWARE_PFM_VERIFY_INVALID_ARGUMENT, status);

	status = firmware_pfm_verify_init_state (&null_hash);
	CuAssertIntEquals (test, FIRMWARE_PFM_VERIFY_INVALID_ARGUMENT, status);

	status = firmware_pfm_verify_init_state (&null_verify);
	CuAssertIntEquals (test, FIRMWARE_PFM_VERIFY_INVALID_ARGUMENT, status);

	status = firmware_pfm_verify_init_state (&null_pcr);
	CuAssertIntEquals (test, FIRMWARE_PFM_VERIFY_INVALID_ARGUMENT, status);

	status = firmware_pfm_verify_init_state (&null_version);
	CuAssertIntEquals (test, FIRMWARE_PFM_VERIFY_INVALID_ARGUMENT, status);

	status = firmware_pfm_verify_init_state (&zero_version_len);
	CuAssertIntEquals (test, FIRMWARE_PFM_VERIFY_INVALID_ARGUMENT, status);

	firmware_pfm_verify_testing_release (test, &fw_verify);
}

static void firmware_pfm_verify_test_static_init_measurement_result_error (CuTest *test)
{
	uint16_t measurement_result = PCR_MEASUREMENT (0, 1);
	uint16_t measurement_version = PCR_MEASUREMENT (0, 3);
	uint16_t measurement_pfm = PCR_MEASUREMENT (0, 5);
	uint16_t measurement_pfm_id = PCR_MEASUREMENT (0, 4);
	uint16_t measurement_plat_id = PCR_MEASUREMENT (0, 2);
	struct firmware_pfm_verify_testing fw_verify = {
		.test = firmware_pfm_verify_static_init (&fw_verify.state, &fw_verify.flash.base,
			&fw_verify.pfm.base, &fw_verify.hash_mock.base, &fw_verify.sig_verify.base,
			&fw_verify.pcr, fw_verify.version, sizeof (fw_verify.version), measurement_result,
			measurement_version, measurement_pfm, measurement_pfm_id, measurement_plat_id)
	};
	int status;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_MANIFEST,
		.msg_index = MANIFEST_LOGGING_RECORD_MEASUREMENT_FAIL,
		.arg1 = measurement_result,
		.arg2 = HASH_ENGINE_START_SHA256_FAILED
	};

	TEST_START;

	firmware_pfm_verify_testing_init_dependencies (test, &fw_verify, measurement_result,
		measurement_version, measurement_pfm, measurement_pfm_id, measurement_plat_id);

	status = mock_expect (&fw_verify.hash_mock.mock, fw_verify.hash_mock.base.start_sha256,
		&fw_verify.hash_mock, HASH_ENGINE_START_SHA256_FAILED);

	status |= mock_expect (&fw_verify.log.mock, fw_verify.log.base.create_entry, &fw_verify.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));

	CuAssertIntEquals (test, 0, status);

	status = firmware_pfm_verify_init_state (&fw_verify.test);
	CuAssertIntEquals (test, HASH_ENGINE_START_SHA256_FAILED, status);

	firmware_pfm_verify_testing_release (test, &fw_verify);
}

static void firmware_pfm_verify_test_static_init_measurement_version_error (CuTest *test)
{
	uint16_t measurement_result = PCR_MEASUREMENT (0, 1);
	uint16_t measurement_version = PCR_MEASUREMENT (0, 3);
	uint16_t measurement_pfm = PCR_MEASUREMENT (0, 5);
	uint16_t measurement_pfm_id = PCR_MEASUREMENT (0, 4);
	uint16_t measurement_plat_id = PCR_MEASUREMENT (0, 2);
	struct firmware_pfm_verify_testing fw_verify = {
		.test = firmware_pfm_verify_static_init (&fw_verify.state, &fw_verify.flash.base,
			&fw_verify.pfm.base, &fw_verify.hash_mock.base, &fw_verify.sig_verify.base,
			&fw_verify.pcr, fw_verify.version, sizeof (fw_verify.version), measurement_result,
			measurement_version, measurement_pfm, measurement_pfm_id, measurement_plat_id)
	};
	int status;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_MANIFEST,
		.msg_index = MANIFEST_LOGGING_RECORD_MEASUREMENT_FAIL,
		.arg1 = measurement_version,
		.arg2 = HASH_ENGINE_START_SHA256_FAILED
	};

	TEST_START;

	firmware_pfm_verify_testing_init_dependencies (test, &fw_verify, measurement_result,
		measurement_version, measurement_pfm, measurement_pfm_id, measurement_plat_id);

	status = firmware_pfm_verify_testing_mock_pcr_update (&fw_verify, 1);

	status |= mock_expect (&fw_verify.hash_mock.mock, fw_verify.hash_mock.base.start_sha256,
		&fw_verify.hash_mock, HASH_ENGINE_START_SHA256_FAILED);

	status |= mock_expect (&fw_verify.log.mock, fw_verify.log.base.create_entry, &fw_verify.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));

	CuAssertIntEquals (test, 0, status);

	status = firmware_pfm_verify_init_state (&fw_verify.test);
	CuAssertIntEquals (test, HASH_ENGINE_START_SHA256_FAILED, status);

	firmware_pfm_verify_testing_release (test, &fw_verify);
}

static void firmware_pfm_verify_test_static_init_measurement_pfm_error (CuTest *test)
{
	uint16_t measurement_result = PCR_MEASUREMENT (0, 1);
	uint16_t measurement_version = PCR_MEASUREMENT (0, 3);
	uint16_t measurement_pfm = PCR_MEASUREMENT (0, 5);
	uint16_t measurement_pfm_id = PCR_MEASUREMENT (0, 4);
	uint16_t measurement_plat_id = PCR_MEASUREMENT (0, 2);
	struct firmware_pfm_verify_testing fw_verify = {
		.test = firmware_pfm_verify_static_init (&fw_verify.state, &fw_verify.flash.base,
			&fw_verify.pfm.base, &fw_verify.hash_mock.base, &fw_verify.sig_verify.base,
			&fw_verify.pcr, fw_verify.version, sizeof (fw_verify.version), measurement_result,
			measurement_version, measurement_pfm, measurement_pfm_id, measurement_plat_id)
	};
	int status;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_MANIFEST,
		.msg_index = MANIFEST_LOGGING_RECORD_MEASUREMENT_FAIL,
		.arg1 = measurement_pfm,
		.arg2 = HASH_ENGINE_START_SHA256_FAILED
	};

	TEST_START;

	firmware_pfm_verify_testing_init_dependencies (test, &fw_verify, measurement_result,
		measurement_version, measurement_pfm, measurement_pfm_id, measurement_plat_id);

	status = firmware_pfm_verify_testing_mock_pcr_update (&fw_verify, 2);

	status |= mock_expect (&fw_verify.hash_mock.mock, fw_verify.hash_mock.base.start_sha256,
		&fw_verify.hash_mock, HASH_ENGINE_START_SHA256_FAILED);

	status |= mock_expect (&fw_verify.log.mock, fw_verify.log.base.create_entry, &fw_verify.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));

	CuAssertIntEquals (test, 0, status);

	status = firmware_pfm_verify_init_state (&fw_verify.test);
	CuAssertIntEquals (test, HASH_ENGINE_START_SHA256_FAILED, status);

	firmware_pfm_verify_testing_release (test, &fw_verify);
}

static void firmware_pfm_verify_test_static_init_measurement_pfm_id_error (CuTest *test)
{
	uint16_t measurement_result = PCR_MEASUREMENT (0, 1);
	uint16_t measurement_version = PCR_MEASUREMENT (0, 3);
	uint16_t measurement_pfm = PCR_MEASUREMENT (0, 5);
	uint16_t measurement_pfm_id = PCR_MEASUREMENT (0, 4);
	uint16_t measurement_plat_id = PCR_MEASUREMENT (0, 2);
	struct firmware_pfm_verify_testing fw_verify = {
		.test = firmware_pfm_verify_static_init (&fw_verify.state, &fw_verify.flash.base,
			&fw_verify.pfm.base, &fw_verify.hash_mock.base, &fw_verify.sig_verify.base,
			&fw_verify.pcr, fw_verify.version, sizeof (fw_verify.version), measurement_result,
			measurement_version, measurement_pfm, measurement_pfm_id, measurement_plat_id)
	};
	int status;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_MANIFEST,
		.msg_index = MANIFEST_LOGGING_RECORD_MEASUREMENT_FAIL,
		.arg1 = measurement_pfm_id,
		.arg2 = HASH_ENGINE_START_SHA256_FAILED
	};

	TEST_START;

	firmware_pfm_verify_testing_init_dependencies (test, &fw_verify, measurement_result,
		measurement_version, measurement_pfm, measurement_pfm_id, measurement_plat_id);

	status = firmware_pfm_verify_testing_mock_pcr_update (&fw_verify, 3);

	status |= mock_expect (&fw_verify.hash_mock.mock, fw_verify.hash_mock.base.start_sha256,
		&fw_verify.hash_mock, HASH_ENGINE_START_SHA256_FAILED);

	status |= mock_expect (&fw_verify.log.mock, fw_verify.log.base.create_entry, &fw_verify.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));

	CuAssertIntEquals (test, 0, status);

	status = firmware_pfm_verify_init_state (&fw_verify.test);
	CuAssertIntEquals (test, HASH_ENGINE_START_SHA256_FAILED, status);

	firmware_pfm_verify_testing_release (test, &fw_verify);
}

static void firmware_pfm_verify_test_static_init_measurement_platform_id_error (CuTest *test)
{
	uint16_t measurement_result = PCR_MEASUREMENT (0, 1);
	uint16_t measurement_version = PCR_MEASUREMENT (0, 3);
	uint16_t measurement_pfm = PCR_MEASUREMENT (0, 5);
	uint16_t measurement_pfm_id = PCR_MEASUREMENT (0, 4);
	uint16_t measurement_plat_id = PCR_MEASUREMENT (0, 2);
	struct firmware_pfm_verify_testing fw_verify = {
		.test = firmware_pfm_verify_static_init (&fw_verify.state, &fw_verify.flash.base,
			&fw_verify.pfm.base, &fw_verify.hash_mock.base, &fw_verify.sig_verify.base,
			&fw_verify.pcr, fw_verify.version, sizeof (fw_verify.version), measurement_result,
			measurement_version, measurement_pfm, measurement_pfm_id, measurement_plat_id)
	};
	int status;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_MANIFEST,
		.msg_index = MANIFEST_LOGGING_RECORD_MEASUREMENT_FAIL,
		.arg1 = measurement_plat_id,
		.arg2 = HASH_ENGINE_START_SHA256_FAILED
	};

	TEST_START;

	firmware_pfm_verify_testing_init_dependencies (test, &fw_verify, measurement_result,
		measurement_version, measurement_pfm, measurement_pfm_id, measurement_plat_id);

	status = firmware_pfm_verify_testing_mock_pcr_update (&fw_verify, 4);

	status |= mock_expect (&fw_verify.hash_mock.mock, fw_verify.hash_mock.base.start_sha256,
		&fw_verify.hash_mock, HASH_ENGINE_START_SHA256_FAILED);

	status |= mock_expect (&fw_verify.log.mock, fw_verify.log.base.create_entry, &fw_verify.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));

	CuAssertIntEquals (test, 0, status);

	status = firmware_pfm_verify_init_state (&fw_verify.test);
	CuAssertIntEquals (test, HASH_ENGINE_START_SHA256_FAILED, status);

	firmware_pfm_verify_testing_release (test, &fw_verify);
}

static void firmware_pfm_verify_test_release_null (CuTest *test)
{
	TEST_START;

	firmware_pfm_verify_release (NULL);
}

static void firmware_pfm_verify_test_run_verification (CuTest *test)
{
	uint16_t measurement_result = PCR_MEASUREMENT (0, 0);
	uint16_t measurement_version = PCR_MEASUREMENT (0, 1);
	uint16_t measurement_pfm = PCR_MEASUREMENT (0, 2);
	uint16_t measurement_pfm_id = PCR_MEASUREMENT (0, 3);
	uint16_t measurement_plat_id = PCR_MEASUREMENT (0, 4);
	struct firmware_pfm_verify_testing fw_verify;
	struct pfm_firmware fw_list;
	const char *fw_exp = {"fw1"};
	struct pfm_firmware_version version;
	struct pfm_firmware_versions version_list;
	const char *version_exp = FIRMWARE_PFM_VERIFY_TESTING_VERSION_STR;
	struct flash_region img_region;
	struct pfm_image_hash img_hash;
	struct pfm_image_list img_list;
	int status;
	struct pcr_measurement measurement;

	TEST_START;

	/* Set up PFM data for a single firmware version for a single firmware component.  The image is
	 * contained in a single region of flash.  More comprehensive testing of this verification flow
	 * is part of the host_fw_util test suite. */
	fw_list.ids = &fw_exp;
	fw_list.count = 1;

	version.fw_version_id = version_exp;
	version.version_addr = 0x123;

	version_list.versions = &version;
	version_list.count = 1;

	img_region.start_addr = 0x10000;
	img_region.length = HASH_TESTING_FULL_BLOCK_4096_LEN;

	img_hash.regions = &img_region;
	img_hash.count = 1;
	memcpy (img_hash.hash, SHA256_FULL_BLOCK_4096_HASH, SHA256_HASH_LENGTH);
	img_hash.hash_length = SHA256_HASH_LENGTH;
	img_hash.hash_type = HASH_TYPE_SHA256;
	img_hash.always_validate = 1;

	img_list.images_hash = &img_hash;
	img_list.images_sig = NULL;
	img_list.count = 1;

	firmware_pfm_verify_testing_init (test, &fw_verify, 0, measurement_result, measurement_version,
		measurement_pfm, measurement_pfm_id, measurement_plat_id);

	/* Verify the PFM. */
	status = mock_expect (&fw_verify.pfm.mock, fw_verify.pfm.base.base.verify, &fw_verify.pfm, 0,
		MOCK_ARG_PTR (&fw_verify.hash), MOCK_ARG_PTR (&fw_verify.sig_verify), MOCK_ARG_PTR (NULL),
		MOCK_ARG (0));

	status |= mock_expect (&fw_verify.pfm.mock, fw_verify.pfm.base.base.is_empty, &fw_verify.pfm,
		0);

	/* Check that there is only one firmware component in the PFM. */
	status |= mock_expect (&fw_verify.pfm.mock, fw_verify.pfm.base.get_firmware, &fw_verify.pfm, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&fw_verify.pfm.mock, 0, &fw_list, sizeof (fw_list), -1);
	status |= mock_expect_save_arg (&fw_verify.pfm.mock, 0, 0);

	status |= mock_expect (&fw_verify.pfm.mock, fw_verify.pfm.base.free_firmware, &fw_verify.pfm, 0,
		MOCK_ARG_SAVED_ARG (0));

	/* Get the firmware version from the PFM. */
	status |= mock_expect (&fw_verify.pfm.mock, fw_verify.pfm.base.get_supported_versions,
		&fw_verify.pfm, 0, MOCK_ARG_PTR (NULL), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&fw_verify.pfm.mock, 1, &version_list, sizeof (version_list), -1);
	status |= mock_expect_save_arg (&fw_verify.pfm.mock, 1, 1);

	/* Get the image verification details. */
	status |= mock_expect (&fw_verify.pfm.mock, fw_verify.pfm.base.get_firmware_images,
		&fw_verify.pfm, 0, MOCK_ARG_PTR (NULL),
		MOCK_ARG_PTR_CONTAINS (version_exp, strlen (version_exp) + 1), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&fw_verify.pfm.mock, 2, &img_list, sizeof (img_list), -1);
	status |= mock_expect_save_arg (&fw_verify.pfm.mock, 2, 2);

	/* Run flash verification. */
	status |= flash_mock_expect_verify_flash (&fw_verify.flash, 0x10000,
		HASH_TESTING_FULL_BLOCK_4096, HASH_TESTING_FULL_BLOCK_4096_LEN);

	status |= mock_expect (&fw_verify.pfm.mock, fw_verify.pfm.base.free_firmware_images,
		&fw_verify.pfm, 0, MOCK_ARG_SAVED_ARG (2));
	status |= mock_expect (&fw_verify.pfm.mock, fw_verify.pfm.base.free_fw_versions, &fw_verify.pfm,
		0, MOCK_ARG_SAVED_ARG (1));

	/* Measure PFM details. */
	status |= mock_expect (&fw_verify.pfm.mock, fw_verify.pfm.base.base.get_hash, &fw_verify.pfm,
		PFM_V2.manifest.hash_len, MOCK_ARG_PTR (&fw_verify.hash), MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (PFM_V2.manifest.hash_len));
	status |= mock_expect_output (&fw_verify.pfm.mock, 1, PFM_V2.manifest.hash,
		PFM_V2.manifest.hash_len, 2);

	status |= mock_expect (&fw_verify.pfm.mock, fw_verify.pfm.base.base.get_id, &fw_verify.pfm, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&fw_verify.pfm.mock, 0, &PFM_V2.manifest.id,
		sizeof (PFM_V2.manifest.id), -1);

	status |= mock_expect (&fw_verify.pfm.mock, fw_verify.pfm.base.base.get_platform_id,
		&fw_verify.pfm, 0, MOCK_ARG_PTR_PTR (NULL), MOCK_ARG (0));
	status |= mock_expect_output (&fw_verify.pfm.mock, 0, &PFM_V2.manifest.plat_id_str,
		sizeof (void*), -1);

	status |= mock_expect (&fw_verify.pfm.mock, fw_verify.pfm.base.base.free_platform_id,
		&fw_verify.pfm, 0, MOCK_ARG_PTR (PFM_V2.manifest.plat_id_str));

	CuAssertIntEquals (test, 0, status);

	status = firmware_pfm_verify_run_verification (&fw_verify.test, NULL);
	CuAssertIntEquals (test, 0, status);

	/* Check verification result measurement. */
	status = pcr_store_get_measurement (&fw_verify.pcr, measurement_result, &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (FIRMWARE_PFM_VERIFY_TESTING_RESULT_SUCCESS_MEASUREMENT,
		measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	/* Check firmware version measurement. */
	status = pcr_store_get_measurement (&fw_verify.pcr, measurement_version, &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (FIRMWARE_PFM_VERIFY_TESTING_VERSION_MEASUREMENT,
		measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	/* Check PFM digest measurement. */
	status = pcr_store_get_measurement (&fw_verify.pcr, measurement_pfm, &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (FIRMWARE_PFM_VERIFY_TESTING_PFM_PFM_V2_MEASUREMENT,
		measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	/* Check PFM ID measurement. */
	status = pcr_store_get_measurement (&fw_verify.pcr, measurement_pfm_id, &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (FIRMWARE_PFM_VERIFY_TESTING_PFM_ID_PFM_V2_MEASUREMENT,
		measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	/* Check PFM platform ID measurement. */
	status = pcr_store_get_measurement (&fw_verify.pcr, measurement_plat_id, &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (FIRMWARE_PFM_VERIFY_TESTING_PLATFORM_ID_PFM_V2_MEASUREMENT,
		measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	firmware_pfm_verify_testing_release (test, &fw_verify);
}

static void firmware_pfm_verify_test_run_verification_supported_pfm_id (CuTest *test)
{
	uint16_t measurement_result = PCR_MEASUREMENT (0, 0);
	uint16_t measurement_version = PCR_MEASUREMENT (0, 1);
	uint16_t measurement_pfm = PCR_MEASUREMENT (0, 2);
	uint16_t measurement_pfm_id = PCR_MEASUREMENT (0, 3);
	uint16_t measurement_plat_id = PCR_MEASUREMENT (0, 4);
	struct firmware_pfm_verify_testing fw_verify;
	struct pfm_firmware fw_list;
	const char *fw_exp = {"fw1"};
	struct pfm_firmware_version version;
	struct pfm_firmware_versions version_list;
	const char *version_exp = FIRMWARE_PFM_VERIFY_TESTING_VERSION_STR;
	struct flash_region img_region;
	struct pfm_image_hash img_hash;
	struct pfm_image_list img_list;
	int status;
	struct pcr_measurement measurement;
	uint32_t pfm_expected_id;

	TEST_START;

	/* Set up PFM data for a single firmware version for a single firmware component.  The image is
	 * contained in a single region of flash.  More comprehensive testing of this verification flow
	 * is part of the host_fw_util test suite. */
	fw_list.ids = &fw_exp;
	fw_list.count = 1;

	version.fw_version_id = version_exp;
	version.version_addr = 0x123;

	version_list.versions = &version;
	version_list.count = 1;

	img_region.start_addr = 0x10000;
	img_region.length = HASH_TESTING_FULL_BLOCK_4096_LEN;

	img_hash.regions = &img_region;
	img_hash.count = 1;
	memcpy (img_hash.hash, SHA256_FULL_BLOCK_4096_HASH, SHA256_HASH_LENGTH);
	img_hash.hash_length = SHA256_HASH_LENGTH;
	img_hash.hash_type = HASH_TYPE_SHA256;
	img_hash.always_validate = 1;

	img_list.images_hash = &img_hash;
	img_list.images_sig = NULL;
	img_list.count = 1;

	pfm_expected_id = PFM_V2.manifest.id;

	firmware_pfm_verify_testing_init (test, &fw_verify, 0, measurement_result, measurement_version,
		measurement_pfm, measurement_pfm_id, measurement_plat_id);

	/* Verify the PFM. */
	status = mock_expect (&fw_verify.pfm.mock, fw_verify.pfm.base.base.verify, &fw_verify.pfm, 0,
		MOCK_ARG_PTR (&fw_verify.hash), MOCK_ARG_PTR (&fw_verify.sig_verify), MOCK_ARG_PTR (NULL),
		MOCK_ARG (0));

	/* Get the PFM ID from the PFM. */
	status |= mock_expect (&fw_verify.pfm.mock, fw_verify.pfm.base.base.get_id, &fw_verify.pfm, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&fw_verify.pfm.mock, 0, &PFM_V2.manifest.id,
		sizeof (PFM_V2.manifest.id), -1);

	status |= mock_expect (&fw_verify.pfm.mock, fw_verify.pfm.base.base.is_empty, &fw_verify.pfm,
		0);

	/* Check that there is only one firmware component in the PFM. */
	status |= mock_expect (&fw_verify.pfm.mock, fw_verify.pfm.base.get_firmware, &fw_verify.pfm, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&fw_verify.pfm.mock, 0, &fw_list, sizeof (fw_list), -1);
	status |= mock_expect_save_arg (&fw_verify.pfm.mock, 0, 0);

	status |= mock_expect (&fw_verify.pfm.mock, fw_verify.pfm.base.free_firmware, &fw_verify.pfm, 0,
		MOCK_ARG_SAVED_ARG (0));

	/* Get the firmware version from the PFM. */
	status |= mock_expect (&fw_verify.pfm.mock, fw_verify.pfm.base.get_supported_versions,
		&fw_verify.pfm, 0, MOCK_ARG_PTR (NULL), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&fw_verify.pfm.mock, 1, &version_list, sizeof (version_list), -1);
	status |= mock_expect_save_arg (&fw_verify.pfm.mock, 1, 1);

	/* Get the image verification details. */
	status |= mock_expect (&fw_verify.pfm.mock, fw_verify.pfm.base.get_firmware_images,
		&fw_verify.pfm, 0, MOCK_ARG_PTR (NULL),
		MOCK_ARG_PTR_CONTAINS (version_exp, strlen (version_exp) + 1), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&fw_verify.pfm.mock, 2, &img_list, sizeof (img_list), -1);
	status |= mock_expect_save_arg (&fw_verify.pfm.mock, 2, 2);

	/* Run flash verification. */
	status |= flash_mock_expect_verify_flash (&fw_verify.flash, 0x10000,
		HASH_TESTING_FULL_BLOCK_4096, HASH_TESTING_FULL_BLOCK_4096_LEN);

	status |= mock_expect (&fw_verify.pfm.mock, fw_verify.pfm.base.free_firmware_images,
		&fw_verify.pfm, 0, MOCK_ARG_SAVED_ARG (2));
	status |= mock_expect (&fw_verify.pfm.mock, fw_verify.pfm.base.free_fw_versions, &fw_verify.pfm,
		0, MOCK_ARG_SAVED_ARG (1));

	/* Measure PFM details. */
	status |= mock_expect (&fw_verify.pfm.mock, fw_verify.pfm.base.base.get_hash, &fw_verify.pfm,
		PFM_V2.manifest.hash_len, MOCK_ARG_PTR (&fw_verify.hash), MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (PFM_V2.manifest.hash_len));
	status |= mock_expect_output (&fw_verify.pfm.mock, 1, PFM_V2.manifest.hash,
		PFM_V2.manifest.hash_len, 2);

	status |= mock_expect (&fw_verify.pfm.mock, fw_verify.pfm.base.base.get_id, &fw_verify.pfm, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&fw_verify.pfm.mock, 0, &PFM_V2.manifest.id,
		sizeof (PFM_V2.manifest.id), -1);

	status |= mock_expect (&fw_verify.pfm.mock, fw_verify.pfm.base.base.get_platform_id,
		&fw_verify.pfm, 0, MOCK_ARG_PTR_PTR (NULL), MOCK_ARG (0));
	status |= mock_expect_output (&fw_verify.pfm.mock, 0, &PFM_V2.manifest.plat_id_str,
		sizeof (void*), -1);

	status |= mock_expect (&fw_verify.pfm.mock, fw_verify.pfm.base.base.free_platform_id,
		&fw_verify.pfm, 0, MOCK_ARG_PTR (PFM_V2.manifest.plat_id_str));

	CuAssertIntEquals (test, 0, status);

	status = firmware_pfm_verify_run_verification (&fw_verify.test, &pfm_expected_id);
	CuAssertIntEquals (test, 0, status);

	/* Check verification result measurement. */
	status = pcr_store_get_measurement (&fw_verify.pcr, measurement_result, &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (FIRMWARE_PFM_VERIFY_TESTING_RESULT_SUCCESS_MEASUREMENT,
		measurement.digest, SHA256_HASH_LENGTH);

	/* Check firmware version measurement. */
	status = pcr_store_get_measurement (&fw_verify.pcr, measurement_version, &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (FIRMWARE_PFM_VERIFY_TESTING_VERSION_MEASUREMENT,
		measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	/* Check PFM digest measurement. */
	status = pcr_store_get_measurement (&fw_verify.pcr, measurement_pfm, &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (FIRMWARE_PFM_VERIFY_TESTING_PFM_PFM_V2_MEASUREMENT,
		measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	/* Check PFM ID measurement. */
	status = pcr_store_get_measurement (&fw_verify.pcr, measurement_pfm_id, &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (FIRMWARE_PFM_VERIFY_TESTING_PFM_ID_PFM_V2_MEASUREMENT,
		measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	/* Check PFM platform ID measurement. */
	status = pcr_store_get_measurement (&fw_verify.pcr, measurement_plat_id, &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (FIRMWARE_PFM_VERIFY_TESTING_PLATFORM_ID_PFM_V2_MEASUREMENT,
		measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	firmware_pfm_verify_testing_release (test, &fw_verify);
}

static void firmware_pfm_verify_test_run_verification_small_version_buffer (CuTest *test)
{
	uint16_t measurement_result = PCR_MEASUREMENT (0, 0);
	uint16_t measurement_version = PCR_MEASUREMENT (0, 1);
	uint16_t measurement_pfm = PCR_MEASUREMENT (0, 2);
	uint16_t measurement_pfm_id = PCR_MEASUREMENT (0, 3);
	uint16_t measurement_plat_id = PCR_MEASUREMENT (0, 4);
	struct firmware_pfm_verify_testing fw_verify;
	struct pfm_firmware fw_list;
	const char *fw_exp = {"fw1"};
	struct pfm_firmware_version version;
	struct pfm_firmware_versions version_list;
	const char *version_exp = "12345";
	struct flash_region img_region;
	struct pfm_image_hash img_hash;
	struct pfm_image_list img_list;
	int status;
	struct pcr_measurement measurement;

	TEST_START;

	/* Set up PFM data for a single firmware version for a single firmware component.  The image is
	 * contained in a single region of flash.  More comprehensive testing of this verification flow
	 * is part of the host_fw_util test suite. */
	fw_list.ids = &fw_exp;
	fw_list.count = 1;

	version.fw_version_id = version_exp;
	version.version_addr = 0x123;

	version_list.versions = &version;
	version_list.count = 1;

	img_region.start_addr = 0x10000;
	img_region.length = HASH_TESTING_FULL_BLOCK_4096_LEN;

	img_hash.regions = &img_region;
	img_hash.count = 1;
	memcpy (img_hash.hash, SHA256_FULL_BLOCK_4096_HASH, SHA256_HASH_LENGTH);
	img_hash.hash_length = SHA256_HASH_LENGTH;
	img_hash.hash_type = HASH_TYPE_SHA256;
	img_hash.always_validate = 1;

	img_list.images_hash = &img_hash;
	img_list.images_sig = NULL;
	img_list.count = 1;

	firmware_pfm_verify_testing_init (test, &fw_verify, strlen (version_exp), measurement_result,
		measurement_version, measurement_pfm, measurement_pfm_id, measurement_plat_id);

	/* Verify the PFM. */
	status = mock_expect (&fw_verify.pfm.mock, fw_verify.pfm.base.base.verify, &fw_verify.pfm, 0,
		MOCK_ARG_PTR (&fw_verify.hash), MOCK_ARG_PTR (&fw_verify.sig_verify), MOCK_ARG_PTR (NULL),
		MOCK_ARG (0));

	status |= mock_expect (&fw_verify.pfm.mock, fw_verify.pfm.base.base.is_empty, &fw_verify.pfm,
		0);

	/* Check that there is only one firmware component in the PFM. */
	status |= mock_expect (&fw_verify.pfm.mock, fw_verify.pfm.base.get_firmware, &fw_verify.pfm, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&fw_verify.pfm.mock, 0, &fw_list, sizeof (fw_list), -1);
	status |= mock_expect_save_arg (&fw_verify.pfm.mock, 0, 0);

	status |= mock_expect (&fw_verify.pfm.mock, fw_verify.pfm.base.free_firmware, &fw_verify.pfm, 0,
		MOCK_ARG_SAVED_ARG (0));

	/* Get the firmware version from the PFM. */
	status |= mock_expect (&fw_verify.pfm.mock, fw_verify.pfm.base.get_supported_versions,
		&fw_verify.pfm, 0, MOCK_ARG_PTR (NULL), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&fw_verify.pfm.mock, 1, &version_list, sizeof (version_list), -1);
	status |= mock_expect_save_arg (&fw_verify.pfm.mock, 1, 1);

	/* Get the image verification details. */
	status |= mock_expect (&fw_verify.pfm.mock, fw_verify.pfm.base.get_firmware_images,
		&fw_verify.pfm, 0, MOCK_ARG_PTR (NULL),
		MOCK_ARG_PTR_CONTAINS (version_exp, strlen (version_exp) + 1), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&fw_verify.pfm.mock, 2, &img_list, sizeof (img_list), -1);
	status |= mock_expect_save_arg (&fw_verify.pfm.mock, 2, 2);

	/* Run flash verification. */
	status |= flash_mock_expect_verify_flash (&fw_verify.flash, 0x10000,
		HASH_TESTING_FULL_BLOCK_4096, HASH_TESTING_FULL_BLOCK_4096_LEN);

	status |= mock_expect (&fw_verify.pfm.mock, fw_verify.pfm.base.free_firmware_images,
		&fw_verify.pfm, 0, MOCK_ARG_SAVED_ARG (2));
	status |= mock_expect (&fw_verify.pfm.mock, fw_verify.pfm.base.free_fw_versions, &fw_verify.pfm,
		0, MOCK_ARG_SAVED_ARG (1));

	/* Measure PFM details. */
	status |= mock_expect (&fw_verify.pfm.mock, fw_verify.pfm.base.base.get_hash, &fw_verify.pfm,
		PFM_V2.manifest.hash_len, MOCK_ARG_PTR (&fw_verify.hash), MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (PFM_V2.manifest.hash_len));
	status |= mock_expect_output (&fw_verify.pfm.mock, 1, PFM_V2.manifest.hash,
		PFM_V2.manifest.hash_len, 2);

	status |= mock_expect (&fw_verify.pfm.mock, fw_verify.pfm.base.base.get_id, &fw_verify.pfm, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&fw_verify.pfm.mock, 0, &PFM_V2.manifest.id,
		sizeof (PFM_V2.manifest.id), -1);

	status |= mock_expect (&fw_verify.pfm.mock, fw_verify.pfm.base.base.get_platform_id,
		&fw_verify.pfm, 0, MOCK_ARG_PTR_PTR (NULL), MOCK_ARG (0));
	status |= mock_expect_output (&fw_verify.pfm.mock, 0, &PFM_V2.manifest.plat_id_str,
		sizeof (void*), -1);

	status |= mock_expect (&fw_verify.pfm.mock, fw_verify.pfm.base.base.free_platform_id,
		&fw_verify.pfm, 0, MOCK_ARG_PTR (PFM_V2.manifest.plat_id_str));

	CuAssertIntEquals (test, 0, status);

	status = firmware_pfm_verify_run_verification (&fw_verify.test, NULL);
	CuAssertIntEquals (test, 0, status);

	/* Check verification result measurement. */
	status = pcr_store_get_measurement (&fw_verify.pcr, measurement_result, &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (FIRMWARE_PFM_VERIFY_TESTING_RESULT_SUCCESS_MEASUREMENT,
		measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	/* Check firmware version measurement. */
	status = pcr_store_get_measurement (&fw_verify.pcr, measurement_version, &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (FIRMWARE_PFM_VERIFY_TESTING_VERSION_MEASUREMENT,
		measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	/* Check PFM digest measurement. */
	status = pcr_store_get_measurement (&fw_verify.pcr, measurement_pfm, &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (FIRMWARE_PFM_VERIFY_TESTING_PFM_PFM_V2_MEASUREMENT,
		measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	/* Check PFM ID measurement. */
	status = pcr_store_get_measurement (&fw_verify.pcr, measurement_pfm_id, &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (FIRMWARE_PFM_VERIFY_TESTING_PFM_ID_PFM_V2_MEASUREMENT,
		measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	/* Check PFM platform ID measurement. */
	status = pcr_store_get_measurement (&fw_verify.pcr, measurement_plat_id, &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (FIRMWARE_PFM_VERIFY_TESTING_PLATFORM_ID_PFM_V2_MEASUREMENT,
		measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	firmware_pfm_verify_testing_release (test, &fw_verify);
}

static void firmware_pfm_verify_test_run_verification_measurement_result_error (CuTest *test)
{
	uint16_t measurement_result = PCR_MEASUREMENT (0, 0);
	uint16_t measurement_version = PCR_MEASUREMENT (0, 1);
	uint16_t measurement_pfm = PCR_MEASUREMENT (0, 2);
	uint16_t measurement_pfm_id = PCR_MEASUREMENT (0, 3);
	uint16_t measurement_plat_id = PCR_MEASUREMENT (0, 4);
	struct firmware_pfm_verify_testing fw_verify;
	struct pfm_firmware fw_list;
	const char *fw_exp = {"fw1"};
	struct pfm_firmware_version version;
	struct pfm_firmware_versions version_list;
	const char *version_exp = FIRMWARE_PFM_VERIFY_TESTING_VERSION_STR;
	struct flash_region img_region;
	struct pfm_image_hash img_hash;
	struct pfm_image_list img_list;
	int status;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_MANIFEST,
		.msg_index = MANIFEST_LOGGING_RECORD_MEASUREMENT_FAIL,
		.arg1 = measurement_result,
		.arg2 = HASH_ENGINE_START_SHA256_FAILED
	};

	TEST_START;

	/* Set up PFM data for a single firmware version for a single firmware component.  The image is
	 * contained in a single region of flash.  More comprehensive testing of this verification flow
	 * is part of the host_fw_util test suite. */
	fw_list.ids = &fw_exp;
	fw_list.count = 1;

	version.fw_version_id = version_exp;
	version.version_addr = 0x123;

	version_list.versions = &version;
	version_list.count = 1;

	img_region.start_addr = 0x10000;
	img_region.length = HASH_TESTING_FULL_BLOCK_4096_LEN;

	img_hash.regions = &img_region;
	img_hash.count = 1;
	memcpy (img_hash.hash, SHA256_FULL_BLOCK_4096_HASH, SHA256_HASH_LENGTH);
	img_hash.hash_length = SHA256_HASH_LENGTH;
	img_hash.hash_type = HASH_TYPE_SHA256;
	img_hash.always_validate = 1;

	img_list.images_hash = &img_hash;
	img_list.images_sig = NULL;
	img_list.count = 1;

	firmware_pfm_verify_testing_init_mocked_hash (test, &fw_verify, 0, measurement_result,
		measurement_version, measurement_pfm, measurement_pfm_id, measurement_plat_id);

	/* Verify the PFM. */
	status = mock_expect (&fw_verify.pfm.mock, fw_verify.pfm.base.base.verify, &fw_verify.pfm, 0,
		MOCK_ARG_PTR (&fw_verify.hash_mock), MOCK_ARG_PTR (&fw_verify.sig_verify),
		MOCK_ARG_PTR (NULL), MOCK_ARG (0));

	status |= mock_expect (&fw_verify.pfm.mock, fw_verify.pfm.base.base.is_empty, &fw_verify.pfm,
		0);

	/* Check that there is only one firmware component in the PFM. */
	status |= mock_expect (&fw_verify.pfm.mock, fw_verify.pfm.base.get_firmware, &fw_verify.pfm, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&fw_verify.pfm.mock, 0, &fw_list, sizeof (fw_list), -1);
	status |= mock_expect_save_arg (&fw_verify.pfm.mock, 0, 0);

	status |= mock_expect (&fw_verify.pfm.mock, fw_verify.pfm.base.free_firmware, &fw_verify.pfm, 0,
		MOCK_ARG_SAVED_ARG (0));

	/* Get the firmware version from the PFM. */
	status |= mock_expect (&fw_verify.pfm.mock, fw_verify.pfm.base.get_supported_versions,
		&fw_verify.pfm, 0, MOCK_ARG_PTR (NULL), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&fw_verify.pfm.mock, 1, &version_list, sizeof (version_list), -1);
	status |= mock_expect_save_arg (&fw_verify.pfm.mock, 1, 1);

	/* Get the image verification details. */
	status |= mock_expect (&fw_verify.pfm.mock, fw_verify.pfm.base.get_firmware_images,
		&fw_verify.pfm, 0, MOCK_ARG_PTR (NULL),
		MOCK_ARG_PTR_CONTAINS (version_exp, strlen (version_exp) + 1), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&fw_verify.pfm.mock, 2, &img_list, sizeof (img_list), -1);
	status |= mock_expect_save_arg (&fw_verify.pfm.mock, 2, 2);

	/* Run flash verification. */
	status |= mock_expect (&fw_verify.hash_mock.mock, fw_verify.hash_mock.base.start_sha256,
		&fw_verify.hash_mock, 0);

	status |= flash_mock_expect_verify_flash_and_hash (&fw_verify.flash, &fw_verify.hash_mock,
		0x10000, HASH_TESTING_FULL_BLOCK_4096, HASH_TESTING_FULL_BLOCK_4096_LEN);

	status |= mock_expect (&fw_verify.hash_mock.mock, fw_verify.hash_mock.base.finish,
		&fw_verify.hash_mock, 0, MOCK_ARG_NOT_NULL, MOCK_ARG_AT_LEAST (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&fw_verify.hash_mock.mock, 0, SHA256_FULL_BLOCK_4096_HASH,
		SHA256_HASH_LENGTH, 1);

	status |= mock_expect (&fw_verify.pfm.mock, fw_verify.pfm.base.free_firmware_images,
		&fw_verify.pfm, 0, MOCK_ARG_SAVED_ARG (2));
	status |= mock_expect (&fw_verify.pfm.mock, fw_verify.pfm.base.free_fw_versions, &fw_verify.pfm,
		0, MOCK_ARG_SAVED_ARG (1));

	/* Measurement failure. */
	status |= mock_expect (&fw_verify.hash_mock.mock, fw_verify.hash_mock.base.start_sha256,
		&fw_verify.hash_mock, HASH_ENGINE_START_SHA256_FAILED);

	status |= mock_expect (&fw_verify.log.mock, fw_verify.log.base.create_entry, &fw_verify.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));

	CuAssertIntEquals (test, 0, status);

	status = firmware_pfm_verify_run_verification (&fw_verify.test, NULL);
	CuAssertIntEquals (test, 0, status);

	firmware_pfm_verify_testing_release (test, &fw_verify);
}

static void firmware_pfm_verify_test_run_verification_measurement_version_error (CuTest *test)
{
	uint16_t measurement_result = PCR_MEASUREMENT (0, 0);
	uint16_t measurement_version = PCR_MEASUREMENT (0, 1);
	uint16_t measurement_pfm = PCR_MEASUREMENT (0, 2);
	uint16_t measurement_pfm_id = PCR_MEASUREMENT (0, 3);
	uint16_t measurement_plat_id = PCR_MEASUREMENT (0, 4);
	struct firmware_pfm_verify_testing fw_verify;
	struct pfm_firmware fw_list;
	const char *fw_exp = {"fw1"};
	struct pfm_firmware_version version;
	struct pfm_firmware_versions version_list;
	const char *version_exp = FIRMWARE_PFM_VERIFY_TESTING_VERSION_STR;
	struct flash_region img_region;
	struct pfm_image_hash img_hash;
	struct pfm_image_list img_list;
	int status;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_MANIFEST,
		.msg_index = MANIFEST_LOGGING_RECORD_MEASUREMENT_FAIL,
		.arg1 = measurement_version,
		.arg2 = HASH_ENGINE_START_SHA256_FAILED
	};

	TEST_START;

	/* Set up PFM data for a single firmware version for a single firmware component.  The image is
	 * contained in a single region of flash.  More comprehensive testing of this verification flow
	 * is part of the host_fw_util test suite. */
	fw_list.ids = &fw_exp;
	fw_list.count = 1;

	version.fw_version_id = version_exp;
	version.version_addr = 0x123;

	version_list.versions = &version;
	version_list.count = 1;

	img_region.start_addr = 0x10000;
	img_region.length = HASH_TESTING_FULL_BLOCK_4096_LEN;

	img_hash.regions = &img_region;
	img_hash.count = 1;
	memcpy (img_hash.hash, SHA256_FULL_BLOCK_4096_HASH, SHA256_HASH_LENGTH);
	img_hash.hash_length = SHA256_HASH_LENGTH;
	img_hash.hash_type = HASH_TYPE_SHA256;
	img_hash.always_validate = 1;

	img_list.images_hash = &img_hash;
	img_list.images_sig = NULL;
	img_list.count = 1;

	firmware_pfm_verify_testing_init_mocked_hash (test, &fw_verify, 0, measurement_result,
		measurement_version, measurement_pfm, measurement_pfm_id, measurement_plat_id);

	/* Verify the PFM. */
	status = mock_expect (&fw_verify.pfm.mock, fw_verify.pfm.base.base.verify, &fw_verify.pfm, 0,
		MOCK_ARG_PTR (&fw_verify.hash_mock), MOCK_ARG_PTR (&fw_verify.sig_verify),
		MOCK_ARG_PTR (NULL), MOCK_ARG (0));

	status |= mock_expect (&fw_verify.pfm.mock, fw_verify.pfm.base.base.is_empty, &fw_verify.pfm,
		0);

	/* Check that there is only one firmware component in the PFM. */
	status |= mock_expect (&fw_verify.pfm.mock, fw_verify.pfm.base.get_firmware, &fw_verify.pfm, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&fw_verify.pfm.mock, 0, &fw_list, sizeof (fw_list), -1);
	status |= mock_expect_save_arg (&fw_verify.pfm.mock, 0, 0);

	status |= mock_expect (&fw_verify.pfm.mock, fw_verify.pfm.base.free_firmware, &fw_verify.pfm, 0,
		MOCK_ARG_SAVED_ARG (0));

	/* Get the firmware version from the PFM. */
	status |= mock_expect (&fw_verify.pfm.mock, fw_verify.pfm.base.get_supported_versions,
		&fw_verify.pfm, 0, MOCK_ARG_PTR (NULL), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&fw_verify.pfm.mock, 1, &version_list, sizeof (version_list), -1);
	status |= mock_expect_save_arg (&fw_verify.pfm.mock, 1, 1);

	/* Get the image verification details. */
	status |= mock_expect (&fw_verify.pfm.mock, fw_verify.pfm.base.get_firmware_images,
		&fw_verify.pfm, 0, MOCK_ARG_PTR (NULL),
		MOCK_ARG_PTR_CONTAINS (version_exp, strlen (version_exp) + 1), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&fw_verify.pfm.mock, 2, &img_list, sizeof (img_list), -1);
	status |= mock_expect_save_arg (&fw_verify.pfm.mock, 2, 2);

	/* Run flash verification. */
	status |= mock_expect (&fw_verify.hash_mock.mock, fw_verify.hash_mock.base.start_sha256,
		&fw_verify.hash_mock, 0);

	status |= flash_mock_expect_verify_flash_and_hash (&fw_verify.flash, &fw_verify.hash_mock,
		0x10000, HASH_TESTING_FULL_BLOCK_4096, HASH_TESTING_FULL_BLOCK_4096_LEN);

	status |= mock_expect (&fw_verify.hash_mock.mock, fw_verify.hash_mock.base.finish,
		&fw_verify.hash_mock, 0, MOCK_ARG_NOT_NULL, MOCK_ARG_AT_LEAST (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&fw_verify.hash_mock.mock, 0, SHA256_FULL_BLOCK_4096_HASH,
		SHA256_HASH_LENGTH, 1);

	status |= mock_expect (&fw_verify.pfm.mock, fw_verify.pfm.base.free_firmware_images,
		&fw_verify.pfm, 0, MOCK_ARG_SAVED_ARG (2));
	status |= mock_expect (&fw_verify.pfm.mock, fw_verify.pfm.base.free_fw_versions, &fw_verify.pfm,
		0, MOCK_ARG_SAVED_ARG (1));

	/* Measurement failure. */
	status |= firmware_pfm_verify_testing_mock_pcr_update (&fw_verify, 1);

	status |= mock_expect (&fw_verify.hash_mock.mock, fw_verify.hash_mock.base.start_sha256,
		&fw_verify.hash_mock, HASH_ENGINE_START_SHA256_FAILED);

	status |= mock_expect (&fw_verify.log.mock, fw_verify.log.base.create_entry, &fw_verify.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));

	CuAssertIntEquals (test, 0, status);

	status = firmware_pfm_verify_run_verification (&fw_verify.test, NULL);
	CuAssertIntEquals (test, 0, status);

	firmware_pfm_verify_testing_release (test, &fw_verify);
}

static void firmware_pfm_verify_test_run_verification_measurement_pfm_error (CuTest *test)
{
	uint16_t measurement_result = PCR_MEASUREMENT (0, 0);
	uint16_t measurement_version = PCR_MEASUREMENT (0, 1);
	uint16_t measurement_pfm = PCR_MEASUREMENT (0, 2);
	uint16_t measurement_pfm_id = PCR_MEASUREMENT (0, 3);
	uint16_t measurement_plat_id = PCR_MEASUREMENT (0, 4);
	struct firmware_pfm_verify_testing fw_verify;
	struct pfm_firmware fw_list;
	const char *fw_exp = {"fw1"};
	struct pfm_firmware_version version;
	struct pfm_firmware_versions version_list;
	const char *version_exp = FIRMWARE_PFM_VERIFY_TESTING_VERSION_STR;
	struct flash_region img_region;
	struct pfm_image_hash img_hash;
	struct pfm_image_list img_list;
	int status;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_MANIFEST,
		.msg_index = MANIFEST_LOGGING_RECORD_MEASUREMENT_FAIL,
		.arg1 = measurement_pfm,
		.arg2 = HASH_ENGINE_START_SHA256_FAILED
	};

	TEST_START;

	/* Set up PFM data for a single firmware version for a single firmware component.  The image is
	 * contained in a single region of flash.  More comprehensive testing of this verification flow
	 * is part of the host_fw_util test suite. */
	fw_list.ids = &fw_exp;
	fw_list.count = 1;

	version.fw_version_id = version_exp;
	version.version_addr = 0x123;

	version_list.versions = &version;
	version_list.count = 1;

	img_region.start_addr = 0x10000;
	img_region.length = HASH_TESTING_FULL_BLOCK_4096_LEN;

	img_hash.regions = &img_region;
	img_hash.count = 1;
	memcpy (img_hash.hash, SHA256_FULL_BLOCK_4096_HASH, SHA256_HASH_LENGTH);
	img_hash.hash_length = SHA256_HASH_LENGTH;
	img_hash.hash_type = HASH_TYPE_SHA256;
	img_hash.always_validate = 1;

	img_list.images_hash = &img_hash;
	img_list.images_sig = NULL;
	img_list.count = 1;

	firmware_pfm_verify_testing_init_mocked_hash (test, &fw_verify, 0, measurement_result,
		measurement_version, measurement_pfm, measurement_pfm_id, measurement_plat_id);

	/* Verify the PFM. */
	status = mock_expect (&fw_verify.pfm.mock, fw_verify.pfm.base.base.verify, &fw_verify.pfm, 0,
		MOCK_ARG_PTR (&fw_verify.hash_mock), MOCK_ARG_PTR (&fw_verify.sig_verify),
		MOCK_ARG_PTR (NULL), MOCK_ARG (0));

	status |= mock_expect (&fw_verify.pfm.mock, fw_verify.pfm.base.base.is_empty, &fw_verify.pfm,
		0);

	/* Check that there is only one firmware component in the PFM. */
	status |= mock_expect (&fw_verify.pfm.mock, fw_verify.pfm.base.get_firmware, &fw_verify.pfm, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&fw_verify.pfm.mock, 0, &fw_list, sizeof (fw_list), -1);
	status |= mock_expect_save_arg (&fw_verify.pfm.mock, 0, 0);

	status |= mock_expect (&fw_verify.pfm.mock, fw_verify.pfm.base.free_firmware, &fw_verify.pfm, 0,
		MOCK_ARG_SAVED_ARG (0));

	/* Get the firmware version from the PFM. */
	status |= mock_expect (&fw_verify.pfm.mock, fw_verify.pfm.base.get_supported_versions,
		&fw_verify.pfm, 0, MOCK_ARG_PTR (NULL), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&fw_verify.pfm.mock, 1, &version_list, sizeof (version_list), -1);
	status |= mock_expect_save_arg (&fw_verify.pfm.mock, 1, 1);

	/* Get the image verification details. */
	status |= mock_expect (&fw_verify.pfm.mock, fw_verify.pfm.base.get_firmware_images,
		&fw_verify.pfm, 0, MOCK_ARG_PTR (NULL),
		MOCK_ARG_PTR_CONTAINS (version_exp, strlen (version_exp) + 1), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&fw_verify.pfm.mock, 2, &img_list, sizeof (img_list), -1);
	status |= mock_expect_save_arg (&fw_verify.pfm.mock, 2, 2);

	/* Run flash verification. */
	status |= mock_expect (&fw_verify.hash_mock.mock, fw_verify.hash_mock.base.start_sha256,
		&fw_verify.hash_mock, 0);

	status |= flash_mock_expect_verify_flash_and_hash (&fw_verify.flash, &fw_verify.hash_mock,
		0x10000, HASH_TESTING_FULL_BLOCK_4096, HASH_TESTING_FULL_BLOCK_4096_LEN);

	status |= mock_expect (&fw_verify.hash_mock.mock, fw_verify.hash_mock.base.finish,
		&fw_verify.hash_mock, 0, MOCK_ARG_NOT_NULL, MOCK_ARG_AT_LEAST (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&fw_verify.hash_mock.mock, 0, SHA256_FULL_BLOCK_4096_HASH,
		SHA256_HASH_LENGTH, 1);

	status |= mock_expect (&fw_verify.pfm.mock, fw_verify.pfm.base.free_firmware_images,
		&fw_verify.pfm, 0, MOCK_ARG_SAVED_ARG (2));
	status |= mock_expect (&fw_verify.pfm.mock, fw_verify.pfm.base.free_fw_versions, &fw_verify.pfm,
		0, MOCK_ARG_SAVED_ARG (1));

	/* Measurement failure. */
	status |= mock_expect (&fw_verify.pfm.mock, fw_verify.pfm.base.base.get_hash, &fw_verify.pfm,
		PFM_V2.manifest.hash_len, MOCK_ARG_PTR (&fw_verify.hash_mock), MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (PFM_V2.manifest.hash_len));
	status |= mock_expect_output (&fw_verify.pfm.mock, 1, PFM_V2.manifest.hash,
		PFM_V2.manifest.hash_len, 2);

	status |= firmware_pfm_verify_testing_mock_pcr_update (&fw_verify, 2);

	status |= mock_expect (&fw_verify.hash_mock.mock, fw_verify.hash_mock.base.start_sha256,
		&fw_verify.hash_mock, HASH_ENGINE_START_SHA256_FAILED);

	status |= mock_expect (&fw_verify.log.mock, fw_verify.log.base.create_entry, &fw_verify.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));

	CuAssertIntEquals (test, 0, status);

	status = firmware_pfm_verify_run_verification (&fw_verify.test, NULL);
	CuAssertIntEquals (test, 0, status);

	firmware_pfm_verify_testing_release (test, &fw_verify);
}

static void firmware_pfm_verify_test_run_verification_measurement_pfm_id_error (CuTest *test)
{
	uint16_t measurement_result = PCR_MEASUREMENT (0, 0);
	uint16_t measurement_version = PCR_MEASUREMENT (0, 1);
	uint16_t measurement_pfm = PCR_MEASUREMENT (0, 2);
	uint16_t measurement_pfm_id = PCR_MEASUREMENT (0, 3);
	uint16_t measurement_plat_id = PCR_MEASUREMENT (0, 4);
	struct firmware_pfm_verify_testing fw_verify;
	struct pfm_firmware fw_list;
	const char *fw_exp = {"fw1"};
	struct pfm_firmware_version version;
	struct pfm_firmware_versions version_list;
	const char *version_exp = FIRMWARE_PFM_VERIFY_TESTING_VERSION_STR;
	struct flash_region img_region;
	struct pfm_image_hash img_hash;
	struct pfm_image_list img_list;
	int status;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_MANIFEST,
		.msg_index = MANIFEST_LOGGING_RECORD_MEASUREMENT_FAIL,
		.arg1 = measurement_pfm_id,
		.arg2 = HASH_ENGINE_START_SHA256_FAILED
	};

	TEST_START;

	/* Set up PFM data for a single firmware version for a single firmware component.  The image is
	 * contained in a single region of flash.  More comprehensive testing of this verification flow
	 * is part of the host_fw_util test suite. */
	fw_list.ids = &fw_exp;
	fw_list.count = 1;

	version.fw_version_id = version_exp;
	version.version_addr = 0x123;

	version_list.versions = &version;
	version_list.count = 1;

	img_region.start_addr = 0x10000;
	img_region.length = HASH_TESTING_FULL_BLOCK_4096_LEN;

	img_hash.regions = &img_region;
	img_hash.count = 1;
	memcpy (img_hash.hash, SHA256_FULL_BLOCK_4096_HASH, SHA256_HASH_LENGTH);
	img_hash.hash_length = SHA256_HASH_LENGTH;
	img_hash.hash_type = HASH_TYPE_SHA256;
	img_hash.always_validate = 1;

	img_list.images_hash = &img_hash;
	img_list.images_sig = NULL;
	img_list.count = 1;

	firmware_pfm_verify_testing_init_mocked_hash (test, &fw_verify, 0, measurement_result,
		measurement_version, measurement_pfm, measurement_pfm_id, measurement_plat_id);

	/* Verify the PFM. */
	status = mock_expect (&fw_verify.pfm.mock, fw_verify.pfm.base.base.verify, &fw_verify.pfm, 0,
		MOCK_ARG_PTR (&fw_verify.hash_mock), MOCK_ARG_PTR (&fw_verify.sig_verify),
		MOCK_ARG_PTR (NULL), MOCK_ARG (0));

	status |= mock_expect (&fw_verify.pfm.mock, fw_verify.pfm.base.base.is_empty, &fw_verify.pfm,
		0);

	/* Check that there is only one firmware component in the PFM. */
	status |= mock_expect (&fw_verify.pfm.mock, fw_verify.pfm.base.get_firmware, &fw_verify.pfm, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&fw_verify.pfm.mock, 0, &fw_list, sizeof (fw_list), -1);
	status |= mock_expect_save_arg (&fw_verify.pfm.mock, 0, 0);

	status |= mock_expect (&fw_verify.pfm.mock, fw_verify.pfm.base.free_firmware, &fw_verify.pfm, 0,
		MOCK_ARG_SAVED_ARG (0));

	/* Get the firmware version from the PFM. */
	status |= mock_expect (&fw_verify.pfm.mock, fw_verify.pfm.base.get_supported_versions,
		&fw_verify.pfm, 0, MOCK_ARG_PTR (NULL), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&fw_verify.pfm.mock, 1, &version_list, sizeof (version_list), -1);
	status |= mock_expect_save_arg (&fw_verify.pfm.mock, 1, 1);

	/* Get the image verification details. */
	status |= mock_expect (&fw_verify.pfm.mock, fw_verify.pfm.base.get_firmware_images,
		&fw_verify.pfm, 0, MOCK_ARG_PTR (NULL),
		MOCK_ARG_PTR_CONTAINS (version_exp, strlen (version_exp) + 1), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&fw_verify.pfm.mock, 2, &img_list, sizeof (img_list), -1);
	status |= mock_expect_save_arg (&fw_verify.pfm.mock, 2, 2);

	/* Run flash verification. */
	status |= mock_expect (&fw_verify.hash_mock.mock, fw_verify.hash_mock.base.start_sha256,
		&fw_verify.hash_mock, 0);

	status |= flash_mock_expect_verify_flash_and_hash (&fw_verify.flash, &fw_verify.hash_mock,
		0x10000, HASH_TESTING_FULL_BLOCK_4096, HASH_TESTING_FULL_BLOCK_4096_LEN);

	status |= mock_expect (&fw_verify.hash_mock.mock, fw_verify.hash_mock.base.finish,
		&fw_verify.hash_mock, 0, MOCK_ARG_NOT_NULL, MOCK_ARG_AT_LEAST (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&fw_verify.hash_mock.mock, 0, SHA256_FULL_BLOCK_4096_HASH,
		SHA256_HASH_LENGTH, 1);

	status |= mock_expect (&fw_verify.pfm.mock, fw_verify.pfm.base.free_firmware_images,
		&fw_verify.pfm, 0, MOCK_ARG_SAVED_ARG (2));
	status |= mock_expect (&fw_verify.pfm.mock, fw_verify.pfm.base.free_fw_versions, &fw_verify.pfm,
		0, MOCK_ARG_SAVED_ARG (1));

	/* Measurement failure. */
	status |= mock_expect (&fw_verify.pfm.mock, fw_verify.pfm.base.base.get_hash, &fw_verify.pfm,
		PFM_V2.manifest.hash_len, MOCK_ARG_PTR (&fw_verify.hash_mock), MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (PFM_V2.manifest.hash_len));
	status |= mock_expect_output (&fw_verify.pfm.mock, 1, PFM_V2.manifest.hash,
		PFM_V2.manifest.hash_len, 2);

	status |= mock_expect (&fw_verify.pfm.mock, fw_verify.pfm.base.base.get_id, &fw_verify.pfm, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&fw_verify.pfm.mock, 0, &PFM_V2.manifest.id,
		sizeof (PFM_V2.manifest.id), -1);

	status |= firmware_pfm_verify_testing_mock_pcr_update (&fw_verify, 3);

	status |= mock_expect (&fw_verify.hash_mock.mock, fw_verify.hash_mock.base.start_sha256,
		&fw_verify.hash_mock, HASH_ENGINE_START_SHA256_FAILED);

	status |= mock_expect (&fw_verify.log.mock, fw_verify.log.base.create_entry, &fw_verify.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));

	CuAssertIntEquals (test, 0, status);

	status = firmware_pfm_verify_run_verification (&fw_verify.test, NULL);
	CuAssertIntEquals (test, 0, status);

	firmware_pfm_verify_testing_release (test, &fw_verify);
}

static void firmware_pfm_verify_test_run_verification_measurement_platform_id_error (CuTest *test)
{
	uint16_t measurement_result = PCR_MEASUREMENT (0, 0);
	uint16_t measurement_version = PCR_MEASUREMENT (0, 1);
	uint16_t measurement_pfm = PCR_MEASUREMENT (0, 2);
	uint16_t measurement_pfm_id = PCR_MEASUREMENT (0, 3);
	uint16_t measurement_plat_id = PCR_MEASUREMENT (0, 4);
	struct firmware_pfm_verify_testing fw_verify;
	struct pfm_firmware fw_list;
	const char *fw_exp = {"fw1"};
	struct pfm_firmware_version version;
	struct pfm_firmware_versions version_list;
	const char *version_exp = FIRMWARE_PFM_VERIFY_TESTING_VERSION_STR;
	struct flash_region img_region;
	struct pfm_image_hash img_hash;
	struct pfm_image_list img_list;
	int status;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_MANIFEST,
		.msg_index = MANIFEST_LOGGING_RECORD_MEASUREMENT_FAIL,
		.arg1 = measurement_plat_id,
		.arg2 = HASH_ENGINE_START_SHA256_FAILED
	};

	TEST_START;

	/* Set up PFM data for a single firmware version for a single firmware component.  The image is
	 * contained in a single region of flash.  More comprehensive testing of this verification flow
	 * is part of the host_fw_util test suite. */
	fw_list.ids = &fw_exp;
	fw_list.count = 1;

	version.fw_version_id = version_exp;
	version.version_addr = 0x123;

	version_list.versions = &version;
	version_list.count = 1;

	img_region.start_addr = 0x10000;
	img_region.length = HASH_TESTING_FULL_BLOCK_4096_LEN;

	img_hash.regions = &img_region;
	img_hash.count = 1;
	memcpy (img_hash.hash, SHA256_FULL_BLOCK_4096_HASH, SHA256_HASH_LENGTH);
	img_hash.hash_length = SHA256_HASH_LENGTH;
	img_hash.hash_type = HASH_TYPE_SHA256;
	img_hash.always_validate = 1;

	img_list.images_hash = &img_hash;
	img_list.images_sig = NULL;
	img_list.count = 1;

	firmware_pfm_verify_testing_init_mocked_hash (test, &fw_verify, 0, measurement_result,
		measurement_version, measurement_pfm, measurement_pfm_id, measurement_plat_id);

	/* Verify the PFM. */
	status = mock_expect (&fw_verify.pfm.mock, fw_verify.pfm.base.base.verify, &fw_verify.pfm, 0,
		MOCK_ARG_PTR (&fw_verify.hash_mock), MOCK_ARG_PTR (&fw_verify.sig_verify),
		MOCK_ARG_PTR (NULL), MOCK_ARG (0));

	status |= mock_expect (&fw_verify.pfm.mock, fw_verify.pfm.base.base.is_empty, &fw_verify.pfm,
		0);

	/* Check that there is only one firmware component in the PFM. */
	status |= mock_expect (&fw_verify.pfm.mock, fw_verify.pfm.base.get_firmware, &fw_verify.pfm, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&fw_verify.pfm.mock, 0, &fw_list, sizeof (fw_list), -1);
	status |= mock_expect_save_arg (&fw_verify.pfm.mock, 0, 0);

	status |= mock_expect (&fw_verify.pfm.mock, fw_verify.pfm.base.free_firmware, &fw_verify.pfm, 0,
		MOCK_ARG_SAVED_ARG (0));

	/* Get the firmware version from the PFM. */
	status |= mock_expect (&fw_verify.pfm.mock, fw_verify.pfm.base.get_supported_versions,
		&fw_verify.pfm, 0, MOCK_ARG_PTR (NULL), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&fw_verify.pfm.mock, 1, &version_list, sizeof (version_list), -1);
	status |= mock_expect_save_arg (&fw_verify.pfm.mock, 1, 1);

	/* Get the image verification details. */
	status |= mock_expect (&fw_verify.pfm.mock, fw_verify.pfm.base.get_firmware_images,
		&fw_verify.pfm, 0, MOCK_ARG_PTR (NULL),
		MOCK_ARG_PTR_CONTAINS (version_exp, strlen (version_exp) + 1), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&fw_verify.pfm.mock, 2, &img_list, sizeof (img_list), -1);
	status |= mock_expect_save_arg (&fw_verify.pfm.mock, 2, 2);

	/* Run flash verification. */
	status |= mock_expect (&fw_verify.hash_mock.mock, fw_verify.hash_mock.base.start_sha256,
		&fw_verify.hash_mock, 0);

	status |= flash_mock_expect_verify_flash_and_hash (&fw_verify.flash, &fw_verify.hash_mock,
		0x10000, HASH_TESTING_FULL_BLOCK_4096, HASH_TESTING_FULL_BLOCK_4096_LEN);

	status |= mock_expect (&fw_verify.hash_mock.mock, fw_verify.hash_mock.base.finish,
		&fw_verify.hash_mock, 0, MOCK_ARG_NOT_NULL, MOCK_ARG_AT_LEAST (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&fw_verify.hash_mock.mock, 0, SHA256_FULL_BLOCK_4096_HASH,
		SHA256_HASH_LENGTH, 1);

	status |= mock_expect (&fw_verify.pfm.mock, fw_verify.pfm.base.free_firmware_images,
		&fw_verify.pfm, 0, MOCK_ARG_SAVED_ARG (2));
	status |= mock_expect (&fw_verify.pfm.mock, fw_verify.pfm.base.free_fw_versions, &fw_verify.pfm,
		0, MOCK_ARG_SAVED_ARG (1));

	/* Measurement failure. */
	status |= mock_expect (&fw_verify.pfm.mock, fw_verify.pfm.base.base.get_hash, &fw_verify.pfm,
		PFM_V2.manifest.hash_len, MOCK_ARG_PTR (&fw_verify.hash_mock), MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (PFM_V2.manifest.hash_len));
	status |= mock_expect_output (&fw_verify.pfm.mock, 1, PFM_V2.manifest.hash,
		PFM_V2.manifest.hash_len, 2);

	status |= mock_expect (&fw_verify.pfm.mock, fw_verify.pfm.base.base.get_id, &fw_verify.pfm, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&fw_verify.pfm.mock, 0, &PFM_V2.manifest.id,
		sizeof (PFM_V2.manifest.id), -1);

	status |= mock_expect (&fw_verify.pfm.mock, fw_verify.pfm.base.base.get_platform_id,
		&fw_verify.pfm, 0, MOCK_ARG_PTR_PTR (NULL), MOCK_ARG (0));
	status |= mock_expect_output (&fw_verify.pfm.mock, 0, &PFM_V2.manifest.plat_id_str,
		sizeof (void*), -1);

	status |= mock_expect (&fw_verify.pfm.mock, fw_verify.pfm.base.base.free_platform_id,
		&fw_verify.pfm, 0, MOCK_ARG_PTR (PFM_V2.manifest.plat_id_str));

	status |= firmware_pfm_verify_testing_mock_pcr_update (&fw_verify, 4);

	status |= mock_expect (&fw_verify.hash_mock.mock, fw_verify.hash_mock.base.start_sha256,
		&fw_verify.hash_mock, HASH_ENGINE_START_SHA256_FAILED);

	status |= mock_expect (&fw_verify.log.mock, fw_verify.log.base.create_entry, &fw_verify.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));

	CuAssertIntEquals (test, 0, status);

	status = firmware_pfm_verify_run_verification (&fw_verify.test, NULL);
	CuAssertIntEquals (test, 0, status);

	firmware_pfm_verify_testing_release (test, &fw_verify);
}

static void firmware_pfm_verify_test_run_verification_static_init (CuTest *test)
{
	uint16_t measurement_result = PCR_MEASUREMENT (0, 5);
	uint16_t measurement_version = PCR_MEASUREMENT (0, 4);
	uint16_t measurement_pfm = PCR_MEASUREMENT (0, 3);
	uint16_t measurement_pfm_id = PCR_MEASUREMENT (0, 2);
	uint16_t measurement_plat_id = PCR_MEASUREMENT (0, 1);
	struct firmware_pfm_verify_testing fw_verify = {
		.test = firmware_pfm_verify_static_init (&fw_verify.state, &fw_verify.flash.base,
			&fw_verify.pfm.base, &fw_verify.hash.base, &fw_verify.sig_verify.base, &fw_verify.pcr,
			fw_verify.version, sizeof (fw_verify.version), measurement_result, measurement_version,
			measurement_pfm, measurement_pfm_id, measurement_plat_id)
	};
	struct pfm_firmware fw_list;
	const char *fw_exp = {"fw1"};
	struct pfm_firmware_version version;
	struct pfm_firmware_versions version_list;
	const char *version_exp = FIRMWARE_PFM_VERIFY_TESTING_VERSION_STR;
	struct flash_region img_region;
	struct pfm_image_hash img_hash;
	struct pfm_image_list img_list;
	int status;
	struct pcr_measurement measurement;

	TEST_START;

	/* Set up PFM data for a single firmware version for a single firmware component.  The image is
	 * contained in a single region of flash.  More comprehensive testing of this verification flow
	 * is part of the host_fw_util test suite. */
	fw_list.ids = &fw_exp;
	fw_list.count = 1;

	version.fw_version_id = version_exp;
	version.version_addr = 0x123;

	version_list.versions = &version;
	version_list.count = 1;

	img_region.start_addr = 0x10000;
	img_region.length = HASH_TESTING_FULL_BLOCK_4096_LEN;

	img_hash.regions = &img_region;
	img_hash.count = 1;
	memcpy (img_hash.hash, SHA256_FULL_BLOCK_4096_HASH, SHA256_HASH_LENGTH);
	img_hash.hash_length = SHA256_HASH_LENGTH;
	img_hash.hash_type = HASH_TYPE_SHA256;
	img_hash.always_validate = 1;

	img_list.images_hash = &img_hash;
	img_list.images_sig = NULL;
	img_list.count = 1;

	firmware_pfm_verify_testing_init_static (test, &fw_verify, measurement_result,
		measurement_version, measurement_pfm, measurement_pfm_id, measurement_plat_id);

	/* Verify the PFM. */
	status = mock_expect (&fw_verify.pfm.mock, fw_verify.pfm.base.base.verify, &fw_verify.pfm, 0,
		MOCK_ARG_PTR (&fw_verify.hash), MOCK_ARG_PTR (&fw_verify.sig_verify), MOCK_ARG_PTR (NULL),
		MOCK_ARG (0));

	status |= mock_expect (&fw_verify.pfm.mock, fw_verify.pfm.base.base.is_empty, &fw_verify.pfm,
		0);

	/* Check that there is only one firmware component in the PFM. */
	status |= mock_expect (&fw_verify.pfm.mock, fw_verify.pfm.base.get_firmware, &fw_verify.pfm, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&fw_verify.pfm.mock, 0, &fw_list, sizeof (fw_list), -1);
	status |= mock_expect_save_arg (&fw_verify.pfm.mock, 0, 0);

	status |= mock_expect (&fw_verify.pfm.mock, fw_verify.pfm.base.free_firmware, &fw_verify.pfm, 0,
		MOCK_ARG_SAVED_ARG (0));

	/* Get the firmware version from the PFM. */
	status |= mock_expect (&fw_verify.pfm.mock, fw_verify.pfm.base.get_supported_versions,
		&fw_verify.pfm, 0, MOCK_ARG_PTR (NULL), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&fw_verify.pfm.mock, 1, &version_list, sizeof (version_list), -1);
	status |= mock_expect_save_arg (&fw_verify.pfm.mock, 1, 1);

	/* Get the image verification details. */
	status |= mock_expect (&fw_verify.pfm.mock, fw_verify.pfm.base.get_firmware_images,
		&fw_verify.pfm, 0, MOCK_ARG_PTR (NULL),
		MOCK_ARG_PTR_CONTAINS (version_exp, strlen (version_exp) + 1), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&fw_verify.pfm.mock, 2, &img_list, sizeof (img_list), -1);
	status |= mock_expect_save_arg (&fw_verify.pfm.mock, 2, 2);

	/* Run flash verification. */
	status |= flash_mock_expect_verify_flash (&fw_verify.flash, 0x10000,
		HASH_TESTING_FULL_BLOCK_4096, HASH_TESTING_FULL_BLOCK_4096_LEN);

	status |= mock_expect (&fw_verify.pfm.mock, fw_verify.pfm.base.free_firmware_images,
		&fw_verify.pfm, 0, MOCK_ARG_SAVED_ARG (2));
	status |= mock_expect (&fw_verify.pfm.mock, fw_verify.pfm.base.free_fw_versions, &fw_verify.pfm,
		0, MOCK_ARG_SAVED_ARG (1));

	/* Measure PFM details. */
	status |= mock_expect (&fw_verify.pfm.mock, fw_verify.pfm.base.base.get_hash, &fw_verify.pfm,
		PFM_V2.manifest.hash_len, MOCK_ARG_PTR (&fw_verify.hash), MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (PFM_V2.manifest.hash_len));
	status |= mock_expect_output (&fw_verify.pfm.mock, 1, PFM_V2.manifest.hash,
		PFM_V2.manifest.hash_len, 2);

	status |= mock_expect (&fw_verify.pfm.mock, fw_verify.pfm.base.base.get_id, &fw_verify.pfm, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&fw_verify.pfm.mock, 0, &PFM_V2.manifest.id,
		sizeof (PFM_V2.manifest.id), -1);

	status |= mock_expect (&fw_verify.pfm.mock, fw_verify.pfm.base.base.get_platform_id,
		&fw_verify.pfm, 0, MOCK_ARG_PTR_PTR (NULL), MOCK_ARG (0));
	status |= mock_expect_output (&fw_verify.pfm.mock, 0, &PFM_V2.manifest.plat_id_str,
		sizeof (void*), -1);

	status |= mock_expect (&fw_verify.pfm.mock, fw_verify.pfm.base.base.free_platform_id,
		&fw_verify.pfm, 0, MOCK_ARG_PTR (PFM_V2.manifest.plat_id_str));

	CuAssertIntEquals (test, 0, status);

	status = firmware_pfm_verify_run_verification (&fw_verify.test, NULL);
	CuAssertIntEquals (test, 0, status);

	/* Check verification result measurement. */
	status = pcr_store_get_measurement (&fw_verify.pcr, measurement_result, &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (FIRMWARE_PFM_VERIFY_TESTING_RESULT_SUCCESS_MEASUREMENT,
		measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	/* Check firmware version measurement. */
	status = pcr_store_get_measurement (&fw_verify.pcr, measurement_version, &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (FIRMWARE_PFM_VERIFY_TESTING_VERSION_MEASUREMENT,
		measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	/* Check PFM digest measurement. */
	status = pcr_store_get_measurement (&fw_verify.pcr, measurement_pfm, &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (FIRMWARE_PFM_VERIFY_TESTING_PFM_PFM_V2_MEASUREMENT,
		measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	/* Check PFM ID measurement. */
	status = pcr_store_get_measurement (&fw_verify.pcr, measurement_pfm_id, &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (FIRMWARE_PFM_VERIFY_TESTING_PFM_ID_PFM_V2_MEASUREMENT,
		measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	/* Check PFM platform ID measurement. */
	status = pcr_store_get_measurement (&fw_verify.pcr, measurement_plat_id, &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (FIRMWARE_PFM_VERIFY_TESTING_PLATFORM_ID_PFM_V2_MEASUREMENT,
		measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	firmware_pfm_verify_testing_release (test, &fw_verify);
}

static void firmware_pfm_verify_test_run_verification_static_init_small_version_buffer (
	CuTest *test)
{
	uint16_t measurement_result = PCR_MEASUREMENT (0, 5);
	uint16_t measurement_version = PCR_MEASUREMENT (0, 4);
	uint16_t measurement_pfm = PCR_MEASUREMENT (0, 3);
	uint16_t measurement_pfm_id = PCR_MEASUREMENT (0, 2);
	uint16_t measurement_plat_id = PCR_MEASUREMENT (0, 1);
	const char *version_exp = "12345";
	struct firmware_pfm_verify_testing fw_verify = {
		.test = firmware_pfm_verify_static_init (&fw_verify.state, &fw_verify.flash.base,
			&fw_verify.pfm.base, &fw_verify.hash.base, &fw_verify.sig_verify.base, &fw_verify.pcr,
			fw_verify.version, strlen (version_exp), measurement_result, measurement_version,
			measurement_pfm, measurement_pfm_id, measurement_plat_id)
	};
	struct pfm_firmware fw_list;
	const char *fw_exp = {"fw1"};
	struct pfm_firmware_version version;
	struct pfm_firmware_versions version_list;
	struct flash_region img_region;
	struct pfm_image_hash img_hash;
	struct pfm_image_list img_list;
	int status;
	struct pcr_measurement measurement;

	TEST_START;

	/* Set up PFM data for a single firmware version for a single firmware component.  The image is
	 * contained in a single region of flash.  More comprehensive testing of this verification flow
	 * is part of the host_fw_util test suite. */
	fw_list.ids = &fw_exp;
	fw_list.count = 1;

	version.fw_version_id = version_exp;
	version.version_addr = 0x123;

	version_list.versions = &version;
	version_list.count = 1;

	img_region.start_addr = 0x10000;
	img_region.length = HASH_TESTING_FULL_BLOCK_4096_LEN;

	img_hash.regions = &img_region;
	img_hash.count = 1;
	memcpy (img_hash.hash, SHA256_FULL_BLOCK_4096_HASH, SHA256_HASH_LENGTH);
	img_hash.hash_length = SHA256_HASH_LENGTH;
	img_hash.hash_type = HASH_TYPE_SHA256;
	img_hash.always_validate = 1;

	img_list.images_hash = &img_hash;
	img_list.images_sig = NULL;
	img_list.count = 1;

	firmware_pfm_verify_testing_init_static (test, &fw_verify, measurement_result,
		measurement_version, measurement_pfm, measurement_pfm_id, measurement_plat_id);

	/* Verify the PFM. */
	status = mock_expect (&fw_verify.pfm.mock, fw_verify.pfm.base.base.verify, &fw_verify.pfm, 0,
		MOCK_ARG_PTR (&fw_verify.hash), MOCK_ARG_PTR (&fw_verify.sig_verify), MOCK_ARG_PTR (NULL),
		MOCK_ARG (0));

	status |= mock_expect (&fw_verify.pfm.mock, fw_verify.pfm.base.base.is_empty, &fw_verify.pfm,
		0);

	/* Check that there is only one firmware component in the PFM. */
	status |= mock_expect (&fw_verify.pfm.mock, fw_verify.pfm.base.get_firmware, &fw_verify.pfm, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&fw_verify.pfm.mock, 0, &fw_list, sizeof (fw_list), -1);
	status |= mock_expect_save_arg (&fw_verify.pfm.mock, 0, 0);

	status |= mock_expect (&fw_verify.pfm.mock, fw_verify.pfm.base.free_firmware, &fw_verify.pfm, 0,
		MOCK_ARG_SAVED_ARG (0));

	/* Get the firmware version from the PFM. */
	status |= mock_expect (&fw_verify.pfm.mock, fw_verify.pfm.base.get_supported_versions,
		&fw_verify.pfm, 0, MOCK_ARG_PTR (NULL), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&fw_verify.pfm.mock, 1, &version_list, sizeof (version_list), -1);
	status |= mock_expect_save_arg (&fw_verify.pfm.mock, 1, 1);

	/* Get the image verification details. */
	status |= mock_expect (&fw_verify.pfm.mock, fw_verify.pfm.base.get_firmware_images,
		&fw_verify.pfm, 0, MOCK_ARG_PTR (NULL),
		MOCK_ARG_PTR_CONTAINS (version_exp, strlen (version_exp) + 1), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&fw_verify.pfm.mock, 2, &img_list, sizeof (img_list), -1);
	status |= mock_expect_save_arg (&fw_verify.pfm.mock, 2, 2);

	/* Run flash verification. */
	status |= flash_mock_expect_verify_flash (&fw_verify.flash, 0x10000,
		HASH_TESTING_FULL_BLOCK_4096, HASH_TESTING_FULL_BLOCK_4096_LEN);

	status |= mock_expect (&fw_verify.pfm.mock, fw_verify.pfm.base.free_firmware_images,
		&fw_verify.pfm, 0, MOCK_ARG_SAVED_ARG (2));
	status |= mock_expect (&fw_verify.pfm.mock, fw_verify.pfm.base.free_fw_versions, &fw_verify.pfm,
		0, MOCK_ARG_SAVED_ARG (1));

	/* Measure PFM details. */
	status |= mock_expect (&fw_verify.pfm.mock, fw_verify.pfm.base.base.get_hash, &fw_verify.pfm,
		PFM_V2.manifest.hash_len, MOCK_ARG_PTR (&fw_verify.hash), MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (PFM_V2.manifest.hash_len));
	status |= mock_expect_output (&fw_verify.pfm.mock, 1, PFM_V2.manifest.hash,
		PFM_V2.manifest.hash_len, 2);

	status |= mock_expect (&fw_verify.pfm.mock, fw_verify.pfm.base.base.get_id, &fw_verify.pfm, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&fw_verify.pfm.mock, 0, &PFM_V2.manifest.id,
		sizeof (PFM_V2.manifest.id), -1);

	status |= mock_expect (&fw_verify.pfm.mock, fw_verify.pfm.base.base.get_platform_id,
		&fw_verify.pfm, 0, MOCK_ARG_PTR_PTR (NULL), MOCK_ARG (0));
	status |= mock_expect_output (&fw_verify.pfm.mock, 0, &PFM_V2.manifest.plat_id_str,
		sizeof (void*), -1);

	status |= mock_expect (&fw_verify.pfm.mock, fw_verify.pfm.base.base.free_platform_id,
		&fw_verify.pfm, 0, MOCK_ARG_PTR (PFM_V2.manifest.plat_id_str));

	CuAssertIntEquals (test, 0, status);

	status = firmware_pfm_verify_run_verification (&fw_verify.test, NULL);
	CuAssertIntEquals (test, 0, status);

	/* Check verification result measurement. */
	status = pcr_store_get_measurement (&fw_verify.pcr, measurement_result, &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (FIRMWARE_PFM_VERIFY_TESTING_RESULT_SUCCESS_MEASUREMENT,
		measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	/* Check firmware version measurement. */
	status = pcr_store_get_measurement (&fw_verify.pcr, measurement_version, &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (FIRMWARE_PFM_VERIFY_TESTING_VERSION_MEASUREMENT,
		measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	/* Check PFM digest measurement. */
	status = pcr_store_get_measurement (&fw_verify.pcr, measurement_pfm, &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (FIRMWARE_PFM_VERIFY_TESTING_PFM_PFM_V2_MEASUREMENT,
		measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	/* Check PFM ID measurement. */
	status = pcr_store_get_measurement (&fw_verify.pcr, measurement_pfm_id, &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (FIRMWARE_PFM_VERIFY_TESTING_PFM_ID_PFM_V2_MEASUREMENT,
		measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	/* Check PFM platform ID measurement. */
	status = pcr_store_get_measurement (&fw_verify.pcr, measurement_plat_id, &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (FIRMWARE_PFM_VERIFY_TESTING_PLATFORM_ID_PFM_V2_MEASUREMENT,
		measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	firmware_pfm_verify_testing_release (test, &fw_verify);
}

static void firmware_pfm_verify_test_run_verification_null (CuTest *test)
{
	uint16_t measurement_result = PCR_MEASUREMENT (0, 0);
	uint16_t measurement_version = PCR_MEASUREMENT (0, 1);
	uint16_t measurement_pfm = PCR_MEASUREMENT (0, 2);
	uint16_t measurement_pfm_id = PCR_MEASUREMENT (0, 3);
	uint16_t measurement_plat_id = PCR_MEASUREMENT (0, 4);
	struct firmware_pfm_verify_testing fw_verify;
	int status;

	TEST_START;

	firmware_pfm_verify_testing_init (test, &fw_verify, 0, measurement_result, measurement_version,
		measurement_pfm, measurement_pfm_id, measurement_plat_id);

	status = firmware_pfm_verify_run_verification (NULL, NULL);
	CuAssertIntEquals (test, FIRMWARE_PFM_VERIFY_INVALID_ARGUMENT, status);

	firmware_pfm_verify_testing_release (test, &fw_verify);
}

static void firmware_pfm_verify_test_run_verification_empty_pfm (CuTest *test)
{
	uint16_t measurement_result = PCR_MEASUREMENT (0, 0);
	uint16_t measurement_version = PCR_MEASUREMENT (0, 1);
	uint16_t measurement_pfm = PCR_MEASUREMENT (0, 2);
	uint16_t measurement_pfm_id = PCR_MEASUREMENT (0, 3);
	uint16_t measurement_plat_id = PCR_MEASUREMENT (0, 4);
	struct firmware_pfm_verify_testing fw_verify;
	int status;
	struct pcr_measurement measurement;

	TEST_START;

	firmware_pfm_verify_testing_init (test, &fw_verify, 0, measurement_result, measurement_version,
		measurement_pfm, measurement_pfm_id, measurement_plat_id);

	/* Seed the measurements and state with valid information. */
	firmware_pfm_verify_testing_run_successful_verification (test, &fw_verify);

	/* Verify the PFM. */
	status = mock_expect (&fw_verify.pfm.mock, fw_verify.pfm.base.base.verify, &fw_verify.pfm, 0,
		MOCK_ARG_PTR (&fw_verify.hash), MOCK_ARG_PTR (&fw_verify.sig_verify), MOCK_ARG_PTR (NULL),
		MOCK_ARG (0));

	status |= mock_expect (&fw_verify.pfm.mock, fw_verify.pfm.base.base.is_empty, &fw_verify.pfm,
		1);

	CuAssertIntEquals (test, 0, status);

	status = firmware_pfm_verify_run_verification (&fw_verify.test, NULL);
	CuAssertIntEquals (test, FIRMWARE_PFM_VERIFY_EMPTY_PFM, status);

	/* Check verification result measurement. */
	status = pcr_store_get_measurement (&fw_verify.pcr, measurement_result, &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (FIRMWARE_PFM_VERIFY_TESTING_RESULT_EMPTY_PFM_MEASUREMENT,
		measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	/* Check firmware version measurement. */
	status = pcr_store_get_measurement (&fw_verify.pcr, measurement_version, &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (FIRMWARE_PFM_VERIFY_TESTING_VERSION_EMPTY_MEASUREMENT,
		measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	/* Check PFM digest measurement. */
	status = pcr_store_get_measurement (&fw_verify.pcr, measurement_pfm, &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (FIRMWARE_PFM_VERIFY_TESTING_PFM_NONE_MEASUREMENT,
		measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	/* Check PFM ID measurement. */
	status = pcr_store_get_measurement (&fw_verify.pcr, measurement_pfm_id, &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (FIRMWARE_PFM_VERIFY_TESTING_PFM_ID_NONE_MEASUREMENT,
		measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	/* Check PFM platform ID measurement. */
	status = pcr_store_get_measurement (&fw_verify.pcr, measurement_plat_id, &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (FIRMWARE_PFM_VERIFY_TESTING_PLATFORM_ID_NONE_MEASUREMENT,
		measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	firmware_pfm_verify_testing_release (test, &fw_verify);
}

static void firmware_pfm_verify_test_run_verification_multiple_fw_components (CuTest *test)
{
	uint16_t measurement_result = PCR_MEASUREMENT (0, 0);
	uint16_t measurement_version = PCR_MEASUREMENT (0, 1);
	uint16_t measurement_pfm = PCR_MEASUREMENT (0, 2);
	uint16_t measurement_pfm_id = PCR_MEASUREMENT (0, 3);
	uint16_t measurement_plat_id = PCR_MEASUREMENT (0, 4);
	struct firmware_pfm_verify_testing fw_verify;
	struct pfm_firmware fw_list;
	const char *fw_exp[] = {"fw1", "fw2"};
	int status;
	struct pcr_measurement measurement;

	TEST_START;

	fw_list.ids = fw_exp;
	fw_list.count = 2;

	firmware_pfm_verify_testing_init (test, &fw_verify, 0, measurement_result, measurement_version,
		measurement_pfm, measurement_pfm_id, measurement_plat_id);

	/* Seed the measurements and state with valid information. */
	firmware_pfm_verify_testing_run_successful_verification (test, &fw_verify);

	/* Verify the PFM. */
	status = mock_expect (&fw_verify.pfm.mock, fw_verify.pfm.base.base.verify, &fw_verify.pfm, 0,
		MOCK_ARG_PTR (&fw_verify.hash), MOCK_ARG_PTR (&fw_verify.sig_verify), MOCK_ARG_PTR (NULL),
		MOCK_ARG (0));

	status |= mock_expect (&fw_verify.pfm.mock, fw_verify.pfm.base.base.is_empty, &fw_verify.pfm,
		0);

	/* Check that there is only one firmware component in the PFM. */
	status |= mock_expect (&fw_verify.pfm.mock, fw_verify.pfm.base.get_firmware, &fw_verify.pfm, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&fw_verify.pfm.mock, 0, &fw_list, sizeof (fw_list), -1);
	status |= mock_expect_save_arg (&fw_verify.pfm.mock, 0, 4);

	status |= mock_expect (&fw_verify.pfm.mock, fw_verify.pfm.base.free_firmware, &fw_verify.pfm, 0,
		MOCK_ARG_SAVED_ARG (4));

	CuAssertIntEquals (test, 0, status);

	status = firmware_pfm_verify_run_verification (&fw_verify.test, NULL);
	CuAssertIntEquals (test, FIRMWARE_PFM_VERIFY_PFM_MULTI_FW, status);

	/* Check verification result measurement. */
	status = pcr_store_get_measurement (&fw_verify.pcr, measurement_result, &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (FIRMWARE_PFM_VERIFY_TESTING_RESULT_MULTI_FW_MEASUREMENT,
		measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	/* Check firmware version measurement. */
	status = pcr_store_get_measurement (&fw_verify.pcr, measurement_version, &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (FIRMWARE_PFM_VERIFY_TESTING_VERSION_EMPTY_MEASUREMENT,
		measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	/* Check PFM digest measurement. */
	status = pcr_store_get_measurement (&fw_verify.pcr, measurement_pfm, &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (FIRMWARE_PFM_VERIFY_TESTING_PFM_NONE_MEASUREMENT,
		measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	/* Check PFM ID measurement. */
	status = pcr_store_get_measurement (&fw_verify.pcr, measurement_pfm_id, &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (FIRMWARE_PFM_VERIFY_TESTING_PFM_ID_NONE_MEASUREMENT,
		measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	/* Check PFM platform ID measurement. */
	status = pcr_store_get_measurement (&fw_verify.pcr, measurement_plat_id, &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (FIRMWARE_PFM_VERIFY_TESTING_PLATFORM_ID_NONE_MEASUREMENT,
		measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	firmware_pfm_verify_testing_release (test, &fw_verify);
}

static void firmware_pfm_verify_test_run_verification_no_fw_versions (CuTest *test)
{
	uint16_t measurement_result = PCR_MEASUREMENT (0, 0);
	uint16_t measurement_version = PCR_MEASUREMENT (0, 1);
	uint16_t measurement_pfm = PCR_MEASUREMENT (0, 2);
	uint16_t measurement_pfm_id = PCR_MEASUREMENT (0, 3);
	uint16_t measurement_plat_id = PCR_MEASUREMENT (0, 4);
	struct firmware_pfm_verify_testing fw_verify;
	struct pfm_firmware fw_list;
	const char *fw_exp = {"fw1"};
	struct pfm_firmware_versions version_list;
	int status;
	struct pcr_measurement measurement;

	TEST_START;

	fw_list.ids = &fw_exp;
	fw_list.count = 1;

	version_list.versions = NULL;
	version_list.count = 0;

	firmware_pfm_verify_testing_init (test, &fw_verify, 0, measurement_result, measurement_version,
		measurement_pfm, measurement_pfm_id, measurement_plat_id);

	/* Seed the measurements and state with valid information. */
	firmware_pfm_verify_testing_run_successful_verification (test, &fw_verify);

	/* Verify the PFM. */
	status = mock_expect (&fw_verify.pfm.mock, fw_verify.pfm.base.base.verify, &fw_verify.pfm, 0,
		MOCK_ARG_PTR (&fw_verify.hash), MOCK_ARG_PTR (&fw_verify.sig_verify), MOCK_ARG_PTR (NULL),
		MOCK_ARG (0));

	status |= mock_expect (&fw_verify.pfm.mock, fw_verify.pfm.base.base.is_empty, &fw_verify.pfm,
		0);

	/* Check that there is only one firmware component in the PFM. */
	status |= mock_expect (&fw_verify.pfm.mock, fw_verify.pfm.base.get_firmware, &fw_verify.pfm, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&fw_verify.pfm.mock, 0, &fw_list, sizeof (fw_list), -1);
	status |= mock_expect_save_arg (&fw_verify.pfm.mock, 0, 4);

	status |= mock_expect (&fw_verify.pfm.mock, fw_verify.pfm.base.free_firmware, &fw_verify.pfm, 0,
		MOCK_ARG_SAVED_ARG (4));

	/* Get the firmware version from the PFM. */
	status |= mock_expect (&fw_verify.pfm.mock, fw_verify.pfm.base.get_supported_versions,
		&fw_verify.pfm, 0, MOCK_ARG_PTR (NULL), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&fw_verify.pfm.mock, 1, &version_list, sizeof (version_list), -1);
	status |= mock_expect_save_arg (&fw_verify.pfm.mock, 1, 5);

	status |= mock_expect (&fw_verify.pfm.mock, fw_verify.pfm.base.free_fw_versions, &fw_verify.pfm,
		0, MOCK_ARG_SAVED_ARG (5));

	CuAssertIntEquals (test, 0, status);

	status = firmware_pfm_verify_run_verification (&fw_verify.test, NULL);
	CuAssertIntEquals (test, FIRMWARE_PFM_VERIFY_PFM_NO_VERSION, status);

	/* Check verification result measurement. */
	status = pcr_store_get_measurement (&fw_verify.pcr, measurement_result, &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (FIRMWARE_PFM_VERIFY_TESTING_RESULT_NO_VERSION_MEASUREMENT,
		measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	/* Check firmware version measurement. */
	status = pcr_store_get_measurement (&fw_verify.pcr, measurement_version, &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (FIRMWARE_PFM_VERIFY_TESTING_VERSION_EMPTY_MEASUREMENT,
		measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	/* Check PFM digest measurement. */
	status = pcr_store_get_measurement (&fw_verify.pcr, measurement_pfm, &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (FIRMWARE_PFM_VERIFY_TESTING_PFM_NONE_MEASUREMENT,
		measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	/* Check PFM ID measurement. */
	status = pcr_store_get_measurement (&fw_verify.pcr, measurement_pfm_id, &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (FIRMWARE_PFM_VERIFY_TESTING_PFM_ID_NONE_MEASUREMENT,
		measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	/* Check PFM platform ID measurement. */
	status = pcr_store_get_measurement (&fw_verify.pcr, measurement_plat_id, &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (FIRMWARE_PFM_VERIFY_TESTING_PLATFORM_ID_NONE_MEASUREMENT,
		measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	firmware_pfm_verify_testing_release (test, &fw_verify);
}

static void firmware_pfm_verify_test_run_verification_multiple_fw_versions (CuTest *test)
{
	uint16_t measurement_result = PCR_MEASUREMENT (0, 0);
	uint16_t measurement_version = PCR_MEASUREMENT (0, 1);
	uint16_t measurement_pfm = PCR_MEASUREMENT (0, 2);
	uint16_t measurement_pfm_id = PCR_MEASUREMENT (0, 3);
	uint16_t measurement_plat_id = PCR_MEASUREMENT (0, 4);
	struct firmware_pfm_verify_testing fw_verify;
	struct pfm_firmware fw_list;
	const char *fw_exp = {"fw1"};
	struct pfm_firmware_version version;
	struct pfm_firmware_versions version_list;
	const char *version_exp[] = {"4321", "8765"};
	int status;
	struct pcr_measurement measurement;

	TEST_START;

	fw_list.ids = &fw_exp;
	fw_list.count = 1;

	version.fw_version_id = version_exp[0];
	version.version_addr = 0x123;

	version.fw_version_id = version_exp[1];
	version.version_addr = 0x456;

	version_list.versions = &version;
	version_list.count = 2;

	firmware_pfm_verify_testing_init (test, &fw_verify, 0, measurement_result, measurement_version,
		measurement_pfm, measurement_pfm_id, measurement_plat_id);

	/* Seed the measurements and state with valid information. */
	firmware_pfm_verify_testing_run_successful_verification (test, &fw_verify);

	/* Verify the PFM. */
	status = mock_expect (&fw_verify.pfm.mock, fw_verify.pfm.base.base.verify, &fw_verify.pfm, 0,
		MOCK_ARG_PTR (&fw_verify.hash), MOCK_ARG_PTR (&fw_verify.sig_verify), MOCK_ARG_PTR (NULL),
		MOCK_ARG (0));

	status |= mock_expect (&fw_verify.pfm.mock, fw_verify.pfm.base.base.is_empty, &fw_verify.pfm,
		0);

	/* Check that there is only one firmware component in the PFM. */
	status |= mock_expect (&fw_verify.pfm.mock, fw_verify.pfm.base.get_firmware, &fw_verify.pfm, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&fw_verify.pfm.mock, 0, &fw_list, sizeof (fw_list), -1);
	status |= mock_expect_save_arg (&fw_verify.pfm.mock, 0, 4);

	status |= mock_expect (&fw_verify.pfm.mock, fw_verify.pfm.base.free_firmware, &fw_verify.pfm, 0,
		MOCK_ARG_SAVED_ARG (4));

	/* Get the firmware version from the PFM. */
	status |= mock_expect (&fw_verify.pfm.mock, fw_verify.pfm.base.get_supported_versions,
		&fw_verify.pfm, 0, MOCK_ARG_PTR (NULL), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&fw_verify.pfm.mock, 1, &version_list, sizeof (version_list), -1);
	status |= mock_expect_save_arg (&fw_verify.pfm.mock, 1, 5);

	status |= mock_expect (&fw_verify.pfm.mock, fw_verify.pfm.base.free_fw_versions, &fw_verify.pfm,
		0, MOCK_ARG_SAVED_ARG (5));

	CuAssertIntEquals (test, 0, status);

	status = firmware_pfm_verify_run_verification (&fw_verify.test, NULL);
	CuAssertIntEquals (test, FIRMWARE_PFM_VERIFY_PFM_MULTI_VERSION, status);

	/* Check verification result measurement. */
	status = pcr_store_get_measurement (&fw_verify.pcr, measurement_result, &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (FIRMWARE_PFM_VERIFY_TESTING_RESULT_MULTI_VERSION_MEASUREMENT,
		measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	/* Check firmware version measurement. */
	status = pcr_store_get_measurement (&fw_verify.pcr, measurement_version, &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (FIRMWARE_PFM_VERIFY_TESTING_VERSION_EMPTY_MEASUREMENT,
		measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	/* Check PFM digest measurement. */
	status = pcr_store_get_measurement (&fw_verify.pcr, measurement_pfm, &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (FIRMWARE_PFM_VERIFY_TESTING_PFM_NONE_MEASUREMENT,
		measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	/* Check PFM ID measurement. */
	status = pcr_store_get_measurement (&fw_verify.pcr, measurement_pfm_id, &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (FIRMWARE_PFM_VERIFY_TESTING_PFM_ID_NONE_MEASUREMENT,
		measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	/* Check PFM platform ID measurement. */
	status = pcr_store_get_measurement (&fw_verify.pcr, measurement_plat_id, &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (FIRMWARE_PFM_VERIFY_TESTING_PLATFORM_ID_NONE_MEASUREMENT,
		measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	firmware_pfm_verify_testing_release (test, &fw_verify);
}

static void firmware_pfm_verify_test_run_verification_no_image (CuTest *test)
{
	uint16_t measurement_result = PCR_MEASUREMENT (0, 0);
	uint16_t measurement_version = PCR_MEASUREMENT (0, 1);
	uint16_t measurement_pfm = PCR_MEASUREMENT (0, 2);
	uint16_t measurement_pfm_id = PCR_MEASUREMENT (0, 3);
	uint16_t measurement_plat_id = PCR_MEASUREMENT (0, 4);
	struct firmware_pfm_verify_testing fw_verify;
	struct pfm_firmware fw_list;
	const char *fw_exp = {"fw1"};
	struct pfm_firmware_version version;
	struct pfm_firmware_versions version_list;
	const char *version_exp = "5678";
	struct pfm_image_list img_list;
	int status;
	struct pcr_measurement measurement;

	TEST_START;

	fw_list.ids = &fw_exp;
	fw_list.count = 1;

	version.fw_version_id = version_exp;
	version.version_addr = 0x123;

	version_list.versions = &version;
	version_list.count = 1;

	img_list.images_hash = NULL;
	img_list.images_sig = NULL;
	img_list.count = 0;

	firmware_pfm_verify_testing_init (test, &fw_verify, 0, measurement_result, measurement_version,
		measurement_pfm, measurement_pfm_id, measurement_plat_id);

	/* Seed the measurements and state with valid information. */
	firmware_pfm_verify_testing_run_successful_verification (test, &fw_verify);

	/* Verify the PFM. */
	status = mock_expect (&fw_verify.pfm.mock, fw_verify.pfm.base.base.verify, &fw_verify.pfm, 0,
		MOCK_ARG_PTR (&fw_verify.hash), MOCK_ARG_PTR (&fw_verify.sig_verify), MOCK_ARG_PTR (NULL),
		MOCK_ARG (0));

	status |= mock_expect (&fw_verify.pfm.mock, fw_verify.pfm.base.base.is_empty, &fw_verify.pfm,
		0);

	/* Check that there is only one firmware component in the PFM. */
	status |= mock_expect (&fw_verify.pfm.mock, fw_verify.pfm.base.get_firmware, &fw_verify.pfm, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&fw_verify.pfm.mock, 0, &fw_list, sizeof (fw_list), -1);
	status |= mock_expect_save_arg (&fw_verify.pfm.mock, 0, 4);

	status |= mock_expect (&fw_verify.pfm.mock, fw_verify.pfm.base.free_firmware, &fw_verify.pfm, 0,
		MOCK_ARG_SAVED_ARG (4));

	/* Get the firmware version from the PFM. */
	status |= mock_expect (&fw_verify.pfm.mock, fw_verify.pfm.base.get_supported_versions,
		&fw_verify.pfm, 0, MOCK_ARG_PTR (NULL), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&fw_verify.pfm.mock, 1, &version_list, sizeof (version_list), -1);
	status |= mock_expect_save_arg (&fw_verify.pfm.mock, 1, 5);

	/* Get the image verification details. */
	status |= mock_expect (&fw_verify.pfm.mock, fw_verify.pfm.base.get_firmware_images,
		&fw_verify.pfm, 0, MOCK_ARG_PTR (NULL),
		MOCK_ARG_PTR_CONTAINS (version_exp, strlen (version_exp) + 1), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&fw_verify.pfm.mock, 2, &img_list, sizeof (img_list), -1);
	status |= mock_expect_save_arg (&fw_verify.pfm.mock, 2, 6);

	status |= mock_expect (&fw_verify.pfm.mock, fw_verify.pfm.base.free_firmware_images,
		&fw_verify.pfm, 0, MOCK_ARG_SAVED_ARG (6));
	status |= mock_expect (&fw_verify.pfm.mock, fw_verify.pfm.base.free_fw_versions, &fw_verify.pfm,
		0, MOCK_ARG_SAVED_ARG (5));

	CuAssertIntEquals (test, 0, status);

	status = firmware_pfm_verify_run_verification (&fw_verify.test, NULL);
	CuAssertIntEquals (test, FIRMWARE_PFM_VERIFY_PFM_NO_IMAGE, status);

	/* Check verification result measurement. */
	status = pcr_store_get_measurement (&fw_verify.pcr, measurement_result, &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (FIRMWARE_PFM_VERIFY_TESTING_RESULT_NO_IMAGE_MEASUREMENT,
		measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	/* Check firmware version measurement. */
	status = pcr_store_get_measurement (&fw_verify.pcr, measurement_version, &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (FIRMWARE_PFM_VERIFY_TESTING_VERSION_EMPTY_MEASUREMENT,
		measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	/* Check PFM digest measurement. */
	status = pcr_store_get_measurement (&fw_verify.pcr, measurement_pfm, &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (FIRMWARE_PFM_VERIFY_TESTING_PFM_NONE_MEASUREMENT,
		measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	/* Check PFM ID measurement. */
	status = pcr_store_get_measurement (&fw_verify.pcr, measurement_pfm_id, &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (FIRMWARE_PFM_VERIFY_TESTING_PFM_ID_NONE_MEASUREMENT,
		measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	/* Check PFM platform ID measurement. */
	status = pcr_store_get_measurement (&fw_verify.pcr, measurement_plat_id, &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (FIRMWARE_PFM_VERIFY_TESTING_PLATFORM_ID_NONE_MEASUREMENT,
		measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	firmware_pfm_verify_testing_release (test, &fw_verify);
}

static void firmware_pfm_verify_test_run_verification_pfm_verify_error (CuTest *test)
{
	uint16_t measurement_result = PCR_MEASUREMENT (0, 0);
	uint16_t measurement_version = PCR_MEASUREMENT (0, 1);
	uint16_t measurement_pfm = PCR_MEASUREMENT (0, 2);
	uint16_t measurement_pfm_id = PCR_MEASUREMENT (0, 3);
	uint16_t measurement_plat_id = PCR_MEASUREMENT (0, 4);
	struct firmware_pfm_verify_testing fw_verify;
	int status;
	struct pcr_measurement measurement;

	TEST_START;

	firmware_pfm_verify_testing_init (test, &fw_verify, 0, measurement_result, measurement_version,
		measurement_pfm, measurement_pfm_id, measurement_plat_id);

	/* Seed the measurements and state with valid information. */
	firmware_pfm_verify_testing_run_successful_verification (test, &fw_verify);

	/* Verify the PFM. */
	status = mock_expect (&fw_verify.pfm.mock, fw_verify.pfm.base.base.verify, &fw_verify.pfm,
		MANIFEST_VERIFY_FAILED, MOCK_ARG_PTR (&fw_verify.hash),
		MOCK_ARG_PTR (&fw_verify.sig_verify), MOCK_ARG_PTR (NULL), MOCK_ARG (0));

	CuAssertIntEquals (test, 0, status);

	status = firmware_pfm_verify_run_verification (&fw_verify.test, NULL);
	CuAssertIntEquals (test, MANIFEST_VERIFY_FAILED, status);

	/* Check verification result measurement. */
	status = pcr_store_get_measurement (&fw_verify.pcr, measurement_result, &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status =
		testing_validate_array (FIRMWARE_PFM_VERIFY_TESTING_RESULT_PFM_VERIFY_FAILED_MEASUREMENT,
		measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	/* Check firmware version measurement. */
	status = pcr_store_get_measurement (&fw_verify.pcr, measurement_version, &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (FIRMWARE_PFM_VERIFY_TESTING_VERSION_EMPTY_MEASUREMENT,
		measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	/* Check PFM digest measurement. */
	status = pcr_store_get_measurement (&fw_verify.pcr, measurement_pfm, &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (FIRMWARE_PFM_VERIFY_TESTING_PFM_NONE_MEASUREMENT,
		measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	/* Check PFM ID measurement. */
	status = pcr_store_get_measurement (&fw_verify.pcr, measurement_pfm_id, &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (FIRMWARE_PFM_VERIFY_TESTING_PFM_ID_NONE_MEASUREMENT,
		measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	/* Check PFM platform ID measurement. */
	status = pcr_store_get_measurement (&fw_verify.pcr, measurement_plat_id, &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (FIRMWARE_PFM_VERIFY_TESTING_PLATFORM_ID_NONE_MEASUREMENT,
		measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	firmware_pfm_verify_testing_release (test, &fw_verify);
}

static void firmware_pfm_verify_test_run_verification_pfm_empty_error (CuTest *test)
{
	uint16_t measurement_result = PCR_MEASUREMENT (0, 0);
	uint16_t measurement_version = PCR_MEASUREMENT (0, 1);
	uint16_t measurement_pfm = PCR_MEASUREMENT (0, 2);
	uint16_t measurement_pfm_id = PCR_MEASUREMENT (0, 3);
	uint16_t measurement_plat_id = PCR_MEASUREMENT (0, 4);
	struct firmware_pfm_verify_testing fw_verify;
	int status;
	struct pcr_measurement measurement;

	TEST_START;

	firmware_pfm_verify_testing_init (test, &fw_verify, 0, measurement_result, measurement_version,
		measurement_pfm, measurement_pfm_id, measurement_plat_id);

	/* Seed the measurements and state with valid information. */
	firmware_pfm_verify_testing_run_successful_verification (test, &fw_verify);

	/* Verify the PFM. */
	status = mock_expect (&fw_verify.pfm.mock, fw_verify.pfm.base.base.verify, &fw_verify.pfm, 0,
		MOCK_ARG_PTR (&fw_verify.hash), MOCK_ARG_PTR (&fw_verify.sig_verify), MOCK_ARG_PTR (NULL),
		MOCK_ARG (0));

	status |= mock_expect (&fw_verify.pfm.mock, fw_verify.pfm.base.base.is_empty, &fw_verify.pfm,
		MANIFEST_CHECK_EMPTY_FAILED);

	CuAssertIntEquals (test, 0, status);

	status = firmware_pfm_verify_run_verification (&fw_verify.test, NULL);
	CuAssertIntEquals (test, MANIFEST_CHECK_EMPTY_FAILED, status);

	/* Check verification result measurement. */
	status = pcr_store_get_measurement (&fw_verify.pcr, measurement_result, &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status =
		testing_validate_array (FIRMWARE_PFM_VERIFY_TESTING_RESULT_PFM_EMPTY_FAILED_MEASUREMENT,
		measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	/* Check firmware version measurement. */
	status = pcr_store_get_measurement (&fw_verify.pcr, measurement_version, &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (FIRMWARE_PFM_VERIFY_TESTING_VERSION_EMPTY_MEASUREMENT,
		measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	/* Check PFM digest measurement. */
	status = pcr_store_get_measurement (&fw_verify.pcr, measurement_pfm, &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (FIRMWARE_PFM_VERIFY_TESTING_PFM_NONE_MEASUREMENT,
		measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	/* Check PFM ID measurement. */
	status = pcr_store_get_measurement (&fw_verify.pcr, measurement_pfm_id, &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (FIRMWARE_PFM_VERIFY_TESTING_PFM_ID_NONE_MEASUREMENT,
		measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	/* Check PFM platform ID measurement. */
	status = pcr_store_get_measurement (&fw_verify.pcr, measurement_plat_id, &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (FIRMWARE_PFM_VERIFY_TESTING_PLATFORM_ID_NONE_MEASUREMENT,
		measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	firmware_pfm_verify_testing_release (test, &fw_verify);
}

static void firmware_pfm_verify_test_run_verification_get_firmware_error (CuTest *test)
{
	uint16_t measurement_result = PCR_MEASUREMENT (0, 0);
	uint16_t measurement_version = PCR_MEASUREMENT (0, 1);
	uint16_t measurement_pfm = PCR_MEASUREMENT (0, 2);
	uint16_t measurement_pfm_id = PCR_MEASUREMENT (0, 3);
	uint16_t measurement_plat_id = PCR_MEASUREMENT (0, 4);
	struct firmware_pfm_verify_testing fw_verify;
	int status;
	struct pcr_measurement measurement;

	TEST_START;

	firmware_pfm_verify_testing_init (test, &fw_verify, 0, measurement_result, measurement_version,
		measurement_pfm, measurement_pfm_id, measurement_plat_id);

	/* Seed the measurements and state with valid information. */
	firmware_pfm_verify_testing_run_successful_verification (test, &fw_verify);

	/* Verify the PFM. */
	status = mock_expect (&fw_verify.pfm.mock, fw_verify.pfm.base.base.verify, &fw_verify.pfm, 0,
		MOCK_ARG_PTR (&fw_verify.hash), MOCK_ARG_PTR (&fw_verify.sig_verify), MOCK_ARG_PTR (NULL),
		MOCK_ARG (0));

	status |= mock_expect (&fw_verify.pfm.mock, fw_verify.pfm.base.base.is_empty, &fw_verify.pfm,
		0);

	/* Check that there is only one firmware component in the PFM. */
	status |= mock_expect (&fw_verify.pfm.mock, fw_verify.pfm.base.get_firmware, &fw_verify.pfm,
		PFM_GET_FW_FAILED, MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	status = firmware_pfm_verify_run_verification (&fw_verify.test, NULL);
	CuAssertIntEquals (test, PFM_GET_FW_FAILED, status);

	/* Check verification result measurement. */
	status = pcr_store_get_measurement (&fw_verify.pcr, measurement_result, &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status =
		testing_validate_array (FIRMWARE_PFM_VERIFY_TESTING_RESULT_PFM_GET_FW_FAILED_MEASUREMENT,
		measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	/* Check firmware version measurement. */
	status = pcr_store_get_measurement (&fw_verify.pcr, measurement_version, &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (FIRMWARE_PFM_VERIFY_TESTING_VERSION_EMPTY_MEASUREMENT,
		measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	/* Check PFM digest measurement. */
	status = pcr_store_get_measurement (&fw_verify.pcr, measurement_pfm, &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (FIRMWARE_PFM_VERIFY_TESTING_PFM_NONE_MEASUREMENT,
		measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	/* Check PFM ID measurement. */
	status = pcr_store_get_measurement (&fw_verify.pcr, measurement_pfm_id, &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (FIRMWARE_PFM_VERIFY_TESTING_PFM_ID_NONE_MEASUREMENT,
		measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	/* Check PFM platform ID measurement. */
	status = pcr_store_get_measurement (&fw_verify.pcr, measurement_plat_id, &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (FIRMWARE_PFM_VERIFY_TESTING_PLATFORM_ID_NONE_MEASUREMENT,
		measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	firmware_pfm_verify_testing_release (test, &fw_verify);
}

static void firmware_pfm_verify_test_run_verification_get_versions_error (CuTest *test)
{
	uint16_t measurement_result = PCR_MEASUREMENT (0, 0);
	uint16_t measurement_version = PCR_MEASUREMENT (0, 1);
	uint16_t measurement_pfm = PCR_MEASUREMENT (0, 2);
	uint16_t measurement_pfm_id = PCR_MEASUREMENT (0, 3);
	uint16_t measurement_plat_id = PCR_MEASUREMENT (0, 4);
	struct firmware_pfm_verify_testing fw_verify;
	struct pfm_firmware fw_list;
	const char *fw_exp = {"fw1"};
	int status;
	struct pcr_measurement measurement;

	TEST_START;

	fw_list.ids = &fw_exp;
	fw_list.count = 1;

	firmware_pfm_verify_testing_init (test, &fw_verify, 0, measurement_result, measurement_version,
		measurement_pfm, measurement_pfm_id, measurement_plat_id);

	/* Seed the measurements and state with valid information. */
	firmware_pfm_verify_testing_run_successful_verification (test, &fw_verify);

	/* Verify the PFM. */
	status = mock_expect (&fw_verify.pfm.mock, fw_verify.pfm.base.base.verify, &fw_verify.pfm, 0,
		MOCK_ARG_PTR (&fw_verify.hash), MOCK_ARG_PTR (&fw_verify.sig_verify), MOCK_ARG_PTR (NULL),
		MOCK_ARG (0));

	status |= mock_expect (&fw_verify.pfm.mock, fw_verify.pfm.base.base.is_empty, &fw_verify.pfm,
		0);

	/* Check that there is only one firmware component in the PFM. */
	status |= mock_expect (&fw_verify.pfm.mock, fw_verify.pfm.base.get_firmware, &fw_verify.pfm, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&fw_verify.pfm.mock, 0, &fw_list, sizeof (fw_list), -1);
	status |= mock_expect_save_arg (&fw_verify.pfm.mock, 0, 4);

	status |= mock_expect (&fw_verify.pfm.mock, fw_verify.pfm.base.free_firmware, &fw_verify.pfm, 0,
		MOCK_ARG_SAVED_ARG (4));

	/* Get the firmware version from the PFM. */
	status |= mock_expect (&fw_verify.pfm.mock, fw_verify.pfm.base.get_supported_versions,
		&fw_verify.pfm, PFM_GET_VERSIONS_FAILED, MOCK_ARG_PTR (NULL), MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	status = firmware_pfm_verify_run_verification (&fw_verify.test, NULL);
	CuAssertIntEquals (test, PFM_GET_VERSIONS_FAILED, status);

	/* Check verification result measurement. */
	status = pcr_store_get_measurement (&fw_verify.pcr, measurement_result, &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status =
		testing_validate_array (
		FIRMWARE_PFM_VERIFY_TESTING_RESULT_PFM_GET_VERSIONS_FAILED_MEASUREMENT, measurement.digest,
		SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	/* Check firmware version measurement. */
	status = pcr_store_get_measurement (&fw_verify.pcr, measurement_version, &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (FIRMWARE_PFM_VERIFY_TESTING_VERSION_EMPTY_MEASUREMENT,
		measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	/* Check PFM digest measurement. */
	status = pcr_store_get_measurement (&fw_verify.pcr, measurement_pfm, &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (FIRMWARE_PFM_VERIFY_TESTING_PFM_NONE_MEASUREMENT,
		measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	/* Check PFM ID measurement. */
	status = pcr_store_get_measurement (&fw_verify.pcr, measurement_pfm_id, &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (FIRMWARE_PFM_VERIFY_TESTING_PFM_ID_NONE_MEASUREMENT,
		measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	/* Check PFM platform ID measurement. */
	status = pcr_store_get_measurement (&fw_verify.pcr, measurement_plat_id, &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (FIRMWARE_PFM_VERIFY_TESTING_PLATFORM_ID_NONE_MEASUREMENT,
		measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	firmware_pfm_verify_testing_release (test, &fw_verify);
}

static void firmware_pfm_verify_test_run_verification_get_images_error (CuTest *test)
{
	uint16_t measurement_result = PCR_MEASUREMENT (0, 0);
	uint16_t measurement_version = PCR_MEASUREMENT (0, 1);
	uint16_t measurement_pfm = PCR_MEASUREMENT (0, 2);
	uint16_t measurement_pfm_id = PCR_MEASUREMENT (0, 3);
	uint16_t measurement_plat_id = PCR_MEASUREMENT (0, 4);
	struct firmware_pfm_verify_testing fw_verify;
	struct pfm_firmware fw_list;
	const char *fw_exp = {"fw1"};
	struct pfm_firmware_version version;
	struct pfm_firmware_versions version_list;
	const char *version_exp = "5678";
	int status;
	struct pcr_measurement measurement;

	TEST_START;

	fw_list.ids = &fw_exp;
	fw_list.count = 1;

	version.fw_version_id = version_exp;
	version.version_addr = 0x123;

	version_list.versions = &version;
	version_list.count = 1;

	firmware_pfm_verify_testing_init (test, &fw_verify, 0, measurement_result, measurement_version,
		measurement_pfm, measurement_pfm_id, measurement_plat_id);

	/* Seed the measurements and state with valid information. */
	firmware_pfm_verify_testing_run_successful_verification (test, &fw_verify);

	/* Verify the PFM. */
	status = mock_expect (&fw_verify.pfm.mock, fw_verify.pfm.base.base.verify, &fw_verify.pfm, 0,
		MOCK_ARG_PTR (&fw_verify.hash), MOCK_ARG_PTR (&fw_verify.sig_verify), MOCK_ARG_PTR (NULL),
		MOCK_ARG (0));

	status |= mock_expect (&fw_verify.pfm.mock, fw_verify.pfm.base.base.is_empty, &fw_verify.pfm,
		0);

	/* Check that there is only one firmware component in the PFM. */
	status |= mock_expect (&fw_verify.pfm.mock, fw_verify.pfm.base.get_firmware, &fw_verify.pfm, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&fw_verify.pfm.mock, 0, &fw_list, sizeof (fw_list), -1);
	status |= mock_expect_save_arg (&fw_verify.pfm.mock, 0, 4);

	status |= mock_expect (&fw_verify.pfm.mock, fw_verify.pfm.base.free_firmware, &fw_verify.pfm, 0,
		MOCK_ARG_SAVED_ARG (4));

	/* Get the firmware version from the PFM. */
	status |= mock_expect (&fw_verify.pfm.mock, fw_verify.pfm.base.get_supported_versions,
		&fw_verify.pfm, 0, MOCK_ARG_PTR (NULL), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&fw_verify.pfm.mock, 1, &version_list, sizeof (version_list), -1);
	status |= mock_expect_save_arg (&fw_verify.pfm.mock, 1, 5);

	/* Get the image verification details. */
	status |= mock_expect (&fw_verify.pfm.mock, fw_verify.pfm.base.get_firmware_images,
		&fw_verify.pfm, PFM_GET_FW_IMAGES_FAILED, MOCK_ARG_PTR (NULL),
		MOCK_ARG_PTR_CONTAINS (version_exp, strlen (version_exp) + 1), MOCK_ARG_NOT_NULL);

	status |= mock_expect (&fw_verify.pfm.mock, fw_verify.pfm.base.free_fw_versions, &fw_verify.pfm,
		0, MOCK_ARG_SAVED_ARG (5));

	CuAssertIntEquals (test, 0, status);

	status = firmware_pfm_verify_run_verification (&fw_verify.test, NULL);
	CuAssertIntEquals (test, PFM_GET_FW_IMAGES_FAILED, status);

	/* Check verification result measurement. */
	status = pcr_store_get_measurement (&fw_verify.pcr, measurement_result, &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status =
		testing_validate_array (
		FIRMWARE_PFM_VERIFY_TESTING_RESULT_PFM_GET_IMAGES_FAILED_MEASUREMENT, measurement.digest,
		SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	/* Check firmware version measurement. */
	status = pcr_store_get_measurement (&fw_verify.pcr, measurement_version, &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (FIRMWARE_PFM_VERIFY_TESTING_VERSION_EMPTY_MEASUREMENT,
		measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	/* Check PFM digest measurement. */
	status = pcr_store_get_measurement (&fw_verify.pcr, measurement_pfm, &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (FIRMWARE_PFM_VERIFY_TESTING_PFM_NONE_MEASUREMENT,
		measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	/* Check PFM ID measurement. */
	status = pcr_store_get_measurement (&fw_verify.pcr, measurement_pfm_id, &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (FIRMWARE_PFM_VERIFY_TESTING_PFM_ID_NONE_MEASUREMENT,
		measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	/* Check PFM platform ID measurement. */
	status = pcr_store_get_measurement (&fw_verify.pcr, measurement_plat_id, &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (FIRMWARE_PFM_VERIFY_TESTING_PLATFORM_ID_NONE_MEASUREMENT,
		measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	firmware_pfm_verify_testing_release (test, &fw_verify);
}

static void firmware_pfm_verify_test_run_verification_flash_verify_error (CuTest *test)
{
	uint16_t measurement_result = PCR_MEASUREMENT (0, 0);
	uint16_t measurement_version = PCR_MEASUREMENT (0, 1);
	uint16_t measurement_pfm = PCR_MEASUREMENT (0, 2);
	uint16_t measurement_pfm_id = PCR_MEASUREMENT (0, 3);
	uint16_t measurement_plat_id = PCR_MEASUREMENT (0, 4);
	struct firmware_pfm_verify_testing fw_verify;
	struct pfm_firmware fw_list;
	const char *fw_exp = {"fw1"};
	struct pfm_firmware_version version;
	struct pfm_firmware_versions version_list;
	const char *version_exp = "5678";
	struct flash_region img_region;
	struct pfm_image_hash img_hash;
	struct pfm_image_list img_list;
	int status;
	struct pcr_measurement measurement;

	TEST_START;

	/* Set up PFM data for a single firmware version for a single firmware component.  The image is
	 * contained in a single region of flash.  More comprehensive testing of this verification flow
	 * is part of the host_fw_util test suite. */
	fw_list.ids = &fw_exp;
	fw_list.count = 1;

	version.fw_version_id = version_exp;
	version.version_addr = 0x123;

	version_list.versions = &version;
	version_list.count = 1;

	img_region.start_addr = 0x10000;
	img_region.length = HASH_TESTING_FULL_BLOCK_4096_LEN;

	img_hash.regions = &img_region;
	img_hash.count = 1;
	memcpy (img_hash.hash, SHA256_FULL_BLOCK_4096_HASH, SHA256_HASH_LENGTH);
	img_hash.hash_length = SHA256_HASH_LENGTH;
	img_hash.hash_type = HASH_TYPE_SHA256;
	img_hash.always_validate = 1;

	img_list.images_hash = &img_hash;
	img_list.images_sig = NULL;
	img_list.count = 1;

	firmware_pfm_verify_testing_init (test, &fw_verify, 0, measurement_result, measurement_version,
		measurement_pfm, measurement_pfm_id, measurement_plat_id);

	/* Verify the PFM. */
	status = mock_expect (&fw_verify.pfm.mock, fw_verify.pfm.base.base.verify, &fw_verify.pfm, 0,
		MOCK_ARG_PTR (&fw_verify.hash), MOCK_ARG_PTR (&fw_verify.sig_verify), MOCK_ARG_PTR (NULL),
		MOCK_ARG (0));

	status |= mock_expect (&fw_verify.pfm.mock, fw_verify.pfm.base.base.is_empty, &fw_verify.pfm,
		0);

	/* Check that there is only one firmware component in the PFM. */
	status |= mock_expect (&fw_verify.pfm.mock, fw_verify.pfm.base.get_firmware, &fw_verify.pfm, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&fw_verify.pfm.mock, 0, &fw_list, sizeof (fw_list), -1);
	status |= mock_expect_save_arg (&fw_verify.pfm.mock, 0, 0);

	status |= mock_expect (&fw_verify.pfm.mock, fw_verify.pfm.base.free_firmware, &fw_verify.pfm, 0,
		MOCK_ARG_SAVED_ARG (0));

	/* Get the firmware version from the PFM. */
	status |= mock_expect (&fw_verify.pfm.mock, fw_verify.pfm.base.get_supported_versions,
		&fw_verify.pfm, 0, MOCK_ARG_PTR (NULL), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&fw_verify.pfm.mock, 1, &version_list, sizeof (version_list), -1);
	status |= mock_expect_save_arg (&fw_verify.pfm.mock, 1, 1);

	/* Get the image verification details. */
	status |= mock_expect (&fw_verify.pfm.mock, fw_verify.pfm.base.get_firmware_images,
		&fw_verify.pfm, 0, MOCK_ARG_PTR (NULL),
		MOCK_ARG_PTR_CONTAINS (version_exp, strlen (version_exp) + 1), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&fw_verify.pfm.mock, 2, &img_list, sizeof (img_list), -1);
	status |= mock_expect_save_arg (&fw_verify.pfm.mock, 2, 2);

	/* Run flash verification. */
	status |= mock_expect (&fw_verify.flash.mock, fw_verify.flash.base.read, &fw_verify.flash,
		FLASH_READ_FAILED, MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG_ANY);

	status |= mock_expect (&fw_verify.pfm.mock, fw_verify.pfm.base.free_firmware_images,
		&fw_verify.pfm, 0, MOCK_ARG_SAVED_ARG (2));
	status |= mock_expect (&fw_verify.pfm.mock, fw_verify.pfm.base.free_fw_versions, &fw_verify.pfm,
		0, MOCK_ARG_SAVED_ARG (1));

	CuAssertIntEquals (test, 0, status);

	status = firmware_pfm_verify_run_verification (&fw_verify.test, NULL);
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	/* Check verification result measurement. */
	status = pcr_store_get_measurement (&fw_verify.pcr, measurement_result, &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status =
		testing_validate_array (FIRMWARE_PFM_VERIFY_TESTING_RESULT_FLASH_FAILED_MEASUREMENT,
		measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	/* Check firmware version measurement. */
	status = pcr_store_get_measurement (&fw_verify.pcr, measurement_version, &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (FIRMWARE_PFM_VERIFY_TESTING_VERSION_EMPTY_MEASUREMENT,
		measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	/* Check PFM digest measurement. */
	status = pcr_store_get_measurement (&fw_verify.pcr, measurement_pfm, &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (FIRMWARE_PFM_VERIFY_TESTING_PFM_NONE_MEASUREMENT,
		measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	/* Check PFM ID measurement. */
	status = pcr_store_get_measurement (&fw_verify.pcr, measurement_pfm_id, &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (FIRMWARE_PFM_VERIFY_TESTING_PFM_ID_NONE_MEASUREMENT,
		measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	/* Check PFM platform ID measurement. */
	status = pcr_store_get_measurement (&fw_verify.pcr, measurement_plat_id, &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (FIRMWARE_PFM_VERIFY_TESTING_PLATFORM_ID_NONE_MEASUREMENT,
		measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	firmware_pfm_verify_testing_release (test, &fw_verify);
}

static void firmware_pfm_verify_test_run_verification_get_id_failed (CuTest *test)
{
	uint16_t measurement_result = PCR_MEASUREMENT (0, 0);
	uint16_t measurement_version = PCR_MEASUREMENT (0, 1);
	uint16_t measurement_pfm = PCR_MEASUREMENT (0, 2);
	uint16_t measurement_pfm_id = PCR_MEASUREMENT (0, 3);
	uint16_t measurement_plat_id = PCR_MEASUREMENT (0, 4);
	struct firmware_pfm_verify_testing fw_verify;
	int status;
	struct pcr_measurement measurement;
	uint32_t pfm_expected_id;

	TEST_START;

	pfm_expected_id = PFM_V2.manifest.id;

	firmware_pfm_verify_testing_init (test, &fw_verify, 0, measurement_result, measurement_version,
		measurement_pfm, measurement_pfm_id, measurement_plat_id);

	/* Seed the measurements and state with valid information. */
	firmware_pfm_verify_testing_run_successful_verification (test, &fw_verify);

	/* Verify the PFM. */
	status = mock_expect (&fw_verify.pfm.mock, fw_verify.pfm.base.base.verify, &fw_verify.pfm, 0,
		MOCK_ARG_PTR (&fw_verify.hash), MOCK_ARG_PTR (&fw_verify.sig_verify), MOCK_ARG_PTR (NULL),
		MOCK_ARG (0));

	/* Get the PFM ID from the PFM. */
	status |= mock_expect (&fw_verify.pfm.mock, fw_verify.pfm.base.base.get_id, &fw_verify.pfm,
		MANIFEST_NO_MANIFEST, MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	status = firmware_pfm_verify_run_verification (&fw_verify.test, &pfm_expected_id);
	CuAssertIntEquals (test, MANIFEST_NO_MANIFEST, status);

	/* Check verification result measurement. */
	status = pcr_store_get_measurement (&fw_verify.pcr, measurement_result, &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status =
		testing_validate_array (FIRMWARE_PFM_VERIFY_TESTING_RESULT_PFM_GET_ID_FAILED_MEASUREMENT,
		measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	/* Check firmware version measurement. */
	status = pcr_store_get_measurement (&fw_verify.pcr, measurement_version, &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (FIRMWARE_PFM_VERIFY_TESTING_VERSION_EMPTY_MEASUREMENT,
		measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0x0, status);

	/* Check PFM digest measurement. */
	status = pcr_store_get_measurement (&fw_verify.pcr, measurement_pfm, &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (FIRMWARE_PFM_VERIFY_TESTING_PFM_NONE_MEASUREMENT,
		measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	/* Check PFM ID measurement. */
	status = pcr_store_get_measurement (&fw_verify.pcr, measurement_pfm_id, &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (FIRMWARE_PFM_VERIFY_TESTING_PFM_ID_NONE_MEASUREMENT,
		measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	/* Check PFM platform ID measurement. */
	status = pcr_store_get_measurement (&fw_verify.pcr, measurement_plat_id, &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (FIRMWARE_PFM_VERIFY_TESTING_PLATFORM_ID_NONE_MEASUREMENT,
		measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	firmware_pfm_verify_testing_release (test, &fw_verify);
}

static void firmware_pfm_verify_test_run_verification_unsupported_pfm_id (CuTest *test)
{
	uint16_t measurement_result = PCR_MEASUREMENT (0, 0);
	uint16_t measurement_version = PCR_MEASUREMENT (0, 1);
	uint16_t measurement_pfm = PCR_MEASUREMENT (0, 2);
	uint16_t measurement_pfm_id = PCR_MEASUREMENT (0, 3);
	uint16_t measurement_plat_id = PCR_MEASUREMENT (0, 4);
	struct firmware_pfm_verify_testing fw_verify;
	int status;
	struct pcr_measurement measurement;
	uint32_t pfm_expected_id;

	TEST_START;

	pfm_expected_id = 0;

	firmware_pfm_verify_testing_init (test, &fw_verify, 0, measurement_result, measurement_version,
		measurement_pfm, measurement_pfm_id, measurement_plat_id);

	/* Seed the measurements and state with valid information. */
	firmware_pfm_verify_testing_run_successful_verification (test, &fw_verify);

	/* Verify the PFM. */
	status = mock_expect (&fw_verify.pfm.mock, fw_verify.pfm.base.base.verify, &fw_verify.pfm, 0,
		MOCK_ARG_PTR (&fw_verify.hash), MOCK_ARG_PTR (&fw_verify.sig_verify), MOCK_ARG_PTR (NULL),
		MOCK_ARG (0));

	/* Get the PFM ID from the PFM. */
	status |= mock_expect (&fw_verify.pfm.mock, fw_verify.pfm.base.base.get_id, &fw_verify.pfm, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&fw_verify.pfm.mock, 0, &PFM_V2.manifest.id,
		sizeof (PFM_V2.manifest.id), -1);

	CuAssertIntEquals (test, 0, status);

	status = firmware_pfm_verify_run_verification (&fw_verify.test, &pfm_expected_id);
	CuAssertIntEquals (test, FIRMWARE_PFM_VERIFY_UNSUPPORTED_ID, status);

	/* Check verification result measurement. */
	status = pcr_store_get_measurement (&fw_verify.pcr, measurement_result, &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status =
		testing_validate_array (FIRMWARE_PFM_VERIFY_TESTING_RESULT_PFM_UNSUPPORTED_ID_MEASUREMENT,
		measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	/* Check firmware version measurement. */
	status = pcr_store_get_measurement (&fw_verify.pcr, measurement_version, &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (FIRMWARE_PFM_VERIFY_TESTING_VERSION_EMPTY_MEASUREMENT,
		measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0x0, status);

	/* Check PFM digest measurement. */
	status = pcr_store_get_measurement (&fw_verify.pcr, measurement_pfm, &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (FIRMWARE_PFM_VERIFY_TESTING_PFM_NONE_MEASUREMENT,
		measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	/* Check PFM ID measurement. */
	status = pcr_store_get_measurement (&fw_verify.pcr, measurement_pfm_id, &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (FIRMWARE_PFM_VERIFY_TESTING_PFM_ID_NONE_MEASUREMENT,
		measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	/* Check PFM platform ID measurement. */
	status = pcr_store_get_measurement (&fw_verify.pcr, measurement_plat_id, &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (FIRMWARE_PFM_VERIFY_TESTING_PLATFORM_ID_NONE_MEASUREMENT,
		measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	firmware_pfm_verify_testing_release (test, &fw_verify);
}

static void firmware_pfm_verify_test_get_fw_version_measured_data_no_verification (CuTest *test)
{
	uint16_t measurement_result = PCR_MEASUREMENT (0, 0);
	uint16_t measurement_version = PCR_MEASUREMENT (0, 1);
	uint16_t measurement_pfm = PCR_MEASUREMENT (0, 2);
	uint16_t measurement_pfm_id = PCR_MEASUREMENT (0, 3);
	uint16_t measurement_plat_id = PCR_MEASUREMENT (0, 4);
	struct firmware_pfm_verify_testing fw_verify;
	const char *expected = "\0";
	char buffer[sizeof (fw_verify.version)];
	size_t length = sizeof (buffer);
	uint32_t total_len;
	int status;

	TEST_START;

	firmware_pfm_verify_testing_init (test, &fw_verify, 0, measurement_result, measurement_version,
		measurement_pfm, measurement_pfm_id, measurement_plat_id);

	strcpy (buffer, "unexpected");

	status = firmware_pfm_verify_get_fw_version_measured_data (&fw_verify.test, 0,
		(uint8_t*) buffer, length, &total_len);
	CuAssertIntEquals (test, strlen (expected) + 1, status);
	CuAssertIntEquals (test, strlen (expected) + 1, total_len);
	CuAssertStrEquals (test, expected, buffer);

	firmware_pfm_verify_testing_release (test, &fw_verify);
}

static void firmware_pfm_verify_test_get_fw_version_measured_data_after_verification (CuTest *test)
{
	uint16_t measurement_result = PCR_MEASUREMENT (0, 0);
	uint16_t measurement_version = PCR_MEASUREMENT (0, 1);
	uint16_t measurement_pfm = PCR_MEASUREMENT (0, 2);
	uint16_t measurement_pfm_id = PCR_MEASUREMENT (0, 3);
	uint16_t measurement_plat_id = PCR_MEASUREMENT (0, 4);
	struct firmware_pfm_verify_testing fw_verify;
	const char *expected = FIRMWARE_PFM_VERIFY_TESTING_VERSION_STR;
	char buffer[sizeof (fw_verify.version)];
	size_t length = sizeof (buffer);
	uint32_t total_len;
	int status;

	TEST_START;

	firmware_pfm_verify_testing_init (test, &fw_verify, 0, measurement_result, measurement_version,
		measurement_pfm, measurement_pfm_id, measurement_plat_id);

	firmware_pfm_verify_testing_run_successful_verification (test, &fw_verify);

	strcpy (buffer, "unexpected");

	status = firmware_pfm_verify_get_fw_version_measured_data (&fw_verify.test, 0,
		(uint8_t*) buffer, length, &total_len);
	CuAssertIntEquals (test, strlen (expected) + 1, status);
	CuAssertIntEquals (test, strlen (expected) + 1, total_len);
	CuAssertStrEquals (test, expected, buffer);

	firmware_pfm_verify_testing_release (test, &fw_verify);
}

static void firmware_pfm_verify_test_get_fw_version_measured_data_offset (CuTest *test)
{
	uint16_t measurement_result = PCR_MEASUREMENT (0, 0);
	uint16_t measurement_version = PCR_MEASUREMENT (0, 1);
	uint16_t measurement_pfm = PCR_MEASUREMENT (0, 2);
	uint16_t measurement_pfm_id = PCR_MEASUREMENT (0, 3);
	uint16_t measurement_plat_id = PCR_MEASUREMENT (0, 4);
	struct firmware_pfm_verify_testing fw_verify;
	const char *expected = FIRMWARE_PFM_VERIFY_TESTING_VERSION_STR;
	char buffer[sizeof (fw_verify.version)];
	size_t length = sizeof (buffer);
	size_t offset = 2;
	uint32_t total_len;
	int status;

	TEST_START;

	firmware_pfm_verify_testing_init (test, &fw_verify, 0, measurement_result, measurement_version,
		measurement_pfm, measurement_pfm_id, measurement_plat_id);

	firmware_pfm_verify_testing_run_successful_verification (test, &fw_verify);

	strcpy (buffer, "unexpected");

	status = firmware_pfm_verify_get_fw_version_measured_data (&fw_verify.test, offset,
		(uint8_t*) buffer, length, &total_len);
	CuAssertIntEquals (test, strlen (expected) + 1 - offset, status);
	CuAssertIntEquals (test, strlen (expected) + 1, total_len);
	CuAssertStrEquals (test, &expected[offset], buffer);

	firmware_pfm_verify_testing_release (test, &fw_verify);
}

static void firmware_pfm_verify_test_get_fw_version_measured_data_offset_more_than_length (
	CuTest *test)
{
	uint16_t measurement_result = PCR_MEASUREMENT (0, 0);
	uint16_t measurement_version = PCR_MEASUREMENT (0, 1);
	uint16_t measurement_pfm = PCR_MEASUREMENT (0, 2);
	uint16_t measurement_pfm_id = PCR_MEASUREMENT (0, 3);
	uint16_t measurement_plat_id = PCR_MEASUREMENT (0, 4);
	struct firmware_pfm_verify_testing fw_verify;
	const char *expected = FIRMWARE_PFM_VERIFY_TESTING_VERSION_STR;
	char buffer[sizeof (fw_verify.version)];
	size_t length = sizeof (buffer);
	size_t offset = strlen (expected) + 2;
	uint32_t total_len;
	int status;

	TEST_START;

	firmware_pfm_verify_testing_init (test, &fw_verify, 0, measurement_result, measurement_version,
		measurement_pfm, measurement_pfm_id, measurement_plat_id);

	firmware_pfm_verify_testing_run_successful_verification (test, &fw_verify);

	strcpy (buffer, "unexpected");

	status = firmware_pfm_verify_get_fw_version_measured_data (&fw_verify.test, offset,
		(uint8_t*) buffer, length, &total_len);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, strlen (expected) + 1, total_len);
	CuAssertStrEquals (test, "unexpected", buffer);

	firmware_pfm_verify_testing_release (test, &fw_verify);
}

static void firmware_pfm_verify_test_get_fw_version_measured_data_static_init (CuTest *test)
{
	uint16_t measurement_result = PCR_MEASUREMENT (0, 0);
	uint16_t measurement_version = PCR_MEASUREMENT (0, 1);
	uint16_t measurement_pfm = PCR_MEASUREMENT (0, 2);
	uint16_t measurement_pfm_id = PCR_MEASUREMENT (0, 3);
	uint16_t measurement_plat_id = PCR_MEASUREMENT (0, 4);
	struct firmware_pfm_verify_testing fw_verify = {
		.test = firmware_pfm_verify_static_init (&fw_verify.state, &fw_verify.flash.base,
			&fw_verify.pfm.base, &fw_verify.hash.base, &fw_verify.sig_verify.base, &fw_verify.pcr,
			fw_verify.version, sizeof (fw_verify.version), measurement_result, measurement_version,
			measurement_pfm, measurement_pfm_id, measurement_plat_id)
	};
	const char *expected = FIRMWARE_PFM_VERIFY_TESTING_VERSION_STR;
	char buffer[sizeof (fw_verify.version)];
	size_t length = sizeof (buffer);
	uint32_t total_len;
	int status;

	TEST_START;

	firmware_pfm_verify_testing_init_static (test, &fw_verify, measurement_result,
		measurement_version, measurement_pfm, measurement_pfm_id, measurement_plat_id);

	firmware_pfm_verify_testing_run_successful_verification (test, &fw_verify);

	strcpy (buffer, "unexpected");

	status = firmware_pfm_verify_get_fw_version_measured_data (&fw_verify.test, 0,
		(uint8_t*) buffer, length, &total_len);
	CuAssertIntEquals (test, strlen (expected) + 1, status);
	CuAssertIntEquals (test, strlen (expected) + 1, total_len);
	CuAssertStrEquals (test, expected, buffer);

	firmware_pfm_verify_testing_release (test, &fw_verify);
}

static void firmware_pfm_verify_test_get_fw_version_measured_data_null (CuTest *test)
{
	uint16_t measurement_result = PCR_MEASUREMENT (0, 0);
	uint16_t measurement_version = PCR_MEASUREMENT (0, 1);
	uint16_t measurement_pfm = PCR_MEASUREMENT (0, 2);
	uint16_t measurement_pfm_id = PCR_MEASUREMENT (0, 3);
	uint16_t measurement_plat_id = PCR_MEASUREMENT (0, 4);
	struct firmware_pfm_verify_testing fw_verify;
	char buffer[sizeof (fw_verify.version)];
	size_t length = sizeof (buffer);
	uint32_t total_len;
	int status;

	TEST_START;

	firmware_pfm_verify_testing_init (test, &fw_verify, 0, measurement_result, measurement_version,
		measurement_pfm, measurement_pfm_id, measurement_plat_id);

	strcpy (buffer, "unexpected");

	status = firmware_pfm_verify_get_fw_version_measured_data (NULL, 0, (uint8_t*) buffer, length,
		&total_len);
	CuAssertIntEquals (test, FIRMWARE_PFM_VERIFY_INVALID_ARGUMENT, status);

	status = firmware_pfm_verify_get_fw_version_measured_data (&fw_verify.test, 0, NULL, length,
		&total_len);
	CuAssertIntEquals (test, FIRMWARE_PFM_VERIFY_INVALID_ARGUMENT, status);

	status = firmware_pfm_verify_get_fw_version_measured_data (&fw_verify.test, 0,
		(uint8_t*) buffer, length, NULL);
	CuAssertIntEquals (test, FIRMWARE_PFM_VERIFY_INVALID_ARGUMENT, status);

	firmware_pfm_verify_testing_release (test, &fw_verify);
}

static void firmware_pfm_verify_test_hash_fw_version_measured_data_no_verification (CuTest *test)
{
	uint16_t measurement_result = PCR_MEASUREMENT (0, 0);
	uint16_t measurement_version = PCR_MEASUREMENT (0, 1);
	uint16_t measurement_pfm = PCR_MEASUREMENT (0, 2);
	uint16_t measurement_pfm_id = PCR_MEASUREMENT (0, 3);
	uint16_t measurement_plat_id = PCR_MEASUREMENT (0, 4);
	struct firmware_pfm_verify_testing fw_verify;
	const char *expected = "\0";
	int status;

	TEST_START;

	firmware_pfm_verify_testing_init (test, &fw_verify, 0, measurement_result, measurement_version,
		measurement_pfm, measurement_pfm_id, measurement_plat_id);

	status = mock_expect (&fw_verify.hash_mock.mock, fw_verify.hash_mock.base.update,
		&fw_verify.hash_mock, 0, MOCK_ARG_PTR_CONTAINS (expected, strlen (expected) + 1),
		MOCK_ARG (strlen (expected) + 1));
	CuAssertIntEquals (test, 0, status);

	status = firmware_pfm_verify_hash_fw_version_measured_data (&fw_verify.test,
		&fw_verify.hash_mock.base);
	CuAssertIntEquals (test, 0, status);

	firmware_pfm_verify_testing_release (test, &fw_verify);
}

static void firmware_pfm_verify_test_hash_fw_version_measured_data_after_verification (CuTest *test)
{
	uint16_t measurement_result = PCR_MEASUREMENT (0, 0);
	uint16_t measurement_version = PCR_MEASUREMENT (0, 1);
	uint16_t measurement_pfm = PCR_MEASUREMENT (0, 2);
	uint16_t measurement_pfm_id = PCR_MEASUREMENT (0, 3);
	uint16_t measurement_plat_id = PCR_MEASUREMENT (0, 4);
	struct firmware_pfm_verify_testing fw_verify;
	const char *expected = FIRMWARE_PFM_VERIFY_TESTING_VERSION_STR;
	int status;

	TEST_START;

	firmware_pfm_verify_testing_init (test, &fw_verify, 0, measurement_result, measurement_version,
		measurement_pfm, measurement_pfm_id, measurement_plat_id);

	firmware_pfm_verify_testing_run_successful_verification (test, &fw_verify);

	status = mock_expect (&fw_verify.hash_mock.mock, fw_verify.hash_mock.base.update,
		&fw_verify.hash_mock, 0, MOCK_ARG_PTR_CONTAINS (expected, strlen (expected) + 1),
		MOCK_ARG (strlen (expected) + 1));
	CuAssertIntEquals (test, 0, status);

	status = firmware_pfm_verify_hash_fw_version_measured_data (&fw_verify.test,
		&fw_verify.hash_mock.base);
	CuAssertIntEquals (test, 0, status);

	firmware_pfm_verify_testing_release (test, &fw_verify);
}

static void firmware_pfm_verify_test_hash_fw_version_measured_data_static_init (CuTest *test)
{
	uint16_t measurement_result = PCR_MEASUREMENT (0, 0);
	uint16_t measurement_version = PCR_MEASUREMENT (0, 1);
	uint16_t measurement_pfm = PCR_MEASUREMENT (0, 2);
	uint16_t measurement_pfm_id = PCR_MEASUREMENT (0, 3);
	uint16_t measurement_plat_id = PCR_MEASUREMENT (0, 4);
	struct firmware_pfm_verify_testing fw_verify = {
		.test = firmware_pfm_verify_static_init (&fw_verify.state, &fw_verify.flash.base,
			&fw_verify.pfm.base, &fw_verify.hash.base, &fw_verify.sig_verify.base, &fw_verify.pcr,
			fw_verify.version, sizeof (fw_verify.version), measurement_result, measurement_version,
			measurement_pfm, measurement_pfm_id, measurement_plat_id)
	};
	const char *expected = FIRMWARE_PFM_VERIFY_TESTING_VERSION_STR;
	int status;

	TEST_START;

	firmware_pfm_verify_testing_init_static (test, &fw_verify, measurement_result,
		measurement_version, measurement_pfm, measurement_pfm_id, measurement_plat_id);

	firmware_pfm_verify_testing_run_successful_verification (test, &fw_verify);

	status = mock_expect (&fw_verify.hash_mock.mock, fw_verify.hash_mock.base.update,
		&fw_verify.hash_mock, 0, MOCK_ARG_PTR_CONTAINS (expected, strlen (expected) + 1),
		MOCK_ARG (strlen (expected) + 1));
	CuAssertIntEquals (test, 0, status);

	status = firmware_pfm_verify_hash_fw_version_measured_data (&fw_verify.test,
		&fw_verify.hash_mock.base);
	CuAssertIntEquals (test, 0, status);

	firmware_pfm_verify_testing_release (test, &fw_verify);
}

static void firmware_pfm_verify_test_hash_fw_version_measured_data_null (CuTest *test)
{
	uint16_t measurement_result = PCR_MEASUREMENT (0, 0);
	uint16_t measurement_version = PCR_MEASUREMENT (0, 1);
	uint16_t measurement_pfm = PCR_MEASUREMENT (0, 2);
	uint16_t measurement_pfm_id = PCR_MEASUREMENT (0, 3);
	uint16_t measurement_plat_id = PCR_MEASUREMENT (0, 4);
	struct firmware_pfm_verify_testing fw_verify;
	int status;

	TEST_START;

	firmware_pfm_verify_testing_init (test, &fw_verify, 0, measurement_result, measurement_version,
		measurement_pfm, measurement_pfm_id, measurement_plat_id);

	status = firmware_pfm_verify_hash_fw_version_measured_data (NULL, &fw_verify.hash_mock.base);
	CuAssertIntEquals (test, FIRMWARE_PFM_VERIFY_INVALID_ARGUMENT, status);

	status = firmware_pfm_verify_hash_fw_version_measured_data (&fw_verify.test, NULL);
	CuAssertIntEquals (test, FIRMWARE_PFM_VERIFY_INVALID_ARGUMENT, status);

	firmware_pfm_verify_testing_release (test, &fw_verify);
}

static void firmware_pfm_verify_test_hash_fw_version_measured_data_hash_error (CuTest *test)
{
	uint16_t measurement_result = PCR_MEASUREMENT (0, 0);
	uint16_t measurement_version = PCR_MEASUREMENT (0, 1);
	uint16_t measurement_pfm = PCR_MEASUREMENT (0, 2);
	uint16_t measurement_pfm_id = PCR_MEASUREMENT (0, 3);
	uint16_t measurement_plat_id = PCR_MEASUREMENT (0, 4);
	struct firmware_pfm_verify_testing fw_verify;
	const char *expected = "\0";
	int status;

	TEST_START;

	firmware_pfm_verify_testing_init (test, &fw_verify, 0, measurement_result, measurement_version,
		measurement_pfm, measurement_pfm_id, measurement_plat_id);

	status = mock_expect (&fw_verify.hash_mock.mock, fw_verify.hash_mock.base.update,
		&fw_verify.hash_mock, HASH_ENGINE_UPDATE_FAILED,
		MOCK_ARG_PTR_CONTAINS (expected, strlen (expected) + 1), MOCK_ARG (strlen (expected) + 1));
	CuAssertIntEquals (test, 0, status);

	status = firmware_pfm_verify_hash_fw_version_measured_data (&fw_verify.test,
		&fw_verify.hash_mock.base);
	CuAssertIntEquals (test, HASH_ENGINE_UPDATE_FAILED, status);

	firmware_pfm_verify_testing_release (test, &fw_verify);
}

static void firmware_pfm_verify_test_get_pfm_digest_measured_data_no_verification (CuTest *test)
{
	uint16_t measurement_result = PCR_MEASUREMENT (0, 0);
	uint16_t measurement_version = PCR_MEASUREMENT (0, 1);
	uint16_t measurement_pfm = PCR_MEASUREMENT (0, 2);
	uint16_t measurement_pfm_id = PCR_MEASUREMENT (0, 3);
	uint16_t measurement_plat_id = PCR_MEASUREMENT (0, 4);
	struct firmware_pfm_verify_testing fw_verify;
	uint8_t expected[SHA256_HASH_LENGTH] = {0};
	uint8_t buffer[SHA256_HASH_LENGTH];
	size_t length = sizeof (buffer);
	uint32_t total_len;
	int status;

	TEST_START;

	firmware_pfm_verify_testing_init (test, &fw_verify, 0, measurement_result, measurement_version,
		measurement_pfm, measurement_pfm_id, measurement_plat_id);

	memset (buffer, 0x55, sizeof (buffer));

	status = firmware_pfm_verify_get_pfm_digest_measured_data (&fw_verify.test, 0, buffer, length,
		&total_len);
	CuAssertIntEquals (test, sizeof (expected), status);
	CuAssertIntEquals (test, sizeof (expected), total_len);

	status = testing_validate_array (expected, buffer, status);
	CuAssertIntEquals (test, 0, status);

	firmware_pfm_verify_testing_release (test, &fw_verify);
}

static void firmware_pfm_verify_test_get_pfm_digest_measured_data_after_verification (CuTest *test)
{
	uint16_t measurement_result = PCR_MEASUREMENT (0, 0);
	uint16_t measurement_version = PCR_MEASUREMENT (0, 1);
	uint16_t measurement_pfm = PCR_MEASUREMENT (0, 2);
	uint16_t measurement_pfm_id = PCR_MEASUREMENT (0, 3);
	uint16_t measurement_plat_id = PCR_MEASUREMENT (0, 4);
	struct firmware_pfm_verify_testing fw_verify;
	uint8_t buffer[SHA256_HASH_LENGTH];
	size_t length = sizeof (buffer);
	uint32_t total_len;
	int status;

	TEST_START;

	firmware_pfm_verify_testing_init (test, &fw_verify, 0, measurement_result, measurement_version,
		measurement_pfm, measurement_pfm_id, measurement_plat_id);

	firmware_pfm_verify_testing_run_successful_verification (test, &fw_verify);

	memset (buffer, 0x55, sizeof (buffer));

	status = mock_expect (&fw_verify.pfm.mock, fw_verify.pfm.base.base.get_hash, &fw_verify.pfm,
		PFM_V2.manifest.hash_len, MOCK_ARG_PTR (&fw_verify.hash.base), MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (PFM_V2.manifest.hash_len));
	status |= mock_expect_output (&fw_verify.pfm.mock, 1, PFM_V2.manifest.hash,
		PFM_V2.manifest.hash_len, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_pfm_verify_get_pfm_digest_measured_data (&fw_verify.test, 0, buffer, length,
		&total_len);
	CuAssertIntEquals (test, PFM_V2.manifest.hash_len, status);
	CuAssertIntEquals (test, PFM_V2.manifest.hash_len, total_len);

	status = testing_validate_array (PFM_V2.manifest.hash, buffer, status);
	CuAssertIntEquals (test, 0, status);

	firmware_pfm_verify_testing_release (test, &fw_verify);
}

static void firmware_pfm_verify_test_get_pfm_digest_measured_data_static_init (CuTest *test)
{
	uint16_t measurement_result = PCR_MEASUREMENT (0, 0);
	uint16_t measurement_version = PCR_MEASUREMENT (0, 1);
	uint16_t measurement_pfm = PCR_MEASUREMENT (0, 2);
	uint16_t measurement_pfm_id = PCR_MEASUREMENT (0, 3);
	uint16_t measurement_plat_id = PCR_MEASUREMENT (0, 4);
	struct firmware_pfm_verify_testing fw_verify = {
		.test = firmware_pfm_verify_static_init (&fw_verify.state, &fw_verify.flash.base,
			&fw_verify.pfm.base, &fw_verify.hash.base, &fw_verify.sig_verify.base, &fw_verify.pcr,
			fw_verify.version, sizeof (fw_verify.version), measurement_result, measurement_version,
			measurement_pfm, measurement_pfm_id, measurement_plat_id)
	};
	uint8_t buffer[SHA256_HASH_LENGTH];
	size_t length = sizeof (buffer);
	uint32_t total_len;
	int status;

	TEST_START;

	firmware_pfm_verify_testing_init_static (test, &fw_verify, measurement_result,
		measurement_version, measurement_pfm, measurement_pfm_id, measurement_plat_id);

	firmware_pfm_verify_testing_run_successful_verification (test, &fw_verify);

	memset (buffer, 0x55, sizeof (buffer));

	status = mock_expect (&fw_verify.pfm.mock, fw_verify.pfm.base.base.get_hash, &fw_verify.pfm,
		PFM_V2.manifest.hash_len, MOCK_ARG_PTR (&fw_verify.hash.base), MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (PFM_V2.manifest.hash_len));
	status |= mock_expect_output (&fw_verify.pfm.mock, 1, PFM_V2.manifest.hash,
		PFM_V2.manifest.hash_len, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_pfm_verify_get_pfm_digest_measured_data (&fw_verify.test, 0, buffer, length,
		&total_len);
	CuAssertIntEquals (test, PFM_V2.manifest.hash_len, status);
	CuAssertIntEquals (test, PFM_V2.manifest.hash_len, total_len);

	status = testing_validate_array (PFM_V2.manifest.hash, buffer, status);
	CuAssertIntEquals (test, 0, status);

	firmware_pfm_verify_testing_release (test, &fw_verify);
}

static void firmware_pfm_verify_test_get_pfm_digest_measured_data_null (CuTest *test)
{
	uint16_t measurement_result = PCR_MEASUREMENT (0, 0);
	uint16_t measurement_version = PCR_MEASUREMENT (0, 1);
	uint16_t measurement_pfm = PCR_MEASUREMENT (0, 2);
	uint16_t measurement_pfm_id = PCR_MEASUREMENT (0, 3);
	uint16_t measurement_plat_id = PCR_MEASUREMENT (0, 4);
	struct firmware_pfm_verify_testing fw_verify;
	uint8_t buffer[SHA256_HASH_LENGTH];
	size_t length = sizeof (buffer);
	uint32_t total_len;
	int status;

	TEST_START;

	firmware_pfm_verify_testing_init (test, &fw_verify, 0, measurement_result, measurement_version,
		measurement_pfm, measurement_pfm_id, measurement_plat_id);

	status = firmware_pfm_verify_get_pfm_digest_measured_data (NULL, 0, buffer, length, &total_len);
	CuAssertIntEquals (test, FIRMWARE_PFM_VERIFY_INVALID_ARGUMENT, status);

	status = firmware_pfm_verify_get_pfm_digest_measured_data (&fw_verify.test, 0, NULL, length,
		&total_len);
	CuAssertIntEquals (test, MANIFEST_MANAGER_INVALID_ARGUMENT, status);

	status = firmware_pfm_verify_get_pfm_digest_measured_data (&fw_verify.test, 0, buffer, length,
		NULL);
	CuAssertIntEquals (test, MANIFEST_MANAGER_INVALID_ARGUMENT, status);

	firmware_pfm_verify_testing_release (test, &fw_verify);
}

static void firmware_pfm_verify_test_hash_pfm_digest_measured_data_no_verification (CuTest *test)
{
	uint16_t measurement_result = PCR_MEASUREMENT (0, 0);
	uint16_t measurement_version = PCR_MEASUREMENT (0, 1);
	uint16_t measurement_pfm = PCR_MEASUREMENT (0, 2);
	uint16_t measurement_pfm_id = PCR_MEASUREMENT (0, 3);
	uint16_t measurement_plat_id = PCR_MEASUREMENT (0, 4);
	struct firmware_pfm_verify_testing fw_verify;
	uint8_t expected[SHA256_HASH_LENGTH] = {0};
	int status;

	TEST_START;

	firmware_pfm_verify_testing_init (test, &fw_verify, 0, measurement_result, measurement_version,
		measurement_pfm, measurement_pfm_id, measurement_plat_id);

	status = mock_expect (&fw_verify.hash_mock.mock, fw_verify.hash_mock.base.update,
		&fw_verify.hash_mock, 0, MOCK_ARG_PTR_CONTAINS (expected, sizeof (expected)),
		MOCK_ARG (sizeof (expected)));

	CuAssertIntEquals (test, 0, status);

	status = firmware_pfm_verify_hash_pfm_digest_measured_data (&fw_verify.test,
		&fw_verify.hash_mock.base);
	CuAssertIntEquals (test, 0, status);

	firmware_pfm_verify_testing_release (test, &fw_verify);
}

static void firmware_pfm_verify_test_hash_pfm_digest_measured_data_after_verification (CuTest *test)
{
	uint16_t measurement_result = PCR_MEASUREMENT (0, 0);
	uint16_t measurement_version = PCR_MEASUREMENT (0, 1);
	uint16_t measurement_pfm = PCR_MEASUREMENT (0, 2);
	uint16_t measurement_pfm_id = PCR_MEASUREMENT (0, 3);
	uint16_t measurement_plat_id = PCR_MEASUREMENT (0, 4);
	struct firmware_pfm_verify_testing fw_verify;
	int status;

	TEST_START;

	firmware_pfm_verify_testing_init (test, &fw_verify, 0, measurement_result, measurement_version,
		measurement_pfm, measurement_pfm_id, measurement_plat_id);

	firmware_pfm_verify_testing_run_successful_verification (test, &fw_verify);

	status = mock_expect (&fw_verify.pfm.mock, fw_verify.pfm.base.base.get_hash, &fw_verify.pfm,
		PFM_V2.manifest.hash_len, MOCK_ARG_PTR (&fw_verify.hash.base), MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (PFM_V2.manifest.hash_len));
	status |= mock_expect_output (&fw_verify.pfm.mock, 1, PFM_V2.manifest.hash,
		PFM_V2.manifest.hash_len, 2);

	status |= mock_expect (&fw_verify.hash_mock.mock, fw_verify.hash_mock.base.update,
		&fw_verify.hash_mock, 0,
		MOCK_ARG_PTR_CONTAINS (PFM_V2.manifest.hash, PFM_V2.manifest.hash_len),
		MOCK_ARG (PFM_V2.manifest.hash_len));

	CuAssertIntEquals (test, 0, status);

	status = firmware_pfm_verify_hash_pfm_digest_measured_data (&fw_verify.test,
		&fw_verify.hash_mock.base);
	CuAssertIntEquals (test, 0, status);

	firmware_pfm_verify_testing_release (test, &fw_verify);
}

static void firmware_pfm_verify_test_hash_pfm_digest_measured_data_static_init (CuTest *test)
{
	uint16_t measurement_result = PCR_MEASUREMENT (0, 0);
	uint16_t measurement_version = PCR_MEASUREMENT (0, 1);
	uint16_t measurement_pfm = PCR_MEASUREMENT (0, 2);
	uint16_t measurement_pfm_id = PCR_MEASUREMENT (0, 3);
	uint16_t measurement_plat_id = PCR_MEASUREMENT (0, 4);
	struct firmware_pfm_verify_testing fw_verify = {
		.test = firmware_pfm_verify_static_init (&fw_verify.state, &fw_verify.flash.base,
			&fw_verify.pfm.base, &fw_verify.hash.base, &fw_verify.sig_verify.base, &fw_verify.pcr,
			fw_verify.version, sizeof (fw_verify.version), measurement_result, measurement_version,
			measurement_pfm, measurement_pfm_id, measurement_plat_id)
	};
	int status;

	TEST_START;

	firmware_pfm_verify_testing_init_static (test, &fw_verify, measurement_result,
		measurement_version, measurement_pfm, measurement_pfm_id, measurement_plat_id);

	firmware_pfm_verify_testing_run_successful_verification (test, &fw_verify);

	status = mock_expect (&fw_verify.pfm.mock, fw_verify.pfm.base.base.get_hash, &fw_verify.pfm,
		PFM_V2.manifest.hash_len, MOCK_ARG_PTR (&fw_verify.hash.base), MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (PFM_V2.manifest.hash_len));
	status |= mock_expect_output (&fw_verify.pfm.mock, 1, PFM_V2.manifest.hash,
		PFM_V2.manifest.hash_len, 2);

	status |= mock_expect (&fw_verify.hash_mock.mock, fw_verify.hash_mock.base.update,
		&fw_verify.hash_mock, 0,
		MOCK_ARG_PTR_CONTAINS (PFM_V2.manifest.hash, PFM_V2.manifest.hash_len),
		MOCK_ARG (PFM_V2.manifest.hash_len));

	CuAssertIntEquals (test, 0, status);

	status = firmware_pfm_verify_hash_pfm_digest_measured_data (&fw_verify.test,
		&fw_verify.hash_mock.base);
	CuAssertIntEquals (test, 0, status);

	firmware_pfm_verify_testing_release (test, &fw_verify);
}

static void firmware_pfm_verify_test_hash_pfm_digest_measured_data_null (CuTest *test)
{
	uint16_t measurement_result = PCR_MEASUREMENT (0, 0);
	uint16_t measurement_version = PCR_MEASUREMENT (0, 1);
	uint16_t measurement_pfm = PCR_MEASUREMENT (0, 2);
	uint16_t measurement_pfm_id = PCR_MEASUREMENT (0, 3);
	uint16_t measurement_plat_id = PCR_MEASUREMENT (0, 4);
	struct firmware_pfm_verify_testing fw_verify;
	int status;

	TEST_START;

	firmware_pfm_verify_testing_init (test, &fw_verify, 0, measurement_result, measurement_version,
		measurement_pfm, measurement_pfm_id, measurement_plat_id);

	status = firmware_pfm_verify_hash_pfm_digest_measured_data (NULL, &fw_verify.hash_mock.base);
	CuAssertIntEquals (test, FIRMWARE_PFM_VERIFY_INVALID_ARGUMENT, status);

	status = firmware_pfm_verify_hash_pfm_digest_measured_data (&fw_verify.test, NULL);
	CuAssertIntEquals (test, MANIFEST_MANAGER_INVALID_ARGUMENT, status);

	firmware_pfm_verify_testing_release (test, &fw_verify);
}

static void firmware_pfm_verify_test_hash_pfm_digest_measured_data_no_verification_hash_error (
	CuTest *test)
{
	uint16_t measurement_result = PCR_MEASUREMENT (0, 0);
	uint16_t measurement_version = PCR_MEASUREMENT (0, 1);
	uint16_t measurement_pfm = PCR_MEASUREMENT (0, 2);
	uint16_t measurement_pfm_id = PCR_MEASUREMENT (0, 3);
	uint16_t measurement_plat_id = PCR_MEASUREMENT (0, 4);
	struct firmware_pfm_verify_testing fw_verify;
	uint8_t expected[SHA256_HASH_LENGTH] = {0};
	int status;

	TEST_START;

	firmware_pfm_verify_testing_init (test, &fw_verify, 0, measurement_result, measurement_version,
		measurement_pfm, measurement_pfm_id, measurement_plat_id);

	status = mock_expect (&fw_verify.hash_mock.mock, fw_verify.hash_mock.base.update,
		&fw_verify.hash_mock, HASH_ENGINE_UPDATE_FAILED,
		MOCK_ARG_PTR_CONTAINS (expected, sizeof (expected)), MOCK_ARG (sizeof (expected)));

	CuAssertIntEquals (test, 0, status);

	status = firmware_pfm_verify_hash_pfm_digest_measured_data (&fw_verify.test,
		&fw_verify.hash_mock.base);
	CuAssertIntEquals (test, HASH_ENGINE_UPDATE_FAILED, status);

	firmware_pfm_verify_testing_release (test, &fw_verify);
}

static void firmware_pfm_verify_test_hash_pfm_digest_measured_data_after_verification_hash_error (
	CuTest *test)
{
	uint16_t measurement_result = PCR_MEASUREMENT (0, 0);
	uint16_t measurement_version = PCR_MEASUREMENT (0, 1);
	uint16_t measurement_pfm = PCR_MEASUREMENT (0, 2);
	uint16_t measurement_pfm_id = PCR_MEASUREMENT (0, 3);
	uint16_t measurement_plat_id = PCR_MEASUREMENT (0, 4);
	struct firmware_pfm_verify_testing fw_verify;
	int status;

	TEST_START;

	firmware_pfm_verify_testing_init (test, &fw_verify, 0, measurement_result, measurement_version,
		measurement_pfm, measurement_pfm_id, measurement_plat_id);

	firmware_pfm_verify_testing_run_successful_verification (test, &fw_verify);

	status = mock_expect (&fw_verify.pfm.mock, fw_verify.pfm.base.base.get_hash, &fw_verify.pfm,
		PFM_V2.manifest.hash_len, MOCK_ARG_PTR (&fw_verify.hash.base), MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (PFM_V2.manifest.hash_len));
	status |= mock_expect_output (&fw_verify.pfm.mock, 1, PFM_V2.manifest.hash,
		PFM_V2.manifest.hash_len, 2);

	status |= mock_expect (&fw_verify.hash_mock.mock, fw_verify.hash_mock.base.update,
		&fw_verify.hash_mock, HASH_ENGINE_UPDATE_FAILED,
		MOCK_ARG_PTR_CONTAINS (PFM_V2.manifest.hash, PFM_V2.manifest.hash_len),
		MOCK_ARG (PFM_V2.manifest.hash_len));

	CuAssertIntEquals (test, 0, status);

	status = firmware_pfm_verify_hash_pfm_digest_measured_data (&fw_verify.test,
		&fw_verify.hash_mock.base);
	CuAssertIntEquals (test, HASH_ENGINE_UPDATE_FAILED, status);

	firmware_pfm_verify_testing_release (test, &fw_verify);
}

static void firmware_pfm_verify_test_get_pfm_id_measured_data_no_verification (CuTest *test)
{
	uint16_t measurement_result = PCR_MEASUREMENT (0, 0);
	uint16_t measurement_version = PCR_MEASUREMENT (0, 1);
	uint16_t measurement_pfm = PCR_MEASUREMENT (0, 2);
	uint16_t measurement_pfm_id = PCR_MEASUREMENT (0, 3);
	uint16_t measurement_plat_id = PCR_MEASUREMENT (0, 4);
	struct firmware_pfm_verify_testing fw_verify;
	uint8_t expected[5] = {0};
	uint8_t buffer[sizeof (expected)];
	size_t length = sizeof (buffer);
	uint32_t total_len;
	int status;

	TEST_START;

	firmware_pfm_verify_testing_init (test, &fw_verify, 0, measurement_result, measurement_version,
		measurement_pfm, measurement_pfm_id, measurement_plat_id);

	memset (buffer, 0x55, sizeof (buffer));

	status = firmware_pfm_verify_get_pfm_id_measured_data (&fw_verify.test, 0, buffer, length,
		&total_len);
	CuAssertIntEquals (test, sizeof (expected), status);
	CuAssertIntEquals (test, sizeof (expected), total_len);

	status = testing_validate_array (expected, buffer, status);
	CuAssertIntEquals (test, 0, status);

	firmware_pfm_verify_testing_release (test, &fw_verify);
}

static void firmware_pfm_verify_test_get_pfm_id_measured_data_after_verification (CuTest *test)
{
	uint16_t measurement_result = PCR_MEASUREMENT (0, 0);
	uint16_t measurement_version = PCR_MEASUREMENT (0, 1);
	uint16_t measurement_pfm = PCR_MEASUREMENT (0, 2);
	uint16_t measurement_pfm_id = PCR_MEASUREMENT (0, 3);
	uint16_t measurement_plat_id = PCR_MEASUREMENT (0, 4);
	struct firmware_pfm_verify_testing fw_verify;
	uint8_t expected[5] = {1, 2, 3, 4, 5};
	uint8_t buffer[sizeof (expected)];
	size_t length = sizeof (buffer);
	uint32_t total_len;
	int status;

	TEST_START;

	firmware_pfm_verify_testing_init (test, &fw_verify, 0, measurement_result, measurement_version,
		measurement_pfm, measurement_pfm_id, measurement_plat_id);

	firmware_pfm_verify_testing_run_successful_verification (test, &fw_verify);

	memset (buffer, 0x55, sizeof (buffer));

	status = mock_expect (&fw_verify.pfm.mock, fw_verify.pfm.base.base.get_id, &fw_verify.pfm, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&fw_verify.pfm.mock, 0, &expected[1], sizeof (expected) - 1, -1);

	CuAssertIntEquals (test, 0, status);

	status = firmware_pfm_verify_get_pfm_id_measured_data (&fw_verify.test, 0, buffer, length,
		&total_len);
	CuAssertIntEquals (test, sizeof (expected), status);
	CuAssertIntEquals (test, sizeof (expected), total_len);

	status = testing_validate_array (expected, buffer, status);
	CuAssertIntEquals (test, 0, status);

	firmware_pfm_verify_testing_release (test, &fw_verify);
}

static void firmware_pfm_verify_test_get_pfm_id_measured_data_static_init (CuTest *test)
{
	uint16_t measurement_result = PCR_MEASUREMENT (0, 0);
	uint16_t measurement_version = PCR_MEASUREMENT (0, 1);
	uint16_t measurement_pfm = PCR_MEASUREMENT (0, 2);
	uint16_t measurement_pfm_id = PCR_MEASUREMENT (0, 3);
	uint16_t measurement_plat_id = PCR_MEASUREMENT (0, 4);
	struct firmware_pfm_verify_testing fw_verify = {
		.test = firmware_pfm_verify_static_init (&fw_verify.state, &fw_verify.flash.base,
			&fw_verify.pfm.base, &fw_verify.hash.base, &fw_verify.sig_verify.base, &fw_verify.pcr,
			fw_verify.version, sizeof (fw_verify.version), measurement_result, measurement_version,
			measurement_pfm, measurement_pfm_id, measurement_plat_id)
	};
	uint8_t expected[5] = {1, 20, 30, 40, 50};
	uint8_t buffer[sizeof (expected)];
	size_t length = sizeof (buffer);
	uint32_t total_len;
	int status;

	TEST_START;

	firmware_pfm_verify_testing_init_static (test, &fw_verify, measurement_result,
		measurement_version, measurement_pfm, measurement_pfm_id, measurement_plat_id);

	firmware_pfm_verify_testing_run_successful_verification (test, &fw_verify);

	memset (buffer, 0x55, sizeof (buffer));

	status = mock_expect (&fw_verify.pfm.mock, fw_verify.pfm.base.base.get_id, &fw_verify.pfm, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&fw_verify.pfm.mock, 0, &expected[1], sizeof (expected) - 1, -1);

	CuAssertIntEquals (test, 0, status);

	status = firmware_pfm_verify_get_pfm_id_measured_data (&fw_verify.test, 0, buffer, length,
		&total_len);
	CuAssertIntEquals (test, sizeof (expected), status);
	CuAssertIntEquals (test, sizeof (expected), total_len);

	status = testing_validate_array (expected, buffer, status);
	CuAssertIntEquals (test, 0, status);

	firmware_pfm_verify_testing_release (test, &fw_verify);
}

static void firmware_pfm_verify_test_get_pfm_id_measured_data_null (CuTest *test)
{
	uint16_t measurement_result = PCR_MEASUREMENT (0, 0);
	uint16_t measurement_version = PCR_MEASUREMENT (0, 1);
	uint16_t measurement_pfm = PCR_MEASUREMENT (0, 2);
	uint16_t measurement_pfm_id = PCR_MEASUREMENT (0, 3);
	uint16_t measurement_plat_id = PCR_MEASUREMENT (0, 4);
	struct firmware_pfm_verify_testing fw_verify;
	uint8_t buffer[5];
	size_t length = sizeof (buffer);
	uint32_t total_len;
	int status;

	TEST_START;

	firmware_pfm_verify_testing_init (test, &fw_verify, 0, measurement_result, measurement_version,
		measurement_pfm, measurement_pfm_id, measurement_plat_id);

	status = firmware_pfm_verify_get_pfm_id_measured_data (NULL, 0, buffer, length, &total_len);
	CuAssertIntEquals (test, FIRMWARE_PFM_VERIFY_INVALID_ARGUMENT, status);

	status = firmware_pfm_verify_get_pfm_id_measured_data (&fw_verify.test, 0, NULL, length,
		&total_len);
	CuAssertIntEquals (test, MANIFEST_MANAGER_INVALID_ARGUMENT, status);

	status = firmware_pfm_verify_get_pfm_id_measured_data (&fw_verify.test, 0, buffer, length,
		NULL);
	CuAssertIntEquals (test, MANIFEST_MANAGER_INVALID_ARGUMENT, status);

	firmware_pfm_verify_testing_release (test, &fw_verify);
}

static void firmware_pfm_verify_test_hash_pfm_id_measured_data_no_verification (CuTest *test)
{
	uint16_t measurement_result = PCR_MEASUREMENT (0, 0);
	uint16_t measurement_version = PCR_MEASUREMENT (0, 1);
	uint16_t measurement_pfm = PCR_MEASUREMENT (0, 2);
	uint16_t measurement_pfm_id = PCR_MEASUREMENT (0, 3);
	uint16_t measurement_plat_id = PCR_MEASUREMENT (0, 4);
	struct firmware_pfm_verify_testing fw_verify;
	uint8_t expected[5] = {0};
	int status;

	TEST_START;

	firmware_pfm_verify_testing_init (test, &fw_verify, 0, measurement_result, measurement_version,
		measurement_pfm, measurement_pfm_id, measurement_plat_id);

	status = mock_expect (&fw_verify.hash_mock.mock, fw_verify.hash_mock.base.update,
		&fw_verify.hash_mock, 0, MOCK_ARG_PTR_CONTAINS (expected, sizeof (expected)),
		MOCK_ARG (sizeof (expected)));

	CuAssertIntEquals (test, 0, status);

	status = firmware_pfm_verify_hash_pfm_id_measured_data (&fw_verify.test,
		&fw_verify.hash_mock.base);
	CuAssertIntEquals (test, 0, status);

	firmware_pfm_verify_testing_release (test, &fw_verify);
}

static void firmware_pfm_verify_test_hash_pfm_id_measured_data_after_verification (CuTest *test)
{
	uint16_t measurement_result = PCR_MEASUREMENT (0, 0);
	uint16_t measurement_version = PCR_MEASUREMENT (0, 1);
	uint16_t measurement_pfm = PCR_MEASUREMENT (0, 2);
	uint16_t measurement_pfm_id = PCR_MEASUREMENT (0, 3);
	uint16_t measurement_plat_id = PCR_MEASUREMENT (0, 4);
	struct firmware_pfm_verify_testing fw_verify;
	uint8_t expected[5] = {1, 2, 3, 4, 5};
	int status;

	TEST_START;

	firmware_pfm_verify_testing_init (test, &fw_verify, 0, measurement_result, measurement_version,
		measurement_pfm, measurement_pfm_id, measurement_plat_id);

	firmware_pfm_verify_testing_run_successful_verification (test, &fw_verify);

	status = mock_expect (&fw_verify.pfm.mock, fw_verify.pfm.base.base.get_id, &fw_verify.pfm, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&fw_verify.pfm.mock, 0, &expected[1], sizeof (expected) - 1, -1);

	status |= mock_expect (&fw_verify.hash_mock.mock, fw_verify.hash_mock.base.update,
		&fw_verify.hash_mock, 0, MOCK_ARG_PTR_CONTAINS (expected, sizeof (expected)),
		MOCK_ARG (sizeof (expected)));

	CuAssertIntEquals (test, 0, status);

	status = firmware_pfm_verify_hash_pfm_id_measured_data (&fw_verify.test,
		&fw_verify.hash_mock.base);
	CuAssertIntEquals (test, 0, status);

	firmware_pfm_verify_testing_release (test, &fw_verify);
}

static void firmware_pfm_verify_test_hash_pfm_id_measured_data_static_init (CuTest *test)
{
	uint16_t measurement_result = PCR_MEASUREMENT (0, 0);
	uint16_t measurement_version = PCR_MEASUREMENT (0, 1);
	uint16_t measurement_pfm = PCR_MEASUREMENT (0, 2);
	uint16_t measurement_pfm_id = PCR_MEASUREMENT (0, 3);
	uint16_t measurement_plat_id = PCR_MEASUREMENT (0, 4);
	struct firmware_pfm_verify_testing fw_verify = {
		.test = firmware_pfm_verify_static_init (&fw_verify.state, &fw_verify.flash.base,
			&fw_verify.pfm.base, &fw_verify.hash.base, &fw_verify.sig_verify.base, &fw_verify.pcr,
			fw_verify.version, sizeof (fw_verify.version), measurement_result, measurement_version,
			measurement_pfm, measurement_pfm_id, measurement_plat_id)
	};
	uint8_t expected[5] = {1, 20, 30, 40, 50};
	int status;

	TEST_START;

	firmware_pfm_verify_testing_init_static (test, &fw_verify, measurement_result,
		measurement_version, measurement_pfm, measurement_pfm_id, measurement_plat_id);

	firmware_pfm_verify_testing_run_successful_verification (test, &fw_verify);

	status = mock_expect (&fw_verify.pfm.mock, fw_verify.pfm.base.base.get_id, &fw_verify.pfm, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&fw_verify.pfm.mock, 0, &expected[1], sizeof (expected) - 1, -1);

	status |= mock_expect (&fw_verify.hash_mock.mock, fw_verify.hash_mock.base.update,
		&fw_verify.hash_mock, 0, MOCK_ARG_PTR_CONTAINS (expected, sizeof (expected)),
		MOCK_ARG (sizeof (expected)));

	CuAssertIntEquals (test, 0, status);

	status = firmware_pfm_verify_hash_pfm_id_measured_data (&fw_verify.test,
		&fw_verify.hash_mock.base);
	CuAssertIntEquals (test, 0, status);

	firmware_pfm_verify_testing_release (test, &fw_verify);
}

static void firmware_pfm_verify_test_hash_pfm_id_measured_data_null (CuTest *test)
{
	uint16_t measurement_result = PCR_MEASUREMENT (0, 0);
	uint16_t measurement_version = PCR_MEASUREMENT (0, 1);
	uint16_t measurement_pfm = PCR_MEASUREMENT (0, 2);
	uint16_t measurement_pfm_id = PCR_MEASUREMENT (0, 3);
	uint16_t measurement_plat_id = PCR_MEASUREMENT (0, 4);
	struct firmware_pfm_verify_testing fw_verify;
	int status;

	TEST_START;

	firmware_pfm_verify_testing_init (test, &fw_verify, 0, measurement_result, measurement_version,
		measurement_pfm, measurement_pfm_id, measurement_plat_id);

	status = firmware_pfm_verify_hash_pfm_id_measured_data (NULL, &fw_verify.hash_mock.base);
	CuAssertIntEquals (test, FIRMWARE_PFM_VERIFY_INVALID_ARGUMENT, status);

	status = firmware_pfm_verify_hash_pfm_id_measured_data (&fw_verify.test, NULL);
	CuAssertIntEquals (test, MANIFEST_MANAGER_INVALID_ARGUMENT, status);

	firmware_pfm_verify_testing_release (test, &fw_verify);
}

static void firmware_pfm_verify_test_hash_pfm_id_measured_data_no_verification_hash_error (
	CuTest *test)
{
	uint16_t measurement_result = PCR_MEASUREMENT (0, 0);
	uint16_t measurement_version = PCR_MEASUREMENT (0, 1);
	uint16_t measurement_pfm = PCR_MEASUREMENT (0, 2);
	uint16_t measurement_pfm_id = PCR_MEASUREMENT (0, 3);
	uint16_t measurement_plat_id = PCR_MEASUREMENT (0, 4);
	struct firmware_pfm_verify_testing fw_verify;
	uint8_t expected[5] = {0};
	int status;

	TEST_START;

	firmware_pfm_verify_testing_init (test, &fw_verify, 0, measurement_result, measurement_version,
		measurement_pfm, measurement_pfm_id, measurement_plat_id);

	status = mock_expect (&fw_verify.hash_mock.mock, fw_verify.hash_mock.base.update,
		&fw_verify.hash_mock, HASH_ENGINE_UPDATE_FAILED,
		MOCK_ARG_PTR_CONTAINS (expected, sizeof (expected)), MOCK_ARG (sizeof (expected)));

	CuAssertIntEquals (test, 0, status);

	status = firmware_pfm_verify_hash_pfm_id_measured_data (&fw_verify.test,
		&fw_verify.hash_mock.base);
	CuAssertIntEquals (test, HASH_ENGINE_UPDATE_FAILED, status);

	firmware_pfm_verify_testing_release (test, &fw_verify);
}

static void firmware_pfm_verify_test_hash_pfm_id_measured_data_after_verification_hash_error (
	CuTest *test)
{
	uint16_t measurement_result = PCR_MEASUREMENT (0, 0);
	uint16_t measurement_version = PCR_MEASUREMENT (0, 1);
	uint16_t measurement_pfm = PCR_MEASUREMENT (0, 2);
	uint16_t measurement_pfm_id = PCR_MEASUREMENT (0, 3);
	uint16_t measurement_plat_id = PCR_MEASUREMENT (0, 4);
	struct firmware_pfm_verify_testing fw_verify;
	uint8_t expected[5] = {1, 2, 3, 4, 5};
	int status;

	TEST_START;

	firmware_pfm_verify_testing_init (test, &fw_verify, 0, measurement_result, measurement_version,
		measurement_pfm, measurement_pfm_id, measurement_plat_id);

	firmware_pfm_verify_testing_run_successful_verification (test, &fw_verify);

	status = mock_expect (&fw_verify.pfm.mock, fw_verify.pfm.base.base.get_id, &fw_verify.pfm, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&fw_verify.pfm.mock, 0, &expected[1], sizeof (expected) - 1, -1);

	status |= mock_expect (&fw_verify.hash_mock.mock, fw_verify.hash_mock.base.update,
		&fw_verify.hash_mock, HASH_ENGINE_UPDATE_FAILED,
		MOCK_ARG_PTR_CONTAINS (expected, sizeof (expected)), MOCK_ARG (sizeof (expected)));

	CuAssertIntEquals (test, 0, status);

	status = firmware_pfm_verify_hash_pfm_id_measured_data (&fw_verify.test,
		&fw_verify.hash_mock.base);
	CuAssertIntEquals (test, HASH_ENGINE_UPDATE_FAILED, status);

	firmware_pfm_verify_testing_release (test, &fw_verify);
}

static void firmware_pfm_verify_test_get_pfm_platform_id_measured_data_no_verification (
	CuTest *test)
{
	uint16_t measurement_result = PCR_MEASUREMENT (0, 0);
	uint16_t measurement_version = PCR_MEASUREMENT (0, 1);
	uint16_t measurement_pfm = PCR_MEASUREMENT (0, 2);
	uint16_t measurement_pfm_id = PCR_MEASUREMENT (0, 3);
	uint16_t measurement_plat_id = PCR_MEASUREMENT (0, 4);
	struct firmware_pfm_verify_testing fw_verify;
	const char *expected = "\0";
	char buffer[64];
	size_t length = sizeof (buffer);
	uint32_t total_len;
	int status;

	TEST_START;

	firmware_pfm_verify_testing_init (test, &fw_verify, 0, measurement_result, measurement_version,
		measurement_pfm, measurement_pfm_id, measurement_plat_id);

	strcpy (buffer, "unexpected");

	status = firmware_pfm_verify_get_pfm_platform_id_measured_data (&fw_verify.test, 0,
		(uint8_t*) buffer, length, &total_len);
	CuAssertIntEquals (test, strlen (expected) + 1, status);
	CuAssertIntEquals (test, strlen (expected) + 1, total_len);
	CuAssertStrEquals (test, expected, buffer);

	firmware_pfm_verify_testing_release (test, &fw_verify);
}

static void firmware_pfm_verify_test_get_pfm_platform_id_measured_data_after_verification (
	CuTest *test)
{
	uint16_t measurement_result = PCR_MEASUREMENT (0, 0);
	uint16_t measurement_version = PCR_MEASUREMENT (0, 1);
	uint16_t measurement_pfm = PCR_MEASUREMENT (0, 2);
	uint16_t measurement_pfm_id = PCR_MEASUREMENT (0, 3);
	uint16_t measurement_plat_id = PCR_MEASUREMENT (0, 4);
	struct firmware_pfm_verify_testing fw_verify;
	const char *expected = PFM_V2.manifest.plat_id_str;
	char buffer[64];
	size_t length = sizeof (buffer);
	uint32_t total_len;
	int status;

	TEST_START;

	firmware_pfm_verify_testing_init (test, &fw_verify, 0, measurement_result, measurement_version,
		measurement_pfm, measurement_pfm_id, measurement_plat_id);

	firmware_pfm_verify_testing_run_successful_verification (test, &fw_verify);

	strcpy (buffer, "unexpected");

	status = mock_expect (&fw_verify.pfm.mock, fw_verify.pfm.base.base.get_platform_id,
		&fw_verify.pfm, 0, MOCK_ARG_PTR_PTR (NULL), MOCK_ARG_ANY);
	status |= mock_expect_output (&fw_verify.pfm.mock, 0, &expected, sizeof (expected), -1);

	status |= mock_expect (&fw_verify.pfm.mock, fw_verify.pfm.base.base.free_platform_id,
		&fw_verify.pfm, 0, MOCK_ARG_PTR (expected));

	CuAssertIntEquals (test, 0, status);

	status = firmware_pfm_verify_get_pfm_platform_id_measured_data (&fw_verify.test, 0,
		(uint8_t*) buffer, length, &total_len);
	CuAssertIntEquals (test, PFM_V2.manifest.plat_id_str_len + 1, status);
	CuAssertIntEquals (test, PFM_V2.manifest.plat_id_str_len + 1, total_len);
	CuAssertStrEquals (test, expected, buffer);

	firmware_pfm_verify_testing_release (test, &fw_verify);
}

static void firmware_pfm_verify_test_get_pfm_platform_id_measured_data_static_init (CuTest *test)
{
	uint16_t measurement_result = PCR_MEASUREMENT (0, 0);
	uint16_t measurement_version = PCR_MEASUREMENT (0, 1);
	uint16_t measurement_pfm = PCR_MEASUREMENT (0, 2);
	uint16_t measurement_pfm_id = PCR_MEASUREMENT (0, 3);
	uint16_t measurement_plat_id = PCR_MEASUREMENT (0, 4);
	struct firmware_pfm_verify_testing fw_verify = {
		.test = firmware_pfm_verify_static_init (&fw_verify.state, &fw_verify.flash.base,
			&fw_verify.pfm.base, &fw_verify.hash.base, &fw_verify.sig_verify.base, &fw_verify.pcr,
			fw_verify.version, sizeof (fw_verify.version), measurement_result, measurement_version,
			measurement_pfm, measurement_pfm_id, measurement_plat_id)
	};
	const char *expected = PFM_V2.manifest.plat_id_str;
	char buffer[64];
	size_t length = sizeof (buffer);
	uint32_t total_len;
	int status;

	TEST_START;

	firmware_pfm_verify_testing_init_static (test, &fw_verify, measurement_result,
		measurement_version, measurement_pfm, measurement_pfm_id, measurement_plat_id);

	firmware_pfm_verify_testing_run_successful_verification (test, &fw_verify);

	strcpy (buffer, "unexpected");

	status = mock_expect (&fw_verify.pfm.mock, fw_verify.pfm.base.base.get_platform_id,
		&fw_verify.pfm, 0, MOCK_ARG_PTR_PTR (NULL), MOCK_ARG_ANY);
	status |= mock_expect_output (&fw_verify.pfm.mock, 0, &expected, sizeof (expected), -1);

	status |= mock_expect (&fw_verify.pfm.mock, fw_verify.pfm.base.base.free_platform_id,
		&fw_verify.pfm, 0, MOCK_ARG_PTR (expected));

	CuAssertIntEquals (test, 0, status);

	status = firmware_pfm_verify_get_pfm_platform_id_measured_data (&fw_verify.test, 0,
		(uint8_t*) buffer, length, &total_len);
	CuAssertIntEquals (test, PFM_V2.manifest.plat_id_str_len + 1, status);
	CuAssertIntEquals (test, PFM_V2.manifest.plat_id_str_len + 1, total_len);
	CuAssertStrEquals (test, expected, buffer);

	firmware_pfm_verify_testing_release (test, &fw_verify);
}

static void firmware_pfm_verify_test_get_pfm_platform_id_measured_data_null (CuTest *test)
{
	uint16_t measurement_result = PCR_MEASUREMENT (0, 0);
	uint16_t measurement_version = PCR_MEASUREMENT (0, 1);
	uint16_t measurement_pfm = PCR_MEASUREMENT (0, 2);
	uint16_t measurement_pfm_id = PCR_MEASUREMENT (0, 3);
	uint16_t measurement_plat_id = PCR_MEASUREMENT (0, 4);
	struct firmware_pfm_verify_testing fw_verify;
	char buffer[64];
	size_t length = sizeof (buffer);
	uint32_t total_len;
	int status;

	TEST_START;

	firmware_pfm_verify_testing_init (test, &fw_verify, 0, measurement_result, measurement_version,
		measurement_pfm, measurement_pfm_id, measurement_plat_id);

	strcpy (buffer, "unexpected");

	status = firmware_pfm_verify_get_pfm_platform_id_measured_data (NULL, 0, (uint8_t*) buffer,
		length, &total_len);
	CuAssertIntEquals (test, FIRMWARE_PFM_VERIFY_INVALID_ARGUMENT, status);

	status = firmware_pfm_verify_get_pfm_platform_id_measured_data (&fw_verify.test, 0, NULL,
		length, &total_len);
	CuAssertIntEquals (test, MANIFEST_MANAGER_INVALID_ARGUMENT, status);

	status = firmware_pfm_verify_get_pfm_platform_id_measured_data (&fw_verify.test, 0,
		(uint8_t*) buffer, length, NULL);
	CuAssertIntEquals (test, MANIFEST_MANAGER_INVALID_ARGUMENT, status);

	firmware_pfm_verify_testing_release (test, &fw_verify);
}

static void firmware_pfm_verify_test_hash_pfm_platform_id_measured_data_no_verification (
	CuTest *test)
{
	uint16_t measurement_result = PCR_MEASUREMENT (0, 0);
	uint16_t measurement_version = PCR_MEASUREMENT (0, 1);
	uint16_t measurement_pfm = PCR_MEASUREMENT (0, 2);
	uint16_t measurement_pfm_id = PCR_MEASUREMENT (0, 3);
	uint16_t measurement_plat_id = PCR_MEASUREMENT (0, 4);
	struct firmware_pfm_verify_testing fw_verify;
	const char *expected = "\0";
	int status;

	TEST_START;

	firmware_pfm_verify_testing_init (test, &fw_verify, 0, measurement_result, measurement_version,
		measurement_pfm, measurement_pfm_id, measurement_plat_id);

	status = mock_expect (&fw_verify.hash_mock.mock, fw_verify.hash_mock.base.update,
		&fw_verify.hash_mock, 0, MOCK_ARG_PTR_CONTAINS (expected, strlen (expected) + 1),
		MOCK_ARG (strlen (expected) + 1));

	CuAssertIntEquals (test, 0, status);

	status = firmware_pfm_verify_hash_pfm_platform_id_measured_data (&fw_verify.test,
		&fw_verify.hash_mock.base);
	CuAssertIntEquals (test, 0, status);

	firmware_pfm_verify_testing_release (test, &fw_verify);
}

static void firmware_pfm_verify_test_hash_pfm_platform_id_measured_data_after_verification (
	CuTest *test)
{
	uint16_t measurement_result = PCR_MEASUREMENT (0, 0);
	uint16_t measurement_version = PCR_MEASUREMENT (0, 1);
	uint16_t measurement_pfm = PCR_MEASUREMENT (0, 2);
	uint16_t measurement_pfm_id = PCR_MEASUREMENT (0, 3);
	uint16_t measurement_plat_id = PCR_MEASUREMENT (0, 4);
	struct firmware_pfm_verify_testing fw_verify;
	const char *expected = PFM_V2.manifest.plat_id_str;
	int status;

	TEST_START;

	firmware_pfm_verify_testing_init (test, &fw_verify, 0, measurement_result, measurement_version,
		measurement_pfm, measurement_pfm_id, measurement_plat_id);

	firmware_pfm_verify_testing_run_successful_verification (test, &fw_verify);

	status = mock_expect (&fw_verify.pfm.mock, fw_verify.pfm.base.base.get_platform_id,
		&fw_verify.pfm, 0, MOCK_ARG_PTR_PTR (NULL), MOCK_ARG_ANY);
	status |= mock_expect_output (&fw_verify.pfm.mock, 0, &expected, sizeof (expected), -1);

	status |= mock_expect (&fw_verify.hash_mock.mock, fw_verify.hash_mock.base.update,
		&fw_verify.hash_mock, 0, MOCK_ARG_PTR_CONTAINS (expected, strlen (expected) + 1),
		MOCK_ARG (strlen (expected) + 1));

	status |= mock_expect (&fw_verify.pfm.mock, fw_verify.pfm.base.base.free_platform_id,
		&fw_verify.pfm, 0, MOCK_ARG_PTR (expected));

	CuAssertIntEquals (test, 0, status);

	status = firmware_pfm_verify_hash_pfm_platform_id_measured_data (&fw_verify.test,
		&fw_verify.hash_mock.base);
	CuAssertIntEquals (test, 0, status);

	firmware_pfm_verify_testing_release (test, &fw_verify);
}

static void firmware_pfm_verify_test_hash_pfm_platform_id_measured_data_static_init (CuTest *test)
{
	uint16_t measurement_result = PCR_MEASUREMENT (0, 0);
	uint16_t measurement_version = PCR_MEASUREMENT (0, 1);
	uint16_t measurement_pfm = PCR_MEASUREMENT (0, 2);
	uint16_t measurement_pfm_id = PCR_MEASUREMENT (0, 3);
	uint16_t measurement_plat_id = PCR_MEASUREMENT (0, 4);
	struct firmware_pfm_verify_testing fw_verify = {
		.test = firmware_pfm_verify_static_init (&fw_verify.state, &fw_verify.flash.base,
			&fw_verify.pfm.base, &fw_verify.hash.base, &fw_verify.sig_verify.base, &fw_verify.pcr,
			fw_verify.version, sizeof (fw_verify.version), measurement_result, measurement_version,
			measurement_pfm, measurement_pfm_id, measurement_plat_id)
	};
	const char *expected = PFM_V2.manifest.plat_id_str;
	int status;

	TEST_START;

	firmware_pfm_verify_testing_init_static (test, &fw_verify, measurement_result,
		measurement_version, measurement_pfm, measurement_pfm_id, measurement_plat_id);

	firmware_pfm_verify_testing_run_successful_verification (test, &fw_verify);

	status = mock_expect (&fw_verify.pfm.mock, fw_verify.pfm.base.base.get_platform_id,
		&fw_verify.pfm, 0, MOCK_ARG_PTR_PTR (NULL), MOCK_ARG_ANY);
	status |= mock_expect_output (&fw_verify.pfm.mock, 0, &expected, sizeof (expected), -1);

	status |= mock_expect (&fw_verify.hash_mock.mock, fw_verify.hash_mock.base.update,
		&fw_verify.hash_mock, 0, MOCK_ARG_PTR_CONTAINS (expected, strlen (expected) + 1),
		MOCK_ARG (strlen (expected) + 1));

	status |= mock_expect (&fw_verify.pfm.mock, fw_verify.pfm.base.base.free_platform_id,
		&fw_verify.pfm, 0, MOCK_ARG_PTR (expected));

	CuAssertIntEquals (test, 0, status);

	status = firmware_pfm_verify_hash_pfm_platform_id_measured_data (&fw_verify.test,
		&fw_verify.hash_mock.base);
	CuAssertIntEquals (test, 0, status);

	firmware_pfm_verify_testing_release (test, &fw_verify);
}

static void firmware_pfm_verify_test_hash_pfm_platform_id_measured_data_null (CuTest *test)
{
	uint16_t measurement_result = PCR_MEASUREMENT (0, 0);
	uint16_t measurement_version = PCR_MEASUREMENT (0, 1);
	uint16_t measurement_pfm = PCR_MEASUREMENT (0, 2);
	uint16_t measurement_pfm_id = PCR_MEASUREMENT (0, 3);
	uint16_t measurement_plat_id = PCR_MEASUREMENT (0, 4);
	struct firmware_pfm_verify_testing fw_verify;
	int status;

	TEST_START;

	firmware_pfm_verify_testing_init (test, &fw_verify, 0, measurement_result, measurement_version,
		measurement_pfm, measurement_pfm_id, measurement_plat_id);

	status = firmware_pfm_verify_hash_pfm_platform_id_measured_data (NULL,
		&fw_verify.hash_mock.base);
	CuAssertIntEquals (test, FIRMWARE_PFM_VERIFY_INVALID_ARGUMENT, status);

	status = firmware_pfm_verify_hash_pfm_platform_id_measured_data (&fw_verify.test, NULL);
	CuAssertIntEquals (test, MANIFEST_MANAGER_INVALID_ARGUMENT, status);

	firmware_pfm_verify_testing_release (test, &fw_verify);
}

static void firmware_pfm_verify_test_hash_pfm_platform_id_measured_data_no_verification_hash_error (
	CuTest *test)
{
	uint16_t measurement_result = PCR_MEASUREMENT (0, 0);
	uint16_t measurement_version = PCR_MEASUREMENT (0, 1);
	uint16_t measurement_pfm = PCR_MEASUREMENT (0, 2);
	uint16_t measurement_pfm_id = PCR_MEASUREMENT (0, 3);
	uint16_t measurement_plat_id = PCR_MEASUREMENT (0, 4);
	struct firmware_pfm_verify_testing fw_verify;
	const char *expected = "\0";
	int status;

	TEST_START;

	firmware_pfm_verify_testing_init (test, &fw_verify, 0, measurement_result, measurement_version,
		measurement_pfm, measurement_pfm_id, measurement_plat_id);

	status = mock_expect (&fw_verify.hash_mock.mock, fw_verify.hash_mock.base.update,
		&fw_verify.hash_mock, HASH_ENGINE_UPDATE_FAILED,
		MOCK_ARG_PTR_CONTAINS (expected, strlen (expected) + 1), MOCK_ARG (strlen (expected) + 1));

	CuAssertIntEquals (test, 0, status);

	status = firmware_pfm_verify_hash_pfm_platform_id_measured_data (&fw_verify.test,
		&fw_verify.hash_mock.base);
	CuAssertIntEquals (test, HASH_ENGINE_UPDATE_FAILED, status);

	firmware_pfm_verify_testing_release (test, &fw_verify);
}

static void
firmware_pfm_verify_test_hash_pfm_platform_id_measured_data_after_verification_hash_error (
	CuTest *test)
{
	uint16_t measurement_result = PCR_MEASUREMENT (0, 0);
	uint16_t measurement_version = PCR_MEASUREMENT (0, 1);
	uint16_t measurement_pfm = PCR_MEASUREMENT (0, 2);
	uint16_t measurement_pfm_id = PCR_MEASUREMENT (0, 3);
	uint16_t measurement_plat_id = PCR_MEASUREMENT (0, 4);
	struct firmware_pfm_verify_testing fw_verify;
	const char *expected = PFM_V2.manifest.plat_id_str;
	int status;

	TEST_START;

	firmware_pfm_verify_testing_init (test, &fw_verify, 0, measurement_result, measurement_version,
		measurement_pfm, measurement_pfm_id, measurement_plat_id);

	firmware_pfm_verify_testing_run_successful_verification (test, &fw_verify);

	status = mock_expect (&fw_verify.pfm.mock, fw_verify.pfm.base.base.get_platform_id,
		&fw_verify.pfm, 0, MOCK_ARG_PTR_PTR (NULL), MOCK_ARG_ANY);
	status |= mock_expect_output (&fw_verify.pfm.mock, 0, &expected, sizeof (expected), -1);

	status |= mock_expect (&fw_verify.hash_mock.mock, fw_verify.hash_mock.base.update,
		&fw_verify.hash_mock, HASH_ENGINE_UPDATE_FAILED,
		MOCK_ARG_PTR_CONTAINS (expected, strlen (expected) + 1), MOCK_ARG (strlen (expected) + 1));

	status |= mock_expect (&fw_verify.pfm.mock, fw_verify.pfm.base.base.free_platform_id,
		&fw_verify.pfm, 0, MOCK_ARG_PTR (expected));

	CuAssertIntEquals (test, 0, status);

	status = firmware_pfm_verify_hash_pfm_platform_id_measured_data (&fw_verify.test,
		&fw_verify.hash_mock.base);
	CuAssertIntEquals (test, HASH_ENGINE_UPDATE_FAILED, status);

	firmware_pfm_verify_testing_release (test, &fw_verify);
}

static void firmware_pfm_verify_test_result_measured_data (CuTest *test)
{
	uint16_t measurement_result = PCR_MEASUREMENT (0, 0);
	uint16_t measurement_version = PCR_MEASUREMENT (0, 1);
	uint16_t measurement_pfm = PCR_MEASUREMENT (0, 2);
	uint16_t measurement_pfm_id = PCR_MEASUREMENT (0, 3);
	uint16_t measurement_plat_id = PCR_MEASUREMENT (0, 4);
	struct firmware_pfm_verify_testing fw_verify;
	struct pcr_measured_data result_data =
		firmware_pfm_verify_result_measured_data_init (&fw_verify.state);

	TEST_START;

	CuAssertIntEquals (test, PCR_DATA_TYPE_MEMORY, result_data.type);
	CuAssertIntEquals (test, sizeof (int32_t), result_data.data.memory.length);
	CuAssertPtrNotNull (test, result_data.data.memory.buffer);

	firmware_pfm_verify_testing_init (test, &fw_verify, 0, measurement_result, measurement_version,
		measurement_pfm, measurement_pfm_id, measurement_plat_id);

	CuAssertIntEquals (test, FIRMWARE_PFM_VERIFY_NOT_VERIFIED,
		*((int32_t*) result_data.data.memory.buffer));

	firmware_pfm_verify_testing_run_successful_verification (test, &fw_verify);

	CuAssertIntEquals (test, 0, *((int32_t*) result_data.data.memory.buffer));

	firmware_pfm_verify_testing_release (test, &fw_verify);
}

static void firmware_pfm_verify_test_version_measured_data (CuTest *test)
{
	struct firmware_pfm_verify_testing fw_verify;
	struct pcr_measured_data version_data =
		firmware_pfm_verify_fw_version_measured_data_init (&fw_verify.test);

	TEST_START;

	CuAssertIntEquals (test, PCR_DATA_TYPE_CALLBACK, version_data.type);
	CuAssertPtrEquals (test, firmware_pfm_verify_get_fw_version_measured_data,
		version_data.data.callback.get_data);
	CuAssertPtrEquals (test, firmware_pfm_verify_hash_fw_version_measured_data,
		version_data.data.callback.hash_data);
	CuAssertPtrEquals (test, &fw_verify.test, version_data.data.callback.context);
}

static void firmware_pfm_verify_test_version_measured_data_no_hash (CuTest *test)
{
	struct firmware_pfm_verify_testing fw_verify;
	struct pcr_measured_data version_data =
		firmware_pfm_verify_fw_version_measured_data_init_no_hash (&fw_verify.test);

	TEST_START;

	CuAssertIntEquals (test, PCR_DATA_TYPE_CALLBACK, version_data.type);
	CuAssertPtrEquals (test, firmware_pfm_verify_get_fw_version_measured_data,
		version_data.data.callback.get_data);
	CuAssertPtrEquals (test, NULL, version_data.data.callback.hash_data);
	CuAssertPtrEquals (test, &fw_verify.test, version_data.data.callback.context);
}

static void firmware_pfm_verify_test_pfm_digest_measured_data (CuTest *test)
{
	struct firmware_pfm_verify_testing fw_verify;
	struct pcr_measured_data pfm_data =
		firmware_pfm_verify_pfm_digest_measured_data_init (&fw_verify.test);

	TEST_START;

	CuAssertIntEquals (test, PCR_DATA_TYPE_CALLBACK, pfm_data.type);
	CuAssertPtrEquals (test, firmware_pfm_verify_get_pfm_digest_measured_data,
		pfm_data.data.callback.get_data);
	CuAssertPtrEquals (test, firmware_pfm_verify_hash_pfm_digest_measured_data,
		pfm_data.data.callback.hash_data);
	CuAssertPtrEquals (test, &fw_verify.test, pfm_data.data.callback.context);
}

static void firmware_pfm_verify_test_pfm_digest_measured_data_no_hash (CuTest *test)
{
	struct firmware_pfm_verify_testing fw_verify;
	struct pcr_measured_data pfm_data =
		firmware_pfm_verify_pfm_digest_measured_data_init_no_hash (&fw_verify.test);

	TEST_START;

	CuAssertIntEquals (test, PCR_DATA_TYPE_CALLBACK, pfm_data.type);
	CuAssertPtrEquals (test, firmware_pfm_verify_get_pfm_digest_measured_data,
		pfm_data.data.callback.get_data);
	CuAssertPtrEquals (test, NULL, pfm_data.data.callback.hash_data);
	CuAssertPtrEquals (test, &fw_verify.test, pfm_data.data.callback.context);
}

static void firmware_pfm_verify_test_pfm_id_measured_data (CuTest *test)
{
	struct firmware_pfm_verify_testing fw_verify;
	struct pcr_measured_data pfm_id_data =
		firmware_pfm_verify_pfm_id_measured_data_init (&fw_verify.test);

	TEST_START;

	CuAssertIntEquals (test, PCR_DATA_TYPE_CALLBACK, pfm_id_data.type);
	CuAssertPtrEquals (test, firmware_pfm_verify_get_pfm_id_measured_data,
		pfm_id_data.data.callback.get_data);
	CuAssertPtrEquals (test, firmware_pfm_verify_hash_pfm_id_measured_data,
		pfm_id_data.data.callback.hash_data);
	CuAssertPtrEquals (test, &fw_verify.test, pfm_id_data.data.callback.context);
}

static void firmware_pfm_verify_test_pfm_id_measured_data_no_hash (CuTest *test)
{
	struct firmware_pfm_verify_testing fw_verify;
	struct pcr_measured_data pfm_id_data =
		firmware_pfm_verify_pfm_id_measured_data_init_no_hash (&fw_verify.test);

	TEST_START;

	CuAssertIntEquals (test, PCR_DATA_TYPE_CALLBACK, pfm_id_data.type);
	CuAssertPtrEquals (test, firmware_pfm_verify_get_pfm_id_measured_data,
		pfm_id_data.data.callback.get_data);
	CuAssertPtrEquals (test, NULL, pfm_id_data.data.callback.hash_data);
	CuAssertPtrEquals (test, &fw_verify.test, pfm_id_data.data.callback.context);
}

static void firmware_pfm_verify_test_pfm_platform_id_measured_data (CuTest *test)
{
	struct firmware_pfm_verify_testing fw_verify;
	struct pcr_measured_data platform_id_data =
		firmware_pfm_verify_pfm_platform_id_measured_data_init (&fw_verify.test);

	TEST_START;

	CuAssertIntEquals (test, PCR_DATA_TYPE_CALLBACK, platform_id_data.type);
	CuAssertPtrEquals (test, firmware_pfm_verify_get_pfm_platform_id_measured_data,
		platform_id_data.data.callback.get_data);
	CuAssertPtrEquals (test, firmware_pfm_verify_hash_pfm_platform_id_measured_data,
		platform_id_data.data.callback.hash_data);
	CuAssertPtrEquals (test, &fw_verify.test, platform_id_data.data.callback.context);
}

static void firmware_pfm_verify_test_pfm_platform_id_measured_data_no_hash (CuTest *test)
{
	struct firmware_pfm_verify_testing fw_verify;
	struct pcr_measured_data platform_id_data =
		firmware_pfm_verify_pfm_platform_id_measured_data_init_no_hash (&fw_verify.test);

	TEST_START;

	CuAssertIntEquals (test, PCR_DATA_TYPE_CALLBACK, platform_id_data.type);
	CuAssertPtrEquals (test, firmware_pfm_verify_get_pfm_platform_id_measured_data,
		platform_id_data.data.callback.get_data);
	CuAssertPtrEquals (test, NULL, platform_id_data.data.callback.hash_data);
	CuAssertPtrEquals (test, &fw_verify.test, platform_id_data.data.callback.context);
}


// *INDENT-OFF*
TEST_SUITE_START (firmware_pfm_verify);

TEST (firmware_pfm_verify_test_init);
TEST (firmware_pfm_verify_test_init_null);
TEST (firmware_pfm_verify_test_init_measurement_result_error);
TEST (firmware_pfm_verify_test_init_measurement_version_error);
TEST (firmware_pfm_verify_test_init_measurement_pfm_error);
TEST (firmware_pfm_verify_test_init_measurement_pfm_id_error);
TEST (firmware_pfm_verify_test_init_measurement_platform_id_error);
TEST (firmware_pfm_verify_test_static_init);
TEST (firmware_pfm_verify_test_static_init_null);
TEST (firmware_pfm_verify_test_static_init_measurement_result_error);
TEST (firmware_pfm_verify_test_static_init_measurement_version_error);
TEST (firmware_pfm_verify_test_static_init_measurement_pfm_error);
TEST (firmware_pfm_verify_test_static_init_measurement_pfm_id_error);
TEST (firmware_pfm_verify_test_static_init_measurement_platform_id_error);
TEST (firmware_pfm_verify_test_release_null);
TEST (firmware_pfm_verify_test_run_verification);
TEST (firmware_pfm_verify_test_run_verification_supported_pfm_id);
TEST (firmware_pfm_verify_test_run_verification_small_version_buffer);
TEST (firmware_pfm_verify_test_run_verification_measurement_result_error);
TEST (firmware_pfm_verify_test_run_verification_measurement_version_error);
TEST (firmware_pfm_verify_test_run_verification_measurement_pfm_error);
TEST (firmware_pfm_verify_test_run_verification_measurement_pfm_id_error);
TEST (firmware_pfm_verify_test_run_verification_measurement_platform_id_error);
TEST (firmware_pfm_verify_test_run_verification_static_init);
TEST (firmware_pfm_verify_test_run_verification_static_init_small_version_buffer);
TEST (firmware_pfm_verify_test_run_verification_null);
TEST (firmware_pfm_verify_test_run_verification_empty_pfm);
TEST (firmware_pfm_verify_test_run_verification_multiple_fw_components);
TEST (firmware_pfm_verify_test_run_verification_no_fw_versions);
TEST (firmware_pfm_verify_test_run_verification_multiple_fw_versions);
TEST (firmware_pfm_verify_test_run_verification_no_image);
TEST (firmware_pfm_verify_test_run_verification_pfm_verify_error);
TEST (firmware_pfm_verify_test_run_verification_pfm_empty_error);
TEST (firmware_pfm_verify_test_run_verification_get_firmware_error);
TEST (firmware_pfm_verify_test_run_verification_get_versions_error);
TEST (firmware_pfm_verify_test_run_verification_get_images_error);
TEST (firmware_pfm_verify_test_run_verification_flash_verify_error);
TEST (firmware_pfm_verify_test_run_verification_get_id_failed);
TEST (firmware_pfm_verify_test_run_verification_unsupported_pfm_id);
TEST (firmware_pfm_verify_test_get_fw_version_measured_data_no_verification);
TEST (firmware_pfm_verify_test_get_fw_version_measured_data_after_verification);
TEST (firmware_pfm_verify_test_get_fw_version_measured_data_offset);
TEST (firmware_pfm_verify_test_get_fw_version_measured_data_offset_more_than_length);
TEST (firmware_pfm_verify_test_get_fw_version_measured_data_static_init);
TEST (firmware_pfm_verify_test_get_fw_version_measured_data_null);
TEST (firmware_pfm_verify_test_hash_fw_version_measured_data_no_verification);
TEST (firmware_pfm_verify_test_hash_fw_version_measured_data_after_verification);
TEST (firmware_pfm_verify_test_hash_fw_version_measured_data_static_init);
TEST (firmware_pfm_verify_test_hash_fw_version_measured_data_null);
TEST (firmware_pfm_verify_test_hash_fw_version_measured_data_hash_error);
TEST (firmware_pfm_verify_test_get_pfm_digest_measured_data_no_verification);
TEST (firmware_pfm_verify_test_get_pfm_digest_measured_data_after_verification);
TEST (firmware_pfm_verify_test_get_pfm_digest_measured_data_static_init);
TEST (firmware_pfm_verify_test_get_pfm_digest_measured_data_null);
TEST (firmware_pfm_verify_test_hash_pfm_digest_measured_data_no_verification);
TEST (firmware_pfm_verify_test_hash_pfm_digest_measured_data_after_verification);
TEST (firmware_pfm_verify_test_hash_pfm_digest_measured_data_static_init);
TEST (firmware_pfm_verify_test_hash_pfm_digest_measured_data_null);
TEST (firmware_pfm_verify_test_hash_pfm_digest_measured_data_no_verification_hash_error);
TEST (firmware_pfm_verify_test_hash_pfm_digest_measured_data_after_verification_hash_error);
TEST (firmware_pfm_verify_test_get_pfm_id_measured_data_no_verification);
TEST (firmware_pfm_verify_test_get_pfm_id_measured_data_after_verification);
TEST (firmware_pfm_verify_test_get_pfm_id_measured_data_static_init);
TEST (firmware_pfm_verify_test_get_pfm_id_measured_data_null);
TEST (firmware_pfm_verify_test_hash_pfm_id_measured_data_no_verification);
TEST (firmware_pfm_verify_test_hash_pfm_id_measured_data_after_verification);
TEST (firmware_pfm_verify_test_hash_pfm_id_measured_data_static_init);
TEST (firmware_pfm_verify_test_hash_pfm_id_measured_data_null);
TEST (firmware_pfm_verify_test_hash_pfm_id_measured_data_no_verification_hash_error);
TEST (firmware_pfm_verify_test_hash_pfm_id_measured_data_after_verification_hash_error);
TEST (firmware_pfm_verify_test_get_pfm_platform_id_measured_data_no_verification);
TEST (firmware_pfm_verify_test_get_pfm_platform_id_measured_data_after_verification);
TEST (firmware_pfm_verify_test_get_pfm_platform_id_measured_data_static_init);
TEST (firmware_pfm_verify_test_get_pfm_platform_id_measured_data_null);
TEST (firmware_pfm_verify_test_hash_pfm_platform_id_measured_data_no_verification);
TEST (firmware_pfm_verify_test_hash_pfm_platform_id_measured_data_after_verification);
TEST (firmware_pfm_verify_test_hash_pfm_platform_id_measured_data_static_init);
TEST (firmware_pfm_verify_test_hash_pfm_platform_id_measured_data_null);
TEST (firmware_pfm_verify_test_hash_pfm_platform_id_measured_data_no_verification_hash_error);
TEST (firmware_pfm_verify_test_hash_pfm_platform_id_measured_data_after_verification_hash_error);
TEST (firmware_pfm_verify_test_result_measured_data);
TEST (firmware_pfm_verify_test_version_measured_data);
TEST (firmware_pfm_verify_test_version_measured_data_no_hash);
TEST (firmware_pfm_verify_test_pfm_digest_measured_data);
TEST (firmware_pfm_verify_test_pfm_digest_measured_data_no_hash);
TEST (firmware_pfm_verify_test_pfm_id_measured_data);
TEST (firmware_pfm_verify_test_pfm_id_measured_data_no_hash);
TEST (firmware_pfm_verify_test_pfm_platform_id_measured_data);
TEST (firmware_pfm_verify_test_pfm_platform_id_measured_data_no_hash);

TEST_SUITE_END;
// *INDENT-ON*
