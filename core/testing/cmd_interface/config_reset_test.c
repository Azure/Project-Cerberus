// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include "testing.h"
#include "cmd_interface/config_reset.h"
#include "testing/mock/intrusion/intrusion_manager_mock.h"
#include "testing/mock/keystore/keystore_mock.h"
#include "testing/mock/manifest/manifest_manager_mock.h"
#include "testing/mock/recovery/recovery_image_manager_mock.h"
#include "testing/mock/state_manager/state_manager_mock.h"
#include "testing/engines/x509_testing_engine.h"
#include "testing/engines/rsa_testing_engine.h"
#include "testing/engines/ecc_testing_engine.h"
#include "testing/riot/riot_core_testing.h"


TEST_SUITE_LABEL ("config_reset");


/**
 * Components necessary for testing reset management of attestation keys.
 */
struct config_reset_testing_keys {
	X509_TESTING_ENGINE x509;				/**< X.509 engine for RIoT certificates. */
	RSA_TESTING_ENGINE rsa;					/**< RSA engine for auxiliary attestation. */
	ECC_TESTING_ENGINE ecc;					/**< ECC engine for auxiliary attestation. */
	struct keystore_mock riot_keystore;		/**< Keystore for RIoT keys. */
	struct riot_key_manager riot;			/**< RIoT keys. */
	struct keystore_mock aux_keystore;		/**< Keystore for attestation keys. */
	struct aux_attestation aux;				/**< Attestation manager. */
};


/**
 * Initialize the RIoT and attestation key managers.
 *
 * @param test The testing framework.
 * @param keys Key management components.
 */
static void config_reset_testing_init_attestation_keys (CuTest *test,
	struct config_reset_testing_keys *keys)
{
	struct riot_keys riot_core;
	int status;
	uint8_t *dev_id_der = NULL;

	riot_core.devid_csr = RIOT_CORE_DEVID_CSR;
	riot_core.devid_csr_length = RIOT_CORE_DEVID_CSR_LEN;

	riot_core.devid_cert = RIOT_CORE_DEVID_CERT;
	riot_core.devid_cert_length = RIOT_CORE_DEVID_CERT_LEN;

	riot_core.alias_key = RIOT_CORE_ALIAS_KEY;
	riot_core.alias_key_length = RIOT_CORE_ALIAS_KEY_LEN;

	riot_core.alias_cert = RIOT_CORE_ALIAS_CERT;
	riot_core.alias_cert_length = RIOT_CORE_ALIAS_CERT_LEN;

	status = X509_TESTING_ENGINE_INIT (&keys->x509);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&keys->rsa);
	CuAssertIntEquals (test, 0, status);

	status = ECC_TESTING_ENGINE_INIT (&keys->ecc);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_init (&keys->riot_keystore);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_init (&keys->aux_keystore);
		CuAssertIntEquals (test, 0, status);

	status = mock_expect (&keys->riot_keystore.mock, keys->riot_keystore.base.load_key,
		&keys->riot_keystore, KEYSTORE_NO_KEY, MOCK_ARG (0), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output_tmp (&keys->riot_keystore.mock, 1, &dev_id_der,
		sizeof (dev_id_der), -1);

	CuAssertIntEquals (test, 0, status);

	status = riot_key_manager_init_static (&keys->riot, &keys->riot_keystore.base, &riot_core,
		&keys->x509.base);
	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_init (&keys->aux, &keys->aux_keystore.base, &keys->rsa.base,
		&keys->riot, &keys->ecc.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&keys->riot_keystore.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&keys->aux_keystore.mock);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Release the RIoT and attestation key managers.  Mocks will be validated.
 *
 * @param test The testing framework.
 * @param keys Key management components.
 */
static void config_reset_testing_release_attestation_keys (CuTest *test,
	struct config_reset_testing_keys *keys)
{
	int status;

	status = keystore_mock_validate_and_release (&keys->riot_keystore);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_validate_and_release (&keys->aux_keystore);
	CuAssertIntEquals (test, 0, status);

	riot_key_manager_release (&keys->riot);
	aux_attestation_release (&keys->aux);

	X509_TESTING_ENGINE_RELEASE (&keys->x509);
	RSA_TESTING_ENGINE_RELEASE (&keys->rsa);
	ECC_TESTING_ENGINE_RELEASE (&keys->ecc);
}


/*******************
 * Test cases
 *******************/

static void config_reset_test_init (CuTest *test)
{
	struct manifest_manager_mock manifest;
	struct state_manager_mock state;
	struct config_reset_testing_keys keys;
	struct config_reset reset;
	int status;
	struct manifest_manager *config[1];
	struct state_manager *state_list[1];
	struct recovery_image_manager_mock recovery;
	struct keystore_mock keystore1;
	struct keystore_mock keystore2;
	struct keystore* keystore_array[] = {&keystore1.base, &keystore2.base};
	struct intrusion_manager_mock intrusion;

	TEST_START;

	status = manifest_manager_mock_init (&manifest);
	CuAssertIntEquals (test, 0, status);
	config[0] = &manifest.base;

	status = state_manager_mock_init (&state);
	state_list[0] = &state.base;

	config_reset_testing_init_attestation_keys (test, &keys);

	status = recovery_image_manager_mock_init (&recovery);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_init (&keystore1);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_init (&keystore2);
	CuAssertIntEquals (test, 0, status);

	status = intrusion_manager_mock_init (&intrusion);
	CuAssertIntEquals (test, 0, status);

	status = config_reset_init (&reset, config, 1, config, 1, state_list, 1, &keys.riot,
		&keys.aux, &recovery.base, keystore_array, 2, &intrusion.base);
	CuAssertIntEquals (test, 0, status);

	status = manifest_manager_mock_validate_and_release (&manifest);
	CuAssertIntEquals (test, 0, status);

	status = state_manager_mock_validate_and_release (&state);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_manager_mock_validate_and_release (&recovery);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_validate_and_release (&keystore1);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_validate_and_release (&keystore2);
	CuAssertIntEquals (test, 0, status);

	status = intrusion_manager_mock_validate_and_release (&intrusion);
	CuAssertIntEquals (test, 0, status);

	config_reset_testing_release_attestation_keys (test, &keys);

	config_reset_release (&reset);
}

static void config_reset_test_init_no_state (CuTest *test)
{
	struct manifest_manager_mock manifest;
	struct config_reset_testing_keys keys;
	struct config_reset reset;
	int status;
	struct manifest_manager *config[1];
	struct recovery_image_manager_mock recovery;
	struct keystore_mock keystore1;
	struct keystore_mock keystore2;
	struct keystore* keystore_array[] = {&keystore1.base, &keystore2.base};
	struct intrusion_manager_mock intrusion;

	TEST_START;

	status = manifest_manager_mock_init (&manifest);
	CuAssertIntEquals (test, 0, status);
	config[0] = &manifest.base;

	status = recovery_image_manager_mock_init (&recovery);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_init (&keystore1);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_init (&keystore2);
	CuAssertIntEquals (test, 0, status);

	status = intrusion_manager_mock_init (&intrusion);
	CuAssertIntEquals (test, 0, status);

	config_reset_testing_init_attestation_keys (test, &keys);

	status = config_reset_init (&reset, config, 1, config, 1, NULL, 0, &keys.riot, &keys.aux,
		&recovery.base, keystore_array, 2, &intrusion.base);
	CuAssertIntEquals (test, 0, status);

	status = manifest_manager_mock_validate_and_release (&manifest);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_manager_mock_validate_and_release (&recovery);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_validate_and_release (&keystore1);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_validate_and_release (&keystore2);
	CuAssertIntEquals (test, 0, status);

	status = intrusion_manager_mock_validate_and_release (&intrusion);
	CuAssertIntEquals (test, 0, status);

	config_reset_testing_release_attestation_keys (test, &keys);

	config_reset_release (&reset);
}

static void config_reset_test_init_no_manifests (CuTest *test)
{
	struct config_reset_testing_keys keys;
	struct config_reset reset;
	struct recovery_image_manager_mock recovery;
	struct keystore_mock keystore1;
	struct keystore_mock keystore2;
	struct keystore* keystore_array[] = {&keystore1.base, &keystore2.base};
	struct intrusion_manager_mock intrusion;
	int status;

	TEST_START;

	config_reset_testing_init_attestation_keys (test, &keys);

	status = recovery_image_manager_mock_init (&recovery);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_init (&keystore1);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_init (&keystore2);
	CuAssertIntEquals (test, 0, status);

	status = intrusion_manager_mock_init (&intrusion);
	CuAssertIntEquals (test, 0, status);

	status = config_reset_init (&reset, NULL, 0, NULL, 0, NULL, 0, &keys.riot, &keys.aux,
		&recovery.base, keystore_array, 2, &intrusion.base);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_manager_mock_validate_and_release (&recovery);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_validate_and_release (&keystore1);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_validate_and_release (&keystore2);
	CuAssertIntEquals (test, 0, status);

	status = intrusion_manager_mock_validate_and_release (&intrusion);
	CuAssertIntEquals (test, 0, status);

	config_reset_testing_release_attestation_keys (test, &keys);

	config_reset_release (&reset);
}

static void config_reset_test_init_no_bypass_manifests (CuTest *test)
{
	struct manifest_manager_mock manifest;
	struct state_manager_mock state;
	struct config_reset_testing_keys keys;
	struct config_reset reset;
	int status;
	struct manifest_manager *config[1];
	struct state_manager *state_list[1];
	struct recovery_image_manager_mock recovery;
	struct keystore_mock keystore1;
	struct keystore_mock keystore2;
	struct keystore* keystore_array[] = {&keystore1.base, &keystore2.base};
	struct intrusion_manager_mock intrusion;

	TEST_START;

	status = manifest_manager_mock_init (&manifest);
	CuAssertIntEquals (test, 0, status);
	config[0] = &manifest.base;

	status = state_manager_mock_init (&state);
	state_list[0] = &state.base;

	status = recovery_image_manager_mock_init (&recovery);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_init (&keystore1);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_init (&keystore2);
	CuAssertIntEquals (test, 0, status);

	status = intrusion_manager_mock_init (&intrusion);
	CuAssertIntEquals (test, 0, status);

	config_reset_testing_init_attestation_keys (test, &keys);

	status = config_reset_init (&reset, NULL, 0, config, 1, state_list, 1, &keys.riot,
		&keys.aux, &recovery.base, keystore_array, 2, &intrusion.base);
	CuAssertIntEquals (test, 0, status);

	status = manifest_manager_mock_validate_and_release (&manifest);
	CuAssertIntEquals (test, 0, status);

	status = state_manager_mock_validate_and_release (&state);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_manager_mock_validate_and_release (&recovery);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_validate_and_release (&keystore1);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_validate_and_release (&keystore2);
	CuAssertIntEquals (test, 0, status);

	status = intrusion_manager_mock_validate_and_release (&intrusion);
	CuAssertIntEquals (test, 0, status);

	config_reset_testing_release_attestation_keys (test, &keys);

	config_reset_release (&reset);
}

static void config_reset_test_init_no_default_manifests (CuTest *test)
{
	struct manifest_manager_mock manifest;
	struct state_manager_mock state;
	struct config_reset_testing_keys keys;
	struct config_reset reset;
	int status;
	struct manifest_manager *config[1];
	struct state_manager *state_list[1];
	struct recovery_image_manager_mock recovery;
	struct keystore_mock keystore1;
	struct keystore_mock keystore2;
	struct keystore* keystore_array[] = {&keystore1.base, &keystore2.base};
	struct intrusion_manager_mock intrusion;

	TEST_START;

	status = manifest_manager_mock_init (&manifest);
	CuAssertIntEquals (test, 0, status);
	config[0] = &manifest.base;

	status = state_manager_mock_init (&state);
	state_list[0] = &state.base;

	status = recovery_image_manager_mock_init (&recovery);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_init (&keystore1);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_init (&keystore2);
	CuAssertIntEquals (test, 0, status);

	status = intrusion_manager_mock_init (&intrusion);
	CuAssertIntEquals (test, 0, status);

	config_reset_testing_init_attestation_keys (test, &keys);

	status = config_reset_init (&reset, config, 1, NULL, 0, state_list, 1, &keys.riot,
		&keys.aux, &recovery.base, keystore_array, 2, &intrusion.base);
	CuAssertIntEquals (test, 0, status);

	status = manifest_manager_mock_validate_and_release (&manifest);
	CuAssertIntEquals (test, 0, status);

	status = state_manager_mock_validate_and_release (&state);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_manager_mock_validate_and_release (&recovery);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_validate_and_release (&keystore1);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_validate_and_release (&keystore2);
	CuAssertIntEquals (test, 0, status);

	status = intrusion_manager_mock_validate_and_release (&intrusion);
	CuAssertIntEquals (test, 0, status);

	config_reset_testing_release_attestation_keys (test, &keys);

	config_reset_release (&reset);
}

static void config_reset_test_init_no_riot (CuTest *test)
{
	struct manifest_manager_mock manifest;
	struct state_manager_mock state;
	struct config_reset_testing_keys keys;
	struct config_reset reset;
	int status;
	struct manifest_manager *config[1];
	struct state_manager *state_list[1];
	struct recovery_image_manager_mock recovery;
	struct keystore_mock keystore1;
	struct keystore_mock keystore2;
	struct keystore* keystore_array[] = {&keystore1.base, &keystore2.base};
	struct intrusion_manager_mock intrusion;

	TEST_START;

	status = manifest_manager_mock_init (&manifest);
	CuAssertIntEquals (test, 0, status);
	config[0] = &manifest.base;

	status = state_manager_mock_init (&state);
	state_list[0] = &state.base;

	status = recovery_image_manager_mock_init (&recovery);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_init (&keystore1);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_init (&keystore2);
	CuAssertIntEquals (test, 0, status);

	status = intrusion_manager_mock_init (&intrusion);
	CuAssertIntEquals (test, 0, status);

	config_reset_testing_init_attestation_keys (test, &keys);

	status = config_reset_init (&reset, config, 1, config, 1, state_list, 1, NULL,
		&keys.aux, &recovery.base, keystore_array, 2, &intrusion.base);
	CuAssertIntEquals (test, 0, status);

	status = manifest_manager_mock_validate_and_release (&manifest);
	CuAssertIntEquals (test, 0, status);

	status = state_manager_mock_validate_and_release (&state);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_manager_mock_validate_and_release (&recovery);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_validate_and_release (&keystore1);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_validate_and_release (&keystore2);
	CuAssertIntEquals (test, 0, status);

	status = intrusion_manager_mock_validate_and_release (&intrusion);
	CuAssertIntEquals (test, 0, status);

	config_reset_testing_release_attestation_keys (test, &keys);

	config_reset_release (&reset);
}

static void config_reset_test_init_no_aux (CuTest *test)
{
	struct manifest_manager_mock manifest;
	struct state_manager_mock state;
	struct config_reset_testing_keys keys;
	struct config_reset reset;
	int status;
	struct manifest_manager *config[1];
	struct state_manager *state_list[1];
	struct recovery_image_manager_mock recovery;
	struct keystore_mock keystore1;
	struct keystore_mock keystore2;
	struct keystore* keystore_array[] = {&keystore1.base, &keystore2.base};
	struct intrusion_manager_mock intrusion;

	TEST_START;

	status = manifest_manager_mock_init (&manifest);
	CuAssertIntEquals (test, 0, status);
	config[0] = &manifest.base;

	status = state_manager_mock_init (&state);
	state_list[0] = &state.base;

	status = recovery_image_manager_mock_init (&recovery);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_init (&keystore1);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_init (&keystore2);
	CuAssertIntEquals (test, 0, status);

	status = intrusion_manager_mock_init (&intrusion);
	CuAssertIntEquals (test, 0, status);

	config_reset_testing_init_attestation_keys (test, &keys);

	status = config_reset_init (&reset, config, 1, config, 1, state_list, 1, &keys.riot, NULL,
		&recovery.base, keystore_array, 2, &intrusion.base);
	CuAssertIntEquals (test, 0, status);

	status = manifest_manager_mock_validate_and_release (&manifest);
	CuAssertIntEquals (test, 0, status);

	status = state_manager_mock_validate_and_release (&state);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_manager_mock_validate_and_release (&recovery);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_validate_and_release (&keystore1);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_validate_and_release (&keystore2);
	CuAssertIntEquals (test, 0, status);

	status = intrusion_manager_mock_validate_and_release (&intrusion);
	CuAssertIntEquals (test, 0, status);

	config_reset_testing_release_attestation_keys (test, &keys);

	config_reset_release (&reset);
}

static void config_reset_test_init_no_recovery (CuTest *test)
{
	struct manifest_manager_mock manifest;
	struct state_manager_mock state;
	struct keystore_mock keystore1;
	struct keystore_mock keystore2;
	struct keystore* keystore_array[] = {&keystore1.base, &keystore2.base};
	struct intrusion_manager_mock intrusion;
	struct config_reset_testing_keys keys;
	struct config_reset reset;
	int status;
	struct manifest_manager *config[1];
	struct state_manager *state_list[1];

	TEST_START;

	status = manifest_manager_mock_init (&manifest);
	CuAssertIntEquals (test, 0, status);
	config[0] = &manifest.base;

	status = state_manager_mock_init (&state);
	state_list[0] = &state.base;

	status = keystore_mock_init (&keystore1);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_init (&keystore2);
	CuAssertIntEquals (test, 0, status);

	status = intrusion_manager_mock_init (&intrusion);
	CuAssertIntEquals (test, 0, status);

	config_reset_testing_init_attestation_keys (test, &keys);

	status = config_reset_init (&reset, config, 1, config, 1, state_list, 1, &keys.riot,
		&keys.aux, NULL, keystore_array, 2, &intrusion.base);
	CuAssertIntEquals (test, 0, status);

	status = manifest_manager_mock_validate_and_release (&manifest);
	CuAssertIntEquals (test, 0, status);

	status = state_manager_mock_validate_and_release (&state);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_validate_and_release (&keystore1);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_validate_and_release (&keystore2);
	CuAssertIntEquals (test, 0, status);

	status = intrusion_manager_mock_validate_and_release (&intrusion);
	CuAssertIntEquals (test, 0, status);

	config_reset_testing_release_attestation_keys (test, &keys);

	config_reset_release (&reset);
}

static void config_reset_test_init_no_keystores (CuTest *test)
{
	struct manifest_manager_mock manifest;
	struct state_manager_mock state;
	struct config_reset_testing_keys keys;
	struct config_reset reset;
	int status;
	struct manifest_manager *config[1];
	struct state_manager *state_list[1];
	struct recovery_image_manager_mock recovery;
	struct intrusion_manager_mock intrusion;

	TEST_START;

	status = manifest_manager_mock_init (&manifest);
	CuAssertIntEquals (test, 0, status);
	config[0] = &manifest.base;

	status = state_manager_mock_init (&state);
	state_list[0] = &state.base;

	config_reset_testing_init_attestation_keys (test, &keys);

	status = recovery_image_manager_mock_init (&recovery);
	CuAssertIntEquals (test, 0, status);

	status = intrusion_manager_mock_init (&intrusion);

	status = config_reset_init (&reset, config, 1, config, 1, state_list, 1, &keys.riot,
		&keys.aux, &recovery.base, NULL, 0, &intrusion.base);
	CuAssertIntEquals (test, 0, status);

	status = manifest_manager_mock_validate_and_release (&manifest);
	CuAssertIntEquals (test, 0, status);

	status = state_manager_mock_validate_and_release (&state);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_manager_mock_validate_and_release (&recovery);
	CuAssertIntEquals (test, 0, status);

	status = intrusion_manager_mock_validate_and_release (&intrusion);

	config_reset_testing_release_attestation_keys (test, &keys);

	config_reset_release (&reset);
}

static void config_reset_test_init_no_intrusion (CuTest *test)
{
	struct manifest_manager_mock manifest;
	struct state_manager_mock state;
	struct config_reset_testing_keys keys;
	struct config_reset reset;
	int status;
	struct manifest_manager *config[1];
	struct state_manager *state_list[1];
	struct recovery_image_manager_mock recovery;
	struct keystore_mock keystore1;
	struct keystore_mock keystore2;
	struct keystore* keystore_array[] = {&keystore1.base, &keystore2.base};

	TEST_START;

	status = manifest_manager_mock_init (&manifest);
	CuAssertIntEquals (test, 0, status);
	config[0] = &manifest.base;

	status = state_manager_mock_init (&state);
	state_list[0] = &state.base;

	config_reset_testing_init_attestation_keys (test, &keys);

	status = recovery_image_manager_mock_init (&recovery);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_init (&keystore1);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_init (&keystore2);
	CuAssertIntEquals (test, 0, status);

	status = config_reset_init (&reset, config, 1, config, 1, state_list, 1, &keys.riot,
		&keys.aux, &recovery.base, keystore_array, 2, NULL);
	CuAssertIntEquals (test, 0, status);

	status = manifest_manager_mock_validate_and_release (&manifest);
	CuAssertIntEquals (test, 0, status);

	status = state_manager_mock_validate_and_release (&state);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_manager_mock_validate_and_release (&recovery);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_validate_and_release (&keystore1);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_validate_and_release (&keystore2);
	CuAssertIntEquals (test, 0, status);

	config_reset_testing_release_attestation_keys (test, &keys);

	config_reset_release (&reset);
}

static void config_reset_test_init_null (CuTest *test)
{
	struct manifest_manager_mock manifest;
	struct state_manager_mock state;
	struct config_reset_testing_keys keys;
	struct config_reset reset;
	int status;
	struct manifest_manager *config[1];
	struct state_manager *state_list[1];
	struct recovery_image_manager_mock recovery;
	struct keystore_mock keystore1;
	struct keystore_mock keystore2;
	struct keystore* keystore_array[] = {&keystore1.base, &keystore2.base};
	struct intrusion_manager_mock intrusion;

	TEST_START;

	status = manifest_manager_mock_init (&manifest);
	CuAssertIntEquals (test, 0, status);
	config[0] = &manifest.base;

	status = state_manager_mock_init (&state);
	state_list[0] = &state.base;

	status = recovery_image_manager_mock_init (&recovery);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_init (&keystore1);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_init (&keystore2);
	CuAssertIntEquals (test, 0, status);

	status = intrusion_manager_mock_init (&intrusion);
	CuAssertIntEquals (test, 0, status);

	config_reset_testing_init_attestation_keys (test, &keys);

	status = config_reset_init (NULL, config, 1, config, 1, state_list, 1, &keys.riot,
		&keys.aux, &recovery.base, keystore_array, 2, &intrusion.base);
	CuAssertIntEquals (test, CONFIG_RESET_INVALID_ARGUMENT, status);

	status = config_reset_init (&reset, NULL, 1, config, 1, state_list, 1, &keys.riot,
		&keys.aux, &recovery.base, keystore_array, 2, &intrusion.base);
	CuAssertIntEquals (test, CONFIG_RESET_INVALID_ARGUMENT, status);

	status = config_reset_init (&reset, config, 1, NULL, 1, state_list, 1, &keys.riot,
		&keys.aux, &recovery.base, keystore_array, 2, &intrusion.base);
	CuAssertIntEquals (test, CONFIG_RESET_INVALID_ARGUMENT, status);

	status = config_reset_init (&reset, config, 1, config, 1, NULL, 1, &keys.riot,
		&keys.aux, &recovery.base, keystore_array, 2, &intrusion.base);
	CuAssertIntEquals (test, CONFIG_RESET_INVALID_ARGUMENT, status);

	status = config_reset_init (&reset, config, 1, config, 1, state_list, 1, &keys.riot,
		&keys.aux, &recovery.base, NULL, 2, &intrusion.base);
	CuAssertIntEquals (test, CONFIG_RESET_INVALID_ARGUMENT, status);

	status = manifest_manager_mock_validate_and_release (&manifest);
	CuAssertIntEquals (test, 0, status);

	status = state_manager_mock_validate_and_release (&state);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_manager_mock_validate_and_release (&recovery);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_validate_and_release (&keystore1);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_validate_and_release (&keystore2);
	CuAssertIntEquals (test, 0, status);

	status = intrusion_manager_mock_validate_and_release (&intrusion);
	CuAssertIntEquals (test, 0, status);

	config_reset_testing_release_attestation_keys (test, &keys);

	config_reset_release (&reset);
}

static void config_reset_test_init_no_manifests_with_state (CuTest *test)
{
	struct state_manager_mock state;
	struct config_reset_testing_keys keys;
	struct config_reset reset;
	int status;
	struct state_manager *state_list[1];
	struct recovery_image_manager_mock recovery;
	struct keystore_mock keystore1;
	struct keystore_mock keystore2;
	struct keystore* keystore_array[] = {&keystore1.base, &keystore2.base};
	struct intrusion_manager_mock intrusion;

	TEST_START;

	status = state_manager_mock_init (&state);
	state_list[0] = &state.base;

	status = recovery_image_manager_mock_init (&recovery);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_init (&keystore1);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_init (&keystore2);
	CuAssertIntEquals (test, 0, status);

	status = intrusion_manager_mock_init (&intrusion);
	CuAssertIntEquals (test, 0, status);

	config_reset_testing_init_attestation_keys (test, &keys);

	status = config_reset_init (&reset, NULL, 0, NULL, 0, state_list, 1, &keys.riot,
		&keys.aux, &recovery.base, keystore_array, 2, &intrusion.base);
	CuAssertIntEquals (test, CONFIG_RESET_NO_MANIFESTS, status);

	status = state_manager_mock_validate_and_release (&state);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_manager_mock_validate_and_release (&recovery);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_validate_and_release (&keystore1);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_validate_and_release (&keystore2);
	CuAssertIntEquals (test, 0, status);

	status = intrusion_manager_mock_validate_and_release (&intrusion);
	CuAssertIntEquals (test, 0, status);

	config_reset_testing_release_attestation_keys (test, &keys);
}

static void config_reset_test_restore_bypass (CuTest *test)
{
	struct manifest_manager_mock manifest;
	struct manifest_manager_mock manifest_extra;
	struct state_manager_mock state;
	struct config_reset_testing_keys keys;
	struct config_reset reset;
	int status;
	struct manifest_manager *bypass[1];
	struct manifest_manager *config[1];
	struct state_manager *state_list[1];
	struct recovery_image_manager_mock recovery;
	struct keystore_mock keystore1;
	struct keystore_mock keystore2;
	struct keystore* keystore_array[] = {&keystore1.base, &keystore2.base};
	struct intrusion_manager_mock intrusion;

	TEST_START;

	status = manifest_manager_mock_init (&manifest);
	CuAssertIntEquals (test, 0, status);
	bypass[0] = &manifest.base;

	status = manifest_manager_mock_init (&manifest_extra);
	CuAssertIntEquals (test, 0, status);
	config[0] = &manifest_extra.base;

	status = state_manager_mock_init (&state);
	state_list[0] = &state.base;

	status = recovery_image_manager_mock_init (&recovery);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_init (&keystore1);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_init (&keystore2);
	CuAssertIntEquals (test, 0, status);

	status = intrusion_manager_mock_init (&intrusion);
	CuAssertIntEquals (test, 0, status);

	config_reset_testing_init_attestation_keys (test, &keys);

	status = config_reset_init (&reset, bypass, 1, config, 1, state_list, 1, &keys.riot,
		&keys.aux, &recovery.base, keystore_array, 2, &intrusion.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manifest.mock, manifest.base.clear_all_manifests, &manifest, 0);
	CuAssertIntEquals (test, 0, status);

	status = config_reset_restore_bypass (&reset);
	CuAssertIntEquals (test, 0, status);

	status = manifest_manager_mock_validate_and_release (&manifest);
	CuAssertIntEquals (test, 0, status);

	status = manifest_manager_mock_validate_and_release (&manifest_extra);
	CuAssertIntEquals (test, 0, status);

	status = state_manager_mock_validate_and_release (&state);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_manager_mock_validate_and_release (&recovery);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_validate_and_release (&keystore1);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_validate_and_release (&keystore2);
	CuAssertIntEquals (test, 0, status);

	status = intrusion_manager_mock_validate_and_release (&intrusion);
	CuAssertIntEquals (test, 0, status);

	config_reset_testing_release_attestation_keys (test, &keys);

	config_reset_release (&reset);
}

static void config_reset_test_restore_bypass_multiple (CuTest *test)
{
	struct manifest_manager_mock manifest1;
	struct manifest_manager_mock manifest2;
	struct manifest_manager_mock manifest3;
	struct manifest_manager_mock manifest_extra;
	struct state_manager_mock state;
	struct config_reset_testing_keys keys;
	struct config_reset reset;
	int status;
	struct manifest_manager *bypass[3];
	struct manifest_manager *config[1];
	struct state_manager *state_list[1];
	struct recovery_image_manager_mock recovery;
	struct keystore_mock keystore1;
	struct keystore_mock keystore2;
	struct keystore* keystore_array[] = {&keystore1.base, &keystore2.base};
	struct intrusion_manager_mock intrusion;

	TEST_START;

	status = manifest_manager_mock_init (&manifest1);
	CuAssertIntEquals (test, 0, status);
	mock_set_name (&manifest1.mock, "manifest_manager1");
	bypass[0] = &manifest1.base;

	status = manifest_manager_mock_init (&manifest2);
	CuAssertIntEquals (test, 0, status);
	mock_set_name (&manifest2.mock, "manifest_manager2");
	bypass[1] = &manifest2.base;

	status = manifest_manager_mock_init (&manifest3);
	CuAssertIntEquals (test, 0, status);
	mock_set_name (&manifest3.mock, "manifest_manager3");
	bypass[2] = &manifest3.base;

	status = manifest_manager_mock_init (&manifest_extra);
	CuAssertIntEquals (test, 0, status);
	config[0] = &manifest_extra.base;

	status = state_manager_mock_init (&state);
	state_list[0] = &state.base;

	status = recovery_image_manager_mock_init (&recovery);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_init (&keystore1);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_init (&keystore2);
	CuAssertIntEquals (test, 0, status);

	status = intrusion_manager_mock_init (&intrusion);
	CuAssertIntEquals (test, 0, status);

	config_reset_testing_init_attestation_keys (test, &keys);

	status = config_reset_init (&reset, bypass, 3, config, 1, state_list, 1, &keys.riot,
		&keys.aux, &recovery.base, keystore_array, 2, &intrusion.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manifest1.mock, manifest1.base.clear_all_manifests, &manifest1, 0);
	status |= mock_expect (&manifest2.mock, manifest2.base.clear_all_manifests, &manifest2, 0);
	status |= mock_expect (&manifest3.mock, manifest3.base.clear_all_manifests, &manifest3, 0);

	CuAssertIntEquals (test, 0, status);

	status = config_reset_restore_bypass (&reset);
	CuAssertIntEquals (test, 0, status);

	status = manifest_manager_mock_validate_and_release (&manifest1);
	CuAssertIntEquals (test, 0, status);

	status = manifest_manager_mock_validate_and_release (&manifest2);
	CuAssertIntEquals (test, 0, status);

	status = manifest_manager_mock_validate_and_release (&manifest3);
	CuAssertIntEquals (test, 0, status);

	status = manifest_manager_mock_validate_and_release (&manifest_extra);
	CuAssertIntEquals (test, 0, status);

	status = state_manager_mock_validate_and_release (&state);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_manager_mock_validate_and_release (&recovery);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_validate_and_release (&keystore1);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_validate_and_release (&keystore2);
	CuAssertIntEquals (test, 0, status);

	status = intrusion_manager_mock_validate_and_release (&intrusion);
	CuAssertIntEquals (test, 0, status);

	config_reset_testing_release_attestation_keys (test, &keys);

	config_reset_release (&reset);
}

static void config_reset_test_restore_bypass_no_manifests (CuTest *test)
{
	struct manifest_manager_mock manifest_extra;
	struct config_reset_testing_keys keys;
	struct config_reset reset;
	int status;
	struct manifest_manager *config[1];
	struct recovery_image_manager_mock recovery;
	struct keystore_mock keystore1;
	struct keystore_mock keystore2;
	struct keystore* keystore_array[] = {&keystore1.base, &keystore2.base};
	struct intrusion_manager_mock intrusion;

	TEST_START;

	status = manifest_manager_mock_init (&manifest_extra);
	CuAssertIntEquals (test, 0, status);
	config[0] = &manifest_extra.base;

	status = recovery_image_manager_mock_init (&recovery);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_init (&keystore1);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_init (&keystore2);
	CuAssertIntEquals (test, 0, status);

	status = intrusion_manager_mock_init (&intrusion);
	CuAssertIntEquals (test, 0, status);

	config_reset_testing_init_attestation_keys (test, &keys);

	status = config_reset_init (&reset, NULL, 0, config, 1, NULL, 0, &keys.riot, &keys.aux,
		&recovery.base, keystore_array, 2, &intrusion.base);
	CuAssertIntEquals (test, 0, status);

	status = config_reset_restore_bypass (&reset);
	CuAssertIntEquals (test, CONFIG_RESET_NO_MANIFESTS, status);

	status = manifest_manager_mock_validate_and_release (&manifest_extra);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_manager_mock_validate_and_release (&recovery);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_validate_and_release (&keystore1);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_validate_and_release (&keystore2);
	CuAssertIntEquals (test, 0, status);

	status = intrusion_manager_mock_validate_and_release (&intrusion);
	CuAssertIntEquals (test, 0, status);

	config_reset_testing_release_attestation_keys (test, &keys);

	config_reset_release (&reset);
}

static void config_reset_test_restore_bypass_null (CuTest *test)
{
	struct manifest_manager_mock manifest;
	struct state_manager_mock state;
	struct config_reset_testing_keys keys;
	struct config_reset reset;
	int status;
	struct manifest_manager *config[1];
	struct state_manager *state_list[1];
	struct recovery_image_manager_mock recovery;
	struct keystore_mock keystore1;
	struct keystore_mock keystore2;
	struct keystore* keystore_array[] = {&keystore1.base, &keystore2.base};
	struct intrusion_manager_mock intrusion;

	TEST_START;

	status = manifest_manager_mock_init (&manifest);
	CuAssertIntEquals (test, 0, status);
	config[0] = &manifest.base;

	status = state_manager_mock_init (&state);
	state_list[0] = &state.base;

	status = recovery_image_manager_mock_init (&recovery);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_init (&keystore1);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_init (&keystore2);
	CuAssertIntEquals (test, 0, status);

	status = intrusion_manager_mock_init (&intrusion);
	CuAssertIntEquals (test, 0, status);

	config_reset_testing_init_attestation_keys (test, &keys);

	status = config_reset_init (&reset, config, 1, config, 1, state_list, 1, &keys.riot,
		&keys.aux, &recovery.base, keystore_array, 2, &intrusion.base);
	CuAssertIntEquals (test, 0, status);

	status = config_reset_restore_bypass (NULL);
	CuAssertIntEquals (test, CONFIG_RESET_INVALID_ARGUMENT, status);

	status = manifest_manager_mock_validate_and_release (&manifest);
	CuAssertIntEquals (test, 0, status);

	status = state_manager_mock_validate_and_release (&state);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_manager_mock_validate_and_release (&recovery);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_validate_and_release (&keystore1);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_validate_and_release (&keystore2);
	CuAssertIntEquals (test, 0, status);

	status = intrusion_manager_mock_validate_and_release (&intrusion);
	CuAssertIntEquals (test, 0, status);

	config_reset_testing_release_attestation_keys (test, &keys);

	config_reset_release (&reset);
}

static void config_reset_test_restore_bypass_clear_error (CuTest *test)
{
	struct manifest_manager_mock manifest1;
	struct manifest_manager_mock manifest2;
	struct manifest_manager_mock manifest3;
	struct manifest_manager_mock manifest_extra;
	struct state_manager_mock state;
	struct config_reset_testing_keys keys;
	struct config_reset reset;
	int status;
	struct manifest_manager *bypass[3];
	struct manifest_manager *config[1];
	struct state_manager *state_list[1];
	struct recovery_image_manager_mock recovery;
	struct keystore_mock keystore1;
	struct keystore_mock keystore2;
	struct keystore* keystore_array[] = {&keystore1.base, &keystore2.base};
	struct intrusion_manager_mock intrusion;

	TEST_START;

	status = manifest_manager_mock_init (&manifest1);
	CuAssertIntEquals (test, 0, status);
	mock_set_name (&manifest1.mock, "manifest_manager1");
	bypass[0] = &manifest1.base;

	status = manifest_manager_mock_init (&manifest2);
	CuAssertIntEquals (test, 0, status);
	mock_set_name (&manifest2.mock, "manifest_manager2");
	bypass[1] = &manifest2.base;

	status = manifest_manager_mock_init (&manifest3);
	CuAssertIntEquals (test, 0, status);
	mock_set_name (&manifest3.mock, "manifest_manager3");
	bypass[2] = &manifest3.base;

	status = manifest_manager_mock_init (&manifest_extra);
	CuAssertIntEquals (test, 0, status);
	config[0] = &manifest_extra.base;

	status = state_manager_mock_init (&state);
	state_list[0] = &state.base;

	status = recovery_image_manager_mock_init (&recovery);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_init (&keystore1);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_init (&keystore2);
	CuAssertIntEquals (test, 0, status);

	status = intrusion_manager_mock_init (&intrusion);
	CuAssertIntEquals (test, 0, status);

	config_reset_testing_init_attestation_keys (test, &keys);

	status = config_reset_init (&reset, bypass, 3, config, 1, state_list, 1, &keys.riot,
		&keys.aux, &recovery.base, keystore_array, 2, &intrusion.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manifest1.mock, manifest1.base.clear_all_manifests, &manifest1, 0);
	status |= mock_expect (&manifest2.mock, manifest2.base.clear_all_manifests, &manifest2,
		MANIFEST_MANAGER_CLEAR_ALL_FAILED);

	CuAssertIntEquals (test, 0, status);

	status = config_reset_restore_bypass (&reset);
	CuAssertIntEquals (test, MANIFEST_MANAGER_CLEAR_ALL_FAILED, status);

	status = manifest_manager_mock_validate_and_release (&manifest1);
	CuAssertIntEquals (test, 0, status);

	status = manifest_manager_mock_validate_and_release (&manifest2);
	CuAssertIntEquals (test, 0, status);

	status = manifest_manager_mock_validate_and_release (&manifest3);
	CuAssertIntEquals (test, 0, status);

	status = manifest_manager_mock_validate_and_release (&manifest_extra);
	CuAssertIntEquals (test, 0, status);

	status = state_manager_mock_validate_and_release (&state);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_manager_mock_validate_and_release (&recovery);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_validate_and_release (&keystore1);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_validate_and_release (&keystore2);
	CuAssertIntEquals (test, 0, status);

	status = intrusion_manager_mock_validate_and_release (&intrusion);
	CuAssertIntEquals (test, 0, status);

	config_reset_testing_release_attestation_keys (test, &keys);

	config_reset_release (&reset);
}

static void config_reset_test_restore_defaults (CuTest *test)
{
	struct manifest_manager_mock manifest;
	struct manifest_manager_mock manifest_extra;
	struct state_manager_mock state;
	struct config_reset_testing_keys keys;
	struct config_reset reset;
	int status;
	struct manifest_manager *bypass[1];
	struct manifest_manager *config[1];
	struct state_manager *state_list[1];
	struct recovery_image_manager_mock recovery;
	struct keystore_mock keystore1;
	struct keystore_mock keystore2;
	struct keystore* keystore_array[] = {&keystore1.base, &keystore2.base};
	struct intrusion_manager_mock intrusion;

	TEST_START;

	status = manifest_manager_mock_init (&manifest);
	CuAssertIntEquals (test, 0, status);
	bypass[0] = &manifest.base;

	status = manifest_manager_mock_init (&manifest_extra);
	CuAssertIntEquals (test, 0, status);
	config[0] = &manifest_extra.base;

	status = state_manager_mock_init (&state);
	state_list[0] = &state.base;

	status = recovery_image_manager_mock_init (&recovery);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_init (&keystore1);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_init (&keystore2);
	CuAssertIntEquals (test, 0, status);

	status = intrusion_manager_mock_init (&intrusion);
	CuAssertIntEquals (test, 0, status);

	config_reset_testing_init_attestation_keys (test, &keys);

	status = config_reset_init (&reset, bypass, 1, config, 1, state_list, 1, &keys.riot,
		&keys.aux, &recovery.base, keystore_array, 2, &intrusion.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manifest.mock, manifest.base.clear_all_manifests, &manifest, 0);
	status |= mock_expect (&manifest_extra.mock, manifest_extra.base.clear_all_manifests,
		&manifest_extra, 0);
	status |= mock_expect (&state.mock, state.base.restore_default_state, &state, 0);

	status |= mock_expect (&keys.riot_keystore.mock, keys.riot_keystore.base.erase_key,
		&keys.riot_keystore, 0, MOCK_ARG (0));
	status |= mock_expect (&keys.riot_keystore.mock, keys.riot_keystore.base.erase_key,
		&keys.riot_keystore, 0, MOCK_ARG (1));
	status |= mock_expect (&keys.riot_keystore.mock, keys.riot_keystore.base.erase_key,
		&keys.riot_keystore, 0, MOCK_ARG (2));

	status |= mock_expect (&keys.aux_keystore.mock, keys.aux_keystore.base.erase_key,
		&keys.aux_keystore, 0, MOCK_ARG (0));

	status |= mock_expect (&recovery.mock, recovery.base.erase_all_recovery_regions,
		&recovery, 0);

	status |= mock_expect (&keystore1.mock, keystore1.base.erase_all_keys, &keystore1, 0);
	status |= mock_expect (&keystore2.mock, keystore2.base.erase_all_keys, &keystore2, 0);

	status |= mock_expect (&intrusion.mock, intrusion.base.handle_intrusion, &intrusion, 0);

	CuAssertIntEquals (test, 0, status);

	status = config_reset_restore_defaults (&reset);
	CuAssertIntEquals (test, 0, status);

	status = manifest_manager_mock_validate_and_release (&manifest);
	CuAssertIntEquals (test, 0, status);

	status = manifest_manager_mock_validate_and_release (&manifest_extra);
	CuAssertIntEquals (test, 0, status);

	status = state_manager_mock_validate_and_release (&state);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_manager_mock_validate_and_release (&recovery);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_validate_and_release (&keystore1);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_validate_and_release (&keystore2);
	CuAssertIntEquals (test, 0, status);

	status = intrusion_manager_mock_validate_and_release (&intrusion);
	CuAssertIntEquals (test, 0, status);

	config_reset_testing_release_attestation_keys (test, &keys);

	config_reset_release (&reset);
}

static void config_reset_test_restore_defaults_multiple_bypass (CuTest *test)
{
	struct manifest_manager_mock manifest1;
	struct manifest_manager_mock manifest2;
	struct manifest_manager_mock manifest3;
	struct manifest_manager_mock manifest_extra;
	struct state_manager_mock state1;
	struct state_manager_mock state2;
	struct state_manager_mock state3;
	struct config_reset_testing_keys keys;
	struct config_reset reset;
	int status;
	struct manifest_manager *bypass[3];
	struct manifest_manager *config[1];
	struct state_manager *state_list[3];
	struct recovery_image_manager_mock recovery;
	struct keystore_mock keystore1;
	struct keystore_mock keystore2;
	struct keystore* keystore_array[] = {&keystore1.base, &keystore2.base};
	struct intrusion_manager_mock intrusion;

	TEST_START;

	status = manifest_manager_mock_init (&manifest1);
	CuAssertIntEquals (test, 0, status);
	mock_set_name (&manifest1.mock, "manifest_manager1");
	bypass[0] = &manifest1.base;

	status = manifest_manager_mock_init (&manifest2);
	CuAssertIntEquals (test, 0, status);
	mock_set_name (&manifest2.mock, "manifest_manager2");
	bypass[1] = &manifest2.base;

	status = manifest_manager_mock_init (&manifest3);
	CuAssertIntEquals (test, 0, status);
	mock_set_name (&manifest3.mock, "manifest_manager3");
	bypass[2] = &manifest3.base;

	status = manifest_manager_mock_init (&manifest_extra);
	CuAssertIntEquals (test, 0, status);
	config[0] = &manifest_extra.base;

	status = state_manager_mock_init (&state1);
	state_list[0] = &state1.base;

	status = state_manager_mock_init (&state2);
	state_list[1] = &state2.base;

	status = state_manager_mock_init (&state3);
	state_list[2] = &state3.base;

	status = recovery_image_manager_mock_init (&recovery);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_init (&keystore1);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_init (&keystore2);
	CuAssertIntEquals (test, 0, status);

	status = intrusion_manager_mock_init (&intrusion);
	CuAssertIntEquals (test, 0, status);

	config_reset_testing_init_attestation_keys (test, &keys);

	status = config_reset_init (&reset, bypass, 3, config, 1, state_list, 3, &keys.riot,
		&keys.aux, &recovery.base, keystore_array, 2, &intrusion.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manifest1.mock, manifest1.base.clear_all_manifests, &manifest1, 0);
	status |= mock_expect (&manifest2.mock, manifest2.base.clear_all_manifests, &manifest2, 0);
	status |= mock_expect (&manifest3.mock, manifest3.base.clear_all_manifests, &manifest3, 0);

	status |= mock_expect (&manifest_extra.mock, manifest_extra.base.clear_all_manifests,
		&manifest_extra, 0);

	status |= mock_expect (&state1.mock, state1.base.restore_default_state, &state1, 0);
	status |= mock_expect (&state2.mock, state2.base.restore_default_state, &state2, 0);
	status |= mock_expect (&state3.mock, state3.base.restore_default_state, &state3, 0);

	status |= mock_expect (&keys.riot_keystore.mock, keys.riot_keystore.base.erase_key,
		&keys.riot_keystore, 0, MOCK_ARG (0));
	status |= mock_expect (&keys.riot_keystore.mock, keys.riot_keystore.base.erase_key,
		&keys.riot_keystore, 0, MOCK_ARG (1));
	status |= mock_expect (&keys.riot_keystore.mock, keys.riot_keystore.base.erase_key,
		&keys.riot_keystore, 0, MOCK_ARG (2));

	status |= mock_expect (&keys.aux_keystore.mock, keys.aux_keystore.base.erase_key,
		&keys.aux_keystore, 0, MOCK_ARG (0));

	status |= mock_expect (&recovery.mock, recovery.base.erase_all_recovery_regions,
		&recovery, 0);

	status |= mock_expect (&keystore1.mock, keystore1.base.erase_all_keys, &keystore1, 0);
	status |= mock_expect (&keystore2.mock, keystore2.base.erase_all_keys, &keystore2, 0);

	status |= mock_expect (&intrusion.mock, intrusion.base.handle_intrusion, &intrusion, 0);

	CuAssertIntEquals (test, 0, status);

	status = config_reset_restore_defaults (&reset);
	CuAssertIntEquals (test, 0, status);

	status = manifest_manager_mock_validate_and_release (&manifest1);
	CuAssertIntEquals (test, 0, status);

	status = manifest_manager_mock_validate_and_release (&manifest2);
	CuAssertIntEquals (test, 0, status);

	status = manifest_manager_mock_validate_and_release (&manifest3);
	CuAssertIntEquals (test, 0, status);

	status = manifest_manager_mock_validate_and_release (&manifest_extra);
	CuAssertIntEquals (test, 0, status);

	status = state_manager_mock_validate_and_release (&state1);
	CuAssertIntEquals (test, 0, status);

	status = state_manager_mock_validate_and_release (&state2);
	CuAssertIntEquals (test, 0, status);

	status = state_manager_mock_validate_and_release (&state3);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_manager_mock_validate_and_release (&recovery);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_validate_and_release (&keystore1);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_validate_and_release (&keystore2);
	CuAssertIntEquals (test, 0, status);

	status = intrusion_manager_mock_validate_and_release (&intrusion);
	CuAssertIntEquals (test, 0, status);

	config_reset_testing_release_attestation_keys (test, &keys);

	config_reset_release (&reset);
}

static void config_reset_test_restore_defaults_multiple_default (CuTest *test)
{
	struct manifest_manager_mock manifest;
	struct manifest_manager_mock manifest_extra1;
	struct manifest_manager_mock manifest_extra2;
	struct manifest_manager_mock manifest_extra3;
	struct state_manager_mock state1;
	struct state_manager_mock state2;
	struct state_manager_mock state3;
	struct config_reset_testing_keys keys;
	struct config_reset reset;
	int status;
	struct manifest_manager *bypass[1];
	struct manifest_manager *config[3];
	struct state_manager *state_list[3];
	struct recovery_image_manager_mock recovery;
	struct keystore_mock keystore1;
	struct keystore_mock keystore2;
	struct keystore* keystore_array[] = {&keystore1.base, &keystore2.base};
	struct intrusion_manager_mock intrusion;

	TEST_START;

	status = manifest_manager_mock_init (&manifest);
	CuAssertIntEquals (test, 0, status);
	bypass[0] = &manifest.base;

	status = manifest_manager_mock_init (&manifest_extra1);
	CuAssertIntEquals (test, 0, status);
	mock_set_name (&manifest_extra1.mock, "manifest_manager1");
	config[0] = &manifest_extra1.base;

	status = manifest_manager_mock_init (&manifest_extra2);
	CuAssertIntEquals (test, 0, status);
	mock_set_name (&manifest_extra2.mock, "manifest_manager2");
	config[1] = &manifest_extra2.base;

	status = manifest_manager_mock_init (&manifest_extra3);
	CuAssertIntEquals (test, 0, status);
	mock_set_name (&manifest_extra3.mock, "manifest_manager3");
	config[2] = &manifest_extra3.base;

	status = state_manager_mock_init (&state1);
	state_list[0] = &state1.base;

	status = state_manager_mock_init (&state2);
	state_list[1] = &state2.base;

	status = state_manager_mock_init (&state3);
	state_list[2] = &state3.base;

	status = recovery_image_manager_mock_init (&recovery);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_init (&keystore1);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_init (&keystore2);
	CuAssertIntEquals (test, 0, status);

	status = intrusion_manager_mock_init (&intrusion);
	CuAssertIntEquals (test, 0, status);

	config_reset_testing_init_attestation_keys (test, &keys);

	status = config_reset_init (&reset, bypass, 1, config, 3, state_list, 3, &keys.riot,
		&keys.aux, &recovery.base, keystore_array, 2, &intrusion.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manifest.mock, manifest.base.clear_all_manifests, &manifest, 0);

	status |= mock_expect (&manifest_extra1.mock, manifest_extra1.base.clear_all_manifests,
		&manifest_extra1, 0);
	status |= mock_expect (&manifest_extra2.mock, manifest_extra2.base.clear_all_manifests,
		&manifest_extra2, 0);
	status |= mock_expect (&manifest_extra3.mock, manifest_extra3.base.clear_all_manifests,
		&manifest_extra3, 0);

	status |= mock_expect (&state1.mock, state1.base.restore_default_state, &state1, 0);
	status |= mock_expect (&state2.mock, state2.base.restore_default_state, &state2, 0);
	status |= mock_expect (&state3.mock, state3.base.restore_default_state, &state3, 0);

	status |= mock_expect (&keys.riot_keystore.mock, keys.riot_keystore.base.erase_key,
		&keys.riot_keystore, 0, MOCK_ARG (0));
	status |= mock_expect (&keys.riot_keystore.mock, keys.riot_keystore.base.erase_key,
		&keys.riot_keystore, 0, MOCK_ARG (1));
	status |= mock_expect (&keys.riot_keystore.mock, keys.riot_keystore.base.erase_key,
		&keys.riot_keystore, 0, MOCK_ARG (2));

	status |= mock_expect (&keys.aux_keystore.mock, keys.aux_keystore.base.erase_key,
		&keys.aux_keystore, 0, MOCK_ARG (0));

	status |= mock_expect (&recovery.mock, recovery.base.erase_all_recovery_regions,
		&recovery, 0);

	status |= mock_expect (&keystore1.mock, keystore1.base.erase_all_keys, &keystore1, 0);
	status |= mock_expect (&keystore2.mock, keystore2.base.erase_all_keys, &keystore2, 0);

	status |= mock_expect (&intrusion.mock, intrusion.base.handle_intrusion, &intrusion, 0);

	CuAssertIntEquals (test, 0, status);

	status = config_reset_restore_defaults (&reset);
	CuAssertIntEquals (test, 0, status);

	status = manifest_manager_mock_validate_and_release (&manifest);
	CuAssertIntEquals (test, 0, status);

	status = manifest_manager_mock_validate_and_release (&manifest_extra1);
	CuAssertIntEquals (test, 0, status);

	status = manifest_manager_mock_validate_and_release (&manifest_extra2);
	CuAssertIntEquals (test, 0, status);

	status = manifest_manager_mock_validate_and_release (&manifest_extra3);
	CuAssertIntEquals (test, 0, status);

	status = state_manager_mock_validate_and_release (&state1);
	CuAssertIntEquals (test, 0, status);

	status = state_manager_mock_validate_and_release (&state2);
	CuAssertIntEquals (test, 0, status);

	status = state_manager_mock_validate_and_release (&state3);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_manager_mock_validate_and_release (&recovery);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_validate_and_release (&keystore1);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_validate_and_release (&keystore2);
	CuAssertIntEquals (test, 0, status);

	status = intrusion_manager_mock_validate_and_release (&intrusion);
	CuAssertIntEquals (test, 0, status);

	config_reset_testing_release_attestation_keys (test, &keys);

	config_reset_release (&reset);
}

static void config_reset_test_restore_defaults_no_bypass_manifests (CuTest *test)
{
	struct manifest_manager_mock manifest_extra;
	struct state_manager_mock state;
	struct config_reset_testing_keys keys;
	struct config_reset reset;
	int status;
	struct manifest_manager *config[1];
	struct state_manager *state_list[1];
	struct recovery_image_manager_mock recovery;
	struct keystore_mock keystore1;
	struct keystore_mock keystore2;
	struct keystore* keystore_array[] = {&keystore1.base, &keystore2.base};
	struct intrusion_manager_mock intrusion;

	TEST_START;

	status = manifest_manager_mock_init (&manifest_extra);
	CuAssertIntEquals (test, 0, status);
	config[0] = &manifest_extra.base;

	status = state_manager_mock_init (&state);
	state_list[0] = &state.base;

	status = recovery_image_manager_mock_init (&recovery);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_init (&keystore1);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_init (&keystore2);
	CuAssertIntEquals (test, 0, status);

	status = intrusion_manager_mock_init (&intrusion);
	CuAssertIntEquals (test, 0, status);

	config_reset_testing_init_attestation_keys (test, &keys);

	status = config_reset_init (&reset, NULL, 0, config, 1, state_list, 1, &keys.riot,
		&keys.aux, &recovery.base, keystore_array, 2, &intrusion.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manifest_extra.mock, manifest_extra.base.clear_all_manifests,
		&manifest_extra, 0);
	status |= mock_expect (&state.mock, state.base.restore_default_state, &state, 0);

	status |= mock_expect (&keys.riot_keystore.mock, keys.riot_keystore.base.erase_key,
		&keys.riot_keystore, 0, MOCK_ARG (0));
	status |= mock_expect (&keys.riot_keystore.mock, keys.riot_keystore.base.erase_key,
		&keys.riot_keystore, 0, MOCK_ARG (1));
	status |= mock_expect (&keys.riot_keystore.mock, keys.riot_keystore.base.erase_key,
		&keys.riot_keystore, 0, MOCK_ARG (2));

	status |= mock_expect (&keys.aux_keystore.mock, keys.aux_keystore.base.erase_key,
		&keys.aux_keystore, 0, MOCK_ARG (0));

	status |= mock_expect (&recovery.mock, recovery.base.erase_all_recovery_regions,
		&recovery, 0);

	status |= mock_expect (&keystore1.mock, keystore1.base.erase_all_keys, &keystore1, 0);
	status |= mock_expect (&keystore2.mock, keystore2.base.erase_all_keys, &keystore2, 0);

	status |= mock_expect (&intrusion.mock, intrusion.base.handle_intrusion, &intrusion, 0);

	CuAssertIntEquals (test, 0, status);

	status = config_reset_restore_defaults (&reset);
	CuAssertIntEquals (test, 0, status);

	status = manifest_manager_mock_validate_and_release (&manifest_extra);
	CuAssertIntEquals (test, 0, status);

	status = state_manager_mock_validate_and_release (&state);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_manager_mock_validate_and_release (&recovery);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_validate_and_release (&keystore1);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_validate_and_release (&keystore2);
	CuAssertIntEquals (test, 0, status);

	status = intrusion_manager_mock_validate_and_release (&intrusion);
	CuAssertIntEquals (test, 0, status);

	config_reset_testing_release_attestation_keys (test, &keys);

	config_reset_release (&reset);
}

static void config_reset_test_restore_defaults_no_default_manifests (CuTest *test)
{
	struct manifest_manager_mock manifest;
	struct state_manager_mock state;
	struct config_reset_testing_keys keys;
	struct config_reset reset;
	int status;
	struct manifest_manager *bypass[1];
	struct state_manager *state_list[1];
	struct recovery_image_manager_mock recovery;
	struct keystore_mock keystore1;
	struct keystore_mock keystore2;
	struct keystore* keystore_array[] = {&keystore1.base, &keystore2.base};
	struct intrusion_manager_mock intrusion;

	TEST_START;

	status = manifest_manager_mock_init (&manifest);
	CuAssertIntEquals (test, 0, status);
	bypass[0] = &manifest.base;

	status = state_manager_mock_init (&state);
	state_list[0] = &state.base;

	status = recovery_image_manager_mock_init (&recovery);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_init (&keystore1);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_init (&keystore2);
	CuAssertIntEquals (test, 0, status);

	status = intrusion_manager_mock_init (&intrusion);
	CuAssertIntEquals (test, 0, status);

	config_reset_testing_init_attestation_keys (test, &keys);

	status = config_reset_init (&reset, bypass, 1, NULL, 0, state_list, 1, &keys.riot,
		&keys.aux, &recovery.base, keystore_array, 2, &intrusion.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manifest.mock, manifest.base.clear_all_manifests, &manifest, 0);
	status |= mock_expect (&state.mock, state.base.restore_default_state, &state, 0);

	status |= mock_expect (&keys.riot_keystore.mock, keys.riot_keystore.base.erase_key,
		&keys.riot_keystore, 0, MOCK_ARG (0));
	status |= mock_expect (&keys.riot_keystore.mock, keys.riot_keystore.base.erase_key,
		&keys.riot_keystore, 0, MOCK_ARG (1));
	status |= mock_expect (&keys.riot_keystore.mock, keys.riot_keystore.base.erase_key,
		&keys.riot_keystore, 0, MOCK_ARG (2));

	status |= mock_expect (&keys.aux_keystore.mock, keys.aux_keystore.base.erase_key,
		&keys.aux_keystore, 0, MOCK_ARG (0));

	status |= mock_expect (&recovery.mock, recovery.base.erase_all_recovery_regions,
		&recovery, 0);

	status |= mock_expect (&keystore1.mock, keystore1.base.erase_all_keys, &keystore1, 0);
	status |= mock_expect (&keystore2.mock, keystore2.base.erase_all_keys, &keystore2, 0);

	status |= mock_expect (&intrusion.mock, intrusion.base.handle_intrusion, &intrusion, 0);

	CuAssertIntEquals (test, 0, status);

	status = config_reset_restore_defaults (&reset);
	CuAssertIntEquals (test, 0, status);

	status = manifest_manager_mock_validate_and_release (&manifest);
	CuAssertIntEquals (test, 0, status);

	status = state_manager_mock_validate_and_release (&state);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_manager_mock_validate_and_release (&recovery);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_validate_and_release (&keystore1);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_validate_and_release (&keystore2);
	CuAssertIntEquals (test, 0, status);

	status = intrusion_manager_mock_validate_and_release (&intrusion);
	CuAssertIntEquals (test, 0, status);

	config_reset_testing_release_attestation_keys (test, &keys);

	config_reset_release (&reset);
}

static void config_reset_test_restore_defaults_no_manifests (CuTest *test)
{
	struct config_reset_testing_keys keys;
	struct config_reset reset;
	struct recovery_image_manager_mock recovery;
	struct keystore_mock keystore1;
	struct keystore_mock keystore2;
	struct keystore* keystore_array[] = {&keystore1.base, &keystore2.base};
	struct intrusion_manager_mock intrusion;
	int status;

	TEST_START;

	config_reset_testing_init_attestation_keys (test, &keys);

	status = recovery_image_manager_mock_init (&recovery);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_init (&keystore1);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_init (&keystore2);
	CuAssertIntEquals (test, 0, status);

	status = intrusion_manager_mock_init (&intrusion);
	CuAssertIntEquals (test, 0, status);

	status = config_reset_init (&reset, NULL, 0, NULL, 0, NULL, 0, &keys.riot, &keys.aux,
		&recovery.base, keystore_array, 2, &intrusion.base);
	CuAssertIntEquals (test, 0, status);

	status |= mock_expect (&keys.riot_keystore.mock, keys.riot_keystore.base.erase_key,
		&keys.riot_keystore, 0, MOCK_ARG (0));
	status |= mock_expect (&keys.riot_keystore.mock, keys.riot_keystore.base.erase_key,
		&keys.riot_keystore, 0, MOCK_ARG (1));
	status |= mock_expect (&keys.riot_keystore.mock, keys.riot_keystore.base.erase_key,
		&keys.riot_keystore, 0, MOCK_ARG (2));

	status |= mock_expect (&keys.aux_keystore.mock, keys.aux_keystore.base.erase_key,
		&keys.aux_keystore, 0, MOCK_ARG (0));

	status |= mock_expect (&recovery.mock, recovery.base.erase_all_recovery_regions,
		&recovery, 0);

	status |= mock_expect (&keystore1.mock, keystore1.base.erase_all_keys, &keystore1, 0);
	status |= mock_expect (&keystore2.mock, keystore2.base.erase_all_keys, &keystore2, 0);

	status |= mock_expect (&intrusion.mock, intrusion.base.handle_intrusion, &intrusion, 0);

	CuAssertIntEquals (test, 0, status);

	status = config_reset_restore_defaults (&reset);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_manager_mock_validate_and_release (&recovery);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_validate_and_release (&keystore1);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_validate_and_release (&keystore2);
	CuAssertIntEquals (test, 0, status);

	status = intrusion_manager_mock_validate_and_release (&intrusion);
	CuAssertIntEquals (test, 0, status);

	config_reset_testing_release_attestation_keys (test, &keys);

	config_reset_release (&reset);
}

static void config_reset_test_restore_defaults_no_state (CuTest *test)
{
	struct manifest_manager_mock manifest;
	struct manifest_manager_mock manifest_extra;
	struct config_reset_testing_keys keys;
	struct config_reset reset;
	int status;
	struct manifest_manager *bypass[1];
	struct manifest_manager *config[1];
	struct recovery_image_manager_mock recovery;
	struct keystore_mock keystore1;
	struct keystore_mock keystore2;
	struct keystore* keystore_array[] = {&keystore1.base, &keystore2.base};
	struct intrusion_manager_mock intrusion;

	TEST_START;

	status = manifest_manager_mock_init (&manifest);
	CuAssertIntEquals (test, 0, status);
	bypass[0] = &manifest.base;

	status = manifest_manager_mock_init (&manifest_extra);
	CuAssertIntEquals (test, 0, status);
	config[0] = &manifest_extra.base;

	status = recovery_image_manager_mock_init (&recovery);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_init (&keystore1);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_init (&keystore2);
	CuAssertIntEquals (test, 0, status);

	status = intrusion_manager_mock_init (&intrusion);
	CuAssertIntEquals (test, 0, status);

	config_reset_testing_init_attestation_keys (test, &keys);

	status = config_reset_init (&reset, bypass, 1, config, 1, NULL, 0, &keys.riot, &keys.aux,
		&recovery.base, keystore_array, 2, &intrusion.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manifest.mock, manifest.base.clear_all_manifests, &manifest, 0);
	status |= mock_expect (&manifest_extra.mock, manifest_extra.base.clear_all_manifests,
		&manifest_extra, 0);

	status |= mock_expect (&keys.riot_keystore.mock, keys.riot_keystore.base.erase_key,
		&keys.riot_keystore, 0, MOCK_ARG (0));
	status |= mock_expect (&keys.riot_keystore.mock, keys.riot_keystore.base.erase_key,
		&keys.riot_keystore, 0, MOCK_ARG (1));
	status |= mock_expect (&keys.riot_keystore.mock, keys.riot_keystore.base.erase_key,
		&keys.riot_keystore, 0, MOCK_ARG (2));

	status |= mock_expect (&keys.aux_keystore.mock, keys.aux_keystore.base.erase_key,
		&keys.aux_keystore, 0, MOCK_ARG (0));

	status |= mock_expect (&recovery.mock, recovery.base.erase_all_recovery_regions,
		&recovery, 0);

	status |= mock_expect (&keystore1.mock, keystore1.base.erase_all_keys, &keystore1, 0);
	status |= mock_expect (&keystore2.mock, keystore2.base.erase_all_keys, &keystore2, 0);

	status |= mock_expect (&intrusion.mock, intrusion.base.handle_intrusion, &intrusion, 0);

	CuAssertIntEquals (test, 0, status);

	status = config_reset_restore_defaults (&reset);
	CuAssertIntEquals (test, 0, status);

	status = manifest_manager_mock_validate_and_release (&manifest);
	CuAssertIntEquals (test, 0, status);

	status = manifest_manager_mock_validate_and_release (&manifest_extra);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_manager_mock_validate_and_release (&recovery);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_validate_and_release (&keystore1);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_validate_and_release (&keystore2);
	CuAssertIntEquals (test, 0, status);

	status = intrusion_manager_mock_validate_and_release (&intrusion);
	CuAssertIntEquals (test, 0, status);

	config_reset_testing_release_attestation_keys (test, &keys);

	config_reset_release (&reset);
}

static void config_reset_test_restore_defaults_no_riot (CuTest *test)
{
	struct manifest_manager_mock manifest;
	struct manifest_manager_mock manifest_extra;
	struct state_manager_mock state;
	struct config_reset_testing_keys keys;
	struct config_reset reset;
	int status;
	struct manifest_manager *bypass[1];
	struct manifest_manager *config[1];
	struct state_manager *state_list[1];
	struct recovery_image_manager_mock recovery;
	struct keystore_mock keystore1;
	struct keystore_mock keystore2;
	struct keystore* keystore_array[] = {&keystore1.base, &keystore2.base};
	struct intrusion_manager_mock intrusion;

	TEST_START;

	status = manifest_manager_mock_init (&manifest);
	CuAssertIntEquals (test, 0, status);
	bypass[0] = &manifest.base;

	status = manifest_manager_mock_init (&manifest_extra);
	CuAssertIntEquals (test, 0, status);
	config[0] = &manifest_extra.base;

	status = state_manager_mock_init (&state);
	state_list[0] = &state.base;

	status = recovery_image_manager_mock_init (&recovery);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_init (&keystore1);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_init (&keystore2);
	CuAssertIntEquals (test, 0, status);

	status = intrusion_manager_mock_init (&intrusion);
	CuAssertIntEquals (test, 0, status);

	config_reset_testing_init_attestation_keys (test, &keys);

	status = config_reset_init (&reset, bypass, 1, config, 1, state_list, 1, NULL,
		&keys.aux, &recovery.base, keystore_array, 2, &intrusion.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manifest.mock, manifest.base.clear_all_manifests, &manifest, 0);
	status |= mock_expect (&manifest_extra.mock, manifest_extra.base.clear_all_manifests,
		&manifest_extra, 0);
	status |= mock_expect (&state.mock, state.base.restore_default_state, &state, 0);

	status |= mock_expect (&keys.aux_keystore.mock, keys.aux_keystore.base.erase_key,
		&keys.aux_keystore, 0, MOCK_ARG (0));

	status |= mock_expect (&recovery.mock, recovery.base.erase_all_recovery_regions,
		&recovery, 0);

	status |= mock_expect (&keystore1.mock, keystore1.base.erase_all_keys, &keystore1, 0);
	status |= mock_expect (&keystore2.mock, keystore2.base.erase_all_keys, &keystore2, 0);

	status |= mock_expect (&intrusion.mock, intrusion.base.handle_intrusion, &intrusion, 0);

	CuAssertIntEquals (test, 0, status);

	status = config_reset_restore_defaults (&reset);
	CuAssertIntEquals (test, 0, status);

	status = manifest_manager_mock_validate_and_release (&manifest);
	CuAssertIntEquals (test, 0, status);

	status = manifest_manager_mock_validate_and_release (&manifest_extra);
	CuAssertIntEquals (test, 0, status);

	status = state_manager_mock_validate_and_release (&state);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_manager_mock_validate_and_release (&recovery);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_validate_and_release (&keystore1);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_validate_and_release (&keystore2);
	CuAssertIntEquals (test, 0, status);

	status = intrusion_manager_mock_validate_and_release (&intrusion);
	CuAssertIntEquals (test, 0, status);

	config_reset_testing_release_attestation_keys (test, &keys);

	config_reset_release (&reset);
}

static void config_reset_test_restore_defaults_no_aux (CuTest *test)
{
	struct manifest_manager_mock manifest;
	struct manifest_manager_mock manifest_extra;
	struct state_manager_mock state;
	struct config_reset_testing_keys keys;
	struct config_reset reset;
	int status;
	struct manifest_manager *bypass[1];
	struct manifest_manager *config[1];
	struct state_manager *state_list[1];
	struct recovery_image_manager_mock recovery;
	struct keystore_mock keystore1;
	struct keystore_mock keystore2;
	struct keystore* keystore_array[] = {&keystore1.base, &keystore2.base};
	struct intrusion_manager_mock intrusion;

	TEST_START;

	status = manifest_manager_mock_init (&manifest);
	CuAssertIntEquals (test, 0, status);
	bypass[0] = &manifest.base;

	status = manifest_manager_mock_init (&manifest_extra);
	CuAssertIntEquals (test, 0, status);
	config[0] = &manifest_extra.base;

	status = state_manager_mock_init (&state);
	state_list[0] = &state.base;

	status = recovery_image_manager_mock_init (&recovery);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_init (&keystore1);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_init (&keystore2);
	CuAssertIntEquals (test, 0, status);

	status = intrusion_manager_mock_init (&intrusion);
	CuAssertIntEquals (test, 0, status);

	config_reset_testing_init_attestation_keys (test, &keys);

	status = config_reset_init (&reset, bypass, 1, config, 1, state_list, 1, &keys.riot, NULL,
		&recovery.base, keystore_array, 2, &intrusion.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manifest.mock, manifest.base.clear_all_manifests, &manifest, 0);
	status |= mock_expect (&manifest_extra.mock, manifest_extra.base.clear_all_manifests,
		&manifest_extra, 0);
	status |= mock_expect (&state.mock, state.base.restore_default_state, &state, 0);

	status |= mock_expect (&keys.riot_keystore.mock, keys.riot_keystore.base.erase_key,
		&keys.riot_keystore, 0, MOCK_ARG (0));
	status |= mock_expect (&keys.riot_keystore.mock, keys.riot_keystore.base.erase_key,
		&keys.riot_keystore, 0, MOCK_ARG (1));
	status |= mock_expect (&keys.riot_keystore.mock, keys.riot_keystore.base.erase_key,
		&keys.riot_keystore, 0, MOCK_ARG (2));

	status |= mock_expect (&recovery.mock, recovery.base.erase_all_recovery_regions,
		&recovery, 0);

	status |= mock_expect (&keystore1.mock, keystore1.base.erase_all_keys, &keystore1, 0);
	status |= mock_expect (&keystore2.mock, keystore2.base.erase_all_keys, &keystore2, 0);

	status |= mock_expect (&intrusion.mock, intrusion.base.handle_intrusion, &intrusion, 0);

	CuAssertIntEquals (test, 0, status);

	status = config_reset_restore_defaults (&reset);
	CuAssertIntEquals (test, 0, status);

	status = manifest_manager_mock_validate_and_release (&manifest);
	CuAssertIntEquals (test, 0, status);

	status = manifest_manager_mock_validate_and_release (&manifest_extra);
	CuAssertIntEquals (test, 0, status);

	status = state_manager_mock_validate_and_release (&state);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_manager_mock_validate_and_release (&recovery);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_validate_and_release (&keystore1);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_validate_and_release (&keystore2);
	CuAssertIntEquals (test, 0, status);

	status = intrusion_manager_mock_validate_and_release (&intrusion);
	CuAssertIntEquals (test, 0, status);

	config_reset_testing_release_attestation_keys (test, &keys);

	config_reset_release (&reset);
}

static void config_reset_test_restore_defaults_no_recovery (CuTest *test)
{
	struct manifest_manager_mock manifest;
	struct manifest_manager_mock manifest_extra;
	struct state_manager_mock state;
	struct keystore_mock keystore1;
	struct keystore_mock keystore2;
	struct keystore* keystore_array[] = {&keystore1.base, &keystore2.base};
	struct intrusion_manager_mock intrusion;
	struct config_reset_testing_keys keys;
	struct config_reset reset;
	int status;
	struct manifest_manager *bypass[1];
	struct manifest_manager *config[1];
	struct state_manager *state_list[1];

	TEST_START;

	status = manifest_manager_mock_init (&manifest);
	CuAssertIntEquals (test, 0, status);
	bypass[0] = &manifest.base;

	status = manifest_manager_mock_init (&manifest_extra);
	CuAssertIntEquals (test, 0, status);
	config[0] = &manifest_extra.base;

	status = state_manager_mock_init (&state);
	state_list[0] = &state.base;

	status = keystore_mock_init (&keystore1);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_init (&keystore2);
	CuAssertIntEquals (test, 0, status);

	status = intrusion_manager_mock_init (&intrusion);
	CuAssertIntEquals (test, 0, status);

	config_reset_testing_init_attestation_keys (test, &keys);

	status = config_reset_init (&reset, bypass, 1, config, 1, state_list, 1, &keys.riot,
		&keys.aux, NULL, keystore_array, 2, &intrusion.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manifest.mock, manifest.base.clear_all_manifests, &manifest, 0);
	status |= mock_expect (&manifest_extra.mock, manifest_extra.base.clear_all_manifests,
		&manifest_extra, 0);
	status |= mock_expect (&state.mock, state.base.restore_default_state, &state, 0);

	status |= mock_expect (&keys.riot_keystore.mock, keys.riot_keystore.base.erase_key,
		&keys.riot_keystore, 0, MOCK_ARG (0));
	status |= mock_expect (&keys.riot_keystore.mock, keys.riot_keystore.base.erase_key,
		&keys.riot_keystore, 0, MOCK_ARG (1));
	status |= mock_expect (&keys.riot_keystore.mock, keys.riot_keystore.base.erase_key,
		&keys.riot_keystore, 0, MOCK_ARG (2));

	status |= mock_expect (&keys.aux_keystore.mock, keys.aux_keystore.base.erase_key,
		&keys.aux_keystore, 0, MOCK_ARG (0));

	status |= mock_expect (&keystore1.mock, keystore1.base.erase_all_keys, &keystore1, 0);
	status |= mock_expect (&keystore2.mock, keystore2.base.erase_all_keys, &keystore2, 0);

	status |= mock_expect (&intrusion.mock, intrusion.base.handle_intrusion, &intrusion, 0);

	CuAssertIntEquals (test, 0, status);

	status = config_reset_restore_defaults (&reset);
	CuAssertIntEquals (test, 0, status);

	status = manifest_manager_mock_validate_and_release (&manifest);
	CuAssertIntEquals (test, 0, status);

	status = manifest_manager_mock_validate_and_release (&manifest_extra);
	CuAssertIntEquals (test, 0, status);

	status = state_manager_mock_validate_and_release (&state);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_validate_and_release (&keystore1);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_validate_and_release (&keystore2);
	CuAssertIntEquals (test, 0, status);

	status = intrusion_manager_mock_validate_and_release (&intrusion);
	CuAssertIntEquals (test, 0, status);

	config_reset_testing_release_attestation_keys (test, &keys);

	config_reset_release (&reset);
}

static void config_reset_test_restore_defaults_no_keystore_array (CuTest *test)
{
	struct manifest_manager_mock manifest;
	struct manifest_manager_mock manifest_extra;
	struct state_manager_mock state;
	struct config_reset_testing_keys keys;
	struct config_reset reset;
	int status;
	struct manifest_manager *bypass[1];
	struct manifest_manager *config[1];
	struct state_manager *state_list[1];
	struct recovery_image_manager_mock recovery;
	struct intrusion_manager_mock intrusion;

	TEST_START;

	status = manifest_manager_mock_init (&manifest);
	CuAssertIntEquals (test, 0, status);
	bypass[0] = &manifest.base;

	status = manifest_manager_mock_init (&manifest_extra);
	CuAssertIntEquals (test, 0, status);
	config[0] = &manifest_extra.base;

	status = state_manager_mock_init (&state);
	state_list[0] = &state.base;

	status = recovery_image_manager_mock_init (&recovery);
	CuAssertIntEquals (test, 0, status);

	status = intrusion_manager_mock_init (&intrusion);
	CuAssertIntEquals (test, 0, status);

	config_reset_testing_init_attestation_keys (test, &keys);

	status = config_reset_init (&reset, bypass, 1, config, 1, state_list, 1, &keys.riot,
		&keys.aux, &recovery.base, NULL, 0, &intrusion.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manifest.mock, manifest.base.clear_all_manifests, &manifest, 0);
	status |= mock_expect (&manifest_extra.mock, manifest_extra.base.clear_all_manifests,
		&manifest_extra, 0);
	status |= mock_expect (&state.mock, state.base.restore_default_state, &state, 0);

	status |= mock_expect (&keys.riot_keystore.mock, keys.riot_keystore.base.erase_key,
		&keys.riot_keystore, 0, MOCK_ARG (0));
	status |= mock_expect (&keys.riot_keystore.mock, keys.riot_keystore.base.erase_key,
		&keys.riot_keystore, 0, MOCK_ARG (1));
	status |= mock_expect (&keys.riot_keystore.mock, keys.riot_keystore.base.erase_key,
		&keys.riot_keystore, 0, MOCK_ARG (2));

	status |= mock_expect (&keys.aux_keystore.mock, keys.aux_keystore.base.erase_key,
		&keys.aux_keystore, 0, MOCK_ARG (0));

	status |= mock_expect (&recovery.mock, recovery.base.erase_all_recovery_regions,
		&recovery, 0);

	status |= mock_expect (&intrusion.mock, intrusion.base.handle_intrusion, &intrusion, 0);

	CuAssertIntEquals (test, 0, status);

	status = config_reset_restore_defaults (&reset);
	CuAssertIntEquals (test, 0, status);

	status = manifest_manager_mock_validate_and_release (&manifest);
	CuAssertIntEquals (test, 0, status);

	status = manifest_manager_mock_validate_and_release (&manifest_extra);
	CuAssertIntEquals (test, 0, status);

	status = state_manager_mock_validate_and_release (&state);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_manager_mock_validate_and_release (&recovery);
	CuAssertIntEquals (test, 0, status);

	status = intrusion_manager_mock_validate_and_release (&intrusion);
	CuAssertIntEquals (test, 0, status);

	config_reset_testing_release_attestation_keys (test, &keys);

	config_reset_release (&reset);
}

static void config_reset_test_restore_defaults_no_intrusion (CuTest *test)
{
	struct manifest_manager_mock manifest;
	struct manifest_manager_mock manifest_extra;
	struct state_manager_mock state;
	struct config_reset_testing_keys keys;
	struct config_reset reset;
	int status;
	struct manifest_manager *bypass[1];
	struct manifest_manager *config[1];
	struct state_manager *state_list[1];
	struct recovery_image_manager_mock recovery;
	struct keystore_mock keystore1;
	struct keystore_mock keystore2;
	struct keystore* keystore_array[] = {&keystore1.base, &keystore2.base};

	TEST_START;

	status = manifest_manager_mock_init (&manifest);
	CuAssertIntEquals (test, 0, status);
	bypass[0] = &manifest.base;

	status = manifest_manager_mock_init (&manifest_extra);
	CuAssertIntEquals (test, 0, status);
	config[0] = &manifest_extra.base;

	status = state_manager_mock_init (&state);
	state_list[0] = &state.base;

	status = recovery_image_manager_mock_init (&recovery);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_init (&keystore1);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_init (&keystore2);
	CuAssertIntEquals (test, 0, status);

	config_reset_testing_init_attestation_keys (test, &keys);

	status = config_reset_init (&reset, bypass, 1, config, 1, state_list, 1, &keys.riot,
		&keys.aux, &recovery.base, keystore_array, 2, NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manifest.mock, manifest.base.clear_all_manifests, &manifest, 0);
	status |= mock_expect (&manifest_extra.mock, manifest_extra.base.clear_all_manifests,
		&manifest_extra, 0);
	status |= mock_expect (&state.mock, state.base.restore_default_state, &state, 0);

	status |= mock_expect (&keys.riot_keystore.mock, keys.riot_keystore.base.erase_key,
		&keys.riot_keystore, 0, MOCK_ARG (0));
	status |= mock_expect (&keys.riot_keystore.mock, keys.riot_keystore.base.erase_key,
		&keys.riot_keystore, 0, MOCK_ARG (1));
	status |= mock_expect (&keys.riot_keystore.mock, keys.riot_keystore.base.erase_key,
		&keys.riot_keystore, 0, MOCK_ARG (2));

	status |= mock_expect (&keys.aux_keystore.mock, keys.aux_keystore.base.erase_key,
		&keys.aux_keystore, 0, MOCK_ARG (0));

	status |= mock_expect (&recovery.mock, recovery.base.erase_all_recovery_regions,
		&recovery, 0);

	status |= mock_expect (&keystore1.mock, keystore1.base.erase_all_keys, &keystore1, 0);
	status |= mock_expect (&keystore2.mock, keystore2.base.erase_all_keys, &keystore2, 0);

	CuAssertIntEquals (test, 0, status);

	status = config_reset_restore_defaults (&reset);
	CuAssertIntEquals (test, 0, status);

	status = manifest_manager_mock_validate_and_release (&manifest);
	CuAssertIntEquals (test, 0, status);

	status = manifest_manager_mock_validate_and_release (&manifest_extra);
	CuAssertIntEquals (test, 0, status);

	status = state_manager_mock_validate_and_release (&state);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_manager_mock_validate_and_release (&recovery);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_validate_and_release (&keystore1);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_validate_and_release (&keystore2);
	CuAssertIntEquals (test, 0, status);

	config_reset_testing_release_attestation_keys (test, &keys);

	config_reset_release (&reset);
}

static void config_reset_test_restore_defaults_null (CuTest *test)
{
	int status;

	TEST_START;

	status = config_reset_restore_defaults (NULL);
	CuAssertIntEquals (test, CONFIG_RESET_INVALID_ARGUMENT, status);
}

static void config_reset_test_restore_defaults_bypass_clear_error (CuTest *test)
{
	struct manifest_manager_mock manifest1;
	struct manifest_manager_mock manifest2;
	struct manifest_manager_mock manifest3;
	struct manifest_manager_mock manifest_extra;
	struct state_manager_mock state1;
	struct state_manager_mock state2;
	struct state_manager_mock state3;
	struct config_reset_testing_keys keys;
	struct config_reset reset;
	int status;
	struct manifest_manager *bypass[3];
	struct manifest_manager *config[1];
	struct state_manager *state_list[3];
	struct recovery_image_manager_mock recovery;
	struct keystore_mock keystore1;
	struct keystore_mock keystore2;
	struct keystore* keystore_array[] = {&keystore1.base, &keystore2.base};
	struct intrusion_manager_mock intrusion;

	TEST_START;

	status = manifest_manager_mock_init (&manifest1);
	CuAssertIntEquals (test, 0, status);
	mock_set_name (&manifest1.mock, "manifest_manager1");
	bypass[0] = &manifest1.base;

	status = manifest_manager_mock_init (&manifest2);
	CuAssertIntEquals (test, 0, status);
	mock_set_name (&manifest2.mock, "manifest_manager2");
	bypass[1] = &manifest2.base;

	status = manifest_manager_mock_init (&manifest3);
	CuAssertIntEquals (test, 0, status);
	mock_set_name (&manifest3.mock, "manifest_manager3");
	bypass[2] = &manifest3.base;

	status = manifest_manager_mock_init (&manifest_extra);
	CuAssertIntEquals (test, 0, status);
	config[0] = &manifest_extra.base;

	status = state_manager_mock_init (&state1);
	state_list[0] = &state1.base;

	status = state_manager_mock_init (&state2);
	state_list[1] = &state2.base;

	status = state_manager_mock_init (&state3);
	state_list[2] = &state3.base;

	status = recovery_image_manager_mock_init (&recovery);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_init (&keystore1);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_init (&keystore2);
	CuAssertIntEquals (test, 0, status);

	status = intrusion_manager_mock_init (&intrusion);
	CuAssertIntEquals (test, 0, status);

	config_reset_testing_init_attestation_keys (test, &keys);

	status = config_reset_init (&reset, bypass, 3, config, 1, state_list, 3, &keys.riot,
		&keys.aux, &recovery.base, keystore_array, 2, &intrusion.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manifest1.mock, manifest1.base.clear_all_manifests, &manifest1, 0);
	status |= mock_expect (&manifest2.mock, manifest2.base.clear_all_manifests, &manifest2,
		MANIFEST_MANAGER_CLEAR_ALL_FAILED);

	CuAssertIntEquals (test, 0, status);

	status = config_reset_restore_defaults (&reset);
	CuAssertIntEquals (test, MANIFEST_MANAGER_CLEAR_ALL_FAILED, status);

	status = manifest_manager_mock_validate_and_release (&manifest1);
	CuAssertIntEquals (test, 0, status);

	status = manifest_manager_mock_validate_and_release (&manifest2);
	CuAssertIntEquals (test, 0, status);

	status = manifest_manager_mock_validate_and_release (&manifest3);
	CuAssertIntEquals (test, 0, status);

	status = manifest_manager_mock_validate_and_release (&manifest_extra);
	CuAssertIntEquals (test, 0, status);

	status = state_manager_mock_validate_and_release (&state1);
	CuAssertIntEquals (test, 0, status);

	status = state_manager_mock_validate_and_release (&state2);
	CuAssertIntEquals (test, 0, status);

	status = state_manager_mock_validate_and_release (&state3);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_manager_mock_validate_and_release (&recovery);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_validate_and_release (&keystore1);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_validate_and_release (&keystore2);
	CuAssertIntEquals (test, 0, status);

	status = intrusion_manager_mock_validate_and_release (&intrusion);
	CuAssertIntEquals (test, 0, status);

	config_reset_testing_release_attestation_keys (test, &keys);

	config_reset_release (&reset);
}

static void config_reset_test_restore_defaults_default_clear_error (CuTest *test)
{
	struct manifest_manager_mock manifest;
	struct manifest_manager_mock manifest_extra1;
	struct manifest_manager_mock manifest_extra2;
	struct manifest_manager_mock manifest_extra3;
	struct state_manager_mock state1;
	struct state_manager_mock state2;
	struct state_manager_mock state3;
	struct config_reset_testing_keys keys;
	struct config_reset reset;
	int status;
	struct manifest_manager *bypass[1];
	struct manifest_manager *config[3];
	struct state_manager *state_list[3];
	struct recovery_image_manager_mock recovery;
	struct keystore_mock keystore1;
	struct keystore_mock keystore2;
	struct keystore* keystore_array[] = {&keystore1.base, &keystore2.base};
	struct intrusion_manager_mock intrusion;

	TEST_START;

	status = manifest_manager_mock_init (&manifest);
	CuAssertIntEquals (test, 0, status);
	bypass[0] = &manifest.base;

	status = manifest_manager_mock_init (&manifest_extra1);
	CuAssertIntEquals (test, 0, status);
	mock_set_name (&manifest_extra1.mock, "manifest_manager1");
	config[0] = &manifest_extra1.base;

	status = manifest_manager_mock_init (&manifest_extra2);
	CuAssertIntEquals (test, 0, status);
	mock_set_name (&manifest_extra2.mock, "manifest_manager2");
	config[1] = &manifest_extra2.base;

	status = manifest_manager_mock_init (&manifest_extra3);
	CuAssertIntEquals (test, 0, status);
	mock_set_name (&manifest_extra3.mock, "manifest_manager3");
	config[2] = &manifest_extra3.base;

	status = state_manager_mock_init (&state1);
	state_list[0] = &state1.base;

	status = state_manager_mock_init (&state2);
	state_list[1] = &state2.base;

	status = state_manager_mock_init (&state3);
	state_list[2] = &state3.base;

	status = recovery_image_manager_mock_init (&recovery);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_init (&keystore1);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_init (&keystore2);
	CuAssertIntEquals (test, 0, status);

	status = intrusion_manager_mock_init (&intrusion);
	CuAssertIntEquals (test, 0, status);

	config_reset_testing_init_attestation_keys (test, &keys);

	status = config_reset_init (&reset, bypass, 1, config, 3, state_list, 3, &keys.riot,
		&keys.aux, &recovery.base, keystore_array, 2, &intrusion.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manifest.mock, manifest.base.clear_all_manifests, &manifest, 0);

	status |= mock_expect (&manifest_extra1.mock, manifest_extra1.base.clear_all_manifests,
		&manifest_extra1, 0);
	status |= mock_expect (&manifest_extra2.mock, manifest_extra2.base.clear_all_manifests,
		&manifest_extra2, MANIFEST_MANAGER_CLEAR_ALL_FAILED);

	CuAssertIntEquals (test, 0, status);

	status = config_reset_restore_defaults (&reset);
	CuAssertIntEquals (test, MANIFEST_MANAGER_CLEAR_ALL_FAILED, status);

	status = manifest_manager_mock_validate_and_release (&manifest);
	CuAssertIntEquals (test, 0, status);

	status = manifest_manager_mock_validate_and_release (&manifest_extra1);
	CuAssertIntEquals (test, 0, status);

	status = manifest_manager_mock_validate_and_release (&manifest_extra2);
	CuAssertIntEquals (test, 0, status);

	status = manifest_manager_mock_validate_and_release (&manifest_extra3);
	CuAssertIntEquals (test, 0, status);

	status = state_manager_mock_validate_and_release (&state1);
	CuAssertIntEquals (test, 0, status);

	status = state_manager_mock_validate_and_release (&state2);
	CuAssertIntEquals (test, 0, status);

	status = state_manager_mock_validate_and_release (&state3);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_manager_mock_validate_and_release (&recovery);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_validate_and_release (&keystore1);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_validate_and_release (&keystore2);
	CuAssertIntEquals (test, 0, status);

	status = intrusion_manager_mock_validate_and_release (&intrusion);
	CuAssertIntEquals (test, 0, status);

	config_reset_testing_release_attestation_keys (test, &keys);

	config_reset_release (&reset);
}

static void config_reset_test_restore_defaults_riot_erase_error (CuTest *test)
{
	struct manifest_manager_mock manifest;
	struct manifest_manager_mock manifest_extra;
	struct state_manager_mock state;
	struct config_reset_testing_keys keys;
	struct config_reset reset;
	int status;
	struct manifest_manager *bypass[1];
	struct manifest_manager *config[1];
	struct state_manager *state_list[1];
	struct recovery_image_manager_mock recovery;
	struct keystore_mock keystore1;
	struct keystore_mock keystore2;
	struct keystore* keystore_array[] = {&keystore1.base, &keystore2.base};
	struct intrusion_manager_mock intrusion;

	TEST_START;

	status = manifest_manager_mock_init (&manifest);
	CuAssertIntEquals (test, 0, status);
	bypass[0] = &manifest.base;

	status = manifest_manager_mock_init (&manifest_extra);
	CuAssertIntEquals (test, 0, status);
	config[0] = &manifest_extra.base;

	status = state_manager_mock_init (&state);
	state_list[0] = &state.base;

	status = recovery_image_manager_mock_init (&recovery);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_init (&keystore1);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_init (&keystore2);
	CuAssertIntEquals (test, 0, status);

	status = intrusion_manager_mock_init (&intrusion);
	CuAssertIntEquals (test, 0, status);

	config_reset_testing_init_attestation_keys (test, &keys);

	status = config_reset_init (&reset, bypass, 1, config, 1, state_list, 1, &keys.riot,
		&keys.aux, &recovery.base, keystore_array, 2, &intrusion.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manifest.mock, manifest.base.clear_all_manifests, &manifest, 0);
	status |= mock_expect (&manifest_extra.mock, manifest_extra.base.clear_all_manifests,
		&manifest_extra, 0);
	status |= mock_expect (&state.mock, state.base.restore_default_state, &state, 0);

	status |= mock_expect (&keys.riot_keystore.mock, keys.riot_keystore.base.erase_key,
		&keys.riot_keystore, KEYSTORE_ERASE_FAILED, MOCK_ARG (0));

	CuAssertIntEquals (test, 0, status);

	status = config_reset_restore_defaults (&reset);
	CuAssertIntEquals (test, KEYSTORE_ERASE_FAILED, status);

	status = manifest_manager_mock_validate_and_release (&manifest);
	CuAssertIntEquals (test, 0, status);

	status = manifest_manager_mock_validate_and_release (&manifest_extra);
	CuAssertIntEquals (test, 0, status);

	status = state_manager_mock_validate_and_release (&state);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_manager_mock_validate_and_release (&recovery);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_validate_and_release (&keystore1);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_validate_and_release (&keystore2);
	CuAssertIntEquals (test, 0, status);

	status = intrusion_manager_mock_validate_and_release (&intrusion);
	CuAssertIntEquals (test, 0, status);

	config_reset_testing_release_attestation_keys (test, &keys);

	config_reset_release (&reset);
}

static void config_reset_test_restore_defaults_aux_erase_error (CuTest *test)
{
	struct manifest_manager_mock manifest;
	struct manifest_manager_mock manifest_extra;
	struct state_manager_mock state;
	struct config_reset_testing_keys keys;
	struct config_reset reset;
	int status;
	struct manifest_manager *bypass[1];
	struct manifest_manager *config[1];
	struct state_manager *state_list[1];
	struct recovery_image_manager_mock recovery;
	struct keystore_mock keystore1;
	struct keystore_mock keystore2;
	struct keystore* keystore_array[] = {&keystore1.base, &keystore2.base};
	struct intrusion_manager_mock intrusion;

	TEST_START;

	status = manifest_manager_mock_init (&manifest);
	CuAssertIntEquals (test, 0, status);
	bypass[0] = &manifest.base;

	status = manifest_manager_mock_init (&manifest_extra);
	CuAssertIntEquals (test, 0, status);
	config[0] = &manifest_extra.base;

	status = state_manager_mock_init (&state);
	state_list[0] = &state.base;

	status = recovery_image_manager_mock_init (&recovery);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_init (&keystore1);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_init (&keystore2);
	CuAssertIntEquals (test, 0, status);

	status = intrusion_manager_mock_init (&intrusion);
	CuAssertIntEquals (test, 0, status);

	config_reset_testing_init_attestation_keys (test, &keys);

	status = config_reset_init (&reset, bypass, 1, config, 1, state_list, 1, &keys.riot,
		&keys.aux, &recovery.base, keystore_array, 2, &intrusion.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manifest.mock, manifest.base.clear_all_manifests, &manifest, 0);
	status |= mock_expect (&manifest_extra.mock, manifest_extra.base.clear_all_manifests,
		&manifest_extra, 0);
	status |= mock_expect (&state.mock, state.base.restore_default_state, &state, 0);

	status |= mock_expect (&keys.riot_keystore.mock, keys.riot_keystore.base.erase_key,
		&keys.riot_keystore, 0, MOCK_ARG (0));
	status |= mock_expect (&keys.riot_keystore.mock, keys.riot_keystore.base.erase_key,
		&keys.riot_keystore, 0, MOCK_ARG (1));
	status |= mock_expect (&keys.riot_keystore.mock, keys.riot_keystore.base.erase_key,
		&keys.riot_keystore, 0, MOCK_ARG (2));

	status |= mock_expect (&keys.aux_keystore.mock, keys.aux_keystore.base.erase_key,
		&keys.aux_keystore, KEYSTORE_ERASE_FAILED, MOCK_ARG (0));

	CuAssertIntEquals (test, 0, status);

	status = config_reset_restore_defaults (&reset);
	CuAssertIntEquals (test, KEYSTORE_ERASE_FAILED, status);

	status = manifest_manager_mock_validate_and_release (&manifest);
	CuAssertIntEquals (test, 0, status);

	status = manifest_manager_mock_validate_and_release (&manifest_extra);
	CuAssertIntEquals (test, 0, status);

	status = state_manager_mock_validate_and_release (&state);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_manager_mock_validate_and_release (&recovery);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_validate_and_release (&keystore1);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_validate_and_release (&keystore2);
	CuAssertIntEquals (test, 0, status);

	status = intrusion_manager_mock_validate_and_release (&intrusion);
	CuAssertIntEquals (test, 0, status);

	config_reset_testing_release_attestation_keys (test, &keys);

	config_reset_release (&reset);
}

static void config_reset_test_restore_defaults_recovery_in_use_error (CuTest *test)
{
	struct manifest_manager_mock manifest;
	struct manifest_manager_mock manifest_extra;
	struct state_manager_mock state;
	struct config_reset_testing_keys keys;
	struct config_reset reset;
	int status;
	struct manifest_manager *bypass[1];
	struct manifest_manager *config[1];
	struct state_manager *state_list[1];
	struct recovery_image_manager_mock recovery;
	struct keystore_mock keystore1;
	struct keystore_mock keystore2;
	struct keystore* keystore_array[] = {&keystore1.base, &keystore2.base};
	struct intrusion_manager_mock intrusion;

	TEST_START;

	status = manifest_manager_mock_init (&manifest);
	CuAssertIntEquals (test, 0, status);
	bypass[0] = &manifest.base;

	status = manifest_manager_mock_init (&manifest_extra);
	CuAssertIntEquals (test, 0, status);
	config[0] = &manifest_extra.base;

	status = state_manager_mock_init (&state);
	state_list[0] = &state.base;

	status = recovery_image_manager_mock_init (&recovery);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_init (&keystore1);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_init (&keystore2);
	CuAssertIntEquals (test, 0, status);

	status = intrusion_manager_mock_init (&intrusion);
	CuAssertIntEquals (test, 0, status);

	config_reset_testing_init_attestation_keys (test, &keys);

	status = config_reset_init (&reset, bypass, 1, config, 1, state_list, 1, &keys.riot,
		&keys.aux, &recovery.base, keystore_array, 2, &intrusion.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manifest.mock, manifest.base.clear_all_manifests, &manifest, 0);
	status |= mock_expect (&manifest_extra.mock, manifest_extra.base.clear_all_manifests,
		&manifest_extra, 0);
	status |= mock_expect (&state.mock, state.base.restore_default_state, &state, 0);

	status |= mock_expect (&keys.riot_keystore.mock, keys.riot_keystore.base.erase_key,
		&keys.riot_keystore, 0, MOCK_ARG (0));
	status |= mock_expect (&keys.riot_keystore.mock, keys.riot_keystore.base.erase_key,
		&keys.riot_keystore, 0, MOCK_ARG (1));
	status |= mock_expect (&keys.riot_keystore.mock, keys.riot_keystore.base.erase_key,
		&keys.riot_keystore, 0, MOCK_ARG (2));

	status |= mock_expect (&keys.aux_keystore.mock, keys.aux_keystore.base.erase_key,
		&keys.aux_keystore, 0, MOCK_ARG (0));

	status |= mock_expect (&recovery.mock, recovery.base.erase_all_recovery_regions,
		&recovery, RECOVERY_IMAGE_MANAGER_IMAGE_IN_USE);

	CuAssertIntEquals (test, 0, status);

	status = config_reset_restore_defaults (&reset);
	CuAssertIntEquals (test, RECOVERY_IMAGE_MANAGER_IMAGE_IN_USE, status);

	status = manifest_manager_mock_validate_and_release (&manifest);
	CuAssertIntEquals (test, 0, status);

	status = manifest_manager_mock_validate_and_release (&manifest_extra);
	CuAssertIntEquals (test, 0, status);

	status = state_manager_mock_validate_and_release (&state);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_manager_mock_validate_and_release (&recovery);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_validate_and_release (&keystore1);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_validate_and_release (&keystore2);
	CuAssertIntEquals (test, 0, status);

	status = intrusion_manager_mock_validate_and_release (&intrusion);
	CuAssertIntEquals (test, 0, status);

	config_reset_testing_release_attestation_keys (test, &keys);

	config_reset_release (&reset);
}

static void config_reset_test_restore_defaults_keystore_array_erase_error (CuTest *test)
{
	struct manifest_manager_mock manifest;
	struct manifest_manager_mock manifest_extra;
	struct state_manager_mock state;
	struct config_reset_testing_keys keys;
	struct config_reset reset;
	int status;
	struct manifest_manager *bypass[1];
	struct manifest_manager *config[1];
	struct state_manager *state_list[1];
	struct recovery_image_manager_mock recovery;
	struct keystore_mock keystore1;
	struct keystore_mock keystore2;
	struct keystore* keystore_array[] = {&keystore1.base, &keystore2.base};
	struct intrusion_manager_mock intrusion;

	TEST_START;

	status = manifest_manager_mock_init (&manifest);
	CuAssertIntEquals (test, 0, status);
	bypass[0] = &manifest.base;

	status = manifest_manager_mock_init (&manifest_extra);
	CuAssertIntEquals (test, 0, status);
	config[0] = &manifest_extra.base;

	status = state_manager_mock_init (&state);
	state_list[0] = &state.base;

	status = recovery_image_manager_mock_init (&recovery);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_init (&keystore1);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_init (&keystore2);
	CuAssertIntEquals (test, 0, status);

	status = intrusion_manager_mock_init (&intrusion);
	CuAssertIntEquals (test, 0, status);

	config_reset_testing_init_attestation_keys (test, &keys);

	status = config_reset_init (&reset, bypass, 1, config, 1, state_list, 1, &keys.riot,
		&keys.aux, &recovery.base, keystore_array, 2, &intrusion.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manifest.mock, manifest.base.clear_all_manifests, &manifest, 0);
	status |= mock_expect (&manifest_extra.mock, manifest_extra.base.clear_all_manifests,
		&manifest_extra, 0);
	status |= mock_expect (&state.mock, state.base.restore_default_state, &state, 0);

	status |= mock_expect (&keys.riot_keystore.mock, keys.riot_keystore.base.erase_key,
		&keys.riot_keystore, 0, MOCK_ARG (0));
	status |= mock_expect (&keys.riot_keystore.mock, keys.riot_keystore.base.erase_key,
		&keys.riot_keystore, 0, MOCK_ARG (1));
	status |= mock_expect (&keys.riot_keystore.mock, keys.riot_keystore.base.erase_key,
		&keys.riot_keystore, 0, MOCK_ARG (2));

	status |= mock_expect (&keys.aux_keystore.mock, keys.aux_keystore.base.erase_key,
		&keys.aux_keystore, 0, MOCK_ARG (0));

	status |= mock_expect (&recovery.mock, recovery.base.erase_all_recovery_regions,
		&recovery, 0);

	status |= mock_expect (&keystore1.mock, keystore1.base.erase_all_keys, &keystore1,
		KEYSTORE_NO_MEMORY);

	CuAssertIntEquals (test, 0, status);

	status = config_reset_restore_defaults (&reset);
	CuAssertIntEquals (test, KEYSTORE_NO_MEMORY, status);

	status = manifest_manager_mock_validate_and_release (&manifest);
	CuAssertIntEquals (test, 0, status);

	status = manifest_manager_mock_validate_and_release (&manifest_extra);
	CuAssertIntEquals (test, 0, status);

	status = state_manager_mock_validate_and_release (&state);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_manager_mock_validate_and_release (&recovery);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_validate_and_release (&keystore1);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_validate_and_release (&keystore2);
	CuAssertIntEquals (test, 0, status);

	status = intrusion_manager_mock_validate_and_release (&intrusion);
	CuAssertIntEquals (test, 0, status);

	config_reset_testing_release_attestation_keys (test, &keys);

	config_reset_release (&reset);
}

static void config_reset_test_restore_defaults_intrusion_error (CuTest *test)
{
	struct manifest_manager_mock manifest;
	struct manifest_manager_mock manifest_extra;
	struct state_manager_mock state;
	struct config_reset_testing_keys keys;
	struct config_reset reset;
	int status;
	struct manifest_manager *bypass[1];
	struct manifest_manager *config[1];
	struct state_manager *state_list[1];
	struct recovery_image_manager_mock recovery;
	struct keystore_mock keystore1;
	struct keystore_mock keystore2;
	struct keystore* keystore_array[] = {&keystore1.base, &keystore2.base};
	struct intrusion_manager_mock intrusion;

	TEST_START;

	status = manifest_manager_mock_init (&manifest);
	CuAssertIntEquals (test, 0, status);
	bypass[0] = &manifest.base;

	status = manifest_manager_mock_init (&manifest_extra);
	CuAssertIntEquals (test, 0, status);
	config[0] = &manifest_extra.base;

	status = state_manager_mock_init (&state);
	state_list[0] = &state.base;

	status = recovery_image_manager_mock_init (&recovery);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_init (&keystore1);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_init (&keystore2);
	CuAssertIntEquals (test, 0, status);

	status = intrusion_manager_mock_init (&intrusion);
	CuAssertIntEquals (test, 0, status);

	config_reset_testing_init_attestation_keys (test, &keys);

	status = config_reset_init (&reset, bypass, 1, config, 1, state_list, 1, &keys.riot,
		&keys.aux, &recovery.base, keystore_array, 2, &intrusion.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manifest.mock, manifest.base.clear_all_manifests, &manifest, 0);
	status |= mock_expect (&manifest_extra.mock, manifest_extra.base.clear_all_manifests,
		&manifest_extra, 0);
	status |= mock_expect (&state.mock, state.base.restore_default_state, &state, 0);

	status |= mock_expect (&keys.riot_keystore.mock, keys.riot_keystore.base.erase_key,
		&keys.riot_keystore, 0, MOCK_ARG (0));
	status |= mock_expect (&keys.riot_keystore.mock, keys.riot_keystore.base.erase_key,
		&keys.riot_keystore, 0, MOCK_ARG (1));
	status |= mock_expect (&keys.riot_keystore.mock, keys.riot_keystore.base.erase_key,
		&keys.riot_keystore, 0, MOCK_ARG (2));

	status |= mock_expect (&keys.aux_keystore.mock, keys.aux_keystore.base.erase_key,
		&keys.aux_keystore, 0, MOCK_ARG (0));

	status |= mock_expect (&recovery.mock, recovery.base.erase_all_recovery_regions,
		&recovery, 0);

	status |= mock_expect (&keystore1.mock, keystore1.base.erase_all_keys, &keystore1, 0);
	status |= mock_expect (&keystore2.mock, keystore2.base.erase_all_keys, &keystore2, 0);

	status |= mock_expect (&intrusion.mock, intrusion.base.handle_intrusion, &intrusion,
		INTRUSION_MANAGER_RESET_FAILED);

	CuAssertIntEquals (test, 0, status);

	status = config_reset_restore_defaults (&reset);
	CuAssertIntEquals (test, INTRUSION_MANAGER_RESET_FAILED, status);

	status = manifest_manager_mock_validate_and_release (&manifest);
	CuAssertIntEquals (test, 0, status);

	status = manifest_manager_mock_validate_and_release (&manifest_extra);
	CuAssertIntEquals (test, 0, status);

	status = state_manager_mock_validate_and_release (&state);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_manager_mock_validate_and_release (&recovery);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_validate_and_release (&keystore1);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_validate_and_release (&keystore2);
	CuAssertIntEquals (test, 0, status);

	status = intrusion_manager_mock_validate_and_release (&intrusion);
	CuAssertIntEquals (test, 0, status);

	config_reset_testing_release_attestation_keys (test, &keys);

	config_reset_release (&reset);
}

static void config_reset_test_restore_platform_config (CuTest *test)
{
	struct manifest_manager_mock manifest;
	struct manifest_manager_mock manifest_extra;
	struct state_manager_mock state;
	struct config_reset_testing_keys keys;
	struct config_reset reset;
	int status;
	struct manifest_manager *bypass[1];
	struct manifest_manager *config[1];
	struct state_manager *state_list[1];
	struct recovery_image_manager_mock recovery;
	struct keystore_mock keystore1;
	struct keystore_mock keystore2;
	struct keystore* keystore_array[] = {&keystore1.base, &keystore2.base};
	struct intrusion_manager_mock intrusion;

	TEST_START;

	status = manifest_manager_mock_init (&manifest);
	CuAssertIntEquals (test, 0, status);
	config[0] = &manifest.base;

	status = manifest_manager_mock_init (&manifest_extra);
	CuAssertIntEquals (test, 0, status);
	bypass[0] = &manifest_extra.base;

	status = state_manager_mock_init (&state);
	state_list[0] = &state.base;

	status = recovery_image_manager_mock_init (&recovery);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_init (&keystore1);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_init (&keystore2);
	CuAssertIntEquals (test, 0, status);

	status = intrusion_manager_mock_init (&intrusion);
	CuAssertIntEquals (test, 0, status);

	config_reset_testing_init_attestation_keys (test, &keys);

	status = config_reset_init (&reset, bypass, 1, config, 1, state_list, 1, &keys.riot,
		&keys.aux, &recovery.base, keystore_array, 2, &intrusion.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manifest.mock, manifest.base.clear_all_manifests, &manifest, 0);
	CuAssertIntEquals (test, 0, status);

	status = config_reset_restore_platform_config (&reset);
	CuAssertIntEquals (test, 0, status);

	status = manifest_manager_mock_validate_and_release (&manifest);
	CuAssertIntEquals (test, 0, status);

	status = manifest_manager_mock_validate_and_release (&manifest_extra);
	CuAssertIntEquals (test, 0, status);

	status = state_manager_mock_validate_and_release (&state);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_manager_mock_validate_and_release (&recovery);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_validate_and_release (&keystore1);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_validate_and_release (&keystore2);
	CuAssertIntEquals (test, 0, status);

	status = intrusion_manager_mock_validate_and_release (&intrusion);
	CuAssertIntEquals (test, 0, status);

	config_reset_testing_release_attestation_keys (test, &keys);

	config_reset_release (&reset);
}

static void config_reset_test_restore_platform_config_multiple (CuTest *test)
{
	struct manifest_manager_mock manifest1;
	struct manifest_manager_mock manifest2;
	struct manifest_manager_mock manifest3;
	struct manifest_manager_mock manifest_extra;
	struct state_manager_mock state;
	struct config_reset_testing_keys keys;
	struct config_reset reset;
	int status;
	struct manifest_manager *bypass[1];
	struct manifest_manager *config[3];
	struct state_manager *state_list[1];
	struct recovery_image_manager_mock recovery;
	struct keystore_mock keystore1;
	struct keystore_mock keystore2;
	struct keystore* keystore_array[] = {&keystore1.base, &keystore2.base};
	struct intrusion_manager_mock intrusion;

	TEST_START;

	status = manifest_manager_mock_init (&manifest1);
	CuAssertIntEquals (test, 0, status);
	mock_set_name (&manifest1.mock, "manifest_manager1");
	config[0] = &manifest1.base;

	status = manifest_manager_mock_init (&manifest2);
	CuAssertIntEquals (test, 0, status);
	mock_set_name (&manifest2.mock, "manifest_manager2");
	config[1] = &manifest2.base;

	status = manifest_manager_mock_init (&manifest3);
	CuAssertIntEquals (test, 0, status);
	mock_set_name (&manifest3.mock, "manifest_manager3");
	config[2] = &manifest3.base;

	status = manifest_manager_mock_init (&manifest_extra);
	CuAssertIntEquals (test, 0, status);
	bypass[0] = &manifest_extra.base;

	status = state_manager_mock_init (&state);
	state_list[0] = &state.base;

	status = recovery_image_manager_mock_init (&recovery);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_init (&keystore1);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_init (&keystore2);
	CuAssertIntEquals (test, 0, status);

	status = intrusion_manager_mock_init (&intrusion);
	CuAssertIntEquals (test, 0, status);

	config_reset_testing_init_attestation_keys (test, &keys);

	status = config_reset_init (&reset, bypass, 1, config, 3, state_list, 1, &keys.riot,
		&keys.aux, &recovery.base, keystore_array, 2, &intrusion.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manifest1.mock, manifest1.base.clear_all_manifests, &manifest1, 0);
	status |= mock_expect (&manifest2.mock, manifest2.base.clear_all_manifests, &manifest2, 0);
	status |= mock_expect (&manifest3.mock, manifest3.base.clear_all_manifests, &manifest3, 0);

	CuAssertIntEquals (test, 0, status);

	status = config_reset_restore_platform_config (&reset);
	CuAssertIntEquals (test, 0, status);

	status = manifest_manager_mock_validate_and_release (&manifest1);
	CuAssertIntEquals (test, 0, status);

	status = manifest_manager_mock_validate_and_release (&manifest2);
	CuAssertIntEquals (test, 0, status);

	status = manifest_manager_mock_validate_and_release (&manifest3);
	CuAssertIntEquals (test, 0, status);

	status = manifest_manager_mock_validate_and_release (&manifest_extra);
	CuAssertIntEquals (test, 0, status);

	status = state_manager_mock_validate_and_release (&state);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_manager_mock_validate_and_release (&recovery);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_validate_and_release (&keystore1);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_validate_and_release (&keystore2);
	CuAssertIntEquals (test, 0, status);

	status = intrusion_manager_mock_validate_and_release (&intrusion);
	CuAssertIntEquals (test, 0, status);

	config_reset_testing_release_attestation_keys (test, &keys);

	config_reset_release (&reset);
}

static void config_reset_test_restore_platform_config_no_manifests (CuTest *test)
{
	struct manifest_manager_mock manifest_extra;
	struct config_reset_testing_keys keys;
	struct config_reset reset;
	int status;
	struct manifest_manager *bypass[1];
	struct recovery_image_manager_mock recovery;
	struct keystore_mock keystore1;
	struct keystore_mock keystore2;
	struct keystore* keystore_array[] = {&keystore1.base, &keystore2.base};
	struct intrusion_manager_mock intrusion;

	TEST_START;

	status = manifest_manager_mock_init (&manifest_extra);
	CuAssertIntEquals (test, 0, status);
	bypass[0] = &manifest_extra.base;

	status = recovery_image_manager_mock_init (&recovery);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_init (&keystore1);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_init (&keystore2);
	CuAssertIntEquals (test, 0, status);

	status = intrusion_manager_mock_init (&intrusion);
	CuAssertIntEquals (test, 0, status);

	config_reset_testing_init_attestation_keys (test, &keys);

	status = config_reset_init (&reset, bypass, 1, NULL, 0, NULL, 0, &keys.riot, &keys.aux,
		&recovery.base, keystore_array, 2, &intrusion.base);
	CuAssertIntEquals (test, 0, status);

	status = config_reset_restore_platform_config (&reset);
	CuAssertIntEquals (test, CONFIG_RESET_NO_MANIFESTS, status);

	status = manifest_manager_mock_validate_and_release (&manifest_extra);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_manager_mock_validate_and_release (&recovery);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_validate_and_release (&keystore1);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_validate_and_release (&keystore2);
	CuAssertIntEquals (test, 0, status);

	status = intrusion_manager_mock_validate_and_release (&intrusion);
	CuAssertIntEquals (test, 0, status);

	config_reset_testing_release_attestation_keys (test, &keys);

	config_reset_release (&reset);
}

static void config_reset_test_restore_platform_config_null (CuTest *test)
{
	struct manifest_manager_mock manifest;
	struct state_manager_mock state;
	struct config_reset_testing_keys keys;
	struct config_reset reset;
	int status;
	struct manifest_manager *config[1];
	struct state_manager *state_list[1];
	struct recovery_image_manager_mock recovery;
	struct keystore_mock keystore1;
	struct keystore_mock keystore2;
	struct keystore* keystore_array[] = {&keystore1.base, &keystore2.base};
	struct intrusion_manager_mock intrusion;

	TEST_START;

	status = manifest_manager_mock_init (&manifest);
	CuAssertIntEquals (test, 0, status);
	config[0] = &manifest.base;

	status = state_manager_mock_init (&state);
	state_list[0] = &state.base;

	status = recovery_image_manager_mock_init (&recovery);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_init (&keystore1);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_init (&keystore2);
	CuAssertIntEquals (test, 0, status);

	status = intrusion_manager_mock_init (&intrusion);
	CuAssertIntEquals (test, 0, status);

	config_reset_testing_init_attestation_keys (test, &keys);

	status = config_reset_init (&reset, config, 1, config, 1, state_list, 1, &keys.riot,
		&keys.aux, &recovery.base, keystore_array, 2, &intrusion.base);
	CuAssertIntEquals (test, 0, status);

	status = config_reset_restore_platform_config (NULL);
	CuAssertIntEquals (test, CONFIG_RESET_INVALID_ARGUMENT, status);

	status = manifest_manager_mock_validate_and_release (&manifest);
	CuAssertIntEquals (test, 0, status);

	status = state_manager_mock_validate_and_release (&state);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_manager_mock_validate_and_release (&recovery);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_validate_and_release (&keystore1);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_validate_and_release (&keystore2);
	CuAssertIntEquals (test, 0, status);

	status = intrusion_manager_mock_validate_and_release (&intrusion);
	CuAssertIntEquals (test, 0, status);

	config_reset_testing_release_attestation_keys (test, &keys);

	config_reset_release (&reset);
}

static void config_reset_test_restore_platform_config_clear_error (CuTest *test)
{
	struct manifest_manager_mock manifest1;
	struct manifest_manager_mock manifest2;
	struct manifest_manager_mock manifest3;
	struct manifest_manager_mock manifest_extra;
	struct state_manager_mock state;
	struct config_reset_testing_keys keys;
	struct config_reset reset;
	int status;
	struct manifest_manager *bypass[1];
	struct manifest_manager *config[3];
	struct state_manager *state_list[1];
	struct recovery_image_manager_mock recovery;
	struct keystore_mock keystore1;
	struct keystore_mock keystore2;
	struct keystore* keystore_array[] = {&keystore1.base, &keystore2.base};
	struct intrusion_manager_mock intrusion;

	TEST_START;

	status = manifest_manager_mock_init (&manifest1);
	CuAssertIntEquals (test, 0, status);
	mock_set_name (&manifest1.mock, "manifest_manager1");
	config[0] = &manifest1.base;

	status = manifest_manager_mock_init (&manifest2);
	CuAssertIntEquals (test, 0, status);
	mock_set_name (&manifest2.mock, "manifest_manager2");
	config[1] = &manifest2.base;

	status = manifest_manager_mock_init (&manifest3);
	CuAssertIntEquals (test, 0, status);
	mock_set_name (&manifest3.mock, "manifest_manager3");
	config[2] = &manifest3.base;

	status = manifest_manager_mock_init (&manifest_extra);
	CuAssertIntEquals (test, 0, status);
	bypass[0] = &manifest_extra.base;

	status = state_manager_mock_init (&state);
	state_list[0] = &state.base;

	status = recovery_image_manager_mock_init (&recovery);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_init (&keystore1);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_init (&keystore2);
	CuAssertIntEquals (test, 0, status);

	status = intrusion_manager_mock_init (&intrusion);
	CuAssertIntEquals (test, 0, status);

	config_reset_testing_init_attestation_keys (test, &keys);

	status = config_reset_init (&reset, bypass, 1, config, 3, state_list, 1, &keys.riot,
		&keys.aux, &recovery.base, keystore_array, 2, &intrusion.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manifest1.mock, manifest1.base.clear_all_manifests, &manifest1, 0);
	status |= mock_expect (&manifest2.mock, manifest2.base.clear_all_manifests, &manifest2,
		MANIFEST_MANAGER_CLEAR_ALL_FAILED);

	CuAssertIntEquals (test, 0, status);

	status = config_reset_restore_platform_config (&reset);
	CuAssertIntEquals (test, MANIFEST_MANAGER_CLEAR_ALL_FAILED, status);

	status = manifest_manager_mock_validate_and_release (&manifest1);
	CuAssertIntEquals (test, 0, status);

	status = manifest_manager_mock_validate_and_release (&manifest2);
	CuAssertIntEquals (test, 0, status);

	status = manifest_manager_mock_validate_and_release (&manifest3);
	CuAssertIntEquals (test, 0, status);

	status = manifest_manager_mock_validate_and_release (&manifest_extra);
	CuAssertIntEquals (test, 0, status);

	status = state_manager_mock_validate_and_release (&state);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_manager_mock_validate_and_release (&recovery);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_validate_and_release (&keystore1);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_validate_and_release (&keystore2);
	CuAssertIntEquals (test, 0, status);

	status = intrusion_manager_mock_validate_and_release (&intrusion);
	CuAssertIntEquals (test, 0, status);

	config_reset_testing_release_attestation_keys (test, &keys);

	config_reset_release (&reset);
}

static void config_reset_test_reset_intrusion (CuTest *test)
{
	struct manifest_manager_mock manifest;
	struct manifest_manager_mock manifest_extra;
	struct state_manager_mock state;
	struct config_reset_testing_keys keys;
	struct config_reset reset;
	int status;
	struct manifest_manager *bypass[1];
	struct manifest_manager *config[1];
	struct state_manager *state_list[1];
	struct recovery_image_manager_mock recovery;
	struct keystore_mock keystore1;
	struct keystore_mock keystore2;
	struct keystore* keystore_array[] = {&keystore1.base, &keystore2.base};
	struct intrusion_manager_mock intrusion;

	TEST_START;

	status = manifest_manager_mock_init (&manifest);
	CuAssertIntEquals (test, 0, status);
	config[0] = &manifest.base;

	status = manifest_manager_mock_init (&manifest_extra);
	CuAssertIntEquals (test, 0, status);
	bypass[0] = &manifest_extra.base;

	status = state_manager_mock_init (&state);
	state_list[0] = &state.base;

	status = recovery_image_manager_mock_init (&recovery);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_init (&keystore1);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_init (&keystore2);
	CuAssertIntEquals (test, 0, status);

	status = intrusion_manager_mock_init (&intrusion);
	CuAssertIntEquals (test, 0, status);

	config_reset_testing_init_attestation_keys (test, &keys);

	status = config_reset_init (&reset, bypass, 1, config, 1, state_list, 1, &keys.riot,
		&keys.aux, &recovery.base, keystore_array, 2, &intrusion.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&intrusion.mock, intrusion.base.reset_intrusion, &intrusion, 0);
	CuAssertIntEquals (test, 0, status);

	status = config_reset_reset_intrusion (&reset);
	CuAssertIntEquals (test, 0, status);

	status = manifest_manager_mock_validate_and_release (&manifest);
	CuAssertIntEquals (test, 0, status);

	status = manifest_manager_mock_validate_and_release (&manifest_extra);
	CuAssertIntEquals (test, 0, status);

	status = state_manager_mock_validate_and_release (&state);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_manager_mock_validate_and_release (&recovery);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_validate_and_release (&keystore1);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_validate_and_release (&keystore2);
	CuAssertIntEquals (test, 0, status);

	status = intrusion_manager_mock_validate_and_release (&intrusion);
	CuAssertIntEquals (test, 0, status);

	config_reset_testing_release_attestation_keys (test, &keys);

	config_reset_release (&reset);
}

static void config_reset_test_reset_intrusion_null (CuTest *test)
{
	struct manifest_manager_mock manifest;
	struct state_manager_mock state;
	struct config_reset_testing_keys keys;
	struct config_reset reset;
	int status;
	struct manifest_manager *config[1];
	struct state_manager *state_list[1];
	struct recovery_image_manager_mock recovery;
	struct keystore_mock keystore1;
	struct keystore_mock keystore2;
	struct keystore* keystore_array[] = {&keystore1.base, &keystore2.base};
	struct intrusion_manager_mock intrusion;

	TEST_START;

	status = manifest_manager_mock_init (&manifest);
	CuAssertIntEquals (test, 0, status);
	config[0] = &manifest.base;

	status = state_manager_mock_init (&state);
	state_list[0] = &state.base;

	status = recovery_image_manager_mock_init (&recovery);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_init (&keystore1);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_init (&keystore2);
	CuAssertIntEquals (test, 0, status);

	status = intrusion_manager_mock_init (&intrusion);
	CuAssertIntEquals (test, 0, status);

	config_reset_testing_init_attestation_keys (test, &keys);

	status = config_reset_init (&reset, config, 1, config, 1, state_list, 1, &keys.riot,
		&keys.aux, &recovery.base, keystore_array, 2, &intrusion.base);
	CuAssertIntEquals (test, 0, status);

	status = config_reset_reset_intrusion (NULL);
	CuAssertIntEquals (test, CONFIG_RESET_INVALID_ARGUMENT, status);

	status = manifest_manager_mock_validate_and_release (&manifest);
	CuAssertIntEquals (test, 0, status);

	status = state_manager_mock_validate_and_release (&state);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_manager_mock_validate_and_release (&recovery);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_validate_and_release (&keystore1);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_validate_and_release (&keystore2);
	CuAssertIntEquals (test, 0, status);

	status = intrusion_manager_mock_validate_and_release (&intrusion);
	CuAssertIntEquals (test, 0, status);

	config_reset_testing_release_attestation_keys (test, &keys);

	config_reset_release (&reset);
}

static void config_reset_test_reset_intrusion_null_intrusion (CuTest *test)
{
	struct manifest_manager_mock manifest;
	struct state_manager_mock state;
	struct config_reset_testing_keys keys;
	struct config_reset reset;
	int status;
	struct manifest_manager *config[1];
	struct state_manager *state_list[1];
	struct recovery_image_manager_mock recovery;
	struct keystore_mock keystore1;
	struct keystore_mock keystore2;
	struct keystore* keystore_array[] = {&keystore1.base, &keystore2.base};

	TEST_START;

	status = manifest_manager_mock_init (&manifest);
	CuAssertIntEquals (test, 0, status);
	config[0] = &manifest.base;

	status = state_manager_mock_init (&state);
	state_list[0] = &state.base;

	status = recovery_image_manager_mock_init (&recovery);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_init (&keystore1);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_init (&keystore2);
	CuAssertIntEquals (test, 0, status);

	config_reset_testing_init_attestation_keys (test, &keys);

	status = config_reset_init (&reset, config, 1, config, 1, state_list, 1, &keys.riot,
		&keys.aux, &recovery.base, keystore_array, 2, NULL);
	CuAssertIntEquals (test, 0, status);

	status = config_reset_reset_intrusion (&reset);
	CuAssertIntEquals (test, 0, status);

	status = manifest_manager_mock_validate_and_release (&manifest);
	CuAssertIntEquals (test, 0, status);

	status = state_manager_mock_validate_and_release (&state);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_manager_mock_validate_and_release (&recovery);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_validate_and_release (&keystore1);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_validate_and_release (&keystore2);
	CuAssertIntEquals (test, 0, status);

	config_reset_testing_release_attestation_keys (test, &keys);

	config_reset_release (&reset);
}

static void config_reset_test_reset_intrusion_reset_error (CuTest *test)
{
	struct manifest_manager_mock manifest;
	struct state_manager_mock state;
	struct config_reset_testing_keys keys;
	struct config_reset reset;
	int status;
	struct manifest_manager *config[1];
	struct state_manager *state_list[1];
	struct recovery_image_manager_mock recovery;
	struct keystore_mock keystore1;
	struct keystore_mock keystore2;
	struct keystore* keystore_array[] = {&keystore1.base, &keystore2.base};
	struct intrusion_manager_mock intrusion;

	TEST_START;

	status = manifest_manager_mock_init (&manifest);
	CuAssertIntEquals (test, 0, status);
	config[0] = &manifest.base;

	status = state_manager_mock_init (&state);
	state_list[0] = &state.base;

	status = recovery_image_manager_mock_init (&recovery);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_init (&keystore1);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_init (&keystore2);
	CuAssertIntEquals (test, 0, status);

	status = intrusion_manager_mock_init (&intrusion);
	CuAssertIntEquals (test, 0, status);

	config_reset_testing_init_attestation_keys (test, &keys);

	status = config_reset_init (&reset, config, 1, config, 1, state_list, 1, &keys.riot,
		&keys.aux, &recovery.base, keystore_array, 2, &intrusion.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&intrusion.mock, intrusion.base.reset_intrusion, &intrusion,
		INTRUSION_MANAGER_RESET_FAILED);
	CuAssertIntEquals (test, 0, status);

	status = config_reset_reset_intrusion (&reset);
	CuAssertIntEquals (test, INTRUSION_MANAGER_RESET_FAILED, status);

	status = manifest_manager_mock_validate_and_release (&manifest);
	CuAssertIntEquals (test, 0, status);

	status = state_manager_mock_validate_and_release (&state);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_manager_mock_validate_and_release (&recovery);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_validate_and_release (&keystore1);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_validate_and_release (&keystore2);
	CuAssertIntEquals (test, 0, status);

	status = intrusion_manager_mock_validate_and_release (&intrusion);
	CuAssertIntEquals (test, 0, status);

	config_reset_testing_release_attestation_keys (test, &keys);

	config_reset_release (&reset);
}


TEST_SUITE_START (config_reset);

TEST (config_reset_test_init);
TEST (config_reset_test_init_no_state);
TEST (config_reset_test_init_no_manifests);
TEST (config_reset_test_init_no_bypass_manifests);
TEST (config_reset_test_init_no_default_manifests);
TEST (config_reset_test_init_no_riot);
TEST (config_reset_test_init_no_aux);
TEST (config_reset_test_init_no_recovery);
TEST (config_reset_test_init_no_keystores);
TEST (config_reset_test_init_no_intrusion);
TEST (config_reset_test_init_null);
TEST (config_reset_test_init_no_manifests_with_state);
TEST (config_reset_test_restore_bypass);
TEST (config_reset_test_restore_bypass_multiple);
TEST (config_reset_test_restore_bypass_no_manifests);
TEST (config_reset_test_restore_bypass_null);
TEST (config_reset_test_restore_bypass_clear_error);
TEST (config_reset_test_restore_defaults);
TEST (config_reset_test_restore_defaults_multiple_bypass);
TEST (config_reset_test_restore_defaults_multiple_default);
TEST (config_reset_test_restore_defaults_no_bypass_manifests);
TEST (config_reset_test_restore_defaults_no_default_manifests);
TEST (config_reset_test_restore_defaults_no_manifests);
TEST (config_reset_test_restore_defaults_no_state);
TEST (config_reset_test_restore_defaults_no_riot);
TEST (config_reset_test_restore_defaults_no_aux);
TEST (config_reset_test_restore_defaults_no_recovery);
TEST (config_reset_test_restore_defaults_no_keystore_array);
TEST (config_reset_test_restore_defaults_no_intrusion);
TEST (config_reset_test_restore_defaults_null);
TEST (config_reset_test_restore_defaults_bypass_clear_error);
TEST (config_reset_test_restore_defaults_default_clear_error);
TEST (config_reset_test_restore_defaults_riot_erase_error);
TEST (config_reset_test_restore_defaults_aux_erase_error);
TEST (config_reset_test_restore_defaults_recovery_in_use_error);
TEST (config_reset_test_restore_defaults_keystore_array_erase_error);
TEST (config_reset_test_restore_defaults_intrusion_error);
TEST (config_reset_test_restore_platform_config);
TEST (config_reset_test_restore_platform_config_multiple);
TEST (config_reset_test_restore_platform_config_no_manifests);
TEST (config_reset_test_restore_platform_config_null);
TEST (config_reset_test_restore_platform_config_clear_error);
TEST (config_reset_test_reset_intrusion);
TEST (config_reset_test_reset_intrusion_null);
TEST (config_reset_test_reset_intrusion_null_intrusion);
TEST (config_reset_test_reset_intrusion_reset_error);

TEST_SUITE_END;
