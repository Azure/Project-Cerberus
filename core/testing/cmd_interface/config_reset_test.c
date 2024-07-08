// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "testing.h"
#include "cmd_interface/config_reset.h"
#include "cmd_interface/config_reset_static.h"
#include "testing/asn1/x509_testing.h"
#include "testing/cmd_interface/config_reset_testing.h"
#include "testing/mock/manifest/manifest_manager_mock.h"
#include "testing/mock/recovery/recovery_image_manager_mock.h"
#include "testing/mock/state_manager/state_manager_mock.h"
#include "testing/riot/riot_core_testing.h"


TEST_SUITE_LABEL ("config_reset");


/**
 * Dependencies for testing the configuration reset manager.
 */
struct config_reset_testing {
	struct manifest_manager_mock manifest_bypass[3];		/**< Bypass manifest managers. */
	struct manifest_manager_mock manifest_config[3];		/**< Platform config manifest managers. */
	struct manifest_manager_mock manifest_components[3];	/**< Component manifest managers. */
	struct state_manager_mock state[3];						/**< State managers to for reset testing. */
	struct config_reset_testing_keys keys;					/**< Handling of attestation keys. */
	struct recovery_image_manager_mock recovery;			/**< Manager for host recovery image.  */
	struct keystore_mock keystore[2];						/**< Keystores containing config to clear. */
	const struct manifest_manager *bypass[3];				/**< List of bypass manifests. */
	const struct manifest_manager *config[3];				/**< List of platform config manifests. */
	const struct manifest_manager *component[3];			/**< List of component manifests. */
	struct state_manager *state_list[3];					/**< List of state managers. */
	const struct keystore *keystore_array[2];				/**< List of keystores. */
	struct config_reset test;								/**< Configuration reset manager under test. */
};


/**
 * Initialize the RIoT and attestation key managers.
 *
 * @param test The testing framework.
 * @param keys Key management components.
 */
void config_reset_testing_init_attestation_keys (CuTest *test,
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
	mock_set_name (&keys->riot_keystore.mock, "riot_keystore");

	status = keystore_mock_init (&keys->aux_keystore);
	CuAssertIntEquals (test, 0, status);
	mock_set_name (&keys->aux_keystore.mock, "aux_keystore");

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
 * Initialize the RIoT and attestation key managers.  The device ID is signed by a root CA.
 *
 * @param test The testing framework.
 * @param keys Key management components.
 */
void config_reset_testing_init_attestation_keys_valid_cert_chain (CuTest *test,
	struct config_reset_testing_keys *keys)
{
	struct riot_keys riot_core;
	int status;
	uint8_t *dev_id_der;
	uint8_t *ca_der;
	uint8_t *int_der = NULL;

	riot_core.devid_csr = RIOT_CORE_DEVID_CSR;
	riot_core.devid_csr_length = RIOT_CORE_DEVID_CSR_LEN;

	riot_core.devid_cert = RIOT_CORE_DEVID_CERT;
	riot_core.devid_cert_length = RIOT_CORE_DEVID_CERT_LEN;

	riot_core.alias_key = RIOT_CORE_ALIAS_KEY;
	riot_core.alias_key_length = RIOT_CORE_ALIAS_KEY_LEN;

	riot_core.alias_cert = RIOT_CORE_ALIAS_CERT;
	riot_core.alias_cert_length = RIOT_CORE_ALIAS_CERT_LEN;

	dev_id_der = platform_malloc (RIOT_CORE_DEVID_SIGNED_CERT_LEN);
	CuAssertPtrNotNull (test, dev_id_der);

	ca_der = platform_malloc (X509_CERTSS_ECC_CA_NOPL_DER_LEN);
	CuAssertPtrNotNull (test, ca_der);

	memcpy (dev_id_der, RIOT_CORE_DEVID_SIGNED_CERT, RIOT_CORE_DEVID_SIGNED_CERT_LEN);
	memcpy (ca_der, X509_CERTSS_ECC_CA_NOPL_DER, X509_CERTSS_ECC_CA_NOPL_DER_LEN);

	status = X509_TESTING_ENGINE_INIT (&keys->x509);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&keys->rsa);
	CuAssertIntEquals (test, 0, status);

	status = ECC_TESTING_ENGINE_INIT (&keys->ecc);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_init (&keys->riot_keystore);
	CuAssertIntEquals (test, 0, status);
	mock_set_name (&keys->riot_keystore.mock, "riot_keystore");

	status = keystore_mock_init (&keys->aux_keystore);
	CuAssertIntEquals (test, 0, status);
	mock_set_name (&keys->aux_keystore.mock, "aux_keystore");

	status = mock_expect (&keys->riot_keystore.mock, keys->riot_keystore.base.load_key,
		&keys->riot_keystore, 0, MOCK_ARG (0), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&keys->riot_keystore.mock, 1, &dev_id_der, sizeof (dev_id_der),
		-1);
	status |= mock_expect_output (&keys->riot_keystore.mock, 2, &RIOT_CORE_DEVID_SIGNED_CERT_LEN,
		sizeof (RIOT_CORE_DEVID_SIGNED_CERT_LEN), -1);

	status |= mock_expect (&keys->riot_keystore.mock, keys->riot_keystore.base.load_key,
		&keys->riot_keystore, 0, MOCK_ARG (1), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&keys->riot_keystore.mock, 1, &ca_der, sizeof (ca_der), -1);
	status |= mock_expect_output (&keys->riot_keystore.mock, 2, &X509_CERTSS_ECC_CA_NOPL_DER_LEN,
		sizeof (X509_CERTSS_ECC_CA_NOPL_DER_LEN), -1);

	status |= mock_expect (&keys->riot_keystore.mock, keys->riot_keystore.base.load_key,
		&keys->riot_keystore, KEYSTORE_NO_KEY, MOCK_ARG (2), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&keys->riot_keystore.mock, 1, &int_der, sizeof (int_der), -1);

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
 *
 * @return 0 if the mocks were validated successful or 1 if not.
 */
int config_reset_testing_release_attestation_keys (CuTest *test,
	struct config_reset_testing_keys *keys)
{
	int status;

	status = keystore_mock_validate_and_release (&keys->riot_keystore);
	status |= keystore_mock_validate_and_release (&keys->aux_keystore);

	riot_key_manager_release (&keys->riot);
	aux_attestation_release (&keys->aux);

	X509_TESTING_ENGINE_RELEASE (&keys->x509);
	RSA_TESTING_ENGINE_RELEASE (&keys->rsa);
	ECC_TESTING_ENGINE_RELEASE (&keys->ecc);

	return status;
}

/**
 * Helper to initialize all dependencies for testing.
 *
 * @param test The test framework.
 * @param reset Testing dependencies to initialize.
 */
static void config_reset_testing_init_dependencies (CuTest *test,
	struct config_reset_testing *reset)
{
	size_t i;
	const char *bypass_name[] = {
		"manifest_bypass[0]", "manifest_bypass[1]", "manifest_bypass[2]"
	};
	const char *config_name[] = {
		"manifest_config[0]", "manifest_config[1]", "manifest_config[2]"
	};
	const char *components_name[] = {
		"manifest_components[0]", "manifest_components[1]", "manifest_components[2]"
	};
	const char *state_name[] = {
		"state[0]", "state[1]", "state[2]"
	};
	const char *keystore_name[] = {
		"keystore[0]", "keystore[1]"
	};
	int status;

	for (i = 0; i < 3; i++) {
		status = manifest_manager_mock_init (&reset->manifest_bypass[i]);
		CuAssertIntEquals (test, 0, status);
		mock_set_name (&reset->manifest_bypass[i].mock, bypass_name[i]);
		reset->bypass[i] = &reset->manifest_bypass[i].base;

		status = manifest_manager_mock_init (&reset->manifest_config[i]);
		CuAssertIntEquals (test, 0, status);
		mock_set_name (&reset->manifest_config[i].mock, config_name[i]);
		reset->config[i] = &reset->manifest_config[i].base;

		status = manifest_manager_mock_init (&reset->manifest_components[i]);
		CuAssertIntEquals (test, 0, status);
		mock_set_name (&reset->manifest_components[i].mock, components_name[i]);
		reset->component[i] = &reset->manifest_components[i].base;

		status = state_manager_mock_init (&reset->state[i]);
		CuAssertIntEquals (test, 0, status);
		mock_set_name (&reset->state[i].mock, state_name[i]);
		reset->state_list[i] = &reset->state[i].base;

		if (i != 2) {
			status = keystore_mock_init (&reset->keystore[i]);
			CuAssertIntEquals (test, 0, status);
			mock_set_name (&reset->keystore[i].mock, keystore_name[i]);
			reset->keystore_array[i] = &reset->keystore[i].base;
		}
	}

	status = recovery_image_manager_mock_init (&reset->recovery);
	CuAssertIntEquals (test, 0, status);

	config_reset_testing_init_attestation_keys (test, &reset->keys);
}

/**
 * Helper to release all testing dependencies.
 *
 * @param test The test framework.
 * @param reset Testing dependencies to release.
 */
static void config_reset_testing_release_dependencies (CuTest *test,
	struct config_reset_testing *reset)
{
	size_t i;
	int status = 0;

	for (i = 0; i < 3; i++) {
		status |= manifest_manager_mock_validate_and_release (&reset->manifest_bypass[i]);
		status |= manifest_manager_mock_validate_and_release (&reset->manifest_config[i]);
		status |= manifest_manager_mock_validate_and_release (&reset->manifest_components[i]);
		status |= state_manager_mock_validate_and_release (&reset->state[i]);

		if (i != 2) {
			status |= keystore_mock_validate_and_release (&reset->keystore[i]);
		}
	}

	status |= recovery_image_manager_mock_validate_and_release (&reset->recovery);
	status |= config_reset_testing_release_attestation_keys (test, &reset->keys);

	CuAssertIntEquals (test, 0, status);
}

/**
 * Initialize a configuration reset handler for testing.
 *
 * @param test The test framework.
 * @param reset Testing dependencies.
 */
static void config_reset_testing_init (CuTest *test, struct config_reset_testing *reset)
{
	int status;

	config_reset_testing_init_dependencies (test, reset);

	status = config_reset_init (&reset->test, reset->bypass, 1, reset->config, 1, reset->component,
		1, reset->state_list, 1, &reset->keys.riot, &reset->keys.aux, &reset->recovery.base,
		reset->keystore_array, 2);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Release configuration reset test components.
 *
 * @param test The test framework.
 * @param reset Testing dependencies to release.
 */
static void config_reset_testing_release (CuTest *test, struct config_reset_testing *reset)
{
	config_reset_release (&reset->test);
	config_reset_testing_release_dependencies (test, reset);
}


/*******************
 * Test cases
 *******************/

static void config_reset_test_init (CuTest *test)
{
	struct config_reset_testing reset;
	int status;

	TEST_START;

	config_reset_testing_init_dependencies (test, &reset);

	status = config_reset_init (&reset.test, reset.bypass, 1, reset.config, 1, reset.component, 1,
		reset.state_list, 1, &reset.keys.riot, &reset.keys.aux, &reset.recovery.base,
		reset.keystore_array, 2);
	CuAssertIntEquals (test, 0, status);

	config_reset_testing_release (test, &reset);
}

static void config_reset_test_init_no_state (CuTest *test)
{
	struct config_reset_testing reset;
	int status;

	TEST_START;

	config_reset_testing_init_dependencies (test, &reset);

	status = config_reset_init (&reset.test, reset.bypass, 1, reset.config, 1, reset.component, 1,
		NULL, 0, &reset.keys.riot, &reset.keys.aux, &reset.recovery.base, reset.keystore_array, 2);
	CuAssertIntEquals (test, 0, status);

	config_reset_testing_release (test, &reset);
}

static void config_reset_test_init_no_manifests (CuTest *test)
{
	struct config_reset_testing reset;
	int status;

	TEST_START;

	config_reset_testing_init_dependencies (test, &reset);

	status = config_reset_init (&reset.test, NULL, 0, NULL, 0, NULL, 0, NULL, 0, &reset.keys.riot,
		&reset.keys.aux, &reset.recovery.base, reset.keystore_array, 2);
	CuAssertIntEquals (test, 0, status);

	config_reset_testing_release (test, &reset);
}

static void config_reset_test_init_no_bypass_manifests (CuTest *test)
{
	struct config_reset_testing reset;
	int status;

	TEST_START;

	config_reset_testing_init_dependencies (test, &reset);

	status = config_reset_init (&reset.test, NULL, 0, reset.config, 1, reset.component, 1,
		reset.state_list, 1, &reset.keys.riot, &reset.keys.aux, &reset.recovery.base,
		reset.keystore_array, 2);
	CuAssertIntEquals (test, 0, status);

	config_reset_testing_release (test, &reset);
}

static void config_reset_test_init_no_default_manifests (CuTest *test)
{
	struct config_reset_testing reset;
	int status;

	TEST_START;

	config_reset_testing_init_dependencies (test, &reset);

	status = config_reset_init (&reset.test, reset.bypass, 1, NULL, 0, reset.component, 1,
		reset.state_list, 1, &reset.keys.riot, &reset.keys.aux, &reset.recovery.base,
		reset.keystore_array, 2);
	CuAssertIntEquals (test, 0, status);

	config_reset_testing_release (test, &reset);
}

static void config_reset_test_init_no_riot (CuTest *test)
{
	struct config_reset_testing reset;
	int status;

	TEST_START;

	config_reset_testing_init_dependencies (test, &reset);

	status = config_reset_init (&reset.test, reset.bypass, 1, reset.config, 1, reset.component, 1,
		reset.state_list, 1, NULL, &reset.keys.aux, &reset.recovery.base, reset.keystore_array, 2);
	CuAssertIntEquals (test, 0, status);

	config_reset_testing_release (test, &reset);
}

static void config_reset_test_init_no_aux (CuTest *test)
{
	struct config_reset_testing reset;
	int status;

	TEST_START;

	config_reset_testing_init_dependencies (test, &reset);

	status = config_reset_init (&reset.test, reset.bypass, 1, reset.config, 1, reset.component, 1,
		reset.state_list, 1, &reset.keys.riot, NULL, &reset.recovery.base, reset.keystore_array, 2);
	CuAssertIntEquals (test, 0, status);

	config_reset_testing_release (test, &reset);
}

static void config_reset_test_init_no_recovery (CuTest *test)
{
	struct config_reset_testing reset;
	int status;

	TEST_START;

	config_reset_testing_init_dependencies (test, &reset);

	status = config_reset_init (&reset.test, reset.bypass, 1, reset.config, 1, reset.component, 1,
		reset.state_list, 1, &reset.keys.riot, &reset.keys.aux, NULL, reset.keystore_array, 2);
	CuAssertIntEquals (test, 0, status);

	config_reset_testing_release (test, &reset);
}

static void config_reset_test_init_no_keystores (CuTest *test)
{
	struct config_reset_testing reset;
	int status;

	TEST_START;

	config_reset_testing_init_dependencies (test, &reset);

	status = config_reset_init (&reset.test, reset.bypass, 1, reset.config, 1, reset.component, 1,
		reset.state_list, 1, &reset.keys.riot, &reset.keys.aux, &reset.recovery.base, NULL, 0);
	CuAssertIntEquals (test, 0, status);

	config_reset_testing_release (test, &reset);
}

static void config_reset_test_init_null (CuTest *test)
{
	struct config_reset_testing reset;
	int status;

	TEST_START;

	config_reset_testing_init_dependencies (test, &reset);

	status = config_reset_init (NULL, reset.bypass, 1, reset.config, 1, reset.component, 1,
		reset.state_list, 1, &reset.keys.riot, &reset.keys.aux, &reset.recovery.base,
		reset.keystore_array, 2);
	CuAssertIntEquals (test, CONFIG_RESET_INVALID_ARGUMENT, status);

	status = config_reset_init (&reset.test, NULL, 1, reset.config, 1, reset.component, 1,
		reset.state_list, 1, &reset.keys.riot, &reset.keys.aux, &reset.recovery.base,
		reset.keystore_array, 2);
	CuAssertIntEquals (test, CONFIG_RESET_INVALID_ARGUMENT, status);

	status = config_reset_init (&reset.test, reset.bypass, 1, NULL, 1, reset.component, 1,
		reset.state_list, 1, &reset.keys.riot, &reset.keys.aux, &reset.recovery.base,
		reset.keystore_array, 2);
	CuAssertIntEquals (test, CONFIG_RESET_INVALID_ARGUMENT, status);

	status = config_reset_init (&reset.test, reset.bypass, 1, reset.config, 1, NULL, 1,
		reset.state_list, 1, &reset.keys.riot, &reset.keys.aux, &reset.recovery.base,
		reset.keystore_array, 2);
	CuAssertIntEquals (test, CONFIG_RESET_INVALID_ARGUMENT, status);

	status = config_reset_init (&reset.test, reset.bypass, 1, reset.config, 1, reset.component, 1,
		NULL, 1, &reset.keys.riot, &reset.keys.aux, &reset.recovery.base, reset.keystore_array, 2);
	CuAssertIntEquals (test, CONFIG_RESET_INVALID_ARGUMENT, status);

	status = config_reset_init (&reset.test, reset.bypass, 1, reset.config, 1, reset.component, 1,
		reset.state_list, 1, &reset.keys.riot, &reset.keys.aux, &reset.recovery.base, NULL, 2);
	CuAssertIntEquals (test, CONFIG_RESET_INVALID_ARGUMENT, status);

	config_reset_testing_release_dependencies (test, &reset);
}

static void config_reset_test_init_no_manifests_with_state (CuTest *test)
{
	struct config_reset_testing reset;
	int status;

	TEST_START;

	config_reset_testing_init_dependencies (test, &reset);

	status = config_reset_init (&reset.test, NULL, 0, NULL, 0, NULL, 0, reset.state_list, 1,
		&reset.keys.riot, &reset.keys.aux, &reset.recovery.base, reset.keystore_array, 2);
	CuAssertIntEquals (test, CONFIG_RESET_NO_MANIFESTS, status);

	config_reset_testing_release_dependencies (test, &reset);
}

static void config_reset_test_static_init (CuTest *test)
{
	struct config_reset_testing reset = {
		.test = config_reset_static_init (reset.bypass, 1, reset.config, 1, reset.component, 1,
			reset.state_list, 1, &reset.keys.riot, &reset.keys.aux, &reset.recovery.base,
			reset.keystore_array, 2)
	};

	TEST_START;

	config_reset_testing_init_dependencies (test, &reset);

	config_reset_testing_release (test, &reset);
}

static void config_reset_test_release_null (CuTest *test)
{
	TEST_START;

	config_reset_release (NULL);
}

static void config_reset_test_restore_bypass (CuTest *test)
{
	struct config_reset_testing reset;
	int status;

	TEST_START;

	config_reset_testing_init (test, &reset);

	status = mock_expect (&reset.manifest_bypass[0].mock,
		reset.manifest_bypass[0].base.clear_all_manifests, &reset.manifest_bypass[0], 0);
	CuAssertIntEquals (test, 0, status);

	status = config_reset_restore_bypass (&reset.test);
	CuAssertIntEquals (test, 0, status);

	config_reset_testing_release (test, &reset);
}

static void config_reset_test_restore_bypass_multiple (CuTest *test)
{
	struct config_reset_testing reset;
	int status;

	TEST_START;

	config_reset_testing_init_dependencies (test, &reset);

	status = config_reset_init (&reset.test, reset.bypass, 3, reset.config, 1, reset.component, 1,
		reset.state_list, 1, &reset.keys.riot, &reset.keys.aux, &reset.recovery.base,
		reset.keystore_array, 2);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&reset.manifest_bypass[0].mock,
		reset.manifest_bypass[0].base.clear_all_manifests, &reset.manifest_bypass[0], 0);
	status |= mock_expect (&reset.manifest_bypass[1].mock,
		reset.manifest_bypass[1].base.clear_all_manifests, &reset.manifest_bypass[1], 0);
	status |= mock_expect (&reset.manifest_bypass[2].mock,
		reset.manifest_bypass[2].base.clear_all_manifests, &reset.manifest_bypass[2], 0);

	CuAssertIntEquals (test, 0, status);

	status = config_reset_restore_bypass (&reset.test);
	CuAssertIntEquals (test, 0, status);

	config_reset_testing_release (test, &reset);
}

static void config_reset_test_restore_bypass_no_manifests (CuTest *test)
{
	struct config_reset_testing reset;
	int status;

	TEST_START;

	config_reset_testing_init_dependencies (test, &reset);

	status = config_reset_init (&reset.test, NULL, 0, reset.config, 1, NULL, 0, NULL, 0,
		&reset.keys.riot, &reset.keys.aux, &reset.recovery.base, reset.keystore_array, 2);
	CuAssertIntEquals (test, 0, status);

	status = config_reset_restore_bypass (&reset.test);
	CuAssertIntEquals (test, CONFIG_RESET_NO_MANIFESTS, status);

	config_reset_testing_release (test, &reset);
}

static void config_reset_test_restore_bypass_static_init (CuTest *test)
{
	struct config_reset_testing reset = {
		.test = config_reset_static_init (reset.bypass, 1, reset.config, 1, reset.component, 1,
			reset.state_list, 1, &reset.keys.riot, &reset.keys.aux, &reset.recovery.base,
			reset.keystore_array, 2)
	};
	int status;

	TEST_START;

	config_reset_testing_init_dependencies (test, &reset);

	status = mock_expect (&reset.manifest_bypass[0].mock,
		reset.manifest_bypass[0].base.clear_all_manifests, &reset.manifest_bypass[0], 0);
	CuAssertIntEquals (test, 0, status);

	status = config_reset_restore_bypass (&reset.test);
	CuAssertIntEquals (test, 0, status);

	config_reset_testing_release (test, &reset);
}

static void config_reset_test_restore_bypass_null (CuTest *test)
{
	struct config_reset_testing reset;
	int status;

	TEST_START;

	config_reset_testing_init (test, &reset);

	status = config_reset_restore_bypass (NULL);
	CuAssertIntEquals (test, CONFIG_RESET_INVALID_ARGUMENT, status);

	config_reset_testing_release (test, &reset);
}

static void config_reset_test_restore_bypass_clear_error (CuTest *test)
{
	struct config_reset_testing reset;
	int status;

	TEST_START;

	config_reset_testing_init_dependencies (test, &reset);

	status = config_reset_init (&reset.test, reset.bypass, 3, reset.config, 1, reset.component, 1,
		reset.state_list, 1, &reset.keys.riot, &reset.keys.aux, &reset.recovery.base,
		reset.keystore_array, 2);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&reset.manifest_bypass[0].mock,
		reset.manifest_bypass[0].base.clear_all_manifests, &reset.manifest_bypass[0], 0);
	status |= mock_expect (&reset.manifest_bypass[1].mock,
		reset.manifest_bypass[1].base.clear_all_manifests, &reset.manifest_bypass[1],
		MANIFEST_MANAGER_CLEAR_ALL_FAILED);

	CuAssertIntEquals (test, 0, status);

	status = config_reset_restore_bypass (&reset.test);
	CuAssertIntEquals (test, MANIFEST_MANAGER_CLEAR_ALL_FAILED, status);

	config_reset_testing_release (test, &reset);
}

static void config_reset_test_restore_defaults (CuTest *test)
{
	struct config_reset_testing reset;
	int status;

	TEST_START;

	config_reset_testing_init (test, &reset);

	status = mock_expect (&reset.manifest_bypass[0].mock,
		reset.manifest_bypass[0].base.clear_all_manifests, &reset.manifest_bypass[0], 0);
	status |= mock_expect (&reset.manifest_config[0].mock,
		reset.manifest_config[0].base.clear_all_manifests, &reset.manifest_config[0], 0);
	status |= mock_expect (&reset.manifest_components[0].mock,
		reset.manifest_components[0].base.clear_all_manifests, &reset.manifest_components[0], 0);
	status |= mock_expect (&reset.state[0].mock, reset.state[0].base.restore_default_state,
		&reset.state[0], 0);

	status |= mock_expect (&reset.keys.riot_keystore.mock, reset.keys.riot_keystore.base.erase_key,
		&reset.keys.riot_keystore, 0, MOCK_ARG (0));
	status |= mock_expect (&reset.keys.riot_keystore.mock, reset.keys.riot_keystore.base.erase_key,
		&reset.keys.riot_keystore, 0, MOCK_ARG (1));
	status |= mock_expect (&reset.keys.riot_keystore.mock, reset.keys.riot_keystore.base.erase_key,
		&reset.keys.riot_keystore, 0, MOCK_ARG (2));

	status |= mock_expect (&reset.keys.aux_keystore.mock, reset.keys.aux_keystore.base.erase_key,
		&reset.keys.aux_keystore, 0, MOCK_ARG (0));

	status |= mock_expect (&reset.recovery.mock, reset.recovery.base.erase_all_recovery_regions,
		&reset.recovery, 0);

	status |= mock_expect (&reset.keystore[0].mock, reset.keystore[0].base.erase_all_keys,
		&reset.keystore[0], 0);
	status |= mock_expect (&reset.keystore[1].mock, reset.keystore[1].base.erase_all_keys,
		&reset.keystore[1], 0);

	CuAssertIntEquals (test, 0, status);

	status = config_reset_restore_defaults (&reset.test);
	CuAssertIntEquals (test, 0, status);

	config_reset_testing_release (test, &reset);
}

static void config_reset_test_restore_defaults_multiple_bypass (CuTest *test)
{
	struct config_reset_testing reset;
	int status;

	TEST_START;

	config_reset_testing_init_dependencies (test, &reset);

	status = config_reset_init (&reset.test, reset.bypass, 3, reset.config, 1, reset.component, 1,
		reset.state_list, 3, &reset.keys.riot, &reset.keys.aux, &reset.recovery.base,
		reset.keystore_array, 2);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&reset.manifest_bypass[0].mock,
		reset.manifest_bypass[0].base.clear_all_manifests, &reset.manifest_bypass[0], 0);
	status |= mock_expect (&reset.manifest_bypass[1].mock,
		reset.manifest_bypass[1].base.clear_all_manifests, &reset.manifest_bypass[1], 0);
	status |= mock_expect (&reset.manifest_bypass[2].mock,
		reset.manifest_bypass[2].base.clear_all_manifests, &reset.manifest_bypass[2], 0);

	status |= mock_expect (&reset.manifest_config[0].mock,
		reset.manifest_config[0].base.clear_all_manifests, &reset.manifest_config[0], 0);

	status |= mock_expect (&reset.manifest_components[0].mock,
		reset.manifest_components[0].base.clear_all_manifests, &reset.manifest_components[0], 0);

	status |= mock_expect (&reset.state[0].mock, reset.state[0].base.restore_default_state,
		&reset.state[0], 0);
	status |= mock_expect (&reset.state[1].mock, reset.state[1].base.restore_default_state,
		&reset.state[1], 0);
	status |= mock_expect (&reset.state[2].mock, reset.state[2].base.restore_default_state,
		&reset.state[2], 0);

	status |= mock_expect (&reset.keys.riot_keystore.mock, reset.keys.riot_keystore.base.erase_key,
		&reset.keys.riot_keystore, 0, MOCK_ARG (0));
	status |= mock_expect (&reset.keys.riot_keystore.mock, reset.keys.riot_keystore.base.erase_key,
		&reset.keys.riot_keystore, 0, MOCK_ARG (1));
	status |= mock_expect (&reset.keys.riot_keystore.mock, reset.keys.riot_keystore.base.erase_key,
		&reset.keys.riot_keystore, 0, MOCK_ARG (2));

	status |= mock_expect (&reset.keys.aux_keystore.mock, reset.keys.aux_keystore.base.erase_key,
		&reset.keys.aux_keystore, 0, MOCK_ARG (0));

	status |= mock_expect (&reset.recovery.mock, reset.recovery.base.erase_all_recovery_regions,
		&reset.recovery, 0);

	status |= mock_expect (&reset.keystore[0].mock, reset.keystore[0].base.erase_all_keys,
		&reset.keystore[0], 0);
	status |= mock_expect (&reset.keystore[1].mock, reset.keystore[1].base.erase_all_keys,
		&reset.keystore[1], 0);

	CuAssertIntEquals (test, 0, status);

	status = config_reset_restore_defaults (&reset.test);
	CuAssertIntEquals (test, 0, status);

	config_reset_testing_release (test, &reset);
}

static void config_reset_test_restore_defaults_multiple_default (CuTest *test)
{
	struct config_reset_testing reset;
	int status;

	TEST_START;

	config_reset_testing_init_dependencies (test, &reset);

	status = config_reset_init (&reset.test, reset.bypass, 1, reset.config, 3, reset.component, 1,
		reset.state_list, 3, &reset.keys.riot, &reset.keys.aux, &reset.recovery.base,
		reset.keystore_array, 2);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&reset.manifest_bypass[0].mock,
		reset.manifest_bypass[0].base.clear_all_manifests, &reset.manifest_bypass[0], 0);

	status |= mock_expect (&reset.manifest_config[0].mock,
		reset.manifest_config[0].base.clear_all_manifests, &reset.manifest_config[0], 0);
	status |= mock_expect (&reset.manifest_config[1].mock,
		reset.manifest_config[1].base.clear_all_manifests, &reset.manifest_config[1], 0);
	status |= mock_expect (&reset.manifest_config[2].mock,
		reset.manifest_config[2].base.clear_all_manifests, &reset.manifest_config[2], 0);

	status |= mock_expect (&reset.manifest_components[0].mock,
		reset.manifest_components[0].base.clear_all_manifests, &reset.manifest_components[0], 0);

	status |= mock_expect (&reset.state[0].mock, reset.state[0].base.restore_default_state,
		&reset.state[0], 0);
	status |= mock_expect (&reset.state[1].mock, reset.state[1].base.restore_default_state,
		&reset.state[1], 0);
	status |= mock_expect (&reset.state[2].mock, reset.state[2].base.restore_default_state,
		&reset.state[2], 0);

	status |= mock_expect (&reset.keys.riot_keystore.mock, reset.keys.riot_keystore.base.erase_key,
		&reset.keys.riot_keystore, 0, MOCK_ARG (0));
	status |= mock_expect (&reset.keys.riot_keystore.mock, reset.keys.riot_keystore.base.erase_key,
		&reset.keys.riot_keystore, 0, MOCK_ARG (1));
	status |= mock_expect (&reset.keys.riot_keystore.mock, reset.keys.riot_keystore.base.erase_key,
		&reset.keys.riot_keystore, 0, MOCK_ARG (2));

	status |= mock_expect (&reset.keys.aux_keystore.mock, reset.keys.aux_keystore.base.erase_key,
		&reset.keys.aux_keystore, 0, MOCK_ARG (0));

	status |= mock_expect (&reset.recovery.mock, reset.recovery.base.erase_all_recovery_regions,
		&reset.recovery, 0);

	status |= mock_expect (&reset.keystore[0].mock, reset.keystore[0].base.erase_all_keys,
		&reset.keystore[0], 0);
	status |= mock_expect (&reset.keystore[1].mock, reset.keystore[1].base.erase_all_keys,
		&reset.keystore[1], 0);

	CuAssertIntEquals (test, 0, status);

	status = config_reset_restore_defaults (&reset.test);
	CuAssertIntEquals (test, 0, status);

	config_reset_testing_release (test, &reset);
}

static void config_reset_test_restore_defaults_multiple_components (CuTest *test)
{
	struct config_reset_testing reset;
	int status;

	TEST_START;

	config_reset_testing_init_dependencies (test, &reset);

	status = config_reset_init (&reset.test, reset.bypass, 1, reset.config, 1, reset.component, 3,
		reset.state_list, 3, &reset.keys.riot, &reset.keys.aux, &reset.recovery.base,
		reset.keystore_array, 2);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&reset.manifest_bypass[0].mock,
		reset.manifest_bypass[0].base.clear_all_manifests, &reset.manifest_bypass[0], 0);

	status |= mock_expect (&reset.manifest_config[0].mock,
		reset.manifest_config[0].base.clear_all_manifests, &reset.manifest_config[0], 0);

	status |= mock_expect (&reset.manifest_components[0].mock,
		reset.manifest_components[0].base.clear_all_manifests, &reset.manifest_components[0], 0);
	status |= mock_expect (&reset.manifest_components[1].mock,
		reset.manifest_components[1].base.clear_all_manifests, &reset.manifest_components[1], 0);
	status |= mock_expect (&reset.manifest_components[2].mock,
		reset.manifest_components[2].base.clear_all_manifests, &reset.manifest_components[2], 0);

	status |= mock_expect (&reset.state[0].mock, reset.state[0].base.restore_default_state,
		&reset.state[0], 0);
	status |= mock_expect (&reset.state[1].mock, reset.state[1].base.restore_default_state,
		&reset.state[1], 0);
	status |= mock_expect (&reset.state[2].mock, reset.state[2].base.restore_default_state,
		&reset.state[2], 0);

	status |= mock_expect (&reset.keys.riot_keystore.mock, reset.keys.riot_keystore.base.erase_key,
		&reset.keys.riot_keystore, 0, MOCK_ARG (0));
	status |= mock_expect (&reset.keys.riot_keystore.mock, reset.keys.riot_keystore.base.erase_key,
		&reset.keys.riot_keystore, 0, MOCK_ARG (1));
	status |= mock_expect (&reset.keys.riot_keystore.mock, reset.keys.riot_keystore.base.erase_key,
		&reset.keys.riot_keystore, 0, MOCK_ARG (2));

	status |= mock_expect (&reset.keys.aux_keystore.mock, reset.keys.aux_keystore.base.erase_key,
		&reset.keys.aux_keystore, 0, MOCK_ARG (0));

	status |= mock_expect (&reset.recovery.mock, reset.recovery.base.erase_all_recovery_regions,
		&reset.recovery, 0);

	status |= mock_expect (&reset.keystore[0].mock, reset.keystore[0].base.erase_all_keys,
		&reset.keystore[0], 0);
	status |= mock_expect (&reset.keystore[1].mock, reset.keystore[1].base.erase_all_keys,
		&reset.keystore[1], 0);

	CuAssertIntEquals (test, 0, status);

	status = config_reset_restore_defaults (&reset.test);
	CuAssertIntEquals (test, 0, status);

	config_reset_testing_release (test, &reset);
}

static void config_reset_test_restore_defaults_no_bypass_manifests (CuTest *test)
{
	struct config_reset_testing reset;
	int status;

	TEST_START;

	config_reset_testing_init_dependencies (test, &reset);

	status = config_reset_init (&reset.test, NULL, 0, reset.config, 1, reset.component, 1,
		reset.state_list, 1, &reset.keys.riot, &reset.keys.aux, &reset.recovery.base,
		reset.keystore_array, 2);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&reset.manifest_config[0].mock,
		reset.manifest_config[0].base.clear_all_manifests, &reset.manifest_config[0], 0);
	status |= mock_expect (&reset.manifest_components[0].mock,
		reset.manifest_components[0].base.clear_all_manifests, &reset.manifest_components[0], 0);
	status |= mock_expect (&reset.state[0].mock, reset.state[0].base.restore_default_state,
		&reset.state[0], 0);

	status |= mock_expect (&reset.keys.riot_keystore.mock, reset.keys.riot_keystore.base.erase_key,
		&reset.keys.riot_keystore, 0, MOCK_ARG (0));
	status |= mock_expect (&reset.keys.riot_keystore.mock, reset.keys.riot_keystore.base.erase_key,
		&reset.keys.riot_keystore, 0, MOCK_ARG (1));
	status |= mock_expect (&reset.keys.riot_keystore.mock, reset.keys.riot_keystore.base.erase_key,
		&reset.keys.riot_keystore, 0, MOCK_ARG (2));

	status |= mock_expect (&reset.keys.aux_keystore.mock, reset.keys.aux_keystore.base.erase_key,
		&reset.keys.aux_keystore, 0, MOCK_ARG (0));

	status |= mock_expect (&reset.recovery.mock, reset.recovery.base.erase_all_recovery_regions,
		&reset.recovery, 0);

	status |= mock_expect (&reset.keystore[0].mock, reset.keystore[0].base.erase_all_keys,
		&reset.keystore[0], 0);
	status |= mock_expect (&reset.keystore[1].mock, reset.keystore[1].base.erase_all_keys,
		&reset.keystore[1], 0);

	CuAssertIntEquals (test, 0, status);

	status = config_reset_restore_defaults (&reset.test);
	CuAssertIntEquals (test, 0, status);

	config_reset_testing_release (test, &reset);
}

static void config_reset_test_restore_defaults_no_default_manifests (CuTest *test)
{
	struct config_reset_testing reset;
	int status;

	TEST_START;

	config_reset_testing_init_dependencies (test, &reset);

	status = config_reset_init (&reset.test, reset.bypass, 1, NULL, 0, reset.component, 1,
		reset.state_list, 1, &reset.keys.riot, &reset.keys.aux, &reset.recovery.base,
		reset.keystore_array, 2);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&reset.manifest_bypass[0].mock,
		reset.manifest_bypass[0].base.clear_all_manifests, &reset.manifest_bypass[0], 0);
	status |= mock_expect (&reset.manifest_components[0].mock,
		reset.manifest_components[0].base.clear_all_manifests, &reset.manifest_components[0], 0);
	status |= mock_expect (&reset.state[0].mock, reset.state[0].base.restore_default_state,
		&reset.state[0], 0);

	status |= mock_expect (&reset.keys.riot_keystore.mock, reset.keys.riot_keystore.base.erase_key,
		&reset.keys.riot_keystore, 0, MOCK_ARG (0));
	status |= mock_expect (&reset.keys.riot_keystore.mock, reset.keys.riot_keystore.base.erase_key,
		&reset.keys.riot_keystore, 0, MOCK_ARG (1));
	status |= mock_expect (&reset.keys.riot_keystore.mock, reset.keys.riot_keystore.base.erase_key,
		&reset.keys.riot_keystore, 0, MOCK_ARG (2));

	status |= mock_expect (&reset.keys.aux_keystore.mock, reset.keys.aux_keystore.base.erase_key,
		&reset.keys.aux_keystore, 0, MOCK_ARG (0));

	status |= mock_expect (&reset.recovery.mock, reset.recovery.base.erase_all_recovery_regions,
		&reset.recovery, 0);

	status |= mock_expect (&reset.keystore[0].mock, reset.keystore[0].base.erase_all_keys,
		&reset.keystore[0], 0);
	status |= mock_expect (&reset.keystore[1].mock, reset.keystore[1].base.erase_all_keys,
		&reset.keystore[1], 0);

	CuAssertIntEquals (test, 0, status);

	status = config_reset_restore_defaults (&reset.test);
	CuAssertIntEquals (test, 0, status);

	config_reset_testing_release (test, &reset);
}

static void config_reset_test_restore_defaults_no_component_manifests (CuTest *test)
{
	struct config_reset_testing reset;
	int status;

	TEST_START;

	config_reset_testing_init_dependencies (test, &reset);

	status = config_reset_init (&reset.test, reset.bypass, 1, reset.config, 1, NULL, 0,
		reset.state_list, 1, &reset.keys.riot, &reset.keys.aux, &reset.recovery.base,
		reset.keystore_array, 2);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&reset.manifest_bypass[0].mock,
		reset.manifest_bypass[0].base.clear_all_manifests, &reset.manifest_bypass[0], 0);
	status |= mock_expect (&reset.manifest_config[0].mock,
		reset.manifest_config[0].base.clear_all_manifests, &reset.manifest_config[0], 0);
	status |= mock_expect (&reset.state[0].mock, reset.state[0].base.restore_default_state,
		&reset.state[0], 0);

	status |= mock_expect (&reset.keys.riot_keystore.mock, reset.keys.riot_keystore.base.erase_key,
		&reset.keys.riot_keystore, 0, MOCK_ARG (0));
	status |= mock_expect (&reset.keys.riot_keystore.mock, reset.keys.riot_keystore.base.erase_key,
		&reset.keys.riot_keystore, 0, MOCK_ARG (1));
	status |= mock_expect (&reset.keys.riot_keystore.mock, reset.keys.riot_keystore.base.erase_key,
		&reset.keys.riot_keystore, 0, MOCK_ARG (2));

	status |= mock_expect (&reset.keys.aux_keystore.mock, reset.keys.aux_keystore.base.erase_key,
		&reset.keys.aux_keystore, 0, MOCK_ARG (0));

	status |= mock_expect (&reset.recovery.mock, reset.recovery.base.erase_all_recovery_regions,
		&reset.recovery, 0);

	status |= mock_expect (&reset.keystore[0].mock, reset.keystore[0].base.erase_all_keys,
		&reset.keystore[0], 0);
	status |= mock_expect (&reset.keystore[1].mock, reset.keystore[1].base.erase_all_keys,
		&reset.keystore[1], 0);

	CuAssertIntEquals (test, 0, status);

	status = config_reset_restore_defaults (&reset.test);
	CuAssertIntEquals (test, 0, status);

	config_reset_testing_release (test, &reset);
}

static void config_reset_test_restore_defaults_no_manifests (CuTest *test)
{
	struct config_reset_testing reset;
	int status;

	TEST_START;

	config_reset_testing_init_dependencies (test, &reset);

	status = config_reset_init (&reset.test, NULL, 0, NULL, 0, NULL, 0, NULL, 0, &reset.keys.riot,
		&reset.keys.aux, &reset.recovery.base, reset.keystore_array, 2);
	CuAssertIntEquals (test, 0, status);

	status |= mock_expect (&reset.keys.riot_keystore.mock, reset.keys.riot_keystore.base.erase_key,
		&reset.keys.riot_keystore, 0, MOCK_ARG (0));
	status |= mock_expect (&reset.keys.riot_keystore.mock, reset.keys.riot_keystore.base.erase_key,
		&reset.keys.riot_keystore, 0, MOCK_ARG (1));
	status |= mock_expect (&reset.keys.riot_keystore.mock, reset.keys.riot_keystore.base.erase_key,
		&reset.keys.riot_keystore, 0, MOCK_ARG (2));

	status |= mock_expect (&reset.keys.aux_keystore.mock, reset.keys.aux_keystore.base.erase_key,
		&reset.keys.aux_keystore, 0, MOCK_ARG (0));

	status |= mock_expect (&reset.recovery.mock, reset.recovery.base.erase_all_recovery_regions,
		&reset.recovery, 0);

	status |= mock_expect (&reset.keystore[0].mock, reset.keystore[0].base.erase_all_keys,
		&reset.keystore[0], 0);
	status |= mock_expect (&reset.keystore[1].mock, reset.keystore[1].base.erase_all_keys,
		&reset.keystore[1], 0);

	CuAssertIntEquals (test, 0, status);

	status = config_reset_restore_defaults (&reset.test);
	CuAssertIntEquals (test, 0, status);

	config_reset_testing_release (test, &reset);
}

static void config_reset_test_restore_defaults_no_state (CuTest *test)
{
	struct config_reset_testing reset;
	int status;

	TEST_START;

	config_reset_testing_init_dependencies (test, &reset);

	status = config_reset_init (&reset.test, reset.bypass, 1, reset.config, 1, reset.component, 1,
		NULL, 0, &reset.keys.riot, &reset.keys.aux, &reset.recovery.base, reset.keystore_array, 2);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&reset.manifest_bypass[0].mock,
		reset.manifest_bypass[0].base.clear_all_manifests, &reset.manifest_bypass[0], 0);
	status |= mock_expect (&reset.manifest_config[0].mock,
		reset.manifest_config[0].base.clear_all_manifests, &reset.manifest_config[0], 0);
	status |= mock_expect (&reset.manifest_components[0].mock,
		reset.manifest_components[0].base.clear_all_manifests, &reset.manifest_components[0], 0);

	status |= mock_expect (&reset.keys.riot_keystore.mock, reset.keys.riot_keystore.base.erase_key,
		&reset.keys.riot_keystore, 0, MOCK_ARG (0));
	status |= mock_expect (&reset.keys.riot_keystore.mock, reset.keys.riot_keystore.base.erase_key,
		&reset.keys.riot_keystore, 0, MOCK_ARG (1));
	status |= mock_expect (&reset.keys.riot_keystore.mock, reset.keys.riot_keystore.base.erase_key,
		&reset.keys.riot_keystore, 0, MOCK_ARG (2));

	status |= mock_expect (&reset.keys.aux_keystore.mock, reset.keys.aux_keystore.base.erase_key,
		&reset.keys.aux_keystore, 0, MOCK_ARG (0));

	status |= mock_expect (&reset.recovery.mock, reset.recovery.base.erase_all_recovery_regions,
		&reset.recovery, 0);

	status |= mock_expect (&reset.keystore[0].mock, reset.keystore[0].base.erase_all_keys,
		&reset.keystore[0], 0);
	status |= mock_expect (&reset.keystore[1].mock, reset.keystore[1].base.erase_all_keys,
		&reset.keystore[1], 0);

	CuAssertIntEquals (test, 0, status);

	status = config_reset_restore_defaults (&reset.test);
	CuAssertIntEquals (test, 0, status);

	config_reset_testing_release (test, &reset);
}

static void config_reset_test_restore_defaults_no_riot (CuTest *test)
{
	struct config_reset_testing reset;
	int status;

	TEST_START;

	config_reset_testing_init_dependencies (test, &reset);

	status = config_reset_init (&reset.test, reset.bypass, 1, reset.config, 1, reset.component, 1,
		reset.state_list, 1, NULL, &reset.keys.aux, &reset.recovery.base, reset.keystore_array, 2);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&reset.manifest_bypass[0].mock,
		reset.manifest_bypass[0].base.clear_all_manifests, &reset.manifest_bypass[0], 0);
	status |= mock_expect (&reset.manifest_config[0].mock,
		reset.manifest_config[0].base.clear_all_manifests, &reset.manifest_config[0], 0);
	status |= mock_expect (&reset.manifest_components[0].mock,
		reset.manifest_components[0].base.clear_all_manifests, &reset.manifest_components[0], 0);
	status |= mock_expect (&reset.state[0].mock, reset.state[0].base.restore_default_state,
		&reset.state[0], 0);

	status |= mock_expect (&reset.keys.aux_keystore.mock, reset.keys.aux_keystore.base.erase_key,
		&reset.keys.aux_keystore, 0, MOCK_ARG (0));

	status |= mock_expect (&reset.recovery.mock, reset.recovery.base.erase_all_recovery_regions,
		&reset.recovery, 0);

	status |= mock_expect (&reset.keystore[0].mock, reset.keystore[0].base.erase_all_keys,
		&reset.keystore[0], 0);
	status |= mock_expect (&reset.keystore[1].mock, reset.keystore[1].base.erase_all_keys,
		&reset.keystore[1], 0);

	CuAssertIntEquals (test, 0, status);

	status = config_reset_restore_defaults (&reset.test);
	CuAssertIntEquals (test, 0, status);

	config_reset_testing_release (test, &reset);
}

static void config_reset_test_restore_defaults_no_aux (CuTest *test)
{
	struct config_reset_testing reset;
	int status;

	TEST_START;

	config_reset_testing_init_dependencies (test, &reset);

	status = config_reset_init (&reset.test, reset.bypass, 1, reset.config, 1, reset.component, 1,
		reset.state_list, 1, &reset.keys.riot, NULL, &reset.recovery.base, reset.keystore_array, 2);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&reset.manifest_bypass[0].mock,
		reset.manifest_bypass[0].base.clear_all_manifests, &reset.manifest_bypass[0], 0);
	status |= mock_expect (&reset.manifest_config[0].mock,
		reset.manifest_config[0].base.clear_all_manifests, &reset.manifest_config[0], 0);
	status |= mock_expect (&reset.manifest_components[0].mock,
		reset.manifest_components[0].base.clear_all_manifests, &reset.manifest_components[0], 0);
	status |= mock_expect (&reset.state[0].mock, reset.state[0].base.restore_default_state,
		&reset.state[0], 0);

	status |= mock_expect (&reset.keys.riot_keystore.mock, reset.keys.riot_keystore.base.erase_key,
		&reset.keys.riot_keystore, 0, MOCK_ARG (0));
	status |= mock_expect (&reset.keys.riot_keystore.mock, reset.keys.riot_keystore.base.erase_key,
		&reset.keys.riot_keystore, 0, MOCK_ARG (1));
	status |= mock_expect (&reset.keys.riot_keystore.mock, reset.keys.riot_keystore.base.erase_key,
		&reset.keys.riot_keystore, 0, MOCK_ARG (2));

	status |= mock_expect (&reset.recovery.mock, reset.recovery.base.erase_all_recovery_regions,
		&reset.recovery, 0);

	status |= mock_expect (&reset.keystore[0].mock, reset.keystore[0].base.erase_all_keys,
		&reset.keystore[0], 0);
	status |= mock_expect (&reset.keystore[1].mock, reset.keystore[1].base.erase_all_keys,
		&reset.keystore[1], 0);

	CuAssertIntEquals (test, 0, status);

	status = config_reset_restore_defaults (&reset.test);
	CuAssertIntEquals (test, 0, status);

	config_reset_testing_release (test, &reset);
}

static void config_reset_test_restore_defaults_no_recovery (CuTest *test)
{
	struct config_reset_testing reset;
	int status;

	TEST_START;

	config_reset_testing_init_dependencies (test, &reset);

	status = config_reset_init (&reset.test, reset.bypass, 1, reset.config, 1, reset.component, 1,
		reset.state_list, 1, &reset.keys.riot, &reset.keys.aux, NULL, reset.keystore_array, 2);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&reset.manifest_bypass[0].mock,
		reset.manifest_bypass[0].base.clear_all_manifests, &reset.manifest_bypass[0], 0);
	status |= mock_expect (&reset.manifest_config[0].mock,
		reset.manifest_config[0].base.clear_all_manifests, &reset.manifest_config[0], 0);
	status |= mock_expect (&reset.manifest_components[0].mock,
		reset.manifest_components[0].base.clear_all_manifests, &reset.manifest_components[0], 0);
	status |= mock_expect (&reset.state[0].mock, reset.state[0].base.restore_default_state,
		&reset.state[0], 0);

	status |= mock_expect (&reset.keys.riot_keystore.mock, reset.keys.riot_keystore.base.erase_key,
		&reset.keys.riot_keystore, 0, MOCK_ARG (0));
	status |= mock_expect (&reset.keys.riot_keystore.mock, reset.keys.riot_keystore.base.erase_key,
		&reset.keys.riot_keystore, 0, MOCK_ARG (1));
	status |= mock_expect (&reset.keys.riot_keystore.mock, reset.keys.riot_keystore.base.erase_key,
		&reset.keys.riot_keystore, 0, MOCK_ARG (2));

	status |= mock_expect (&reset.keys.aux_keystore.mock, reset.keys.aux_keystore.base.erase_key,
		&reset.keys.aux_keystore, 0, MOCK_ARG (0));

	status |= mock_expect (&reset.keystore[0].mock, reset.keystore[0].base.erase_all_keys,
		&reset.keystore[0], 0);
	status |= mock_expect (&reset.keystore[1].mock, reset.keystore[1].base.erase_all_keys,
		&reset.keystore[1], 0);

	CuAssertIntEquals (test, 0, status);

	status = config_reset_restore_defaults (&reset.test);
	CuAssertIntEquals (test, 0, status);

	config_reset_testing_release (test, &reset);
}

static void config_reset_test_restore_defaults_no_keystore_array (CuTest *test)
{
	struct config_reset_testing reset;
	int status;

	TEST_START;

	config_reset_testing_init_dependencies (test, &reset);

	status = config_reset_init (&reset.test, reset.bypass, 1, reset.config, 1, reset.component, 1,
		reset.state_list, 1, &reset.keys.riot, &reset.keys.aux, &reset.recovery.base, NULL, 0);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&reset.manifest_bypass[0].mock,
		reset.manifest_bypass[0].base.clear_all_manifests, &reset.manifest_bypass[0], 0);
	status |= mock_expect (&reset.manifest_config[0].mock,
		reset.manifest_config[0].base.clear_all_manifests, &reset.manifest_config[0], 0);
	status |= mock_expect (&reset.manifest_components[0].mock,
		reset.manifest_components[0].base.clear_all_manifests, &reset.manifest_components[0], 0);
	status |= mock_expect (&reset.state[0].mock, reset.state[0].base.restore_default_state,
		&reset.state[0], 0);

	status |= mock_expect (&reset.keys.riot_keystore.mock, reset.keys.riot_keystore.base.erase_key,
		&reset.keys.riot_keystore, 0, MOCK_ARG (0));
	status |= mock_expect (&reset.keys.riot_keystore.mock, reset.keys.riot_keystore.base.erase_key,
		&reset.keys.riot_keystore, 0, MOCK_ARG (1));
	status |= mock_expect (&reset.keys.riot_keystore.mock, reset.keys.riot_keystore.base.erase_key,
		&reset.keys.riot_keystore, 0, MOCK_ARG (2));

	status |= mock_expect (&reset.keys.aux_keystore.mock, reset.keys.aux_keystore.base.erase_key,
		&reset.keys.aux_keystore, 0, MOCK_ARG (0));

	status |= mock_expect (&reset.recovery.mock, reset.recovery.base.erase_all_recovery_regions,
		&reset.recovery, 0);

	CuAssertIntEquals (test, 0, status);

	status = config_reset_restore_defaults (&reset.test);
	CuAssertIntEquals (test, 0, status);

	config_reset_testing_release (test, &reset);
}

static void config_reset_test_restore_defaults_static_init (CuTest *test)
{
	struct config_reset_testing reset = {
		.test = config_reset_static_init (reset.bypass, 1, reset.config, 1, reset.component, 1,
			reset.state_list, 1, &reset.keys.riot, &reset.keys.aux, &reset.recovery.base,
			reset.keystore_array, 2)
	};
	int status;

	TEST_START;

	config_reset_testing_init_dependencies (test, &reset);

	status = mock_expect (&reset.manifest_bypass[0].mock,
		reset.manifest_bypass[0].base.clear_all_manifests, &reset.manifest_bypass[0], 0);
	status |= mock_expect (&reset.manifest_config[0].mock,
		reset.manifest_config[0].base.clear_all_manifests, &reset.manifest_config[0], 0);
	status |= mock_expect (&reset.manifest_components[0].mock,
		reset.manifest_components[0].base.clear_all_manifests, &reset.manifest_components[0], 0);
	status |= mock_expect (&reset.state[0].mock, reset.state[0].base.restore_default_state,
		&reset.state[0], 0);

	status |= mock_expect (&reset.keys.riot_keystore.mock, reset.keys.riot_keystore.base.erase_key,
		&reset.keys.riot_keystore, 0, MOCK_ARG (0));
	status |= mock_expect (&reset.keys.riot_keystore.mock, reset.keys.riot_keystore.base.erase_key,
		&reset.keys.riot_keystore, 0, MOCK_ARG (1));
	status |= mock_expect (&reset.keys.riot_keystore.mock, reset.keys.riot_keystore.base.erase_key,
		&reset.keys.riot_keystore, 0, MOCK_ARG (2));

	status |= mock_expect (&reset.keys.aux_keystore.mock, reset.keys.aux_keystore.base.erase_key,
		&reset.keys.aux_keystore, 0, MOCK_ARG (0));

	status |= mock_expect (&reset.recovery.mock, reset.recovery.base.erase_all_recovery_regions,
		&reset.recovery, 0);

	status |= mock_expect (&reset.keystore[0].mock, reset.keystore[0].base.erase_all_keys,
		&reset.keystore[0], 0);
	status |= mock_expect (&reset.keystore[1].mock, reset.keystore[1].base.erase_all_keys,
		&reset.keystore[1], 0);

	CuAssertIntEquals (test, 0, status);

	status = config_reset_restore_defaults (&reset.test);
	CuAssertIntEquals (test, 0, status);

	config_reset_testing_release (test, &reset);
}

static void config_reset_test_restore_defaults_null (CuTest *test)
{
	struct config_reset_testing reset;
	int status;

	TEST_START;

	config_reset_testing_init (test, &reset);

	status = config_reset_restore_defaults (NULL);
	CuAssertIntEquals (test, CONFIG_RESET_INVALID_ARGUMENT, status);

	config_reset_testing_release (test, &reset);
}

static void config_reset_test_restore_defaults_bypass_clear_error (CuTest *test)
{
	struct config_reset_testing reset;
	int status;

	TEST_START;

	config_reset_testing_init_dependencies (test, &reset);

	status = config_reset_init (&reset.test, reset.bypass, 3, reset.config, 1, reset.component, 1,
		reset.state_list, 3, &reset.keys.riot, &reset.keys.aux, &reset.recovery.base,
		reset.keystore_array, 2);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&reset.manifest_bypass[0].mock,
		reset.manifest_bypass[0].base.clear_all_manifests, &reset.manifest_bypass[0], 0);
	status |= mock_expect (&reset.manifest_bypass[1].mock,
		reset.manifest_bypass[1].base.clear_all_manifests, &reset.manifest_bypass[1],
		MANIFEST_MANAGER_CLEAR_ALL_FAILED);

	CuAssertIntEquals (test, 0, status);

	status = config_reset_restore_defaults (&reset.test);
	CuAssertIntEquals (test, MANIFEST_MANAGER_CLEAR_ALL_FAILED, status);

	config_reset_testing_release (test, &reset);
}

static void config_reset_test_restore_defaults_default_clear_error (CuTest *test)
{
	struct config_reset_testing reset;
	int status;

	TEST_START;

	config_reset_testing_init_dependencies (test, &reset);

	status = config_reset_init (&reset.test, reset.bypass, 1, reset.config, 3, reset.component, 1,
		reset.state_list, 3, &reset.keys.riot, &reset.keys.aux, &reset.recovery.base,
		reset.keystore_array, 2);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&reset.manifest_bypass[0].mock,
		reset.manifest_bypass[0].base.clear_all_manifests, &reset.manifest_bypass[0], 0);

	status |= mock_expect (&reset.manifest_config[0].mock,
		reset.manifest_config[0].base.clear_all_manifests, &reset.manifest_config[0], 0);
	status |= mock_expect (&reset.manifest_config[1].mock,
		reset.manifest_config[1].base.clear_all_manifests, &reset.manifest_config[1],
		MANIFEST_MANAGER_CLEAR_ALL_FAILED);

	CuAssertIntEquals (test, 0, status);

	status = config_reset_restore_defaults (&reset.test);
	CuAssertIntEquals (test, MANIFEST_MANAGER_CLEAR_ALL_FAILED, status);

	config_reset_testing_release (test, &reset);
}

static void config_reset_test_restore_defaults_components_clear_error (CuTest *test)
{
	struct config_reset_testing reset;
	int status;

	TEST_START;

	config_reset_testing_init_dependencies (test, &reset);

	status = config_reset_init (&reset.test, reset.bypass, 1, reset.config, 1, reset.component, 3,
		reset.state_list, 3, &reset.keys.riot, &reset.keys.aux, &reset.recovery.base,
		reset.keystore_array, 2);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&reset.manifest_bypass[0].mock,
		reset.manifest_bypass[0].base.clear_all_manifests, &reset.manifest_bypass[0], 0);

	status |= mock_expect (&reset.manifest_config[0].mock,
		reset.manifest_config[0].base.clear_all_manifests, &reset.manifest_config[0], 0);

	status |= mock_expect (&reset.manifest_components[0].mock,
		reset.manifest_components[0].base.clear_all_manifests, &reset.manifest_components[0], 0);
	status |= mock_expect (&reset.manifest_components[1].mock,
		reset.manifest_components[1].base.clear_all_manifests, &reset.manifest_components[1],
		MANIFEST_MANAGER_CLEAR_ALL_FAILED);

	CuAssertIntEquals (test, 0, status);

	status = config_reset_restore_defaults (&reset.test);
	CuAssertIntEquals (test, MANIFEST_MANAGER_CLEAR_ALL_FAILED, status);

	config_reset_testing_release (test, &reset);
}

static void config_reset_test_restore_defaults_state_restore_error (CuTest *test)
{
	struct config_reset_testing reset;
	int status;

	TEST_START;

	config_reset_testing_init_dependencies (test, &reset);

	status = config_reset_init (&reset.test, reset.bypass, 3, reset.config, 1, reset.component, 1,
		reset.state_list, 3, &reset.keys.riot, &reset.keys.aux, &reset.recovery.base,
		reset.keystore_array, 2);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&reset.manifest_bypass[0].mock,
		reset.manifest_bypass[0].base.clear_all_manifests, &reset.manifest_bypass[0], 0);
	status |= mock_expect (&reset.manifest_bypass[1].mock,
		reset.manifest_bypass[1].base.clear_all_manifests, &reset.manifest_bypass[1], 0);
	status |= mock_expect (&reset.manifest_bypass[2].mock,
		reset.manifest_bypass[2].base.clear_all_manifests, &reset.manifest_bypass[2], 0);

	status |= mock_expect (&reset.manifest_config[0].mock,
		reset.manifest_config[0].base.clear_all_manifests, &reset.manifest_config[0], 0);

	status |= mock_expect (&reset.manifest_components[0].mock,
		reset.manifest_components[0].base.clear_all_manifests, &reset.manifest_components[0], 0);

	status |= mock_expect (&reset.state[0].mock, reset.state[0].base.restore_default_state,
		&reset.state[0], 0);
	status |= mock_expect (&reset.state[1].mock, reset.state[1].base.restore_default_state,
		&reset.state[1], STATE_MANAGER_DEFAULTS_FAILED);

	CuAssertIntEquals (test, 0, status);

	status = config_reset_restore_defaults (&reset.test);
	CuAssertIntEquals (test, STATE_MANAGER_DEFAULTS_FAILED, status);

	config_reset_testing_release (test, &reset);
}

static void config_reset_test_restore_defaults_riot_erase_error (CuTest *test)
{
	struct config_reset_testing reset;
	int status;

	TEST_START;

	config_reset_testing_init (test, &reset);

	status = mock_expect (&reset.manifest_bypass[0].mock,
		reset.manifest_bypass[0].base.clear_all_manifests, &reset.manifest_bypass[0], 0);
	status |= mock_expect (&reset.manifest_config[0].mock,
		reset.manifest_config[0].base.clear_all_manifests, &reset.manifest_config[0], 0);
	status |= mock_expect (&reset.manifest_components[0].mock,
		reset.manifest_components[0].base.clear_all_manifests, &reset.manifest_components[0], 0);
	status |= mock_expect (&reset.state[0].mock, reset.state[0].base.restore_default_state,
		&reset.state[0], 0);

	status |= mock_expect (&reset.keys.riot_keystore.mock, reset.keys.riot_keystore.base.erase_key,
		&reset.keys.riot_keystore, KEYSTORE_ERASE_FAILED, MOCK_ARG (0));

	CuAssertIntEquals (test, 0, status);

	status = config_reset_restore_defaults (&reset.test);
	CuAssertIntEquals (test, KEYSTORE_ERASE_FAILED, status);

	config_reset_testing_release (test, &reset);
}

static void config_reset_test_restore_defaults_aux_erase_error (CuTest *test)
{
	struct config_reset_testing reset;
	int status;

	TEST_START;

	config_reset_testing_init (test, &reset);

	status = mock_expect (&reset.manifest_bypass[0].mock,
		reset.manifest_bypass[0].base.clear_all_manifests, &reset.manifest_bypass[0], 0);
	status |= mock_expect (&reset.manifest_config[0].mock,
		reset.manifest_config[0].base.clear_all_manifests, &reset.manifest_config[0], 0);
	status |= mock_expect (&reset.manifest_components[0].mock,
		reset.manifest_components[0].base.clear_all_manifests, &reset.manifest_components[0], 0);
	status |= mock_expect (&reset.state[0].mock, reset.state[0].base.restore_default_state,
		&reset.state[0], 0);

	status |= mock_expect (&reset.keys.riot_keystore.mock, reset.keys.riot_keystore.base.erase_key,
		&reset.keys.riot_keystore, 0, MOCK_ARG (0));
	status |= mock_expect (&reset.keys.riot_keystore.mock, reset.keys.riot_keystore.base.erase_key,
		&reset.keys.riot_keystore, 0, MOCK_ARG (1));
	status |= mock_expect (&reset.keys.riot_keystore.mock, reset.keys.riot_keystore.base.erase_key,
		&reset.keys.riot_keystore, 0, MOCK_ARG (2));

	status |= mock_expect (&reset.keys.aux_keystore.mock, reset.keys.aux_keystore.base.erase_key,
		&reset.keys.aux_keystore, KEYSTORE_ERASE_FAILED, MOCK_ARG (0));

	CuAssertIntEquals (test, 0, status);

	status = config_reset_restore_defaults (&reset.test);
	CuAssertIntEquals (test, KEYSTORE_ERASE_FAILED, status);

	config_reset_testing_release (test, &reset);
}

static void config_reset_test_restore_defaults_recovery_in_use_error (CuTest *test)
{
	struct config_reset_testing reset;
	int status;

	TEST_START;

	config_reset_testing_init (test, &reset);

	status = mock_expect (&reset.manifest_bypass[0].mock,
		reset.manifest_bypass[0].base.clear_all_manifests, &reset.manifest_bypass[0], 0);
	status |= mock_expect (&reset.manifest_config[0].mock,
		reset.manifest_config[0].base.clear_all_manifests, &reset.manifest_config[0], 0);
	status |= mock_expect (&reset.manifest_components[0].mock,
		reset.manifest_components[0].base.clear_all_manifests, &reset.manifest_components[0], 0);
	status |= mock_expect (&reset.state[0].mock, reset.state[0].base.restore_default_state,
		&reset.state[0], 0);

	status |= mock_expect (&reset.keys.riot_keystore.mock, reset.keys.riot_keystore.base.erase_key,
		&reset.keys.riot_keystore, 0, MOCK_ARG (0));
	status |= mock_expect (&reset.keys.riot_keystore.mock, reset.keys.riot_keystore.base.erase_key,
		&reset.keys.riot_keystore, 0, MOCK_ARG (1));
	status |= mock_expect (&reset.keys.riot_keystore.mock, reset.keys.riot_keystore.base.erase_key,
		&reset.keys.riot_keystore, 0, MOCK_ARG (2));

	status |= mock_expect (&reset.keys.aux_keystore.mock, reset.keys.aux_keystore.base.erase_key,
		&reset.keys.aux_keystore, 0, MOCK_ARG (0));

	status |= mock_expect (&reset.recovery.mock, reset.recovery.base.erase_all_recovery_regions,
		&reset.recovery, RECOVERY_IMAGE_MANAGER_IMAGE_IN_USE);

	CuAssertIntEquals (test, 0, status);

	status = config_reset_restore_defaults (&reset.test);
	CuAssertIntEquals (test, RECOVERY_IMAGE_MANAGER_IMAGE_IN_USE, status);

	config_reset_testing_release (test, &reset);
}

static void config_reset_test_restore_defaults_keystore_array_erase_error (CuTest *test)
{
	struct config_reset_testing reset;
	int status;

	TEST_START;

	config_reset_testing_init (test, &reset);

	status = mock_expect (&reset.manifest_bypass[0].mock,
		reset.manifest_bypass[0].base.clear_all_manifests, &reset.manifest_bypass[0], 0);
	status |= mock_expect (&reset.manifest_config[0].mock,
		reset.manifest_config[0].base.clear_all_manifests, &reset.manifest_config[0], 0);
	status |= mock_expect (&reset.manifest_components[0].mock,
		reset.manifest_components[0].base.clear_all_manifests, &reset.manifest_components[0], 0);
	status |= mock_expect (&reset.state[0].mock, reset.state[0].base.restore_default_state,
		&reset.state[0], 0);

	status |= mock_expect (&reset.keys.riot_keystore.mock, reset.keys.riot_keystore.base.erase_key,
		&reset.keys.riot_keystore, 0, MOCK_ARG (0));
	status |= mock_expect (&reset.keys.riot_keystore.mock, reset.keys.riot_keystore.base.erase_key,
		&reset.keys.riot_keystore, 0, MOCK_ARG (1));
	status |= mock_expect (&reset.keys.riot_keystore.mock, reset.keys.riot_keystore.base.erase_key,
		&reset.keys.riot_keystore, 0, MOCK_ARG (2));

	status |= mock_expect (&reset.keys.aux_keystore.mock, reset.keys.aux_keystore.base.erase_key,
		&reset.keys.aux_keystore, 0, MOCK_ARG (0));

	status |= mock_expect (&reset.recovery.mock, reset.recovery.base.erase_all_recovery_regions,
		&reset.recovery, 0);

	status |= mock_expect (&reset.keystore[0].mock, reset.keystore[0].base.erase_all_keys,
		&reset.keystore[0], KEYSTORE_ERASE_FAILED);

	CuAssertIntEquals (test, 0, status);

	status = config_reset_restore_defaults (&reset.test);
	CuAssertIntEquals (test, KEYSTORE_ERASE_FAILED, status);

	config_reset_testing_release (test, &reset);
}

static void config_reset_test_restore_platform_config (CuTest *test)
{
	struct config_reset_testing reset;
	int status;

	TEST_START;

	config_reset_testing_init (test, &reset);

	status = mock_expect (&reset.manifest_config[0].mock,
		reset.manifest_config[0].base.clear_all_manifests, &reset.manifest_config[0], 0);
	CuAssertIntEquals (test, 0, status);

	status = config_reset_restore_platform_config (&reset.test);
	CuAssertIntEquals (test, 0, status);

	config_reset_testing_release (test, &reset);
}

static void config_reset_test_restore_platform_config_multiple (CuTest *test)
{
	struct config_reset_testing reset;
	int status;

	TEST_START;

	config_reset_testing_init_dependencies (test, &reset);

	status = config_reset_init (&reset.test, reset.bypass, 1, reset.config, 3, reset.component, 1,
		reset.state_list, 1, &reset.keys.riot, &reset.keys.aux, &reset.recovery.base,
		reset.keystore_array, 2);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&reset.manifest_config[0].mock,
		reset.manifest_config[0].base.clear_all_manifests, &reset.manifest_config[0], 0);
	status |= mock_expect (&reset.manifest_config[1].mock,
		reset.manifest_config[1].base.clear_all_manifests, &reset.manifest_config[1], 0);
	status |= mock_expect (&reset.manifest_config[2].mock,
		reset.manifest_config[2].base.clear_all_manifests, &reset.manifest_config[2], 0);

	CuAssertIntEquals (test, 0, status);

	status = config_reset_restore_platform_config (&reset.test);
	CuAssertIntEquals (test, 0, status);

	config_reset_testing_release (test, &reset);
}

static void config_reset_test_restore_platform_config_no_manifests (CuTest *test)
{
	struct config_reset_testing reset;
	int status;

	TEST_START;

	config_reset_testing_init_dependencies (test, &reset);

	status = config_reset_init (&reset.test, reset.bypass, 1, NULL, 0, reset.component, 1, NULL, 0,
		&reset.keys.riot, &reset.keys.aux, &reset.recovery.base, reset.keystore_array, 2);
	CuAssertIntEquals (test, 0, status);

	status = config_reset_restore_platform_config (&reset.test);
	CuAssertIntEquals (test, CONFIG_RESET_NO_MANIFESTS, status);

	config_reset_testing_release (test, &reset);
}

static void config_reset_test_restore_platform_config_static_init (CuTest *test)
{
	struct config_reset_testing reset = {
		.test = config_reset_static_init (reset.bypass, 1, reset.config, 1, reset.component, 1,
			reset.state_list, 1, &reset.keys.riot, &reset.keys.aux, &reset.recovery.base,
			reset.keystore_array, 2)
	};
	int status;

	TEST_START;

	config_reset_testing_init_dependencies (test, &reset);

	status = mock_expect (&reset.manifest_config[0].mock,
		reset.manifest_config[0].base.clear_all_manifests, &reset.manifest_config[0], 0);
	CuAssertIntEquals (test, 0, status);

	status = config_reset_restore_platform_config (&reset.test);
	CuAssertIntEquals (test, 0, status);

	config_reset_testing_release (test, &reset);
}

static void config_reset_test_restore_platform_config_null (CuTest *test)
{
	struct config_reset_testing reset;
	int status;

	TEST_START;

	config_reset_testing_init (test, &reset);

	status = config_reset_restore_platform_config (NULL);
	CuAssertIntEquals (test, CONFIG_RESET_INVALID_ARGUMENT, status);

	config_reset_testing_release (test, &reset);
}

static void config_reset_test_restore_platform_config_clear_error (CuTest *test)
{
	struct config_reset_testing reset;
	int status;

	TEST_START;

	config_reset_testing_init_dependencies (test, &reset);

	status = config_reset_init (&reset.test, reset.bypass, 1, reset.config, 3, reset.component, 1,
		reset.state_list, 1, &reset.keys.riot, &reset.keys.aux, &reset.recovery.base,
		reset.keystore_array, 2);
	CuAssertIntEquals (test, 0, status);

	status |= mock_expect (&reset.manifest_config[0].mock,
		reset.manifest_config[0].base.clear_all_manifests, &reset.manifest_config[0], 0);
	status |= mock_expect (&reset.manifest_config[1].mock,
		reset.manifest_config[1].base.clear_all_manifests, &reset.manifest_config[1],
		MANIFEST_MANAGER_CLEAR_ALL_FAILED);

	CuAssertIntEquals (test, 0, status);

	status = config_reset_restore_platform_config (&reset.test);
	CuAssertIntEquals (test, MANIFEST_MANAGER_CLEAR_ALL_FAILED, status);

	config_reset_testing_release (test, &reset);
}

static void config_reset_test_clear_component_manifests (CuTest *test)
{
	struct config_reset_testing reset;
	int status;

	TEST_START;

	config_reset_testing_init (test, &reset);

	status = mock_expect (&reset.manifest_components[0].mock,
		reset.manifest_components[0].base.clear_all_manifests, &reset.manifest_components[0], 0);
	CuAssertIntEquals (test, 0, status);

	status = config_reset_clear_component_manifests (&reset.test);
	CuAssertIntEquals (test, 0, status);

	config_reset_testing_release (test, &reset);
}

static void config_reset_test_clear_component_manifests_multiple (CuTest *test)
{
	struct config_reset_testing reset;
	int status;

	TEST_START;

	config_reset_testing_init_dependencies (test, &reset);

	status = config_reset_init (&reset.test, reset.bypass, 1, reset.config, 1, reset.component, 3,
		reset.state_list, 1, &reset.keys.riot, &reset.keys.aux, &reset.recovery.base,
		reset.keystore_array, 2);
	CuAssertIntEquals (test, 0, status);

	status |= mock_expect (&reset.manifest_components[0].mock,
		reset.manifest_components[0].base.clear_all_manifests, &reset.manifest_components[0], 0);
	status |= mock_expect (&reset.manifest_components[1].mock,
		reset.manifest_components[1].base.clear_all_manifests, &reset.manifest_components[1], 0);
	status |= mock_expect (&reset.manifest_components[2].mock,
		reset.manifest_components[2].base.clear_all_manifests, &reset.manifest_components[2], 0);

	CuAssertIntEquals (test, 0, status);

	status = config_reset_clear_component_manifests (&reset.test);
	CuAssertIntEquals (test, 0, status);

	config_reset_testing_release (test, &reset);
}

static void config_reset_test_clear_component_manifests_no_manifests (CuTest *test)
{
	struct config_reset_testing reset;
	int status;

	TEST_START;

	config_reset_testing_init_dependencies (test, &reset);

	status = config_reset_init (&reset.test, reset.bypass, 1, NULL, 0, NULL, 0, NULL, 0,
		&reset.keys.riot, &reset.keys.aux, &reset.recovery.base, reset.keystore_array, 2);
	CuAssertIntEquals (test, 0, status);

	status = config_reset_clear_component_manifests (&reset.test);
	CuAssertIntEquals (test, CONFIG_RESET_NO_MANIFESTS, status);

	config_reset_testing_release (test, &reset);
}

static void config_reset_test_clear_component_manifests_static_init (CuTest *test)
{
	struct config_reset_testing reset = {
		.test = config_reset_static_init (reset.bypass, 1, reset.config, 1, reset.component, 1,
			reset.state_list, 1, &reset.keys.riot, &reset.keys.aux, &reset.recovery.base,
			reset.keystore_array, 2)
	};
	int status;

	TEST_START;

	config_reset_testing_init_dependencies (test, &reset);

	status = mock_expect (&reset.manifest_components[0].mock,
		reset.manifest_components[0].base.clear_all_manifests, &reset.manifest_components[0], 0);
	CuAssertIntEquals (test, 0, status);

	status = config_reset_clear_component_manifests (&reset.test);
	CuAssertIntEquals (test, 0, status);

	config_reset_testing_release (test, &reset);
}

static void config_reset_test_clear_component_manifests_null (CuTest *test)
{
	struct config_reset_testing reset;
	int status;

	TEST_START;

	config_reset_testing_init (test, &reset);

	status = config_reset_clear_component_manifests (NULL);
	CuAssertIntEquals (test, CONFIG_RESET_INVALID_ARGUMENT, status);

	config_reset_testing_release (test, &reset);
}

static void config_reset_test_clear_component_manifests_clear_error (CuTest *test)
{
	struct config_reset_testing reset;
	int status;

	TEST_START;

	config_reset_testing_init_dependencies (test, &reset);

	status = config_reset_init (&reset.test, reset.bypass, 1, reset.config, 1, reset.component, 3,
		reset.state_list, 1, &reset.keys.riot, &reset.keys.aux, &reset.recovery.base,
		reset.keystore_array, 2);
	CuAssertIntEquals (test, 0, status);

	status |= mock_expect (&reset.manifest_components[0].mock,
		reset.manifest_components[0].base.clear_all_manifests, &reset.manifest_components[0], 0);
	status |= mock_expect (&reset.manifest_components[1].mock,
		reset.manifest_components[1].base.clear_all_manifests, &reset.manifest_components[1],
		MANIFEST_MANAGER_CLEAR_ALL_FAILED);

	CuAssertIntEquals (test, 0, status);

	status = config_reset_clear_component_manifests (&reset.test);
	CuAssertIntEquals (test, MANIFEST_MANAGER_CLEAR_ALL_FAILED, status);

	config_reset_testing_release (test, &reset);
}


// *INDENT-OFF*
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
TEST (config_reset_test_init_null);
TEST (config_reset_test_init_no_manifests_with_state);
TEST (config_reset_test_static_init);
TEST (config_reset_test_release_null);
TEST (config_reset_test_restore_bypass);
TEST (config_reset_test_restore_bypass_multiple);
TEST (config_reset_test_restore_bypass_no_manifests);
TEST (config_reset_test_restore_bypass_static_init);
TEST (config_reset_test_restore_bypass_null);
TEST (config_reset_test_restore_bypass_clear_error);
TEST (config_reset_test_restore_defaults);
TEST (config_reset_test_restore_defaults_multiple_bypass);
TEST (config_reset_test_restore_defaults_multiple_default);
TEST (config_reset_test_restore_defaults_multiple_components);
TEST (config_reset_test_restore_defaults_no_bypass_manifests);
TEST (config_reset_test_restore_defaults_no_default_manifests);
TEST (config_reset_test_restore_defaults_no_component_manifests);
TEST (config_reset_test_restore_defaults_no_manifests);
TEST (config_reset_test_restore_defaults_no_state);
TEST (config_reset_test_restore_defaults_no_riot);
TEST (config_reset_test_restore_defaults_no_aux);
TEST (config_reset_test_restore_defaults_no_recovery);
TEST (config_reset_test_restore_defaults_no_keystore_array);
TEST (config_reset_test_restore_defaults_static_init);
TEST (config_reset_test_restore_defaults_null);
TEST (config_reset_test_restore_defaults_bypass_clear_error);
TEST (config_reset_test_restore_defaults_default_clear_error);
TEST (config_reset_test_restore_defaults_components_clear_error);
TEST (config_reset_test_restore_defaults_state_restore_error);
TEST (config_reset_test_restore_defaults_riot_erase_error);
TEST (config_reset_test_restore_defaults_aux_erase_error);
TEST (config_reset_test_restore_defaults_recovery_in_use_error);
TEST (config_reset_test_restore_defaults_keystore_array_erase_error);
TEST (config_reset_test_restore_platform_config);
TEST (config_reset_test_restore_platform_config_multiple);
TEST (config_reset_test_restore_platform_config_no_manifests);
TEST (config_reset_test_restore_platform_config_static_init);
TEST (config_reset_test_restore_platform_config_null);
TEST (config_reset_test_restore_platform_config_clear_error);
TEST (config_reset_test_clear_component_manifests);
TEST (config_reset_test_clear_component_manifests_multiple);
TEST (config_reset_test_clear_component_manifests_no_manifests);
TEST (config_reset_test_clear_component_manifests_static_init);
TEST (config_reset_test_clear_component_manifests_null);
TEST (config_reset_test_clear_component_manifests_clear_error);

TEST_SUITE_END;
// *INDENT-ON*
