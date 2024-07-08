// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "testing.h"
#include "cmd_interface/authorized_execution_config_reset.h"
#include "cmd_interface/authorized_execution_config_reset_static.h"
#include "cmd_interface/cmd_logging.h"
#include "cmd_interface/config_reset.h"
#include "testing/cmd_interface/config_reset_testing.h"
#include "testing/logging/debug_log_testing.h"
#include "testing/mock/keystore/keystore_mock.h"
#include "testing/mock/logging/logging_mock.h"
#include "testing/mock/manifest/manifest_manager_mock.h"
#include "testing/mock/recovery/recovery_image_manager_mock.h"
#include "testing/mock/state_manager/state_manager_mock.h"


TEST_SUITE_LABEL ("authorized_execution_config_reset");


/**
 * Dependencies for testing.
 */
struct authorized_execution_config_reset_testing {
	struct manifest_manager_mock manifest_bypass;		/**< Bypass manifest to clear. */
	struct manifest_manager_mock manifest_config;		/**< Config manifest to clear. */
	struct manifest_manager_mock manifest_components;	/**< Component manifest to clear. */
	struct state_manager_mock state_mgr;				/**< State to clear. */
	struct keystore_mock keystore;						/**< Extra keystore to clear. */
	struct recovery_image_manager_mock recovery;		/**< Mock for recovery image management. */
	struct config_reset_testing_keys keys;				/**< RIoT and aux keys. */
	const struct manifest_manager *bypass[1];			/**< List of bypass manifests. */
	const struct manifest_manager *config[1];			/**< List of config manifests. */
	const struct manifest_manager *components[1];		/**< List of component manifests. */
	struct state_manager *state_list[1];				/**< List of state managers. */
	const struct keystore *keystores[1];				/**< List of keystores. */
	struct config_reset reset;							/**< Configuration reset manager. */
	struct logging_mock log;							/**< Mock for debug logging. */
	struct authorized_execution_config_reset test;		/**< Authorized execution under test. */
};


/**
 * Initialize testing dependencies.
 *
 * @param test The testing framework.
 * @param execution The testing components to initialize.
 */
static void authorized_execution_config_reset_testing_init_dependencies (CuTest *test,
	struct authorized_execution_config_reset_testing *execution)
{
	int status;

	debug_log = NULL;

	config_reset_testing_init_attestation_keys (test, &execution->keys);

	status = manifest_manager_mock_init (&execution->manifest_bypass);
	CuAssertIntEquals (test, 0, status);
	mock_set_name (&execution->manifest_bypass.mock, "manifest_bypass");
	execution->bypass[0] = &execution->manifest_bypass.base;

	status = manifest_manager_mock_init (&execution->manifest_config);
	CuAssertIntEquals (test, 0, status);
	mock_set_name (&execution->manifest_config.mock, "manifest_config");
	execution->config[0] = &execution->manifest_config.base;

	status = manifest_manager_mock_init (&execution->manifest_components);
	CuAssertIntEquals (test, 0, status);
	mock_set_name (&execution->manifest_components.mock, "manifest_components");
	execution->components[0] = &execution->manifest_components.base;

	status = state_manager_mock_init (&execution->state_mgr);
	CuAssertIntEquals (test, 0, status);
	execution->state_list[0] = &execution->state_mgr.base;

	status = recovery_image_manager_mock_init (&execution->recovery);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_init (&execution->keystore);
	CuAssertIntEquals (test, 0, status);
	execution->keystores[0] = &execution->keystore.base;

	status = config_reset_init (&execution->reset, execution->bypass, 1, execution->config, 1,
		execution->components, 1, execution->state_list, 1, &execution->keys.riot,
		&execution->keys.aux, &execution->recovery.base, execution->keystores, 1);
	CuAssertIntEquals (test, 0, status);

	status = logging_mock_init (&execution->log);
	CuAssertIntEquals (test, 0, status);

	debug_log = &execution->log.base;
}

/**
 * Release all testing dependencies and validate all mocks.
 *
 * @param test The testing framework.
 * @param execution The testing dependencies to release.
 */
static void authorized_execution_config_reset_testing_release_dependencies (CuTest *test,
	struct authorized_execution_config_reset_testing *execution)
{
	int status;

	debug_log = NULL;

	status = manifest_manager_mock_validate_and_release (&execution->manifest_bypass);
	status |= manifest_manager_mock_validate_and_release (&execution->manifest_config);
	status |= manifest_manager_mock_validate_and_release (&execution->manifest_components);
	status |= state_manager_mock_validate_and_release (&execution->state_mgr);
	status |= recovery_image_manager_mock_validate_and_release (&execution->recovery);
	status |= keystore_mock_validate_and_release (&execution->keystore);
	status |= logging_mock_validate_and_release (&execution->log);
	status |= config_reset_testing_release_attestation_keys (test, &execution->keys);

	CuAssertIntEquals (test, 0, status);

	config_reset_release (&execution->reset);
}

/**
 * Initialize a restore bypass mode instance for testing.
 *
 * @param test The testing framework.
 * @param execution The testing components to initialize.
 */
static void authorized_execution_config_reset_testing_init_restore_bypass (CuTest *test,
	struct authorized_execution_config_reset_testing *execution)
{
	int status;

	authorized_execution_config_reset_testing_init_dependencies (test, execution);

	status = authorized_execution_config_reset_init_restore_bypass (&execution->test,
		&execution->reset);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Initialize a restore defaults instance for testing.
 *
 * @param test The testing framework.
 * @param execution The testing components to initialize.
 */
static void authorized_execution_config_reset_testing_init_restore_defaults (CuTest *test,
	struct authorized_execution_config_reset_testing *execution)
{
	int status;

	authorized_execution_config_reset_testing_init_dependencies (test, execution);

	status = authorized_execution_config_reset_init_restore_defaults (&execution->test,
		&execution->reset);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Initialize a clear platform config instance for testing.
 *
 * @param test The testing framework.
 * @param execution The testing components to initialize.
 */
static void authorized_execution_config_reset_testing_init_restore_platform_config (CuTest *test,
	struct authorized_execution_config_reset_testing *execution)
{
	int status;

	authorized_execution_config_reset_testing_init_dependencies (test, execution);

	status = authorized_execution_config_reset_init_restore_platform_config (&execution->test,
		&execution->reset);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Initialize a clear component manifests instance for testing.
 *
 * @param test The testing framework.
 * @param execution The testing components to initialize.
 */
static void authorized_execution_config_reset_testing_init_clear_component_manifests (CuTest *test,
	struct authorized_execution_config_reset_testing *execution)
{
	int status;

	authorized_execution_config_reset_testing_init_dependencies (test, execution);

	status = authorized_execution_config_reset_init_clear_component_manifests (&execution->test,
		&execution->reset);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Release a test instance and validate all mocks.
 *
 * @param test The testing framework.
 * @param execution The testing components to release.
 */
static void authorized_execution_config_reset_testing_release (CuTest *test,
	struct authorized_execution_config_reset_testing *execution)
{
	authorized_execution_config_reset_release (&execution->test);

	authorized_execution_config_reset_testing_release_dependencies (test, execution);
}


/*******************
 * Test cases
 *******************/

static void authorized_execution_config_reset_test_init_restore_bypass (CuTest *test)
{
	struct authorized_execution_config_reset_testing execution;
	int status;

	TEST_START;

	authorized_execution_config_reset_testing_init_dependencies (test, &execution);

	status = authorized_execution_config_reset_init_restore_bypass (&execution.test,
		&execution.reset);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, execution.test.base.execute);
	CuAssertPtrNotNull (test, execution.test.base.get_status_identifiers);

	authorized_execution_config_reset_testing_release (test, &execution);
}

static void authorized_execution_config_reset_test_init_restore_bypass_null (CuTest *test)
{
	struct authorized_execution_config_reset_testing execution;
	int status;

	TEST_START;

	authorized_execution_config_reset_testing_init_dependencies (test, &execution);

	status = authorized_execution_config_reset_init_restore_bypass (NULL, &execution.reset);
	CuAssertIntEquals (test, AUTHORIZED_EXECUTION_INVALID_ARGUMENT, status);

	status = authorized_execution_config_reset_init_restore_bypass (&execution.test, NULL);
	CuAssertIntEquals (test, AUTHORIZED_EXECUTION_INVALID_ARGUMENT, status);

	authorized_execution_config_reset_testing_release_dependencies (test, &execution);
}

static void authorized_execution_config_reset_test_init_restore_defaults (CuTest *test)
{
	struct authorized_execution_config_reset_testing execution;
	int status;

	TEST_START;

	authorized_execution_config_reset_testing_init_dependencies (test, &execution);

	status = authorized_execution_config_reset_init_restore_defaults (&execution.test,
		&execution.reset);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, execution.test.base.execute);
	CuAssertPtrNotNull (test, execution.test.base.get_status_identifiers);

	authorized_execution_config_reset_testing_release (test, &execution);
}

static void authorized_execution_config_reset_test_init_restore_defaults_null (CuTest *test)
{
	struct authorized_execution_config_reset_testing execution;
	int status;

	TEST_START;

	authorized_execution_config_reset_testing_init_dependencies (test, &execution);

	status = authorized_execution_config_reset_init_restore_defaults (NULL,	&execution.reset);
	CuAssertIntEquals (test, AUTHORIZED_EXECUTION_INVALID_ARGUMENT, status);

	status = authorized_execution_config_reset_init_restore_defaults (&execution.test, NULL);
	CuAssertIntEquals (test, AUTHORIZED_EXECUTION_INVALID_ARGUMENT, status);

	authorized_execution_config_reset_testing_release_dependencies (test, &execution);
}

static void authorized_execution_config_reset_test_init_restore_platform_config (CuTest *test)
{
	struct authorized_execution_config_reset_testing execution;
	int status;

	TEST_START;

	authorized_execution_config_reset_testing_init_dependencies (test, &execution);

	status = authorized_execution_config_reset_init_restore_platform_config (&execution.test,
		&execution.reset);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, execution.test.base.execute);
	CuAssertPtrNotNull (test, execution.test.base.get_status_identifiers);

	authorized_execution_config_reset_testing_release (test, &execution);
}

static void authorized_execution_config_reset_test_init_restore_platform_config_null (CuTest *test)
{
	struct authorized_execution_config_reset_testing execution;
	int status;

	TEST_START;

	authorized_execution_config_reset_testing_init_dependencies (test, &execution);

	status = authorized_execution_config_reset_init_restore_platform_config (NULL,
		&execution.reset);
	CuAssertIntEquals (test, AUTHORIZED_EXECUTION_INVALID_ARGUMENT, status);

	status = authorized_execution_config_reset_init_restore_platform_config (&execution.test, NULL);
	CuAssertIntEquals (test, AUTHORIZED_EXECUTION_INVALID_ARGUMENT, status);

	authorized_execution_config_reset_testing_release_dependencies (test, &execution);
}

static void authorized_execution_config_reset_test_init_clear_component_manifests (CuTest *test)
{
	struct authorized_execution_config_reset_testing execution;
	int status;

	TEST_START;

	authorized_execution_config_reset_testing_init_dependencies (test, &execution);

	status = authorized_execution_config_reset_init_clear_component_manifests (&execution.test,
		&execution.reset);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, execution.test.base.execute);
	CuAssertPtrNotNull (test, execution.test.base.get_status_identifiers);

	authorized_execution_config_reset_testing_release (test, &execution);
}

static void authorized_execution_config_reset_test_init_clear_component_manifests_null (
	CuTest *test)
{
	struct authorized_execution_config_reset_testing execution;
	int status;

	TEST_START;

	authorized_execution_config_reset_testing_init_dependencies (test, &execution);

	status = authorized_execution_config_reset_init_clear_component_manifests (NULL,
		&execution.reset);
	CuAssertIntEquals (test, AUTHORIZED_EXECUTION_INVALID_ARGUMENT, status);

	status = authorized_execution_config_reset_init_clear_component_manifests (&execution.test,
		NULL);
	CuAssertIntEquals (test, AUTHORIZED_EXECUTION_INVALID_ARGUMENT, status);

	authorized_execution_config_reset_testing_release_dependencies (test, &execution);
}

static void authorized_execution_config_reset_test_static_init_restore_bypass (CuTest *test)
{
	struct authorized_execution_config_reset_testing execution = {
		.test = authorized_execution_config_reset_static_init_restore_bypass (&execution.reset)
	};

	TEST_START;

	CuAssertPtrNotNull (test, execution.test.base.execute);
	CuAssertPtrNotNull (test, execution.test.base.get_status_identifiers);

	authorized_execution_config_reset_testing_init_dependencies (test, &execution);

	authorized_execution_config_reset_testing_release (test, &execution);
}

static void authorized_execution_config_reset_test_static_init_restore_defaults (CuTest *test)
{
	struct authorized_execution_config_reset_testing execution = {
		.test = authorized_execution_config_reset_static_init_restore_defaults (&execution.reset)
	};

	TEST_START;

	CuAssertPtrNotNull (test, execution.test.base.execute);
	CuAssertPtrNotNull (test, execution.test.base.get_status_identifiers);

	authorized_execution_config_reset_testing_init_dependencies (test, &execution);

	authorized_execution_config_reset_testing_release (test, &execution);
}

static void authorized_execution_config_reset_test_static_init_restore_platform_config (
	CuTest *test)
{
	struct authorized_execution_config_reset_testing execution = {
		.test =
			authorized_execution_config_reset_static_init_restore_platform_config (&execution.reset)
	};

	TEST_START;

	CuAssertPtrNotNull (test, execution.test.base.execute);
	CuAssertPtrNotNull (test, execution.test.base.get_status_identifiers);

	authorized_execution_config_reset_testing_init_dependencies (test, &execution);

	authorized_execution_config_reset_testing_release (test, &execution);
}

static void authorized_execution_config_reset_test_static_init_clear_component_manifests (
	CuTest *test)
{
	struct authorized_execution_config_reset_testing execution = {
		.test =
			authorized_execution_config_reset_static_init_clear_component_manifests (
			&execution.reset)
	};

	TEST_START;

	CuAssertPtrNotNull (test, execution.test.base.execute);
	CuAssertPtrNotNull (test, execution.test.base.get_status_identifiers);

	authorized_execution_config_reset_testing_init_dependencies (test, &execution);

	authorized_execution_config_reset_testing_release (test, &execution);
}

static void authorized_execution_config_reset_test_release_null (CuTest *test)
{
	TEST_START;

	authorized_execution_config_reset_release (NULL);
}

static void authorized_execution_config_reset_test_execute_restore_bypass (CuTest *test)
{
	struct authorized_execution_config_reset_testing execution;
	bool reset_req = false;
	int status;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_INFO,
		.component = DEBUG_LOG_COMPONENT_CMD_INTERFACE,
		.msg_index = CMD_LOGGING_BYPASS_RESTORED,
		.arg1 = 0,
		.arg2 = 0
	};

	TEST_START;

	authorized_execution_config_reset_testing_init_restore_bypass (test, &execution);

	status = mock_expect (&execution.manifest_bypass.mock,
		execution.manifest_bypass.base.clear_all_manifests, &execution.manifest_bypass, 0);

	status |= mock_expect (&execution.log.mock, execution.log.base.create_entry, &execution.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));

	CuAssertIntEquals (test, 0, status);

	status = execution.test.base.execute (&execution.test.base, &reset_req);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, false, reset_req);

	authorized_execution_config_reset_testing_release (test, &execution);
}

static void authorized_execution_config_reset_test_execute_restore_bypass_failure (CuTest *test)
{
	struct authorized_execution_config_reset_testing execution;
	bool reset_req = false;
	int status;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_CMD_INTERFACE,
		.msg_index = CMD_LOGGING_RESTORE_BYPASS_FAIL,
		.arg1 = MANIFEST_MANAGER_CLEAR_ALL_FAILED,
		.arg2 = 0
	};

	TEST_START;

	authorized_execution_config_reset_testing_init_restore_bypass (test, &execution);

	status = mock_expect (&execution.manifest_bypass.mock,
		execution.manifest_bypass.base.clear_all_manifests, &execution.manifest_bypass,
		MANIFEST_MANAGER_CLEAR_ALL_FAILED);

	status |= mock_expect (&execution.log.mock, execution.log.base.create_entry, &execution.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));

	CuAssertIntEquals (test, 0, status);

	status = execution.test.base.execute (&execution.test.base, &reset_req);
	CuAssertIntEquals (test, MANIFEST_MANAGER_CLEAR_ALL_FAILED, status);
	CuAssertIntEquals (test, false, reset_req);

	authorized_execution_config_reset_testing_release (test, &execution);
}

static void authorized_execution_config_reset_test_execute_restore_bypass_static_init (CuTest *test)
{
	struct authorized_execution_config_reset_testing execution = {
		.test = authorized_execution_config_reset_static_init_restore_bypass (&execution.reset)
	};
	bool reset_req = true;
	int status;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_INFO,
		.component = DEBUG_LOG_COMPONENT_CMD_INTERFACE,
		.msg_index = CMD_LOGGING_BYPASS_RESTORED,
		.arg1 = 0,
		.arg2 = 0
	};

	TEST_START;

	authorized_execution_config_reset_testing_init_dependencies (test, &execution);

	status = mock_expect (&execution.manifest_bypass.mock,
		execution.manifest_bypass.base.clear_all_manifests, &execution.manifest_bypass, 0);

	status |= mock_expect (&execution.log.mock, execution.log.base.create_entry, &execution.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));

	CuAssertIntEquals (test, 0, status);

	status = execution.test.base.execute (&execution.test.base, &reset_req);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, true, reset_req);

	authorized_execution_config_reset_testing_release (test, &execution);
}

static void authorized_execution_config_reset_test_execute_restore_defaults (CuTest *test)
{
	struct authorized_execution_config_reset_testing execution;
	bool reset_req = false;
	int status;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_INFO,
		.component = DEBUG_LOG_COMPONENT_CMD_INTERFACE,
		.msg_index = CMD_LOGGING_DEFAULTS_RESTORED,
		.arg1 = 0,
		.arg2 = 0
	};

	TEST_START;

	authorized_execution_config_reset_testing_init_restore_defaults (test, &execution);

	status = mock_expect (&execution.manifest_bypass.mock,
		execution.manifest_bypass.base.clear_all_manifests, &execution.manifest_bypass, 0);
	status |= mock_expect (&execution.manifest_config.mock,
		execution.manifest_config.base.clear_all_manifests, &execution.manifest_config, 0);
	status |= mock_expect (&execution.manifest_components.mock,
		execution.manifest_components.base.clear_all_manifests, &execution.manifest_components, 0);
	status |= mock_expect (&execution.state_mgr.mock,
		execution.state_mgr.base.restore_default_state, &execution.state_mgr, 0);

	status |= mock_expect (&execution.keys.riot_keystore.mock,
		execution.keys.riot_keystore.base.erase_key, &execution.keys.riot_keystore, 0,
		MOCK_ARG (0));
	status |= mock_expect (&execution.keys.riot_keystore.mock,
		execution.keys.riot_keystore.base.erase_key, &execution.keys.riot_keystore, 0,
		MOCK_ARG (1));
	status |= mock_expect (&execution.keys.riot_keystore.mock,
		execution.keys.riot_keystore.base.erase_key, &execution.keys.riot_keystore, 0,
		MOCK_ARG (2));

	status |= mock_expect (&execution.keys.aux_keystore.mock,
		execution.keys.aux_keystore.base.erase_key, &execution.keys.aux_keystore, 0, MOCK_ARG (0));

	status |= mock_expect (&execution.recovery.mock,
		execution.recovery.base.erase_all_recovery_regions, &execution.recovery, 0);

	status |= mock_expect (&execution.keystore.mock, execution.keystore.base.erase_all_keys,
		&execution.keystore, 0);

	status |= mock_expect (&execution.log.mock, execution.log.base.create_entry, &execution.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));

	CuAssertIntEquals (test, 0, status);

	status = execution.test.base.execute (&execution.test.base, &reset_req);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, false, reset_req);

	authorized_execution_config_reset_testing_release (test, &execution);
}

static void authorized_execution_config_reset_test_execute_restore_defaults_failure (CuTest *test)
{
	struct authorized_execution_config_reset_testing execution;
	bool reset_req = false;
	int status;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_CMD_INTERFACE,
		.msg_index = CMD_LOGGING_RESTORE_DEFAULTS_FAIL,
		.arg1 = MANIFEST_MANAGER_CLEAR_ALL_FAILED,
		.arg2 = 0
	};

	TEST_START;

	authorized_execution_config_reset_testing_init_restore_defaults (test, &execution);

	status = mock_expect (&execution.manifest_bypass.mock,
		execution.manifest_bypass.base.clear_all_manifests, &execution.manifest_bypass,
		MANIFEST_MANAGER_CLEAR_ALL_FAILED);

	status |= mock_expect (&execution.log.mock, execution.log.base.create_entry, &execution.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));

	CuAssertIntEquals (test, 0, status);

	status = execution.test.base.execute (&execution.test.base, &reset_req);
	CuAssertIntEquals (test, MANIFEST_MANAGER_CLEAR_ALL_FAILED, status);
	CuAssertIntEquals (test, false, reset_req);

	authorized_execution_config_reset_testing_release (test, &execution);
}

static void authorized_execution_config_reset_test_execute_restore_defaults_static_init (
	CuTest *test)
{
	struct authorized_execution_config_reset_testing execution = {
		.test = authorized_execution_config_reset_static_init_restore_defaults (&execution.reset)
	};
	bool reset_req = true;
	int status;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_INFO,
		.component = DEBUG_LOG_COMPONENT_CMD_INTERFACE,
		.msg_index = CMD_LOGGING_DEFAULTS_RESTORED,
		.arg1 = 0,
		.arg2 = 0
	};

	TEST_START;

	authorized_execution_config_reset_testing_init_dependencies (test, &execution);

	status = mock_expect (&execution.manifest_bypass.mock,
		execution.manifest_bypass.base.clear_all_manifests, &execution.manifest_bypass, 0);
	status |= mock_expect (&execution.manifest_config.mock,
		execution.manifest_config.base.clear_all_manifests, &execution.manifest_config, 0);
	status |= mock_expect (&execution.manifest_components.mock,
		execution.manifest_components.base.clear_all_manifests, &execution.manifest_components, 0);
	status |= mock_expect (&execution.state_mgr.mock,
		execution.state_mgr.base.restore_default_state, &execution.state_mgr, 0);

	status |= mock_expect (&execution.keys.riot_keystore.mock,
		execution.keys.riot_keystore.base.erase_key, &execution.keys.riot_keystore, 0,
		MOCK_ARG (0));
	status |= mock_expect (&execution.keys.riot_keystore.mock,
		execution.keys.riot_keystore.base.erase_key, &execution.keys.riot_keystore, 0,
		MOCK_ARG (1));
	status |= mock_expect (&execution.keys.riot_keystore.mock,
		execution.keys.riot_keystore.base.erase_key, &execution.keys.riot_keystore, 0,
		MOCK_ARG (2));

	status |= mock_expect (&execution.keys.aux_keystore.mock,
		execution.keys.aux_keystore.base.erase_key, &execution.keys.aux_keystore, 0, MOCK_ARG (0));

	status |= mock_expect (&execution.recovery.mock,
		execution.recovery.base.erase_all_recovery_regions, &execution.recovery, 0);

	status |= mock_expect (&execution.keystore.mock, execution.keystore.base.erase_all_keys,
		&execution.keystore, 0);

	status |= mock_expect (&execution.log.mock, execution.log.base.create_entry, &execution.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));

	CuAssertIntEquals (test, 0, status);

	status = execution.test.base.execute (&execution.test.base, &reset_req);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, true, reset_req);

	authorized_execution_config_reset_testing_release (test, &execution);
}

static void authorized_execution_config_reset_test_execute_clear_platform_config (CuTest *test)
{
	struct authorized_execution_config_reset_testing execution;
	bool reset_req = false;
	int status;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_INFO,
		.component = DEBUG_LOG_COMPONENT_CMD_INTERFACE,
		.msg_index = CMD_LOGGING_CLEAR_PLATFORM_CONFIG,
		.arg1 = 0,
		.arg2 = 0
	};

	TEST_START;

	authorized_execution_config_reset_testing_init_restore_platform_config (test, &execution);

	status = mock_expect (&execution.manifest_config.mock,
		execution.manifest_config.base.clear_all_manifests, &execution.manifest_config, 0);

	status |= mock_expect (&execution.log.mock, execution.log.base.create_entry, &execution.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));

	CuAssertIntEquals (test, 0, status);

	status = execution.test.base.execute (&execution.test.base, &reset_req);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, true, reset_req);

	authorized_execution_config_reset_testing_release (test, &execution);
}

static void authorized_execution_config_reset_test_execute_clear_platform_config_failure (
	CuTest *test)
{
	struct authorized_execution_config_reset_testing execution;
	bool reset_req = false;
	int status;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_CMD_INTERFACE,
		.msg_index = CMD_LOGGING_CLEAR_PLATFORM_FAIL,
		.arg1 = MANIFEST_MANAGER_CLEAR_ALL_FAILED,
		.arg2 = 0
	};

	TEST_START;

	authorized_execution_config_reset_testing_init_restore_platform_config (test, &execution);

	status = mock_expect (&execution.manifest_config.mock,
		execution.manifest_config.base.clear_all_manifests, &execution.manifest_config,
		MANIFEST_MANAGER_CLEAR_ALL_FAILED);

	status |= mock_expect (&execution.log.mock, execution.log.base.create_entry, &execution.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));

	CuAssertIntEquals (test, 0, status);

	status = execution.test.base.execute (&execution.test.base, &reset_req);
	CuAssertIntEquals (test, MANIFEST_MANAGER_CLEAR_ALL_FAILED, status);
	CuAssertIntEquals (test, false, reset_req);

	authorized_execution_config_reset_testing_release (test, &execution);
}

static void authorized_execution_config_reset_test_execute_clear_platform_config_no_reset_req (
	CuTest *test)
{
	struct authorized_execution_config_reset_testing execution;
	int status;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_INFO,
		.component = DEBUG_LOG_COMPONENT_CMD_INTERFACE,
		.msg_index = CMD_LOGGING_CLEAR_PLATFORM_CONFIG,
		.arg1 = 0,
		.arg2 = 0
	};

	TEST_START;

	authorized_execution_config_reset_testing_init_restore_platform_config (test, &execution);

	status = mock_expect (&execution.manifest_config.mock,
		execution.manifest_config.base.clear_all_manifests, &execution.manifest_config, 0);

	status |= mock_expect (&execution.log.mock, execution.log.base.create_entry, &execution.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));

	CuAssertIntEquals (test, 0, status);

	status = execution.test.base.execute (&execution.test.base, NULL);
	CuAssertIntEquals (test, 0, status);

	authorized_execution_config_reset_testing_release (test, &execution);
}

static void authorized_execution_config_reset_test_execute_clear_platform_config_static_init (
	CuTest *test)
{
	struct authorized_execution_config_reset_testing execution = {
		.test =
			authorized_execution_config_reset_static_init_restore_platform_config (&execution.reset)
	};
	bool reset_req = false;
	int status;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_INFO,
		.component = DEBUG_LOG_COMPONENT_CMD_INTERFACE,
		.msg_index = CMD_LOGGING_CLEAR_PLATFORM_CONFIG,
		.arg1 = 0,
		.arg2 = 0
	};

	TEST_START;

	authorized_execution_config_reset_testing_init_dependencies (test, &execution);

	status = mock_expect (&execution.manifest_config.mock,
		execution.manifest_config.base.clear_all_manifests, &execution.manifest_config, 0);

	status |= mock_expect (&execution.log.mock, execution.log.base.create_entry, &execution.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));

	CuAssertIntEquals (test, 0, status);

	status = execution.test.base.execute (&execution.test.base, &reset_req);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, true, reset_req);

	authorized_execution_config_reset_testing_release (test, &execution);
}

static void authorized_execution_config_reset_test_execute_clear_component_manifests (CuTest *test)
{
	struct authorized_execution_config_reset_testing execution;
	bool reset_req = false;
	int status;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_INFO,
		.component = DEBUG_LOG_COMPONENT_CMD_INTERFACE,
		.msg_index = CMD_LOGGING_CLEAR_CFM,
		.arg1 = 0,
		.arg2 = 0
	};

	TEST_START;

	authorized_execution_config_reset_testing_init_clear_component_manifests (test, &execution);

	status = mock_expect (&execution.manifest_components.mock,
		execution.manifest_components.base.clear_all_manifests, &execution.manifest_components, 0);

	status |= mock_expect (&execution.log.mock, execution.log.base.create_entry, &execution.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));

	CuAssertIntEquals (test, 0, status);

	status = execution.test.base.execute (&execution.test.base, &reset_req);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, false, reset_req);

	authorized_execution_config_reset_testing_release (test, &execution);
}

static void authorized_execution_config_reset_test_execute_clear_component_manifests_failure (
	CuTest *test)
{
	struct authorized_execution_config_reset_testing execution;
	bool reset_req = false;
	int status;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_CMD_INTERFACE,
		.msg_index = CMD_LOGGING_CLEAR_CFM_FAIL,
		.arg1 = MANIFEST_MANAGER_CLEAR_ALL_FAILED,
		.arg2 = 0
	};

	TEST_START;

	authorized_execution_config_reset_testing_init_clear_component_manifests (test, &execution);

	status = mock_expect (&execution.manifest_components.mock,
		execution.manifest_components.base.clear_all_manifests, &execution.manifest_components,
		MANIFEST_MANAGER_CLEAR_ALL_FAILED);

	status |= mock_expect (&execution.log.mock, execution.log.base.create_entry, &execution.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));

	CuAssertIntEquals (test, 0, status);

	status = execution.test.base.execute (&execution.test.base, &reset_req);
	CuAssertIntEquals (test, MANIFEST_MANAGER_CLEAR_ALL_FAILED, status);
	CuAssertIntEquals (test, false, reset_req);

	authorized_execution_config_reset_testing_release (test, &execution);
}

static void authorized_execution_config_reset_test_execute_clear_component_manifests_static_init (
	CuTest *test)
{
	struct authorized_execution_config_reset_testing execution = {
		.test =
			authorized_execution_config_reset_static_init_clear_component_manifests (
			&execution.reset)
	};
	bool reset_req = true;
	int status;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_INFO,
		.component = DEBUG_LOG_COMPONENT_CMD_INTERFACE,
		.msg_index = CMD_LOGGING_CLEAR_CFM,
		.arg1 = 0,
		.arg2 = 0
	};

	TEST_START;

	authorized_execution_config_reset_testing_init_dependencies (test, &execution);

	status = mock_expect (&execution.manifest_components.mock,
		execution.manifest_components.base.clear_all_manifests, &execution.manifest_components, 0);

	status |= mock_expect (&execution.log.mock, execution.log.base.create_entry, &execution.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));

	CuAssertIntEquals (test, 0, status);

	status = execution.test.base.execute (&execution.test.base, &reset_req);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, true, reset_req);

	authorized_execution_config_reset_testing_release (test, &execution);
}

static void authorized_execution_config_reset_test_execute_null (CuTest *test)
{
	struct authorized_execution_config_reset_testing execution;
	bool reset_req = false;
	int status;

	TEST_START;

	authorized_execution_config_reset_testing_init_restore_bypass (test, &execution);

	status = execution.test.base.execute (NULL, &reset_req);
	CuAssertIntEquals (test, AUTHORIZED_EXECUTION_INVALID_ARGUMENT, status);
	CuAssertIntEquals (test, false, reset_req);

	authorized_execution_config_reset_testing_release (test, &execution);
}

static void authorized_execution_config_reset_test_get_status_identifiers_restore_bypass (
	CuTest *test)
{
	struct authorized_execution_config_reset_testing execution;
	uint8_t start;
	uint8_t error;

	TEST_START;

	authorized_execution_config_reset_testing_init_restore_bypass (test, &execution);

	execution.test.base.get_status_identifiers (&execution.test.base, &start, &error);
	CuAssertIntEquals (test, CONFIG_RESET_STATUS_RESTORE_BYPASS, start);
	CuAssertIntEquals (test, CONFIG_RESET_STATUS_BYPASS_FAILED, error);

	authorized_execution_config_reset_testing_release (test, &execution);
}

static void authorized_execution_config_reset_test_get_status_identifiers_restore_bypass_static_init
(
	CuTest *test)
{
	struct authorized_execution_config_reset_testing execution = {
		.test = authorized_execution_config_reset_static_init_restore_bypass (&execution.reset)
	};
	uint8_t start;
	uint8_t error;

	TEST_START;

	authorized_execution_config_reset_testing_init_dependencies (test, &execution);

	execution.test.base.get_status_identifiers (&execution.test.base, &start, &error);
	CuAssertIntEquals (test, CONFIG_RESET_STATUS_RESTORE_BYPASS, start);
	CuAssertIntEquals (test, CONFIG_RESET_STATUS_BYPASS_FAILED, error);

	authorized_execution_config_reset_testing_release (test, &execution);
}

static void authorized_execution_config_reset_test_get_status_identifiers_restore_defaults (
	CuTest *test)
{
	struct authorized_execution_config_reset_testing execution;
	uint8_t start;
	uint8_t error;

	TEST_START;

	authorized_execution_config_reset_testing_init_restore_defaults (test, &execution);

	execution.test.base.get_status_identifiers (&execution.test.base, &start, &error);
	CuAssertIntEquals (test, CONFIG_RESET_STATUS_RESTORE_DEFAULTS, start);
	CuAssertIntEquals (test, CONFIG_RESET_STATUS_DEFAULTS_FAILED, error);

	authorized_execution_config_reset_testing_release (test, &execution);
}

static void
authorized_execution_config_reset_test_get_status_identifiers_restore_defaults_static_init (
	CuTest *test)
{
	struct authorized_execution_config_reset_testing execution = {
		.test = authorized_execution_config_reset_static_init_restore_defaults (&execution.reset)
	};
	uint8_t start;
	uint8_t error;

	TEST_START;

	authorized_execution_config_reset_testing_init_dependencies (test, &execution);

	execution.test.base.get_status_identifiers (&execution.test.base, &start, &error);
	CuAssertIntEquals (test, CONFIG_RESET_STATUS_RESTORE_DEFAULTS, start);
	CuAssertIntEquals (test, CONFIG_RESET_STATUS_DEFAULTS_FAILED, error);

	authorized_execution_config_reset_testing_release (test, &execution);
}

static void authorized_execution_config_reset_test_get_status_identifiers_restore_platform_config (
	CuTest *test)
{
	struct authorized_execution_config_reset_testing execution;
	uint8_t start;
	uint8_t error;

	TEST_START;

	authorized_execution_config_reset_testing_init_restore_platform_config (test, &execution);

	execution.test.base.get_status_identifiers (&execution.test.base, &start, &error);
	CuAssertIntEquals (test, CONFIG_RESET_STATUS_CLEAR_PLATFORM_CONFIG, start);
	CuAssertIntEquals (test, CONFIG_RESET_STATUS_PLATFORM_CONFIG_FAILED, error);

	authorized_execution_config_reset_testing_release (test, &execution);
}

static void
authorized_execution_config_reset_test_get_status_identifiers_restore_platform_config_static_init (
	CuTest *test)
{
	struct authorized_execution_config_reset_testing execution = {
		.test =
			authorized_execution_config_reset_static_init_restore_platform_config (&execution.reset)
	};
	uint8_t start;
	uint8_t error;

	TEST_START;

	authorized_execution_config_reset_testing_init_dependencies (test, &execution);

	execution.test.base.get_status_identifiers (&execution.test.base, &start, &error);
	CuAssertIntEquals (test, CONFIG_RESET_STATUS_CLEAR_PLATFORM_CONFIG, start);
	CuAssertIntEquals (test, CONFIG_RESET_STATUS_PLATFORM_CONFIG_FAILED, error);

	authorized_execution_config_reset_testing_release (test, &execution);
}

static void authorized_execution_config_reset_test_get_status_identifiers_clear_component_manifests
(
	CuTest *test)
{
	struct authorized_execution_config_reset_testing execution;
	uint8_t start;
	uint8_t error;

	TEST_START;

	authorized_execution_config_reset_testing_init_clear_component_manifests (test, &execution);

	execution.test.base.get_status_identifiers (&execution.test.base, &start, &error);
	CuAssertIntEquals (test, CONFIG_RESET_STATUS_CLEAR_COMPONENT_MANIFESTS, start);
	CuAssertIntEquals (test, CONFIG_RESET_STATUS_COMPONENT_MANIFESTS_FAILED, error);

	authorized_execution_config_reset_testing_release (test, &execution);
}

static void
authorized_execution_config_reset_test_get_status_identifiers_clear_component_manifests_static_init
(
	CuTest *test)
{
	struct authorized_execution_config_reset_testing execution = {
		.test =
			authorized_execution_config_reset_static_init_clear_component_manifests (
			&execution.reset)
	};
	uint8_t start;
	uint8_t error;

	TEST_START;

	authorized_execution_config_reset_testing_init_dependencies (test, &execution);

	execution.test.base.get_status_identifiers (&execution.test.base, &start, &error);
	CuAssertIntEquals (test, CONFIG_RESET_STATUS_CLEAR_COMPONENT_MANIFESTS, start);
	CuAssertIntEquals (test, CONFIG_RESET_STATUS_COMPONENT_MANIFESTS_FAILED, error);

	authorized_execution_config_reset_testing_release (test, &execution);
}

static void authorized_execution_config_reset_test_get_status_identifiers_null (CuTest *test)
{
	struct authorized_execution_config_reset_testing execution;
	uint8_t start;
	uint8_t error;

	TEST_START;

	authorized_execution_config_reset_testing_init_restore_bypass (test, &execution);

	execution.test.base.get_status_identifiers (NULL, &start, &error);
	CuAssertIntEquals (test, CONFIG_RESET_STATUS_AUTHORIZED_OPERATION, start);
	CuAssertIntEquals (test, CONFIG_RESET_STATUS_AUTHORIZED_OP_FAILED, error);

	execution.test.base.get_status_identifiers (&execution.test.base, NULL, &error);
	CuAssertIntEquals (test, CONFIG_RESET_STATUS_BYPASS_FAILED, error);

	execution.test.base.get_status_identifiers (&execution.test.base, &start, NULL);
	CuAssertIntEquals (test, CONFIG_RESET_STATUS_RESTORE_BYPASS, start);

	authorized_execution_config_reset_testing_release (test, &execution);
}


// *INDENT-OFF*
TEST_SUITE_START (authorized_execution_config_reset);

TEST (authorized_execution_config_reset_test_init_restore_bypass);
TEST (authorized_execution_config_reset_test_init_restore_bypass_null);
TEST (authorized_execution_config_reset_test_init_restore_defaults);
TEST (authorized_execution_config_reset_test_init_restore_defaults_null);
TEST (authorized_execution_config_reset_test_init_restore_platform_config);
TEST (authorized_execution_config_reset_test_init_restore_platform_config_null);
TEST (authorized_execution_config_reset_test_init_clear_component_manifests);
TEST (authorized_execution_config_reset_test_init_clear_component_manifests_null);
TEST (authorized_execution_config_reset_test_static_init_restore_bypass);
TEST (authorized_execution_config_reset_test_static_init_restore_defaults);
TEST (authorized_execution_config_reset_test_static_init_restore_platform_config);
TEST (authorized_execution_config_reset_test_static_init_clear_component_manifests);
TEST (authorized_execution_config_reset_test_release_null);
TEST (authorized_execution_config_reset_test_execute_restore_bypass);
TEST (authorized_execution_config_reset_test_execute_restore_bypass_failure);
TEST (authorized_execution_config_reset_test_execute_restore_bypass_static_init);
TEST (authorized_execution_config_reset_test_execute_restore_defaults);
TEST (authorized_execution_config_reset_test_execute_restore_defaults_failure);
TEST (authorized_execution_config_reset_test_execute_restore_defaults_static_init);
TEST (authorized_execution_config_reset_test_execute_clear_platform_config);
TEST (authorized_execution_config_reset_test_execute_clear_platform_config_failure);
TEST (authorized_execution_config_reset_test_execute_clear_platform_config_no_reset_req);
TEST (authorized_execution_config_reset_test_execute_clear_platform_config_static_init);
TEST (authorized_execution_config_reset_test_execute_clear_component_manifests);
TEST (authorized_execution_config_reset_test_execute_clear_component_manifests_failure);
TEST (authorized_execution_config_reset_test_execute_clear_component_manifests_static_init);
TEST (authorized_execution_config_reset_test_execute_null);
TEST (authorized_execution_config_reset_test_get_status_identifiers_restore_bypass);
TEST (authorized_execution_config_reset_test_get_status_identifiers_restore_bypass_static_init);
TEST (authorized_execution_config_reset_test_get_status_identifiers_restore_defaults);
TEST (authorized_execution_config_reset_test_get_status_identifiers_restore_defaults_static_init);
TEST (authorized_execution_config_reset_test_get_status_identifiers_restore_platform_config);
TEST (authorized_execution_config_reset_test_get_status_identifiers_restore_platform_config_static_init);
TEST (authorized_execution_config_reset_test_get_status_identifiers_clear_component_manifests);
TEST (authorized_execution_config_reset_test_get_status_identifiers_clear_component_manifests_static_init);
TEST (authorized_execution_config_reset_test_get_status_identifiers_null);

TEST_SUITE_END;
// *INDENT-ON*
