// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "testing.h"
#include "cmd_interface/attestation_cmd_interface.h"
#include "cmd_interface/cmd_background_handler.h"
#include "cmd_interface/cmd_background_handler_static.h"
#include "cmd_interface/cmd_logging.h"
#include "crypto/aes.h"
#include "flash/flash_common.h"
#include "logging/logging_flash.h"
#include "riot/riot_logging.h"
#include "testing/asn1/x509_testing.h"
#include "testing/attestation/aux_attestation_testing.h"
#include "testing/cmd_interface/config_reset_testing.h"
#include "testing/engines/hash_testing_engine.h"
#include "testing/logging/debug_log_testing.h"
#include "testing/mock/attestation/attestation_responder_mock.h"
#include "testing/mock/common/authorized_execution_mock.h"
#include "testing/mock/crypto/rsa_mock.h"
#include "testing/mock/logging/logging_mock.h"
#include "testing/mock/system/event_task_mock.h"
#include "testing/riot/riot_core_testing.h"


TEST_SUITE_LABEL ("cmd_background_handler");


/**
 * Dependencies for testing.
 */
struct cmd_background_handler_testing {
	HASH_TESTING_ENGINE hash;						/**< Hash engine for attestation. */
	struct config_reset_testing_keys keys;			/**< RIoT and aux keys. */
	struct authorized_execution_mock execution;		/**< Mock for an operation execution context. */
	struct attestation_responder_mock attestation;	/**< Mock for attestation requests. */
	struct rsa_engine_mock rsa_mock;				/**< Mock for RSA operations. */
	struct logging_mock log;						/**< Mock for debug logging. */
	struct event_task_mock task;					/**< Mock for the command task. */
	struct event_task_context context;				/**< Event context for event processing. */
	struct event_task_context *context_ptr;			/**< Pointer to the event context. */
	struct cmd_background_handler_state state;		/**< Context for the background handler. */
	struct cmd_background_handler test;				/**< Background command handler under test. */
};


/**
 * Initialize testing dependencies.
 *
 * @param test The testing framework.
 * @param handler The testing components to initialize.
 * @param valid_cert_chain Flag to seed with a valid certificate chain.
 */
static void cmd_background_handler_testing_init_dependencies_and_certs (CuTest *test,
	struct cmd_background_handler_testing *handler, bool valid_cert_chain)
{
	int status;

	debug_log = NULL;
	if (valid_cert_chain) {
		config_reset_testing_init_attestation_keys_valid_cert_chain (test, &handler->keys);
	}
	else {
		config_reset_testing_init_attestation_keys (test, &handler->keys);
	}

	status = HASH_TESTING_ENGINE_INIT (&handler->hash);
	CuAssertIntEquals (test, 0, status);

	status = authorized_execution_mock_init (&handler->execution);
	CuAssertIntEquals (test, 0, status);

	status = attestation_responder_mock_init (&handler->attestation);
	CuAssertIntEquals (test, 0, status);

	status = rsa_mock_init (&handler->rsa_mock);
	CuAssertIntEquals (test, 0, status);

	status = logging_mock_init (&handler->log);
	CuAssertIntEquals (test, 0, status);

	status = event_task_mock_init (&handler->task);
	CuAssertIntEquals (test, 0, status);

	memset (&handler->context, 0, sizeof (handler->context));
	handler->context_ptr = &handler->context;

	debug_log = &handler->log.base;
}

/**
 * Initialize testing dependencies.
 *
 * @param test The testing framework.
 * @param handler The testing components to initialize.
 */
static void cmd_background_handler_testing_init_dependencies (CuTest *test,
	struct cmd_background_handler_testing *handler)
{
	cmd_background_handler_testing_init_dependencies_and_certs (test, handler, false);
}

/**
 * Initialize an instance for testing.
 *
 * @param test The testing framework.
 * @param handler The testing components to initialize.
 */
static void cmd_background_handler_testing_init (CuTest *test,
	struct cmd_background_handler_testing *handler)
{
	int status;

	cmd_background_handler_testing_init_dependencies_and_certs (test, handler, false);

	status = cmd_background_handler_init (&handler->test, &handler->state,
		&handler->attestation.base, &handler->hash.base, &handler->keys.riot, &handler->task.base);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Initialize an instance with a valid cert chain for testing.
 *
 * @param test The testing framework.
 * @param handler The testing components to initialize.
 */
static void cmd_background_handler_testing_init_valid_certs (CuTest *test,
	struct cmd_background_handler_testing *handler)
{
	int status;

	cmd_background_handler_testing_init_dependencies_and_certs (test, handler, true);

	status = cmd_background_handler_init (&handler->test, &handler->state,
		&handler->attestation.base, &handler->hash.base, &handler->keys.riot, &handler->task.base);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Initialize an instance for testing.  Aux attestation will use a mock RSA instance.
 *
 * @param test The testing framework.
 * @param handler The testing components to initialize.
 */
static void cmd_background_handler_testing_init_mock_rsa (CuTest *test,
	struct cmd_background_handler_testing *handler)
{
	int status;

	cmd_background_handler_testing_init_dependencies_and_certs (test, handler, false);

	aux_attestation_release (&handler->keys.aux);
	status = aux_attestation_init (&handler->keys.aux, &handler->keys.aux_keystore.base,
		&handler->rsa_mock.base, &handler->keys.riot, &handler->keys.ecc.base);
	CuAssertIntEquals (test, 0, status);

	status = cmd_background_handler_init (&handler->test, &handler->state,
		&handler->attestation.base, &handler->hash.base, &handler->keys.riot, &handler->task.base);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Initialize a static instance for testing.
 *
 * @param test The testing framework.
 * @param handler The testing components to initialize.
 */
static void cmd_background_handler_testing_init_static (CuTest *test,
	struct cmd_background_handler_testing *handler, struct cmd_background_handler *test_static)
{
	int status;

	cmd_background_handler_testing_init_dependencies_and_certs (test, handler, false);

	status = cmd_background_handler_init_state (test_static);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Initialize a static instance with a valid cert chain for testing.
 *
 * @param test The testing framework.
 * @param handler The testing components to initialize.
 */
static void cmd_background_handler_testing_init_static_valid_certs (CuTest *test,
	struct cmd_background_handler_testing *handler, struct cmd_background_handler *test_static)
{
	int status;

	cmd_background_handler_testing_init_dependencies_and_certs (test, handler, true);

	status = cmd_background_handler_init_state (test_static);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Initialize a static instance for testing.  Aux attestation will use a mock RSA instance.
 *
 * @param test The testing framework.
 * @param handler The testing components to initialize.
 */
static void cmd_background_handler_testing_init_static_mock_rsa (CuTest *test,
	struct cmd_background_handler_testing *handler, struct cmd_background_handler *test_static)
{
	int status;

	cmd_background_handler_testing_init_dependencies_and_certs (test, handler, false);

	aux_attestation_release (&handler->keys.aux);
	status = aux_attestation_init (&handler->keys.aux, &handler->keys.aux_keystore.base,
		&handler->rsa_mock.base, &handler->keys.riot, &handler->keys.ecc.base);
	CuAssertIntEquals (test, 0, status);

	status = cmd_background_handler_init_state (test_static);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Release all testing dependencies and validate all mocks.
 *
 * @param test The testing framework.
 * @param handler The testing dependencies to release.
 */
static void cmd_background_handler_testing_release_dependencies (CuTest *test,
	struct cmd_background_handler_testing *handler)
{
	int status;

	debug_log = NULL;

	status = authorized_execution_mock_validate_and_release (&handler->execution);
	status |= attestation_responder_mock_validate_and_release (&handler->attestation);
	status |= rsa_mock_validate_and_release (&handler->rsa_mock);
	status |= logging_mock_validate_and_release (&handler->log);
	status |= event_task_mock_validate_and_release (&handler->task);
	status |= config_reset_testing_release_attestation_keys (test, &handler->keys);

	CuAssertIntEquals (test, 0, status);
}

/**
 * Release a test instance and validate all mocks.
 *
 * @param test The testing framework.
 * @param handler The testing components to release.
 */
static void cmd_background_handler_testing_validate_and_release (CuTest *test,
	struct cmd_background_handler_testing *handler)
{
	cmd_background_handler_release (&handler->test);

	cmd_background_handler_testing_release_dependencies (test, handler);
}

/*******************
 * Test cases
 *******************/

static void cmd_background_handler_test_init (CuTest *test)
{
	struct cmd_background_handler_testing handler;
	int status;

	TEST_START;

	cmd_background_handler_testing_init_dependencies (test, &handler);

	status = cmd_background_handler_init (&handler.test, &handler.state, &handler.attestation.base,
		&handler.hash.base, &handler.keys.riot, &handler.task.base);
	CuAssertIntEquals (test, 0, status);

#ifdef CMD_ENABLE_UNSEAL
	CuAssertPtrNotNull (test, handler.test.base_cmd.unseal_start);
	CuAssertPtrNotNull (test, handler.test.base_cmd.unseal_result);
#endif
#ifdef CMD_ENABLE_RESET_CONFIG
	CuAssertPtrNotNull (test, handler.test.base_cmd.execute_authorized_operation);
	CuAssertPtrNotNull (test, handler.test.base_cmd.get_authorized_operation_status);
#endif
#ifdef CMD_ENABLE_DEBUG_LOG
	CuAssertPtrNotNull (test, handler.test.base_cmd.debug_log_clear);
#ifdef CMD_SUPPORT_DEBUG_COMMANDS
	CuAssertPtrNotNull (test, handler.test.base_cmd.debug_log_fill);
#endif
#endif
	CuAssertPtrNotNull (test, handler.test.base_cmd.authenticate_riot_certs);
	CuAssertPtrNotNull (test, handler.test.base_cmd.get_riot_cert_chain_state);
	CuAssertPtrNotNull (test, handler.test.base_cmd.reboot_device);

	CuAssertPtrEquals (test, NULL, handler.test.base_event.prepare);
	CuAssertPtrNotNull (test, handler.test.base_event.execute);

	cmd_background_handler_testing_validate_and_release (test, &handler);
}

static void cmd_background_handler_test_init_null (CuTest *test)
{
	struct cmd_background_handler_testing handler;
	int status;

	TEST_START;

	cmd_background_handler_testing_init_dependencies (test, &handler);

	status = cmd_background_handler_init (NULL, &handler.state, &handler.attestation.base,
		&handler.hash.base, &handler.keys.riot, &handler.task.base);
	CuAssertIntEquals (test, CMD_BACKGROUND_INVALID_ARGUMENT, status);

	status = cmd_background_handler_init (&handler.test, NULL, &handler.attestation.base,
		&handler.hash.base, &handler.keys.riot, &handler.task.base);
	CuAssertIntEquals (test, CMD_BACKGROUND_INVALID_ARGUMENT, status);

	status = cmd_background_handler_init (&handler.test, &handler.state, &handler.attestation.base,
		&handler.hash.base, NULL, &handler.task.base);
	CuAssertIntEquals (test, CMD_BACKGROUND_INVALID_ARGUMENT, status);

	status = cmd_background_handler_init (&handler.test, &handler.state, &handler.attestation.base,
		&handler.hash.base, &handler.keys.riot, NULL);
	CuAssertIntEquals (test, CMD_BACKGROUND_INVALID_ARGUMENT, status);

	cmd_background_handler_testing_release_dependencies (test, &handler);
}

static void cmd_background_handler_test_static_init (CuTest *test)
{
	struct cmd_background_handler_testing handler;
	struct cmd_background_handler test_static = cmd_background_handler_static_init (&handler.state,
		&handler.attestation.base, &handler.hash.base, &handler.keys.riot, &handler.task.base);
	int status;

	TEST_START;

	cmd_background_handler_testing_init_dependencies (test, &handler);

#ifdef CMD_ENABLE_UNSEAL
	CuAssertPtrNotNull (test, test_static.base_cmd.unseal_start);
	CuAssertPtrNotNull (test, test_static.base_cmd.unseal_result);
#endif
#ifdef CMD_ENABLE_RESET_CONFIG
	CuAssertPtrNotNull (test, test_static.base_cmd.execute_authorized_operation);
	CuAssertPtrNotNull (test, test_static.base_cmd.get_authorized_operation_status);
#endif
#ifdef CMD_ENABLE_DEBUG_LOG
	CuAssertPtrNotNull (test, test_static.base_cmd.debug_log_clear);
#ifdef CMD_SUPPORT_DEBUG_COMMANDS
	CuAssertPtrNotNull (test, test_static.base_cmd.debug_log_fill);
#endif
#endif
	CuAssertPtrNotNull (test, test_static.base_cmd.authenticate_riot_certs);
	CuAssertPtrNotNull (test, test_static.base_cmd.get_riot_cert_chain_state);
	CuAssertPtrNotNull (test, test_static.base_cmd.reboot_device);

	CuAssertPtrEquals (test, NULL, test_static.base_event.prepare);
	CuAssertPtrNotNull (test, test_static.base_event.execute);

	status = cmd_background_handler_init_state (&test_static);
	CuAssertIntEquals (test, 0, status);

	cmd_background_handler_testing_release_dependencies (test, &handler);
	cmd_background_handler_release (&test_static);
}

static void cmd_background_handler_test_static_init_null (CuTest *test)
{
	struct cmd_background_handler_testing handler;
	struct cmd_background_handler test_static = cmd_background_handler_static_init (&handler.state,
		&handler.attestation.base, &handler.hash.base, &handler.keys.riot, &handler.task.base);
	int status;

	TEST_START;

	cmd_background_handler_testing_init_dependencies (test, &handler);

	status = cmd_background_handler_init_state (NULL);
	CuAssertIntEquals (test, CMD_BACKGROUND_INVALID_ARGUMENT, status);

	test_static.state = NULL;
	status = cmd_background_handler_init_state (&test_static);
	CuAssertIntEquals (test, CMD_BACKGROUND_INVALID_ARGUMENT, status);

	test_static.state = &handler.state;
	test_static.keys = NULL;
	status = cmd_background_handler_init_state (&test_static);
	CuAssertIntEquals (test, CMD_BACKGROUND_INVALID_ARGUMENT, status);

	test_static.keys = &handler.keys.riot;
	test_static.task = NULL;
	status = cmd_background_handler_init_state (&test_static);
	CuAssertIntEquals (test, CMD_BACKGROUND_INVALID_ARGUMENT, status);

	cmd_background_handler_testing_release_dependencies (test, &handler);
	cmd_background_handler_release (&test_static);
}

static void cmd_background_handler_test_release_null (CuTest *test)
{
	TEST_START;

	cmd_background_handler_release (NULL);
}

#ifdef CMD_ENABLE_UNSEAL
static void cmd_background_handler_test_unseal_result (CuTest *test)
{
	struct cmd_background_handler_testing handler;
	int status;
	uint8_t key[AES256_KEY_LENGTH];
	size_t key_length = sizeof (key);
	uint32_t result;

	TEST_START;

	cmd_background_handler_testing_init (test, &handler);

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_cmd.unseal_result (&handler.test.base_cmd, key, &key_length,
		&result);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, ATTESTATION_CMD_STATUS_NONE_STARTED, result);
	CuAssertIntEquals (test, 0, key_length);

	cmd_background_handler_testing_validate_and_release (test, &handler);
}

static void cmd_background_handler_test_unseal_result_static_init (CuTest *test)
{
	struct cmd_background_handler_testing handler;
	struct cmd_background_handler test_static = cmd_background_handler_static_init (&handler.state,
		&handler.attestation.base, &handler.hash.base, &handler.keys.riot, &handler.task.base);
	int status;
	uint8_t key[AES256_KEY_LENGTH];
	size_t key_length = sizeof (key);
	uint32_t result;

	TEST_START;

	cmd_background_handler_testing_init_static (test, &handler, &test_static);

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = test_static.base_cmd.unseal_result (&test_static.base_cmd, key, &key_length, &result);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, ATTESTATION_CMD_STATUS_NONE_STARTED, result);
	CuAssertIntEquals (test, 0, key_length);

	cmd_background_handler_testing_release_dependencies (test, &handler);
	cmd_background_handler_release (&test_static);
}

static void cmd_background_handler_test_unseal_result_null (CuTest *test)
{
	struct cmd_background_handler_testing handler;
	int status;
	uint8_t key[AES256_KEY_LENGTH];
	size_t key_length = sizeof (key);
	uint32_t result;

	TEST_START;

	cmd_background_handler_testing_init (test, &handler);

	status = handler.test.base_cmd.unseal_result (NULL, key, &key_length, &result);
	CuAssertIntEquals (test, CMD_BACKGROUND_INVALID_ARGUMENT, status);

	status = handler.test.base_cmd.unseal_result (&handler.test.base_cmd, NULL, &key_length,
		&result);
	CuAssertIntEquals (test, CMD_BACKGROUND_INVALID_ARGUMENT, status);

	status = handler.test.base_cmd.unseal_result (&handler.test.base_cmd, key, NULL, &result);
	CuAssertIntEquals (test, CMD_BACKGROUND_INVALID_ARGUMENT, status);

	status = handler.test.base_cmd.unseal_result (&handler.test.base_cmd, key, &key_length,	NULL);
	CuAssertIntEquals (test, CMD_BACKGROUND_INVALID_ARGUMENT, status);

	cmd_background_handler_testing_validate_and_release (test, &handler);
}

static void cmd_background_handler_test_unseal_result_no_unseal_support (CuTest *test)
{
	struct cmd_background_handler_testing handler;
	int status;
	uint8_t key[AES256_KEY_LENGTH];
	size_t key_length = sizeof (key);
	uint32_t result;

	TEST_START;

	cmd_background_handler_testing_init_dependencies (test, &handler);

	status = cmd_background_handler_init (&handler.test, &handler.state, NULL, &handler.hash.base,
		&handler.keys.riot, &handler.task.base);
	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_cmd.unseal_result (&handler.test.base_cmd, key, &key_length,
		&result);
	CuAssertIntEquals (test, CMD_BACKGROUND_UNSUPPORTED_REQUEST, status);

	cmd_background_handler_release (&handler.test);

	status = cmd_background_handler_init (&handler.test, &handler.state, &handler.attestation.base,
		NULL, &handler.keys.riot, &handler.task.base);
	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_cmd.unseal_result (&handler.test.base_cmd, key, &key_length,
		&result);
	CuAssertIntEquals (test, CMD_BACKGROUND_UNSUPPORTED_REQUEST, status);

	cmd_background_handler_testing_validate_and_release (test, &handler);
}
#endif

#ifdef CMD_ENABLE_RESET_CONFIG
static void cmd_background_handler_test_get_authorized_operation_status (CuTest *test)
{
	struct cmd_background_handler_testing handler;
	int status;

	TEST_START;

	cmd_background_handler_testing_init (test, &handler);

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_cmd.get_authorized_operation_status (&handler.test.base_cmd);
	CuAssertIntEquals (test, CONFIG_RESET_STATUS_NONE_STARTED, status);

	cmd_background_handler_testing_validate_and_release (test, &handler);
}

static void cmd_background_handler_test_get_authorized_operation_status_static_init (CuTest *test)
{
	struct cmd_background_handler_testing handler;
	struct cmd_background_handler test_static = cmd_background_handler_static_init (&handler.state,
		&handler.attestation.base, &handler.hash.base, &handler.keys.riot, &handler.task.base);
	int status;

	TEST_START;

	cmd_background_handler_testing_init_static (test, &handler, &test_static);

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = test_static.base_cmd.get_authorized_operation_status (&test_static.base_cmd);
	CuAssertIntEquals (test, CONFIG_RESET_STATUS_NONE_STARTED, status);

	cmd_background_handler_testing_release_dependencies (test, &handler);
	cmd_background_handler_release (&test_static);
}

static void cmd_background_handler_test_get_authorized_operation_status_null (CuTest *test)
{
	struct cmd_background_handler_testing handler;
	int status;

	TEST_START;

	cmd_background_handler_testing_init (test, &handler);

	status = handler.test.base_cmd.get_authorized_operation_status (NULL);
	CuAssertIntEquals (test,
		(((CMD_BACKGROUND_INVALID_ARGUMENT & 0x00ffffff) << 8) | CONFIG_RESET_STATUS_UNKNOWN),
		status);

	cmd_background_handler_testing_validate_and_release (test, &handler);
}
#endif

static void cmd_background_handler_test_get_riot_cert_chain_state (CuTest *test)
{
	struct cmd_background_handler_testing handler;
	int status;

	TEST_START;

	cmd_background_handler_testing_init (test, &handler);

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_cmd.get_riot_cert_chain_state (&handler.test.base_cmd);
	CuAssertIntEquals (test, RIOT_CERT_STATE_CHAIN_INVALID, status);

	cmd_background_handler_testing_validate_and_release (test, &handler);
}

static void cmd_background_handler_test_get_riot_cert_chain_state_valid_certs (CuTest *test)
{
	struct cmd_background_handler_testing handler;
	int status;

	TEST_START;

	cmd_background_handler_testing_init_valid_certs (test, &handler);

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_cmd.get_riot_cert_chain_state (&handler.test.base_cmd);
	CuAssertIntEquals (test, RIOT_CERT_STATE_CHAIN_VALID, status);

	cmd_background_handler_testing_validate_and_release (test, &handler);
}

static void cmd_background_handler_test_get_riot_cert_chain_state_static_init (CuTest *test)
{
	struct cmd_background_handler_testing handler;
	struct cmd_background_handler test_static = cmd_background_handler_static_init (&handler.state,
		&handler.attestation.base, &handler.hash.base, &handler.keys.riot, &handler.task.base);
	int status;

	TEST_START;

	cmd_background_handler_testing_init_static (test, &handler, &test_static);

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = test_static.base_cmd.get_riot_cert_chain_state (&test_static.base_cmd);
	CuAssertIntEquals (test, RIOT_CERT_STATE_CHAIN_INVALID, status);

	cmd_background_handler_testing_release_dependencies (test, &handler);
	cmd_background_handler_release (&test_static);
}

static void cmd_background_handler_test_get_riot_cert_chain_state_static_init_valid_certs (
	CuTest *test)
{
	struct cmd_background_handler_testing handler;
	struct cmd_background_handler test_static = cmd_background_handler_static_init (&handler.state,
		&handler.attestation.base, &handler.hash.base, &handler.keys.riot, &handler.task.base);
	int status;

	TEST_START;

	cmd_background_handler_testing_init_static_valid_certs (test, &handler, &test_static);

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = test_static.base_cmd.get_riot_cert_chain_state (&test_static.base_cmd);
	CuAssertIntEquals (test, RIOT_CERT_STATE_CHAIN_VALID, status);

	cmd_background_handler_testing_release_dependencies (test, &handler);
	cmd_background_handler_release (&test_static);
}

static void cmd_background_handler_test_get_riot_cert_chain_state_null (CuTest *test)
{
	struct cmd_background_handler_testing handler;
	int status;

	TEST_START;

	cmd_background_handler_testing_init (test, &handler);

	status = handler.test.base_cmd.get_riot_cert_chain_state (NULL);
	CuAssertIntEquals (test, CMD_BACKGROUND_INVALID_ARGUMENT, status);

	cmd_background_handler_testing_validate_and_release (test, &handler);
}

#ifdef CMD_ENABLE_UNSEAL
static void cmd_background_handler_test_unseal_start (CuTest *test)
{
	struct cmd_background_handler_testing handler;
	int status;
	uint8_t unseal_data[] = {0x11, 0x12, 0x13, 0x14, 0x15};
	uint8_t key[AES256_KEY_LENGTH];
	size_t key_length = sizeof (key);
	uint32_t result;

	TEST_START;

	cmd_background_handler_testing_init (test, &handler);

	status = mock_expect (&handler.task.mock, handler.task.base.get_event_context, &handler.task, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&handler.task.mock, 0, &handler.context_ptr,
		sizeof (handler.context_ptr), -1);

	status |= mock_expect (&handler.task.mock, handler.task.base.notify, &handler.task, 0,
		MOCK_ARG_PTR (&handler.test.base_event));

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_cmd.unseal_start (&handler.test.base_cmd, unseal_data,
		sizeof (unseal_data));
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, CMD_BACKGROUND_HANDLER_ACTION_RUN_UNSEAL, handler.context.action);
	CuAssertIntEquals (test, sizeof (unseal_data), handler.context.buffer_length);

	status = testing_validate_array (unseal_data, handler.context.event_buffer,
		sizeof (unseal_data));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_cmd.unseal_result (&handler.test.base_cmd, key, &key_length,
		&result);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, ATTESTATION_CMD_STATUS_RUNNING, result);
	CuAssertIntEquals (test, 0, key_length);

	cmd_background_handler_testing_validate_and_release (test, &handler);
}

static void cmd_background_handler_test_unseal_start_max_message (CuTest *test)
{
	struct cmd_background_handler_testing handler;
	int status;
	uint8_t unseal_data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	uint8_t key[AES256_KEY_LENGTH];
	size_t key_length = sizeof (key);
	uint32_t result;
	size_t i;

	TEST_START;

	for (i = 0; i < sizeof (unseal_data); i++) {
		unseal_data[i] = i;
	}

	cmd_background_handler_testing_init (test, &handler);

	status = mock_expect (&handler.task.mock, handler.task.base.get_event_context, &handler.task, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&handler.task.mock, 0, &handler.context_ptr,
		sizeof (handler.context_ptr), -1);

	status |= mock_expect (&handler.task.mock, handler.task.base.notify, &handler.task, 0,
		MOCK_ARG_PTR (&handler.test.base_event));

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_cmd.unseal_start (&handler.test.base_cmd, unseal_data,
		sizeof (unseal_data));
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, CMD_BACKGROUND_HANDLER_ACTION_RUN_UNSEAL, handler.context.action);
	CuAssertIntEquals (test, sizeof (unseal_data), handler.context.buffer_length);

	status = testing_validate_array (unseal_data, handler.context.event_buffer,
		sizeof (unseal_data));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_cmd.unseal_result (&handler.test.base_cmd, key, &key_length,
		&result);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, ATTESTATION_CMD_STATUS_RUNNING, result);
	CuAssertIntEquals (test, 0, key_length);

	cmd_background_handler_testing_validate_and_release (test, &handler);
}

static void cmd_background_handler_test_unseal_start_static_init (CuTest *test)
{
	struct cmd_background_handler_testing handler;
	struct cmd_background_handler test_static = cmd_background_handler_static_init (&handler.state,
		&handler.attestation.base, &handler.hash.base, &handler.keys.riot, &handler.task.base);
	int status;
	uint8_t unseal_data[] = {0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18};
	uint8_t key[AES256_KEY_LENGTH];
	size_t key_length = sizeof (key);
	uint32_t result;

	TEST_START;

	cmd_background_handler_testing_init_static (test, &handler, &test_static);

	status = mock_expect (&handler.task.mock, handler.task.base.get_event_context, &handler.task, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&handler.task.mock, 0, &handler.context_ptr,
		sizeof (handler.context_ptr), -1);

	status |= mock_expect (&handler.task.mock, handler.task.base.notify, &handler.task, 0,
		MOCK_ARG_PTR (&test_static.base_event));

	CuAssertIntEquals (test, 0, status);

	status = test_static.base_cmd.unseal_start (&test_static.base_cmd, unseal_data,
		sizeof (unseal_data));
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, CMD_BACKGROUND_HANDLER_ACTION_RUN_UNSEAL, handler.context.action);
	CuAssertIntEquals (test, sizeof (unseal_data), handler.context.buffer_length);

	status = testing_validate_array (unseal_data, handler.context.event_buffer,
		sizeof (unseal_data));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = test_static.base_cmd.unseal_result (&test_static.base_cmd, key, &key_length, &result);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, ATTESTATION_CMD_STATUS_RUNNING, result);
	CuAssertIntEquals (test, 0, key_length);

	cmd_background_handler_testing_release_dependencies (test, &handler);
	cmd_background_handler_release (&test_static);
}

static void cmd_background_handler_test_unseal_start_null (CuTest *test)
{
	struct cmd_background_handler_testing handler;
	int status;
	uint8_t unseal_data[] = {0x11, 0x12, 0x13, 0x14, 0x15};

	TEST_START;

	cmd_background_handler_testing_init (test, &handler);

	status = handler.test.base_cmd.unseal_start (NULL, unseal_data,	sizeof (unseal_data));
	CuAssertIntEquals (test, CMD_BACKGROUND_INVALID_ARGUMENT, status);

	status = handler.test.base_cmd.unseal_start (&handler.test.base_cmd, NULL,
		sizeof (unseal_data));
	CuAssertIntEquals (test, CMD_BACKGROUND_INVALID_ARGUMENT, status);

	status = handler.test.base_cmd.unseal_start (&handler.test.base_cmd, unseal_data, 0);
	CuAssertIntEquals (test, CMD_BACKGROUND_INVALID_ARGUMENT, status);

	cmd_background_handler_testing_validate_and_release (test, &handler);
}

static void cmd_background_handler_test_unseal_start_no_unseal_support (CuTest *test)
{
	struct cmd_background_handler_testing handler;
	int status;
	uint8_t unseal_data[] = {0x11, 0x12, 0x13, 0x14, 0x15};

	TEST_START;

	cmd_background_handler_testing_init_dependencies (test, &handler);

	status = cmd_background_handler_init (&handler.test, &handler.state, NULL, &handler.hash.base,
		&handler.keys.riot, &handler.task.base);
	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_cmd.unseal_start (&handler.test.base_cmd, unseal_data,
		sizeof (unseal_data));
	CuAssertIntEquals (test, CMD_BACKGROUND_UNSUPPORTED_REQUEST, status);

	cmd_background_handler_release (&handler.test);

	status = cmd_background_handler_init (&handler.test, &handler.state, &handler.attestation.base,
		NULL, &handler.keys.riot, &handler.task.base);
	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_cmd.unseal_start (&handler.test.base_cmd, unseal_data,
		sizeof (unseal_data));
	CuAssertIntEquals (test, CMD_BACKGROUND_UNSUPPORTED_REQUEST, status);

	cmd_background_handler_testing_validate_and_release (test, &handler);
}

static void cmd_background_handler_test_unseal_start_data_too_long (CuTest *test)
{
	struct cmd_background_handler_testing handler;
	int status;
	uint8_t unseal_data[] = {0x11, 0x12, 0x13, 0x14, 0x15};

	TEST_START;

	cmd_background_handler_testing_init (test, &handler);

	status = handler.test.base_cmd.unseal_start (&handler.test.base_cmd, unseal_data,
		EVENT_TASK_CONTEXT_BUFFER_LENGTH + 1);
	CuAssertIntEquals (test, CMD_BACKGROUND_INPUT_TOO_BIG, status);

	cmd_background_handler_testing_validate_and_release (test, &handler);
}

static void cmd_background_handler_test_unseal_start_no_task (CuTest *test)
{
	struct cmd_background_handler_testing handler;
	int status;
	uint8_t unseal_data[] = {0x11, 0x12, 0x13, 0x14, 0x15};
	void *null_ptr = NULL;
	uint8_t key[AES256_KEY_LENGTH];
	size_t key_length = sizeof (key);
	uint32_t result;

	TEST_START;

	cmd_background_handler_testing_init (test, &handler);
	handler.context_ptr = NULL;

	status = mock_expect (&handler.task.mock, handler.task.base.get_event_context, &handler.task,
		EVENT_TASK_NO_TASK, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&handler.task.mock, 0, &null_ptr, sizeof (null_ptr), -1);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_cmd.unseal_start (&handler.test.base_cmd, unseal_data,
		sizeof (unseal_data));
	CuAssertIntEquals (test, CMD_BACKGROUND_NO_TASK, status);

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_cmd.unseal_result (&handler.test.base_cmd, key, &key_length,
		&result);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test,
		(((CMD_BACKGROUND_NO_TASK & 0x00ffffff) << 8) | ATTESTATION_CMD_STATUS_TASK_NOT_RUNNING),
		result);
	CuAssertIntEquals (test, 0, key_length);

	cmd_background_handler_testing_validate_and_release (test, &handler);
}

static void cmd_background_handler_test_unseal_start_task_busy (CuTest *test)
{
	struct cmd_background_handler_testing handler;
	int status;
	uint8_t unseal_data[] = {0x11, 0x12, 0x13, 0x14, 0x15};
	void *null_ptr = NULL;
	uint8_t key[AES256_KEY_LENGTH];
	size_t key_length = sizeof (key);
	uint32_t result;

	TEST_START;

	cmd_background_handler_testing_init (test, &handler);
	handler.context_ptr = NULL;

	status = mock_expect (&handler.task.mock, handler.task.base.get_event_context, &handler.task,
		EVENT_TASK_BUSY, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&handler.task.mock, 0, &null_ptr, sizeof (null_ptr), -1);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_cmd.unseal_start (&handler.test.base_cmd, unseal_data,
		sizeof (unseal_data));
	CuAssertIntEquals (test, CMD_BACKGROUND_TASK_BUSY, status);

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_cmd.unseal_result (&handler.test.base_cmd, key, &key_length,
		&result);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, ATTESTATION_CMD_STATUS_NONE_STARTED, result);
	CuAssertIntEquals (test, 0, key_length);

	cmd_background_handler_testing_validate_and_release (test, &handler);
}

static void cmd_background_handler_test_unseal_start_get_context_error (CuTest *test)
{
	struct cmd_background_handler_testing handler;
	int status;
	uint8_t unseal_data[] = {0x11, 0x12, 0x13, 0x14, 0x15};
	void *null_ptr = NULL;
	uint8_t key[AES256_KEY_LENGTH];
	size_t key_length = sizeof (key);
	uint32_t result;

	TEST_START;

	cmd_background_handler_testing_init (test, &handler);
	handler.context_ptr = NULL;

	status = mock_expect (&handler.task.mock, handler.task.base.get_event_context, &handler.task,
		EVENT_TASK_GET_CONTEXT_FAILED, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&handler.task.mock, 0, &null_ptr, sizeof (null_ptr), -1);

	/* Need to lock while updating the status. */
	status |= mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_cmd.unseal_start (&handler.test.base_cmd, unseal_data,
		sizeof (unseal_data));
	CuAssertIntEquals (test, EVENT_TASK_GET_CONTEXT_FAILED, status);

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_cmd.unseal_result (&handler.test.base_cmd, key, &key_length,
		&result);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, (((EVENT_TASK_GET_CONTEXT_FAILED & 0x00ffffff) << 8) |
			ATTESTATION_CMD_STATUS_INTERNAL_ERROR), result);
	CuAssertIntEquals (test, 0, key_length);

	cmd_background_handler_testing_validate_and_release (test, &handler);
}

static void cmd_background_handler_test_unseal_start_notify_error (CuTest *test)
{
	struct cmd_background_handler_testing handler;
	int status;
	uint8_t unseal_data[] = {0x11, 0x12, 0x13, 0x14, 0x15};
	uint8_t key[AES256_KEY_LENGTH];
	size_t key_length = sizeof (key);
	uint32_t result;

	TEST_START;

	cmd_background_handler_testing_init (test, &handler);

	status = mock_expect (&handler.task.mock, handler.task.base.get_event_context, &handler.task, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&handler.task.mock, 0, &handler.context_ptr,
		sizeof (handler.context_ptr), -1);

	status |= mock_expect (&handler.task.mock, handler.task.base.notify, &handler.task,
		EVENT_TASK_NOTIFY_FAILED, MOCK_ARG_PTR (&handler.test.base_event));

	/* Need to lock while updating the status. */
	status |= mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_cmd.unseal_start (&handler.test.base_cmd, unseal_data,
		sizeof (unseal_data));
	CuAssertIntEquals (test, EVENT_TASK_NOTIFY_FAILED, status);

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_cmd.unseal_result (&handler.test.base_cmd, key, &key_length,
		&result);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test,
		(((EVENT_TASK_NOTIFY_FAILED & 0x00ffffff) << 8) | ATTESTATION_CMD_STATUS_INTERNAL_ERROR),
		result);
	CuAssertIntEquals (test, 0, key_length);

	cmd_background_handler_testing_validate_and_release (test, &handler);
}
#endif

#ifdef CMD_ENABLE_RESET_CONFIG
static void cmd_background_handler_test_execute_authorized_operation (CuTest *test)
{
	struct cmd_background_handler_testing handler;
	struct authorized_execution *op_ptr = &handler.execution.base;
	int status;

	TEST_START;

	cmd_background_handler_testing_init (test, &handler);

	status = mock_expect (&handler.task.mock, handler.task.base.get_event_context, &handler.task, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&handler.task.mock, 0, &handler.context_ptr,
		sizeof (handler.context_ptr), -1);

	status |= mock_expect (&handler.task.mock, handler.task.base.notify, &handler.task, 0,
		MOCK_ARG_PTR (&handler.test.base_event));

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_cmd.execute_authorized_operation (&handler.test.base_cmd,
		&handler.execution.base);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, CMD_BACKGROUND_HANDLER_ACTION_AUTHORIZED_OP, handler.context.action);
	CuAssertIntEquals (test, sizeof (&handler.execution.base), handler.context.buffer_length);

	status = testing_validate_array ((uint8_t*) &op_ptr, handler.context.event_buffer,
		sizeof (op_ptr));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_cmd.get_authorized_operation_status (&handler.test.base_cmd);
	CuAssertIntEquals (test, CONFIG_RESET_STATUS_STARTING, status);

	cmd_background_handler_testing_validate_and_release (test, &handler);
}

static void cmd_background_handler_test_execute_authorized_operation_static_init (CuTest *test)
{
	struct cmd_background_handler_testing handler;
	struct cmd_background_handler test_static = cmd_background_handler_static_init (&handler.state,
		&handler.attestation.base, &handler.hash.base, &handler.keys.riot, &handler.task.base);
	struct authorized_execution *op_ptr = &handler.execution.base;
	int status;

	TEST_START;

	cmd_background_handler_testing_init_static (test, &handler, &test_static);

	status = mock_expect (&handler.task.mock, handler.task.base.get_event_context, &handler.task, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&handler.task.mock, 0, &handler.context_ptr,
		sizeof (handler.context_ptr), -1);

	status |= mock_expect (&handler.task.mock, handler.task.base.notify, &handler.task, 0,
		MOCK_ARG_PTR (&test_static.base_event));

	CuAssertIntEquals (test, 0, status);

	status = test_static.base_cmd.execute_authorized_operation (&test_static.base_cmd,
		&handler.execution.base);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, CMD_BACKGROUND_HANDLER_ACTION_AUTHORIZED_OP, handler.context.action);
	CuAssertIntEquals (test, sizeof (&handler.execution.base), handler.context.buffer_length);

	status = testing_validate_array ((uint8_t*) &op_ptr, handler.context.event_buffer,
		sizeof (op_ptr));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = test_static.base_cmd.get_authorized_operation_status (&test_static.base_cmd);
	CuAssertIntEquals (test, CONFIG_RESET_STATUS_STARTING, status);

	cmd_background_handler_testing_release_dependencies (test, &handler);
	cmd_background_handler_release (&test_static);
}

static void cmd_background_handler_test_execute_authorized_operation_null (CuTest *test)
{
	struct cmd_background_handler_testing handler;
	int status;

	TEST_START;

	cmd_background_handler_testing_init (test, &handler);

	status = handler.test.base_cmd.execute_authorized_operation (NULL, &handler.execution.base);
	CuAssertIntEquals (test, CMD_BACKGROUND_INVALID_ARGUMENT, status);

	status = handler.test.base_cmd.execute_authorized_operation (&handler.test.base_cmd, NULL);
	CuAssertIntEquals (test, CMD_BACKGROUND_INVALID_ARGUMENT, status);

	cmd_background_handler_testing_validate_and_release (test, &handler);
}

static void cmd_background_handler_test_execute_authorized_operation_no_task (CuTest *test)
{
	struct cmd_background_handler_testing handler;
	int status;
	void *null_ptr = NULL;

	TEST_START;

	cmd_background_handler_testing_init (test, &handler);
	handler.context_ptr = NULL;

	status = mock_expect (&handler.task.mock, handler.task.base.get_event_context, &handler.task,
		EVENT_TASK_NO_TASK, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&handler.task.mock, 0, &null_ptr, sizeof (null_ptr), -1);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_cmd.execute_authorized_operation (&handler.test.base_cmd,
		&handler.execution.base);
	CuAssertIntEquals (test, CMD_BACKGROUND_NO_TASK, status);

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_cmd.get_authorized_operation_status (&handler.test.base_cmd);
	CuAssertIntEquals (test,
		(((CMD_BACKGROUND_NO_TASK & 0x00ffffff) << 8) | CONFIG_RESET_STATUS_TASK_NOT_RUNNING),
		status);

	cmd_background_handler_testing_validate_and_release (test, &handler);
}

static void cmd_background_handler_test_execute_authorized_operation_task_busy (CuTest *test)
{
	struct cmd_background_handler_testing handler;
	int status;
	void *null_ptr = NULL;

	TEST_START;

	cmd_background_handler_testing_init (test, &handler);
	handler.context_ptr = NULL;

	status = mock_expect (&handler.task.mock, handler.task.base.get_event_context, &handler.task,
		EVENT_TASK_BUSY, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&handler.task.mock, 0, &null_ptr, sizeof (null_ptr), -1);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_cmd.execute_authorized_operation (&handler.test.base_cmd,
		&handler.execution.base);
	CuAssertIntEquals (test, CMD_BACKGROUND_TASK_BUSY, status);

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_cmd.get_authorized_operation_status (&handler.test.base_cmd);
	CuAssertIntEquals (test, CONFIG_RESET_STATUS_NONE_STARTED, status);

	cmd_background_handler_testing_validate_and_release (test, &handler);
}

static void cmd_background_handler_test_execute_authorized_operation_get_context_error (
	CuTest *test)
{
	struct cmd_background_handler_testing handler;
	int status;
	void *null_ptr = NULL;

	TEST_START;

	cmd_background_handler_testing_init (test, &handler);
	handler.context_ptr = NULL;

	status = mock_expect (&handler.task.mock, handler.task.base.get_event_context, &handler.task,
		EVENT_TASK_GET_CONTEXT_FAILED, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&handler.task.mock, 0, &null_ptr, sizeof (null_ptr), -1);

	/* Need to lock while updating the status. */
	status |= mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_cmd.execute_authorized_operation (&handler.test.base_cmd,
		&handler.execution.base);
	CuAssertIntEquals (test, EVENT_TASK_GET_CONTEXT_FAILED, status);

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_cmd.get_authorized_operation_status (&handler.test.base_cmd);
	CuAssertIntEquals (test,
		(((EVENT_TASK_GET_CONTEXT_FAILED & 0x00ffffff) << 8) | CONFIG_RESET_STATUS_INTERNAL_ERROR),
		status);

	cmd_background_handler_testing_validate_and_release (test, &handler);
}

static void cmd_background_handler_test_execute_authorized_operation_notify_error (CuTest *test)
{
	struct cmd_background_handler_testing handler;
	int status;

	TEST_START;

	cmd_background_handler_testing_init (test, &handler);

	status = mock_expect (&handler.task.mock, handler.task.base.get_event_context, &handler.task, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&handler.task.mock, 0, &handler.context_ptr,
		sizeof (handler.context_ptr), -1);

	status |= mock_expect (&handler.task.mock, handler.task.base.notify, &handler.task,
		EVENT_TASK_NOTIFY_FAILED, MOCK_ARG_PTR (&handler.test.base_event));

	/* Need to lock while updating the status. */
	status |= mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_cmd.execute_authorized_operation (&handler.test.base_cmd,
		&handler.execution.base);
	CuAssertIntEquals (test, EVENT_TASK_NOTIFY_FAILED, status);

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_cmd.get_authorized_operation_status (&handler.test.base_cmd);
	CuAssertIntEquals (test,
		(((EVENT_TASK_NOTIFY_FAILED & 0x00ffffff) << 8) | CONFIG_RESET_STATUS_INTERNAL_ERROR),
		status);

	cmd_background_handler_testing_validate_and_release (test, &handler);
}
#endif

#ifdef CMD_ENABLE_DEBUG_LOG
static void cmd_background_handler_test_debug_log_clear (CuTest *test)
{
	struct cmd_background_handler_testing handler;
	int status;

	TEST_START;

	cmd_background_handler_testing_init (test, &handler);

	status = mock_expect (&handler.task.mock, handler.task.base.get_event_context, &handler.task, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&handler.task.mock, 0, &handler.context_ptr,
		sizeof (handler.context_ptr), -1);

	status |= mock_expect (&handler.task.mock, handler.task.base.notify, &handler.task, 0,
		MOCK_ARG_PTR (&handler.test.base_event));

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_cmd.debug_log_clear (&handler.test.base_cmd);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, CMD_BACKGROUND_HANDLER_ACTION_DEBUG_LOG_CLEAR, handler.context.action);

	cmd_background_handler_testing_validate_and_release (test, &handler);
}

static void cmd_background_handler_test_debug_log_clear_static_init (CuTest *test)
{
	struct cmd_background_handler_testing handler;
	struct cmd_background_handler test_static = cmd_background_handler_static_init (&handler.state,
		&handler.attestation.base, &handler.hash.base, &handler.keys.riot, &handler.task.base);
	int status;

	TEST_START;

	cmd_background_handler_testing_init_static (test, &handler, &test_static);

	status = mock_expect (&handler.task.mock, handler.task.base.get_event_context, &handler.task, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&handler.task.mock, 0, &handler.context_ptr,
		sizeof (handler.context_ptr), -1);

	status |= mock_expect (&handler.task.mock, handler.task.base.notify, &handler.task, 0,
		MOCK_ARG_PTR (&test_static.base_event));

	CuAssertIntEquals (test, 0, status);

	status = test_static.base_cmd.debug_log_clear (&test_static.base_cmd);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, CMD_BACKGROUND_HANDLER_ACTION_DEBUG_LOG_CLEAR, handler.context.action);

	cmd_background_handler_testing_release_dependencies (test, &handler);
	cmd_background_handler_release (&test_static);
}

static void cmd_background_handler_test_debug_log_clear_null (CuTest *test)
{
	struct cmd_background_handler_testing handler;
	int status;

	TEST_START;

	cmd_background_handler_testing_init (test, &handler);

	status = handler.test.base_cmd.debug_log_clear (NULL);
	CuAssertIntEquals (test, CMD_BACKGROUND_INVALID_ARGUMENT, status);

	cmd_background_handler_testing_validate_and_release (test, &handler);
}

static void cmd_background_handler_test_debug_log_clear_no_task (CuTest *test)
{
	struct cmd_background_handler_testing handler;
	int status;
	void *null_ptr = NULL;

	TEST_START;

	cmd_background_handler_testing_init (test, &handler);
	handler.context_ptr = NULL;

	status = mock_expect (&handler.task.mock, handler.task.base.get_event_context, &handler.task,
		EVENT_TASK_NO_TASK, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&handler.task.mock, 0, &null_ptr, sizeof (null_ptr), -1);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_cmd.debug_log_clear (&handler.test.base_cmd);
	CuAssertIntEquals (test, CMD_BACKGROUND_NO_TASK, status);

	cmd_background_handler_testing_validate_and_release (test, &handler);
}

static void cmd_background_handler_test_debug_log_clear_task_busy (CuTest *test)
{
	struct cmd_background_handler_testing handler;
	int status;
	void *null_ptr = NULL;

	TEST_START;

	cmd_background_handler_testing_init (test, &handler);
	handler.context_ptr = NULL;

	status = mock_expect (&handler.task.mock, handler.task.base.get_event_context, &handler.task,
		EVENT_TASK_BUSY, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&handler.task.mock, 0, &null_ptr, sizeof (null_ptr), -1);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_cmd.debug_log_clear (&handler.test.base_cmd);
	CuAssertIntEquals (test, CMD_BACKGROUND_TASK_BUSY, status);

	cmd_background_handler_testing_validate_and_release (test, &handler);
}

static void cmd_background_handler_test_debug_log_clear_get_context_error (CuTest *test)
{
	struct cmd_background_handler_testing handler;
	int status;
	void *null_ptr = NULL;

	TEST_START;

	cmd_background_handler_testing_init (test, &handler);
	handler.context_ptr = NULL;

	status = mock_expect (&handler.task.mock, handler.task.base.get_event_context, &handler.task,
		EVENT_TASK_GET_CONTEXT_FAILED, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&handler.task.mock, 0, &null_ptr, sizeof (null_ptr), -1);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_cmd.debug_log_clear (&handler.test.base_cmd);
	CuAssertIntEquals (test, EVENT_TASK_GET_CONTEXT_FAILED, status);

	cmd_background_handler_testing_validate_and_release (test, &handler);
}

static void cmd_background_handler_test_debug_log_clear_notify_error (CuTest *test)
{
	struct cmd_background_handler_testing handler;
	int status;

	TEST_START;

	cmd_background_handler_testing_init (test, &handler);

	status = mock_expect (&handler.task.mock, handler.task.base.get_event_context, &handler.task, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&handler.task.mock, 0, &handler.context_ptr,
		sizeof (handler.context_ptr), -1);

	status |= mock_expect (&handler.task.mock, handler.task.base.notify, &handler.task,
		EVENT_TASK_NOTIFY_FAILED, MOCK_ARG_PTR (&handler.test.base_event));

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_cmd.debug_log_clear (&handler.test.base_cmd);
	CuAssertIntEquals (test, EVENT_TASK_NOTIFY_FAILED, status);

	cmd_background_handler_testing_validate_and_release (test, &handler);
}

#ifdef CMD_SUPPORT_DEBUG_COMMANDS
static void cmd_background_handler_test_debug_log_fill (CuTest *test)
{
	struct cmd_background_handler_testing handler;
	int status;

	TEST_START;

	cmd_background_handler_testing_init (test, &handler);

	status = mock_expect (&handler.task.mock, handler.task.base.get_event_context, &handler.task, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&handler.task.mock, 0, &handler.context_ptr,
		sizeof (handler.context_ptr), -1);

	status |= mock_expect (&handler.task.mock, handler.task.base.notify, &handler.task, 0,
		MOCK_ARG_PTR (&handler.test.base_event));

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_cmd.debug_log_fill (&handler.test.base_cmd);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, CMD_BACKGROUND_HANDLER_ACTION_DEBUG_LOG_FILL, handler.context.action);

	cmd_background_handler_testing_validate_and_release (test, &handler);
}

static void cmd_background_handler_test_debug_log_fill_static_init (CuTest *test)
{
	struct cmd_background_handler_testing handler;
	struct cmd_background_handler test_static = cmd_background_handler_static_init (&handler.state,
		&handler.attestation.base, &handler.hash.base, &handler.keys.riot, &handler.task.base);
	int status;

	TEST_START;

	cmd_background_handler_testing_init_static (test, &handler, &test_static);

	status = mock_expect (&handler.task.mock, handler.task.base.get_event_context, &handler.task, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&handler.task.mock, 0, &handler.context_ptr,
		sizeof (handler.context_ptr), -1);

	status |= mock_expect (&handler.task.mock, handler.task.base.notify, &handler.task, 0,
		MOCK_ARG_PTR (&test_static.base_event));

	CuAssertIntEquals (test, 0, status);

	status = test_static.base_cmd.debug_log_fill (&test_static.base_cmd);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, CMD_BACKGROUND_HANDLER_ACTION_DEBUG_LOG_FILL, handler.context.action);

	cmd_background_handler_testing_release_dependencies (test, &handler);
	cmd_background_handler_release (&test_static);
}

static void cmd_background_handler_test_debug_log_fill_null (CuTest *test)
{
	struct cmd_background_handler_testing handler;
	int status;

	TEST_START;

	cmd_background_handler_testing_init (test, &handler);

	status = handler.test.base_cmd.debug_log_fill (NULL);
	CuAssertIntEquals (test, CMD_BACKGROUND_INVALID_ARGUMENT, status);

	cmd_background_handler_testing_validate_and_release (test, &handler);
}

static void cmd_background_handler_test_debug_log_fill_no_task (CuTest *test)
{
	struct cmd_background_handler_testing handler;
	int status;
	void *null_ptr = NULL;

	TEST_START;

	cmd_background_handler_testing_init (test, &handler);
	handler.context_ptr = NULL;

	status = mock_expect (&handler.task.mock, handler.task.base.get_event_context, &handler.task,
		EVENT_TASK_NO_TASK, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&handler.task.mock, 0, &null_ptr, sizeof (null_ptr), -1);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_cmd.debug_log_fill (&handler.test.base_cmd);
	CuAssertIntEquals (test, CMD_BACKGROUND_NO_TASK, status);

	cmd_background_handler_testing_validate_and_release (test, &handler);
}

static void cmd_background_handler_test_debug_log_fill_task_busy (CuTest *test)
{
	struct cmd_background_handler_testing handler;
	int status;
	void *null_ptr = NULL;

	TEST_START;

	cmd_background_handler_testing_init (test, &handler);
	handler.context_ptr = NULL;

	status = mock_expect (&handler.task.mock, handler.task.base.get_event_context, &handler.task,
		EVENT_TASK_BUSY, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&handler.task.mock, 0, &null_ptr, sizeof (null_ptr), -1);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_cmd.debug_log_fill (&handler.test.base_cmd);
	CuAssertIntEquals (test, CMD_BACKGROUND_TASK_BUSY, status);

	cmd_background_handler_testing_validate_and_release (test, &handler);
}

static void cmd_background_handler_test_debug_log_fill_get_context_error (CuTest *test)
{
	struct cmd_background_handler_testing handler;
	int status;
	void *null_ptr = NULL;

	TEST_START;

	cmd_background_handler_testing_init (test, &handler);
	handler.context_ptr = NULL;

	status = mock_expect (&handler.task.mock, handler.task.base.get_event_context, &handler.task,
		EVENT_TASK_GET_CONTEXT_FAILED, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&handler.task.mock, 0, &null_ptr, sizeof (null_ptr), -1);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_cmd.debug_log_fill (&handler.test.base_cmd);
	CuAssertIntEquals (test, EVENT_TASK_GET_CONTEXT_FAILED, status);

	cmd_background_handler_testing_validate_and_release (test, &handler);
}

static void cmd_background_handler_test_debug_log_fill_notify_error (CuTest *test)
{
	struct cmd_background_handler_testing handler;
	int status;

	TEST_START;

	cmd_background_handler_testing_init (test, &handler);

	status = mock_expect (&handler.task.mock, handler.task.base.get_event_context, &handler.task, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&handler.task.mock, 0, &handler.context_ptr,
		sizeof (handler.context_ptr), -1);

	status |= mock_expect (&handler.task.mock, handler.task.base.notify, &handler.task,
		EVENT_TASK_NOTIFY_FAILED, MOCK_ARG_PTR (&handler.test.base_event));

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_cmd.debug_log_fill (&handler.test.base_cmd);
	CuAssertIntEquals (test, EVENT_TASK_NOTIFY_FAILED, status);

	cmd_background_handler_testing_validate_and_release (test, &handler);
}
#endif
#endif

static void cmd_background_handler_test_authenticate_riot_certs (CuTest *test)
{
	struct cmd_background_handler_testing handler;
	int status;

	TEST_START;

	cmd_background_handler_testing_init (test, &handler);

	status = mock_expect (&handler.task.mock, handler.task.base.get_event_context, &handler.task, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&handler.task.mock, 0, &handler.context_ptr,
		sizeof (handler.context_ptr), -1);

	status |= mock_expect (&handler.task.mock, handler.task.base.notify, &handler.task, 0,
		MOCK_ARG_PTR (&handler.test.base_event));

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_cmd.authenticate_riot_certs (&handler.test.base_cmd);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, CMD_BACKGROUND_HANDLER_ACTION_AUTH_RIOT, handler.context.action);

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_cmd.get_riot_cert_chain_state (&handler.test.base_cmd);
	CuAssertIntEquals (test, RIOT_CERT_STATE_VALIDATING, status);

	cmd_background_handler_testing_validate_and_release (test, &handler);
}

static void cmd_background_handler_test_authenticate_riot_certs_static_init (CuTest *test)
{
	struct cmd_background_handler_testing handler;
	struct cmd_background_handler test_static = cmd_background_handler_static_init (&handler.state,
		&handler.attestation.base, &handler.hash.base, &handler.keys.riot, &handler.task.base);
	int status;

	TEST_START;

	cmd_background_handler_testing_init_static (test, &handler, &test_static);

	status = mock_expect (&handler.task.mock, handler.task.base.get_event_context, &handler.task, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&handler.task.mock, 0, &handler.context_ptr,
		sizeof (handler.context_ptr), -1);

	status |= mock_expect (&handler.task.mock, handler.task.base.notify, &handler.task, 0,
		MOCK_ARG_PTR (&test_static.base_event));

	CuAssertIntEquals (test, 0, status);

	status = test_static.base_cmd.authenticate_riot_certs (&test_static.base_cmd);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, CMD_BACKGROUND_HANDLER_ACTION_AUTH_RIOT, handler.context.action);

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = test_static.base_cmd.get_riot_cert_chain_state (&test_static.base_cmd);
	CuAssertIntEquals (test, RIOT_CERT_STATE_VALIDATING, status);

	cmd_background_handler_testing_release_dependencies (test, &handler);
	cmd_background_handler_release (&test_static);
}

static void cmd_background_handler_test_authenticate_riot_certs_null (CuTest *test)
{
	struct cmd_background_handler_testing handler;
	int status;

	TEST_START;

	cmd_background_handler_testing_init (test, &handler);

	status = handler.test.base_cmd.authenticate_riot_certs (NULL);
	CuAssertIntEquals (test, CMD_BACKGROUND_INVALID_ARGUMENT, status);

	cmd_background_handler_testing_validate_and_release (test, &handler);
}

static void cmd_background_handler_test_authenticate_riot_certs_no_task (CuTest *test)
{
	struct cmd_background_handler_testing handler;
	int status;
	void *null_ptr = NULL;

	TEST_START;

	cmd_background_handler_testing_init (test, &handler);
	handler.context_ptr = NULL;

	status = mock_expect (&handler.task.mock, handler.task.base.get_event_context, &handler.task,
		EVENT_TASK_NO_TASK, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&handler.task.mock, 0, &null_ptr, sizeof (null_ptr), -1);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_cmd.authenticate_riot_certs (&handler.test.base_cmd);
	CuAssertIntEquals (test, CMD_BACKGROUND_NO_TASK, status);

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_cmd.get_riot_cert_chain_state (&handler.test.base_cmd);
	CuAssertIntEquals (test,
		(((CMD_BACKGROUND_NO_TASK & 0x00ffffff) << 8) | RIOT_CERT_STATE_CHAIN_INVALID), status);

	cmd_background_handler_testing_validate_and_release (test, &handler);
}

static void cmd_background_handler_test_authenticate_riot_certs_task_busy (CuTest *test)
{
	struct cmd_background_handler_testing handler;
	int status;
	void *null_ptr = NULL;

	TEST_START;

	cmd_background_handler_testing_init (test, &handler);
	handler.context_ptr = NULL;

	status = mock_expect (&handler.task.mock, handler.task.base.get_event_context, &handler.task,
		EVENT_TASK_BUSY, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&handler.task.mock, 0, &null_ptr, sizeof (null_ptr), -1);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_cmd.authenticate_riot_certs (&handler.test.base_cmd);
	CuAssertIntEquals (test, CMD_BACKGROUND_TASK_BUSY, status);

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_cmd.get_riot_cert_chain_state (&handler.test.base_cmd);
	CuAssertIntEquals (test, RIOT_CERT_STATE_CHAIN_INVALID, status);

	cmd_background_handler_testing_validate_and_release (test, &handler);
}

static void cmd_background_handler_test_authenticate_riot_certs_get_context_error (CuTest *test)
{
	struct cmd_background_handler_testing handler;
	int status;
	void *null_ptr = NULL;

	TEST_START;

	cmd_background_handler_testing_init (test, &handler);
	handler.context_ptr = NULL;

	status = mock_expect (&handler.task.mock, handler.task.base.get_event_context, &handler.task,
		EVENT_TASK_GET_CONTEXT_FAILED, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&handler.task.mock, 0, &null_ptr, sizeof (null_ptr), -1);

	/* Need to lock while updating the status. */
	status |= mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_cmd.authenticate_riot_certs (&handler.test.base_cmd);
	CuAssertIntEquals (test, EVENT_TASK_GET_CONTEXT_FAILED, status);

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_cmd.get_riot_cert_chain_state (&handler.test.base_cmd);
	CuAssertIntEquals (test,
		(((EVENT_TASK_GET_CONTEXT_FAILED & 0x00ffffff) << 8) | RIOT_CERT_STATE_CHAIN_INVALID),
		status);

	cmd_background_handler_testing_validate_and_release (test, &handler);
}

static void cmd_background_handler_test_authenticate_riot_certs_notify_error (CuTest *test)
{
	struct cmd_background_handler_testing handler;
	int status;

	TEST_START;

	cmd_background_handler_testing_init (test, &handler);

	status = mock_expect (&handler.task.mock, handler.task.base.get_event_context, &handler.task, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&handler.task.mock, 0, &handler.context_ptr,
		sizeof (handler.context_ptr), -1);

	status |= mock_expect (&handler.task.mock, handler.task.base.notify, &handler.task,
		EVENT_TASK_NOTIFY_FAILED, MOCK_ARG_PTR (&handler.test.base_event));

	/* Need to lock while updating the status. */
	status |= mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_cmd.authenticate_riot_certs (&handler.test.base_cmd);
	CuAssertIntEquals (test, EVENT_TASK_NOTIFY_FAILED, status);

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_cmd.get_riot_cert_chain_state (&handler.test.base_cmd);
	CuAssertIntEquals (test,
		(((EVENT_TASK_NOTIFY_FAILED & 0x00ffffff) << 8) | RIOT_CERT_STATE_CHAIN_INVALID), status);

	cmd_background_handler_testing_validate_and_release (test, &handler);
}

static void cmd_background_handler_test_reboot_device (CuTest *test)
{
	struct cmd_background_handler_testing handler;
	int status;

	TEST_START;

	cmd_background_handler_testing_init (test, &handler);

	status = mock_expect (&handler.task.mock, handler.task.base.get_event_context, &handler.task, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&handler.task.mock, 0, &handler.context_ptr,
		sizeof (handler.context_ptr), -1);

	status |= mock_expect (&handler.task.mock, handler.task.base.notify, &handler.task, 0,
		MOCK_ARG_PTR (&handler.test.base_event));

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_cmd.reboot_device (&handler.test.base_cmd);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, CMD_BACKGROUND_HANDLER_ACTION_REBOOT_DEVICE, handler.context.action);

	cmd_background_handler_testing_validate_and_release (test, &handler);
}

static void cmd_background_handler_test_reboot_device_static_init (CuTest *test)
{
	struct cmd_background_handler_testing handler;
	struct cmd_background_handler test_static = cmd_background_handler_static_init (&handler.state,
		&handler.attestation.base, &handler.hash.base, &handler.keys.riot, &handler.task.base);
	int status;

	TEST_START;

	cmd_background_handler_testing_init (test, &handler);

	status = mock_expect (&handler.task.mock, handler.task.base.get_event_context, &handler.task, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&handler.task.mock, 0, &handler.context_ptr,
		sizeof (handler.context_ptr), -1);

	status |= mock_expect (&handler.task.mock, handler.task.base.notify, &handler.task, 0,
		MOCK_ARG_PTR (&test_static.base_event));

	CuAssertIntEquals (test, 0, status);

	status = test_static.base_cmd.reboot_device (&test_static.base_cmd);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, CMD_BACKGROUND_HANDLER_ACTION_REBOOT_DEVICE, handler.context.action);

	cmd_background_handler_testing_release_dependencies (test, &handler);
	cmd_background_handler_release (&test_static);
}

static void cmd_background_handler_test_reboot_device_null (CuTest *test)
{
	struct cmd_background_handler_testing handler;
	int status;

	TEST_START;

	cmd_background_handler_testing_init (test, &handler);

	status = handler.test.base_cmd.reboot_device (NULL);
	CuAssertIntEquals (test, CMD_BACKGROUND_INVALID_ARGUMENT, status);

	cmd_background_handler_testing_validate_and_release (test, &handler);
}

static void cmd_background_handler_test_reboot_device_no_task (CuTest *test)
{
	struct cmd_background_handler_testing handler;
	int status;
	void *null_ptr = NULL;

	TEST_START;

	cmd_background_handler_testing_init (test, &handler);
	handler.context_ptr = NULL;

	status = mock_expect (&handler.task.mock, handler.task.base.get_event_context, &handler.task,
		EVENT_TASK_NO_TASK, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&handler.task.mock, 0, &null_ptr, sizeof (null_ptr), -1);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_cmd.reboot_device (&handler.test.base_cmd);
	CuAssertIntEquals (test, CMD_BACKGROUND_NO_TASK, status);

	cmd_background_handler_testing_validate_and_release (test, &handler);
}

static void cmd_background_handler_test_reboot_device_task_busy (CuTest *test)
{
	struct cmd_background_handler_testing handler;
	int status;
	void *null_ptr = NULL;

	TEST_START;

	cmd_background_handler_testing_init (test, &handler);
	handler.context_ptr = NULL;

	status = mock_expect (&handler.task.mock, handler.task.base.get_event_context, &handler.task,
		EVENT_TASK_BUSY, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&handler.task.mock, 0, &null_ptr, sizeof (null_ptr), -1);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_cmd.reboot_device (&handler.test.base_cmd);
	CuAssertIntEquals (test, CMD_BACKGROUND_TASK_BUSY, status);

	cmd_background_handler_testing_validate_and_release (test, &handler);
}

static void cmd_background_handler_test_reboot_device_get_context_error (CuTest *test)
{
	struct cmd_background_handler_testing handler;
	int status;
	void *null_ptr = NULL;

	TEST_START;

	cmd_background_handler_testing_init (test, &handler);
	handler.context_ptr = NULL;

	status = mock_expect (&handler.task.mock, handler.task.base.get_event_context, &handler.task,
		EVENT_TASK_GET_CONTEXT_FAILED, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&handler.task.mock, 0, &null_ptr, sizeof (null_ptr), -1);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_cmd.reboot_device (&handler.test.base_cmd);
	CuAssertIntEquals (test, EVENT_TASK_GET_CONTEXT_FAILED, status);

	cmd_background_handler_testing_validate_and_release (test, &handler);
}

static void cmd_background_handler_test_reboot_device_notify_error (CuTest *test)
{
	struct cmd_background_handler_testing handler;
	int status;

	TEST_START;

	cmd_background_handler_testing_init (test, &handler);

	status = mock_expect (&handler.task.mock, handler.task.base.get_event_context, &handler.task, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&handler.task.mock, 0, &handler.context_ptr,
		sizeof (handler.context_ptr), -1);

	status |= mock_expect (&handler.task.mock, handler.task.base.notify, &handler.task,
		EVENT_TASK_NOTIFY_FAILED, MOCK_ARG_PTR (&handler.test.base_event));

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_cmd.reboot_device (&handler.test.base_cmd);
	CuAssertIntEquals (test, EVENT_TASK_NOTIFY_FAILED, status);

	cmd_background_handler_testing_validate_and_release (test, &handler);
}

static void cmd_background_handler_test_generate_aux_key (CuTest *test)
{
	struct cmd_background_handler_testing handler;
	int status;

#ifdef ATTESTATION_SUPPORT_RSA_UNSEAL
	struct aux_attestation *aux_ptr = &handler.keys.aux;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_INFO,
		.component = DEBUG_LOG_COMPONENT_CMD_INTERFACE,
		.msg_index = CMD_LOGGING_GENERATE_AUX_KEY,
		.arg1 = 0,
		.arg2 = 0
	};
#endif

	TEST_START;

	cmd_background_handler_testing_init (test, &handler);

#ifdef ATTESTATION_SUPPORT_RSA_UNSEAL
	status = mock_expect (&handler.log.mock, handler.log.base.create_entry, &handler.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));

	status |= mock_expect (&handler.task.mock, handler.task.base.get_event_context, &handler.task,
		0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&handler.task.mock, 0, &handler.context_ptr,
		sizeof (handler.context_ptr), -1);

	status |= mock_expect (&handler.task.mock, handler.task.base.notify, &handler.task, 0,
		MOCK_ARG_PTR (&handler.test.base_event));

	CuAssertIntEquals (test, 0, status);

	status = cmd_background_handler_generate_aux_key (&handler.test, &handler.keys.aux);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, CMD_BACKGROUND_HANDLER_ACTION_AUX_KEY_GEN, handler.context.action);
	CuAssertIntEquals (test, sizeof (aux_ptr), handler.context.buffer_length);

	aux_ptr = *((struct aux_attestation**) handler.context.event_buffer);
	CuAssertPtrEquals (test, &handler.keys.aux, aux_ptr);
#else
	status = cmd_background_handler_generate_aux_key (&handler.test, &handler.keys.aux);
	CuAssertIntEquals (test, CMD_BACKGROUND_UNSUPPORTED_REQUEST, status);
#endif

	cmd_background_handler_testing_validate_and_release (test, &handler);
}

static void cmd_background_handler_test_generate_aux_key_static_init (CuTest *test)
{
	struct cmd_background_handler_testing handler;
	struct cmd_background_handler test_static = cmd_background_handler_static_init (&handler.state,
		&handler.attestation.base, &handler.hash.base, &handler.keys.riot, &handler.task.base);
	int status;

#ifdef ATTESTATION_SUPPORT_RSA_UNSEAL
	struct aux_attestation *aux_ptr = &handler.keys.aux;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_INFO,
		.component = DEBUG_LOG_COMPONENT_CMD_INTERFACE,
		.msg_index = CMD_LOGGING_GENERATE_AUX_KEY,
		.arg1 = 0,
		.arg2 = 0
	};
#endif

	TEST_START;

	cmd_background_handler_testing_init_static (test, &handler, &test_static);

#ifdef ATTESTATION_SUPPORT_RSA_UNSEAL
	status = mock_expect (&handler.log.mock, handler.log.base.create_entry, &handler.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));

	status = mock_expect (&handler.task.mock, handler.task.base.get_event_context, &handler.task, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&handler.task.mock, 0, &handler.context_ptr,
		sizeof (handler.context_ptr), -1);

	status |= mock_expect (&handler.task.mock, handler.task.base.notify, &handler.task, 0,
		MOCK_ARG_PTR (&test_static.base_event));

	CuAssertIntEquals (test, 0, status);

	status = cmd_background_handler_generate_aux_key (&test_static, &handler.keys.aux);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, CMD_BACKGROUND_HANDLER_ACTION_AUX_KEY_GEN, handler.context.action);
	CuAssertIntEquals (test, sizeof (aux_ptr), handler.context.buffer_length);

	aux_ptr = *((struct aux_attestation**) handler.context.event_buffer);
	CuAssertPtrEquals (test, &handler.keys.aux, aux_ptr);
#else
	status = cmd_background_handler_generate_aux_key (&test_static, &handler.keys.aux);
	CuAssertIntEquals (test, CMD_BACKGROUND_UNSUPPORTED_REQUEST, status);
#endif

	cmd_background_handler_testing_release_dependencies (test, &handler);
	cmd_background_handler_release (&test_static);
}

#ifdef ATTESTATION_SUPPORT_RSA_UNSEAL
static void cmd_background_handler_test_generate_aux_key_null (CuTest *test)
{
	struct cmd_background_handler_testing handler;
	int status;

	TEST_START;

	cmd_background_handler_testing_init (test, &handler);

	status = cmd_background_handler_generate_aux_key (NULL, &handler.keys.aux);
	CuAssertIntEquals (test, CMD_BACKGROUND_INVALID_ARGUMENT, status);

	status = cmd_background_handler_generate_aux_key (&handler.test, NULL);
	CuAssertIntEquals (test, CMD_BACKGROUND_INVALID_ARGUMENT, status);

	cmd_background_handler_testing_validate_and_release (test, &handler);
}

static void cmd_background_handler_test_generate_aux_key_no_task (CuTest *test)
{
	struct cmd_background_handler_testing handler;
	int status;
	void *null_ptr = NULL;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_INFO,
		.component = DEBUG_LOG_COMPONENT_CMD_INTERFACE,
		.msg_index = CMD_LOGGING_GENERATE_AUX_KEY,
		.arg1 = 0,
		.arg2 = 0
	};
	struct debug_log_entry_info entry_fail = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_CMD_INTERFACE,
		.msg_index = CMD_LOGGING_AUX_KEY,
		.arg1 = CMD_BACKGROUND_NO_TASK,
		.arg2 = 0
	};

	TEST_START;

	cmd_background_handler_testing_init (test, &handler);
	handler.context_ptr = NULL;

	status = mock_expect (&handler.log.mock, handler.log.base.create_entry, &handler.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));

	status |= mock_expect (&handler.task.mock, handler.task.base.get_event_context, &handler.task,
		EVENT_TASK_NO_TASK, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&handler.task.mock, 0, &null_ptr, sizeof (null_ptr), -1);

	status |= mock_expect (&handler.log.mock, handler.log.base.create_entry, &handler.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry_fail, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry_fail)));

	CuAssertIntEquals (test, 0, status);

	status = cmd_background_handler_generate_aux_key (&handler.test, &handler.keys.aux);
	CuAssertIntEquals (test, CMD_BACKGROUND_NO_TASK, status);

	cmd_background_handler_testing_validate_and_release (test, &handler);
}

static void cmd_background_handler_test_generate_aux_key_task_busy (CuTest *test)
{
	struct cmd_background_handler_testing handler;
	int status;
	void *null_ptr = NULL;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_INFO,
		.component = DEBUG_LOG_COMPONENT_CMD_INTERFACE,
		.msg_index = CMD_LOGGING_GENERATE_AUX_KEY,
		.arg1 = 0,
		.arg2 = 0
	};
	struct debug_log_entry_info entry_fail = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_CMD_INTERFACE,
		.msg_index = CMD_LOGGING_AUX_KEY,
		.arg1 = CMD_BACKGROUND_TASK_BUSY,
		.arg2 = 0
	};

	TEST_START;

	cmd_background_handler_testing_init (test, &handler);
	handler.context_ptr = NULL;

	status = mock_expect (&handler.log.mock, handler.log.base.create_entry, &handler.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));

	status |= mock_expect (&handler.task.mock, handler.task.base.get_event_context, &handler.task,
		EVENT_TASK_BUSY, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&handler.task.mock, 0, &null_ptr, sizeof (null_ptr), -1);

	status |= mock_expect (&handler.log.mock, handler.log.base.create_entry, &handler.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry_fail, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry_fail)));

	CuAssertIntEquals (test, 0, status);

	status = cmd_background_handler_generate_aux_key (&handler.test, &handler.keys.aux);
	CuAssertIntEquals (test, CMD_BACKGROUND_TASK_BUSY, status);

	cmd_background_handler_testing_validate_and_release (test, &handler);
}

static void cmd_background_handler_test_generate_aux_key_get_context_error (CuTest *test)
{
	struct cmd_background_handler_testing handler;
	int status;
	void *null_ptr = NULL;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_INFO,
		.component = DEBUG_LOG_COMPONENT_CMD_INTERFACE,
		.msg_index = CMD_LOGGING_GENERATE_AUX_KEY,
		.arg1 = 0,
		.arg2 = 0
	};
	struct debug_log_entry_info entry_fail = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_CMD_INTERFACE,
		.msg_index = CMD_LOGGING_AUX_KEY,
		.arg1 = EVENT_TASK_GET_CONTEXT_FAILED,
		.arg2 = 0
	};

	TEST_START;

	cmd_background_handler_testing_init (test, &handler);
	handler.context_ptr = NULL;

	status = mock_expect (&handler.log.mock, handler.log.base.create_entry, &handler.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));

	status |= mock_expect (&handler.task.mock, handler.task.base.get_event_context, &handler.task,
		EVENT_TASK_GET_CONTEXT_FAILED, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&handler.task.mock, 0, &null_ptr, sizeof (null_ptr), -1);

	status |= mock_expect (&handler.log.mock, handler.log.base.create_entry, &handler.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry_fail, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry_fail)));

	CuAssertIntEquals (test, 0, status);

	status = cmd_background_handler_generate_aux_key (&handler.test, &handler.keys.aux);
	CuAssertIntEquals (test, EVENT_TASK_GET_CONTEXT_FAILED, status);

	cmd_background_handler_testing_validate_and_release (test, &handler);
}

static void cmd_background_handler_test_generate_aux_key_notify_error (CuTest *test)
{
	struct cmd_background_handler_testing handler;
	int status;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_INFO,
		.component = DEBUG_LOG_COMPONENT_CMD_INTERFACE,
		.msg_index = CMD_LOGGING_GENERATE_AUX_KEY,
		.arg1 = 0,
		.arg2 = 0
	};
	struct debug_log_entry_info entry_fail = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_CMD_INTERFACE,
		.msg_index = CMD_LOGGING_AUX_KEY,
		.arg1 = EVENT_TASK_NOTIFY_FAILED,
		.arg2 = 0
	};

	TEST_START;

	cmd_background_handler_testing_init (test, &handler);

	status = mock_expect (&handler.log.mock, handler.log.base.create_entry, &handler.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));

	status |= mock_expect (&handler.task.mock, handler.task.base.get_event_context, &handler.task,
		0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&handler.task.mock, 0, &handler.context_ptr,
		sizeof (handler.context_ptr), -1);

	status |= mock_expect (&handler.task.mock, handler.task.base.notify, &handler.task,
		EVENT_TASK_NOTIFY_FAILED, MOCK_ARG_PTR (&handler.test.base_event));

	status |= mock_expect (&handler.log.mock, handler.log.base.create_entry, &handler.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry_fail, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry_fail)));

	CuAssertIntEquals (test, 0, status);

	status = cmd_background_handler_generate_aux_key (&handler.test, &handler.keys.aux);
	CuAssertIntEquals (test, EVENT_TASK_NOTIFY_FAILED, status);

	cmd_background_handler_testing_validate_and_release (test, &handler);
}
#endif

#ifdef CMD_ENABLE_UNSEAL
static void cmd_background_handler_test_execute_unseal_rsa (CuTest *test)
{
	struct cmd_background_handler_testing handler;
	int status;
	bool reset = false;
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	size_t length;
	struct cerberus_protocol_message_unseal *req = (struct cerberus_protocol_message_unseal*) data;
	struct cerberus_protocol_unseal_pmrs sealing;
	uint8_t key[AES256_KEY_LENGTH];
	size_t key_length = sizeof (key);
	uint32_t result;

	TEST_START;

	/* Set up the unsealing request data. */
	memset (sealing.pmr[0], 0x11, sizeof (sealing.pmr[0]));
	memset (sealing.pmr[1], 0x22, sizeof (sealing.pmr[0]));
	memset (sealing.pmr[2], 0x33, sizeof (sealing.pmr[0]));
	memset (sealing.pmr[3], 0x44, sizeof (sealing.pmr[0]));
	memset (sealing.pmr[4], 0x55, sizeof (sealing.pmr[0]));

	memset (data, 0, sizeof (data));
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_UNSEAL_MESSAGE;

	req->hmac_type = CERBERUS_PROTOCOL_UNSEAL_HMAC_SHA256;
	req->seed_type = CERBERUS_PROTOCOL_UNSEAL_SEED_RSA;
	req->seed_params.rsa.padding = CERBERUS_PROTOCOL_UNSEAL_RSA_OAEP_SHA256;
	req->seed_length = KEY_SEED_ENCRYPT_OAEP_LEN;
	memcpy (&req->seed, KEY_SEED_ENCRYPT_OAEP, KEY_SEED_ENCRYPT_OAEP_LEN);
	cerberus_protocol_unseal_ciphertext_length (req) = CIPHER_TEXT_LEN;
	memcpy (cerberus_protocol_unseal_ciphertext (req), CIPHER_TEXT, CIPHER_TEXT_LEN);
	cerberus_protocol_unseal_hmac_length (req) = PAYLOAD_HMAC_LEN;
	memcpy (cerberus_protocol_unseal_hmac (req), PAYLOAD_HMAC, PAYLOAD_HMAC_LEN);
	memcpy ((uint8_t*) cerberus_protocol_get_unseal_pmr_sealing (req), &sealing, sizeof (sealing));
	length = (sizeof (struct cerberus_protocol_message_unseal) - 1) +
		KEY_SEED_ENCRYPT_OAEP_LEN + 2 + CIPHER_TEXT_LEN + 2 + PAYLOAD_HMAC_LEN + sizeof (sealing);

	cmd_background_handler_testing_init (test, &handler);

	status = mock_expect (&handler.attestation.mock,
		handler.attestation.base.aux_attestation_unseal, &handler.attestation.base, 0,
		MOCK_ARG_PTR (&handler.hash.base), MOCK_ARG (AUX_ATTESTATION_KEY_256BIT),
		MOCK_ARG_PTR_CONTAINS (KEY_SEED_ENCRYPT_OAEP, KEY_SEED_ENCRYPT_OAEP_LEN),
		MOCK_ARG (KEY_SEED_ENCRYPT_OAEP_LEN), MOCK_ARG (CERBERUS_PROTOCOL_UNSEAL_SEED_RSA),
		MOCK_ARG (AUX_ATTESTATION_PARAM_OAEP_SHA256),
		MOCK_ARG_PTR_CONTAINS (PAYLOAD_HMAC, PAYLOAD_HMAC_LEN), MOCK_ARG (HMAC_SHA256),
		MOCK_ARG_PTR_CONTAINS (CIPHER_TEXT, CIPHER_TEXT_LEN), MOCK_ARG (CIPHER_TEXT_LEN),
		MOCK_ARG_PTR_CONTAINS (&sealing, sizeof (sealing)), MOCK_ARG (5), MOCK_ARG_NOT_NULL,
		MOCK_ARG (AES256_KEY_LENGTH));
	status |= mock_expect_output (&handler.attestation.mock, 12, ENCRYPTION_KEY, ENCRYPTION_KEY_LEN,
		13);

	/* Lock for state update: 0 */
	status |= mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	handler.context.action = CMD_BACKGROUND_HANDLER_ACTION_RUN_UNSEAL;
	handler.context.buffer_length = length;
	memcpy (handler.context.event_buffer, data, length);

	handler.test.base_event.execute (&handler.test.base_event, handler.context_ptr, &reset);
	CuAssertIntEquals (test, 0, reset);

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_cmd.unseal_result (&handler.test.base_cmd, key, &key_length,
		&result);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0, result);
	CuAssertIntEquals (test, AES256_KEY_LENGTH, key_length);

	status = testing_validate_array (ENCRYPTION_KEY, key, key_length);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_cmd.unseal_result (&handler.test.base_cmd, key, &key_length,
		&result);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, ATTESTATION_CMD_STATUS_NONE_STARTED, result);
	CuAssertIntEquals (test, 0, key_length);

	cmd_background_handler_testing_validate_and_release (test, &handler);
}

static void cmd_background_handler_test_execute_unseal_ecc (CuTest *test)
{
	struct cmd_background_handler_testing handler;
	int status;
	bool reset = false;
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	size_t length;
	struct cerberus_protocol_message_unseal *req = (struct cerberus_protocol_message_unseal*) data;
	struct cerberus_protocol_unseal_pmrs sealing;
	uint8_t key[AES256_KEY_LENGTH];
	size_t key_length = sizeof (key);
	uint32_t result;

	TEST_START;

	/* Set up the unsealing request data. */
	memset (sealing.pmr[0], 0x11, sizeof (sealing.pmr[0]));
	memset (sealing.pmr[1], 0x22, sizeof (sealing.pmr[0]));
	memset (sealing.pmr[2], 0x33, sizeof (sealing.pmr[0]));
	memset (sealing.pmr[3], 0x44, sizeof (sealing.pmr[0]));
	memset (sealing.pmr[4], 0x55, sizeof (sealing.pmr[0]));

	memset (data, 0, sizeof (data));
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_UNSEAL_MESSAGE;

	req->hmac_type = CERBERUS_PROTOCOL_UNSEAL_HMAC_SHA256;
	req->seed_type = CERBERUS_PROTOCOL_UNSEAL_SEED_ECDH;
	req->seed_params.ecdh.processing = CERBERUS_PROTOCOL_UNSEAL_ECDH_SHA256;
	req->seed_length = KEY_SEED_ENCRYPT_OAEP_LEN;
	memcpy (&req->seed, KEY_SEED_ENCRYPT_OAEP, KEY_SEED_ENCRYPT_OAEP_LEN);
	cerberus_protocol_unseal_ciphertext_length (req) = CIPHER_TEXT_LEN;
	memcpy (cerberus_protocol_unseal_ciphertext (req), CIPHER_TEXT, CIPHER_TEXT_LEN);
	cerberus_protocol_unseal_hmac_length (req) = PAYLOAD_HMAC_LEN;
	memcpy (cerberus_protocol_unseal_hmac (req), PAYLOAD_HMAC, PAYLOAD_HMAC_LEN);
	memcpy ((uint8_t*) cerberus_protocol_get_unseal_pmr_sealing (req), &sealing, sizeof (sealing));
	length = (sizeof (struct cerberus_protocol_message_unseal) - 1) +
		KEY_SEED_ENCRYPT_OAEP_LEN + 2 + CIPHER_TEXT_LEN + 2 + PAYLOAD_HMAC_LEN + sizeof (sealing);

	cmd_background_handler_testing_init (test, &handler);

	status = mock_expect (&handler.attestation.mock,
		handler.attestation.base.aux_attestation_unseal, &handler.attestation.base, 0,
		MOCK_ARG_PTR (&handler.hash.base), MOCK_ARG (AUX_ATTESTATION_KEY_256BIT),
		MOCK_ARG_PTR_CONTAINS (KEY_SEED_ENCRYPT_OAEP, KEY_SEED_ENCRYPT_OAEP_LEN),
		MOCK_ARG (KEY_SEED_ENCRYPT_OAEP_LEN), MOCK_ARG (CERBERUS_PROTOCOL_UNSEAL_SEED_ECDH),
		MOCK_ARG (AUX_ATTESTATION_PARAM_ECDH_SHA256),
		MOCK_ARG_PTR_CONTAINS (PAYLOAD_HMAC, PAYLOAD_HMAC_LEN), MOCK_ARG (HMAC_SHA256),
		MOCK_ARG_PTR_CONTAINS (CIPHER_TEXT, CIPHER_TEXT_LEN), MOCK_ARG (CIPHER_TEXT_LEN),
		MOCK_ARG_PTR_CONTAINS (&sealing, sizeof (sealing)), MOCK_ARG (5), MOCK_ARG_NOT_NULL,
		MOCK_ARG (AES256_KEY_LENGTH));
	status |= mock_expect_output (&handler.attestation.mock, 12, ENCRYPTION_KEY, ENCRYPTION_KEY_LEN,
		13);

	/* Lock for state update: 0 */
	status |= mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	handler.context.action = CMD_BACKGROUND_HANDLER_ACTION_RUN_UNSEAL;
	handler.context.buffer_length = length;
	memcpy (handler.context.event_buffer, data, length);

	handler.test.base_event.execute (&handler.test.base_event, handler.context_ptr, &reset);
	CuAssertIntEquals (test, 0, reset);

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_cmd.unseal_result (&handler.test.base_cmd, key, &key_length,
		&result);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0, result);
	CuAssertIntEquals (test, AES256_KEY_LENGTH, key_length);

	status = testing_validate_array (ENCRYPTION_KEY, key, key_length);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_cmd.unseal_result (&handler.test.base_cmd, key, &key_length,
		&result);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, ATTESTATION_CMD_STATUS_NONE_STARTED, result);
	CuAssertIntEquals (test, 0, key_length);

	cmd_background_handler_testing_validate_and_release (test, &handler);
}

static void cmd_background_handler_test_execute_unseal_result_buffer_too_small (CuTest *test)
{
	struct cmd_background_handler_testing handler;
	int status;
	bool reset = false;
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	size_t length;
	struct cerberus_protocol_message_unseal *req = (struct cerberus_protocol_message_unseal*) data;
	struct cerberus_protocol_unseal_pmrs sealing;
	uint8_t key[AES256_KEY_LENGTH];
	size_t key_length = sizeof (key) - 1;
	uint32_t result;

	TEST_START;

	/* Set up the unsealing request data. */
	memset (sealing.pmr[0], 0x11, sizeof (sealing.pmr[0]));
	memset (sealing.pmr[1], 0x22, sizeof (sealing.pmr[0]));
	memset (sealing.pmr[2], 0x33, sizeof (sealing.pmr[0]));
	memset (sealing.pmr[3], 0x44, sizeof (sealing.pmr[0]));
	memset (sealing.pmr[4], 0x55, sizeof (sealing.pmr[0]));

	memset (data, 0, sizeof (data));
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_UNSEAL_MESSAGE;

	req->hmac_type = CERBERUS_PROTOCOL_UNSEAL_HMAC_SHA256;
	req->seed_type = CERBERUS_PROTOCOL_UNSEAL_SEED_RSA;
	req->seed_params.rsa.padding = CERBERUS_PROTOCOL_UNSEAL_RSA_OAEP_SHA256;
	req->seed_length = KEY_SEED_ENCRYPT_OAEP_LEN;
	memcpy (&req->seed, KEY_SEED_ENCRYPT_OAEP, KEY_SEED_ENCRYPT_OAEP_LEN);
	cerberus_protocol_unseal_ciphertext_length (req) = CIPHER_TEXT_LEN;
	memcpy (cerberus_protocol_unseal_ciphertext (req), CIPHER_TEXT, CIPHER_TEXT_LEN);
	cerberus_protocol_unseal_hmac_length (req) = PAYLOAD_HMAC_LEN;
	memcpy (cerberus_protocol_unseal_hmac (req), PAYLOAD_HMAC, PAYLOAD_HMAC_LEN);
	memcpy ((uint8_t*) cerberus_protocol_get_unseal_pmr_sealing (req), &sealing, sizeof (sealing));
	length = (sizeof (struct cerberus_protocol_message_unseal) - 1) +
		KEY_SEED_ENCRYPT_OAEP_LEN + 2 + CIPHER_TEXT_LEN + 2 + PAYLOAD_HMAC_LEN + sizeof (sealing);

	cmd_background_handler_testing_init (test, &handler);

	status = mock_expect (&handler.attestation.mock,
		handler.attestation.base.aux_attestation_unseal, &handler.attestation.base, 0,
		MOCK_ARG_PTR (&handler.hash.base), MOCK_ARG (AUX_ATTESTATION_KEY_256BIT),
		MOCK_ARG_PTR_CONTAINS (KEY_SEED_ENCRYPT_OAEP, KEY_SEED_ENCRYPT_OAEP_LEN),
		MOCK_ARG (KEY_SEED_ENCRYPT_OAEP_LEN), MOCK_ARG (CERBERUS_PROTOCOL_UNSEAL_SEED_RSA),
		MOCK_ARG (AUX_ATTESTATION_PARAM_OAEP_SHA256),
		MOCK_ARG_PTR_CONTAINS (PAYLOAD_HMAC, PAYLOAD_HMAC_LEN), MOCK_ARG (HMAC_SHA256),
		MOCK_ARG_PTR_CONTAINS (CIPHER_TEXT, CIPHER_TEXT_LEN), MOCK_ARG (CIPHER_TEXT_LEN),
		MOCK_ARG_PTR_CONTAINS (&sealing, sizeof (sealing)), MOCK_ARG (5), MOCK_ARG_NOT_NULL,
		MOCK_ARG (AES256_KEY_LENGTH));
	status |= mock_expect_output (&handler.attestation.mock, 12, ENCRYPTION_KEY, ENCRYPTION_KEY_LEN,
		13);

	/* Lock for state update: 0 */
	status |= mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	handler.context.action = CMD_BACKGROUND_HANDLER_ACTION_RUN_UNSEAL;
	handler.context.buffer_length = length;
	memcpy (handler.context.event_buffer, data, length);

	handler.test.base_event.execute (&handler.test.base_event, handler.context_ptr, &reset);
	CuAssertIntEquals (test, 0, reset);

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_cmd.unseal_result (&handler.test.base_cmd, key, &key_length,
		&result);
	CuAssertIntEquals (test, CMD_BACKGROUND_BUF_TOO_SMALL, status);
	CuAssertIntEquals (test, 0, result);
	CuAssertIntEquals (test, sizeof (key) - 1, key_length);

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	key_length = sizeof (key);
	status = handler.test.base_cmd.unseal_result (&handler.test.base_cmd, key, &key_length,
		&result);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0, result);
	CuAssertIntEquals (test, AES256_KEY_LENGTH, key_length);

	status = testing_validate_array (ENCRYPTION_KEY, key, key_length);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_cmd.unseal_result (&handler.test.base_cmd, key, &key_length,
		&result);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, ATTESTATION_CMD_STATUS_NONE_STARTED, result);
	CuAssertIntEquals (test, 0, key_length);

	cmd_background_handler_testing_validate_and_release (test, &handler);
}

static void cmd_background_handler_test_execute_unseal_failure (CuTest *test)
{
	struct cmd_background_handler_testing handler;
	int status;
	bool reset = false;
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	size_t length;
	struct cerberus_protocol_message_unseal *req = (struct cerberus_protocol_message_unseal*) data;
	struct cerberus_protocol_unseal_pmrs sealing;
	uint8_t key[AES256_KEY_LENGTH];
	size_t key_length = sizeof (key);
	uint32_t result;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_CMD_INTERFACE,
		.msg_index = CMD_LOGGING_UNSEAL_FAIL,
		.arg1 = ATTESTATION_UNSUPPORTED_OPERATION,
		.arg2 = 0
	};

	TEST_START;

	/* Set up the unsealing request data. */
	memset (sealing.pmr[0], 0x11, sizeof (sealing.pmr[0]));
	memset (sealing.pmr[1], 0x22, sizeof (sealing.pmr[0]));
	memset (sealing.pmr[2], 0x33, sizeof (sealing.pmr[0]));
	memset (sealing.pmr[3], 0x44, sizeof (sealing.pmr[0]));
	memset (sealing.pmr[4], 0x55, sizeof (sealing.pmr[0]));

	memset (data, 0, sizeof (data));
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_UNSEAL_MESSAGE;

	req->hmac_type = CERBERUS_PROTOCOL_UNSEAL_HMAC_SHA256;
	req->seed_type = CERBERUS_PROTOCOL_UNSEAL_SEED_RSA;
	req->seed_params.rsa.padding = CERBERUS_PROTOCOL_UNSEAL_RSA_OAEP_SHA256;
	req->seed_length = KEY_SEED_ENCRYPT_OAEP_LEN;
	memcpy (&req->seed, KEY_SEED_ENCRYPT_OAEP, KEY_SEED_ENCRYPT_OAEP_LEN);
	cerberus_protocol_unseal_ciphertext_length (req) = CIPHER_TEXT_LEN;
	memcpy (cerberus_protocol_unseal_ciphertext (req), CIPHER_TEXT, CIPHER_TEXT_LEN);
	cerberus_protocol_unseal_hmac_length (req) = PAYLOAD_HMAC_LEN;
	memcpy (cerberus_protocol_unseal_hmac (req), PAYLOAD_HMAC, PAYLOAD_HMAC_LEN);
	memcpy ((uint8_t*) cerberus_protocol_get_unseal_pmr_sealing (req), &sealing, sizeof (sealing));
	length = (sizeof (struct cerberus_protocol_message_unseal) - 1) +
		KEY_SEED_ENCRYPT_OAEP_LEN + 2 + CIPHER_TEXT_LEN + 2 + PAYLOAD_HMAC_LEN + sizeof (sealing);

	cmd_background_handler_testing_init (test, &handler);

	status = mock_expect (&handler.attestation.mock,
		handler.attestation.base.aux_attestation_unseal, &handler.attestation.base,
		ATTESTATION_UNSUPPORTED_OPERATION, MOCK_ARG_PTR (&handler.hash.base),
		MOCK_ARG (AUX_ATTESTATION_KEY_256BIT),
		MOCK_ARG_PTR_CONTAINS (KEY_SEED_ENCRYPT_OAEP, KEY_SEED_ENCRYPT_OAEP_LEN),
		MOCK_ARG (KEY_SEED_ENCRYPT_OAEP_LEN), MOCK_ARG (CERBERUS_PROTOCOL_UNSEAL_SEED_RSA),
		MOCK_ARG (AUX_ATTESTATION_PARAM_OAEP_SHA256),
		MOCK_ARG_PTR_CONTAINS (PAYLOAD_HMAC, PAYLOAD_HMAC_LEN), MOCK_ARG (HMAC_SHA256),
		MOCK_ARG_PTR_CONTAINS (CIPHER_TEXT, CIPHER_TEXT_LEN), MOCK_ARG (CIPHER_TEXT_LEN),
		MOCK_ARG_PTR_CONTAINS (&sealing, sizeof (sealing)), MOCK_ARG (5), MOCK_ARG_NOT_NULL,
		MOCK_ARG (AES256_KEY_LENGTH));
	status |= mock_expect_output (&handler.attestation.mock, 12, ENCRYPTION_KEY, ENCRYPTION_KEY_LEN,
		13);

	status |= mock_expect (&handler.log.mock, handler.log.base.create_entry, &handler.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));

	/* Lock for state update: ATTESTATION_CMD_STATUS_FAILURE */
	status |= mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	handler.context.action = CMD_BACKGROUND_HANDLER_ACTION_RUN_UNSEAL;
	handler.context.buffer_length = length;
	memcpy (handler.context.event_buffer, data, length);

	handler.test.base_event.execute (&handler.test.base_event, handler.context_ptr, &reset);
	CuAssertIntEquals (test, 0, reset);

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_cmd.unseal_result (&handler.test.base_cmd, key, &key_length,
		&result);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test,
		(((ATTESTATION_UNSUPPORTED_OPERATION & 0x00ffffff) << 8) | ATTESTATION_CMD_STATUS_FAILURE),
		result);
	CuAssertIntEquals (test, 0, key_length);

	status = testing_validate_array (ENCRYPTION_KEY, key, key_length);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_cmd.unseal_result (&handler.test.base_cmd, key, &key_length,
		&result);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test,
		(((ATTESTATION_UNSUPPORTED_OPERATION & 0x00ffffff) << 8) | ATTESTATION_CMD_STATUS_FAILURE),
		result);
	CuAssertIntEquals (test, 0, key_length);

	cmd_background_handler_testing_validate_and_release (test, &handler);
}

static void cmd_background_handler_test_execute_unseal_static_init (CuTest *test)
{
	struct cmd_background_handler_testing handler;
	struct cmd_background_handler test_static = cmd_background_handler_static_init (&handler.state,
		&handler.attestation.base, &handler.hash.base, &handler.keys.riot, &handler.task.base);
	int status;
	bool reset = false;
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	size_t length;
	struct cerberus_protocol_message_unseal *req = (struct cerberus_protocol_message_unseal*) data;
	struct cerberus_protocol_unseal_pmrs sealing;
	uint8_t key[AES256_KEY_LENGTH];
	size_t key_length = sizeof (key);
	uint32_t result;

	TEST_START;

	/* Set up the unsealing request data. */
	memset (sealing.pmr[0], 0x11, sizeof (sealing.pmr[0]));
	memset (sealing.pmr[1], 0x22, sizeof (sealing.pmr[0]));
	memset (sealing.pmr[2], 0x33, sizeof (sealing.pmr[0]));
	memset (sealing.pmr[3], 0x44, sizeof (sealing.pmr[0]));
	memset (sealing.pmr[4], 0x55, sizeof (sealing.pmr[0]));

	memset (data, 0, sizeof (data));
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_UNSEAL_MESSAGE;

	req->hmac_type = CERBERUS_PROTOCOL_UNSEAL_HMAC_SHA256;
	req->seed_type = CERBERUS_PROTOCOL_UNSEAL_SEED_RSA;
	req->seed_params.rsa.padding = CERBERUS_PROTOCOL_UNSEAL_RSA_OAEP_SHA1;
	req->seed_length = KEY_SEED_ENCRYPT_OAEP_LEN;
	memcpy (&req->seed, KEY_SEED_ENCRYPT_OAEP, KEY_SEED_ENCRYPT_OAEP_LEN);
	cerberus_protocol_unseal_ciphertext_length (req) = CIPHER_TEXT_LEN;
	memcpy (cerberus_protocol_unseal_ciphertext (req), CIPHER_TEXT, CIPHER_TEXT_LEN);
	cerberus_protocol_unseal_hmac_length (req) = PAYLOAD_HMAC_LEN;
	memcpy (cerberus_protocol_unseal_hmac (req), PAYLOAD_HMAC, PAYLOAD_HMAC_LEN);
	memcpy ((uint8_t*) cerberus_protocol_get_unseal_pmr_sealing (req), &sealing, sizeof (sealing));
	length = (sizeof (struct cerberus_protocol_message_unseal) - 1) +
		KEY_SEED_ENCRYPT_OAEP_LEN + 2 + CIPHER_TEXT_LEN + 2 + PAYLOAD_HMAC_LEN + sizeof (sealing);

	cmd_background_handler_testing_init_static (test, &handler, &test_static);

	status = mock_expect (&handler.attestation.mock,
		handler.attestation.base.aux_attestation_unseal, &handler.attestation.base, 0,
		MOCK_ARG_PTR (&handler.hash.base), MOCK_ARG (AUX_ATTESTATION_KEY_256BIT),
		MOCK_ARG_PTR_CONTAINS (KEY_SEED_ENCRYPT_OAEP, KEY_SEED_ENCRYPT_OAEP_LEN),
		MOCK_ARG (KEY_SEED_ENCRYPT_OAEP_LEN), MOCK_ARG (CERBERUS_PROTOCOL_UNSEAL_SEED_RSA),
		MOCK_ARG (AUX_ATTESTATION_PARAM_OAEP_SHA1),
		MOCK_ARG_PTR_CONTAINS (PAYLOAD_HMAC, PAYLOAD_HMAC_LEN), MOCK_ARG (HMAC_SHA256),
		MOCK_ARG_PTR_CONTAINS (CIPHER_TEXT, CIPHER_TEXT_LEN), MOCK_ARG (CIPHER_TEXT_LEN),
		MOCK_ARG_PTR_CONTAINS (&sealing, sizeof (sealing)), MOCK_ARG (5), MOCK_ARG_NOT_NULL,
		MOCK_ARG (AES256_KEY_LENGTH));
	status |= mock_expect_output (&handler.attestation.mock, 12, ENCRYPTION_KEY, ENCRYPTION_KEY_LEN,
		13);

	/* Lock for state update: 0 */
	status |= mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	handler.context.action = CMD_BACKGROUND_HANDLER_ACTION_RUN_UNSEAL;
	handler.context.buffer_length = length;
	memcpy (handler.context.event_buffer, data, length);

	test_static.base_event.execute (&test_static.base_event, handler.context_ptr, &reset);
	CuAssertIntEquals (test, 0, reset);

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = test_static.base_cmd.unseal_result (&test_static.base_cmd, key, &key_length, &result);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0, result);
	CuAssertIntEquals (test, AES256_KEY_LENGTH, key_length);

	status = testing_validate_array (ENCRYPTION_KEY, key, key_length);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = test_static.base_cmd.unseal_result (&test_static.base_cmd, key, &key_length, &result);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, ATTESTATION_CMD_STATUS_NONE_STARTED, result);
	CuAssertIntEquals (test, 0, key_length);

	cmd_background_handler_testing_release_dependencies (test, &handler);
	cmd_background_handler_release (&test_static);
}
#endif

#ifdef CMD_ENABLE_RESET_CONFIG
static void cmd_background_handler_test_execute_execute_authorized_operation (CuTest *test)
{
	struct cmd_background_handler_testing handler;
	struct authorized_execution *op_ptr = &handler.execution.base;
	uint8_t start_code = CONFIG_RESET_STATUS_AUTHORIZED_OPERATION;
	uint8_t error_code = CONFIG_RESET_STATUS_AUTHORIZED_OP_FAILED;
	int status;
	bool reset = false;
	bool reset_req = true;

	TEST_START;

	cmd_background_handler_testing_init (test, &handler);

	/* Lock for state update: CONFIG_RESET_STATUS_AUTHORIZED_OPERATION */
	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	status |= mock_expect (&handler.execution.mock, handler.execution.base.get_status_identifiers,
		&handler.execution, 0, MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&handler.execution.mock, 0, &start_code, sizeof (start_code), -1);
	status |= mock_expect_output (&handler.execution.mock, 1, &error_code, sizeof (error_code), -1);

	status |= mock_expect (&handler.execution.mock, handler.execution.base.execute,
		&handler.execution, 0, MOCK_ARG_PTR (&reset));
	status |= mock_expect_output (&handler.execution.mock, 0, &reset_req, sizeof (reset_req), -1);

	/* Lock for state update: 0 */
	status |= mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	handler.context.action = CMD_BACKGROUND_HANDLER_ACTION_AUTHORIZED_OP;
	handler.context.buffer_length = sizeof (&handler.execution);
	memcpy (handler.context.event_buffer, (uint8_t*) &op_ptr, sizeof (op_ptr));

	handler.test.base_event.execute (&handler.test.base_event, handler.context_ptr, &reset);
	CuAssertIntEquals (test, true, reset);

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_cmd.get_authorized_operation_status (&handler.test.base_cmd);
	CuAssertIntEquals (test, 0, status);

	cmd_background_handler_testing_validate_and_release (test, &handler);
}

static void cmd_background_handler_test_execute_execute_authorized_operation_failure (CuTest *test)
{
	struct cmd_background_handler_testing handler;
	struct authorized_execution *op_ptr = &handler.execution.base;
	uint8_t start_code = CONFIG_RESET_STATUS_AUTHORIZED_OPERATION;
	uint8_t error_code = CONFIG_RESET_STATUS_AUTHORIZED_OP_FAILED;
	int status;
	bool reset = false;

	TEST_START;

	cmd_background_handler_testing_init (test, &handler);

	/* Lock for state update: CONFIG_RESET_STATUS_AUTHORIZED_OPERATION */
	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	status |= mock_expect (&handler.execution.mock, handler.execution.base.get_status_identifiers,
		&handler.execution, 0, MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&handler.execution.mock, 0, &start_code, sizeof (start_code), -1);
	status |= mock_expect_output (&handler.execution.mock, 1, &error_code, sizeof (error_code), -1);

	status |= mock_expect (&handler.execution.mock, handler.execution.base.execute,
		&handler.execution, AUTHORIZED_EXECUTION_EXECUTE_FAILED, MOCK_ARG_PTR (&reset));

	/* Lock for state update: 0 */
	status |= mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	handler.context.action = CMD_BACKGROUND_HANDLER_ACTION_AUTHORIZED_OP;
	handler.context.buffer_length = sizeof (&handler.execution);
	memcpy (handler.context.event_buffer, (uint8_t*) &op_ptr, sizeof (op_ptr));

	handler.test.base_event.execute (&handler.test.base_event, handler.context_ptr, &reset);
	CuAssertIntEquals (test, 0, reset);

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_cmd.get_authorized_operation_status (&handler.test.base_cmd);
	CuAssertIntEquals (test, (((AUTHORIZED_EXECUTION_EXECUTE_FAILED & 0x00ffffff) << 8) |
			CONFIG_RESET_STATUS_AUTHORIZED_OP_FAILED), status);

	cmd_background_handler_testing_validate_and_release (test, &handler);
}

static void cmd_background_handler_test_execute_execute_authorized_operation_failure_bypass_error (
	CuTest *test)
{
	struct cmd_background_handler_testing handler;
	struct authorized_execution *op_ptr = &handler.execution.base;
	uint8_t start_code = CONFIG_RESET_STATUS_RESTORE_BYPASS;
	uint8_t error_code = CONFIG_RESET_STATUS_BYPASS_FAILED;
	int status;
	bool reset = false;

	TEST_START;

	cmd_background_handler_testing_init (test, &handler);

	/* Lock for state update: CONFIG_RESET_STATUS_RESTORE_BYPASS */
	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	status |= mock_expect (&handler.execution.mock, handler.execution.base.get_status_identifiers,
		&handler.execution, 0, MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&handler.execution.mock, 0, &start_code, sizeof (start_code), -1);
	status |= mock_expect_output (&handler.execution.mock, 1, &error_code, sizeof (error_code), -1);

	status |= mock_expect (&handler.execution.mock, handler.execution.base.execute,
		&handler.execution, MANIFEST_MANAGER_CLEAR_ALL_FAILED, MOCK_ARG_PTR (&reset));

	/* Lock for state update: 0 */
	status |= mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	handler.context.action = CMD_BACKGROUND_HANDLER_ACTION_AUTHORIZED_OP;
	handler.context.buffer_length = sizeof (&handler.execution);
	memcpy (handler.context.event_buffer, (uint8_t*) &op_ptr, sizeof (op_ptr));

	handler.test.base_event.execute (&handler.test.base_event, handler.context_ptr, &reset);
	CuAssertIntEquals (test, 0, reset);

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_cmd.get_authorized_operation_status (&handler.test.base_cmd);
	CuAssertIntEquals (test, (((MANIFEST_MANAGER_CLEAR_ALL_FAILED & 0x00ffffff) << 8) |
			CONFIG_RESET_STATUS_BYPASS_FAILED), status);

	cmd_background_handler_testing_validate_and_release (test, &handler);
}

static void cmd_background_handler_test_execute_execute_authorized_operation_static_init (
	CuTest *test)
{
	struct cmd_background_handler_testing handler;
	struct cmd_background_handler test_static = cmd_background_handler_static_init (&handler.state,
		&handler.attestation.base, &handler.hash.base, &handler.keys.riot, &handler.task.base);
	struct authorized_execution *op_ptr = &handler.execution.base;
	uint8_t start_code = CONFIG_RESET_STATUS_AUTHORIZED_OPERATION;
	uint8_t error_code = CONFIG_RESET_STATUS_AUTHORIZED_OP_FAILED;
	int status;
	bool reset = false;

	TEST_START;

	cmd_background_handler_testing_init_static (test, &handler, &test_static);

	/* Lock for state update: CONFIG_RESET_STATUS_AUTHORIZED_OPERATION */
	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	status |= mock_expect (&handler.execution.mock, handler.execution.base.get_status_identifiers,
		&handler.execution, 0, MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&handler.execution.mock, 0, &start_code, sizeof (start_code), -1);
	status |= mock_expect_output (&handler.execution.mock, 1, &error_code, sizeof (error_code), -1);

	status |= mock_expect (&handler.execution.mock, handler.execution.base.execute,
		&handler.execution, 0, MOCK_ARG_PTR (&reset));

	/* Lock for state update: 0 */
	status |= mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	handler.context.action = CMD_BACKGROUND_HANDLER_ACTION_AUTHORIZED_OP;
	handler.context.buffer_length = sizeof (&handler.execution);
	memcpy (handler.context.event_buffer, (uint8_t*) &op_ptr, sizeof (op_ptr));

	test_static.base_event.execute (&test_static.base_event, handler.context_ptr, &reset);
	CuAssertIntEquals (test, 0, reset);

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = test_static.base_cmd.get_authorized_operation_status (&test_static.base_cmd);
	CuAssertIntEquals (test, 0, status);

	cmd_background_handler_testing_release_dependencies (test, &handler);
	cmd_background_handler_release (&test_static);
}
#endif

#ifdef CMD_ENABLE_DEBUG_LOG
static void cmd_background_handler_test_execute_debug_log_clear (CuTest *test)
{
	struct cmd_background_handler_testing handler;
	int status;
	bool reset = false;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_INFO,
		.component = DEBUG_LOG_COMPONENT_CMD_INTERFACE,
		.msg_index = CMD_LOGGING_DEBUG_LOG_CLEARED,
		.arg1 = 0,
		.arg2 = 0
	};

	TEST_START;

	cmd_background_handler_testing_init (test, &handler);

	status = mock_expect (&handler.log.mock, handler.log.base.clear, &handler.log, 0);

	status |= mock_expect (&handler.log.mock, handler.log.base.create_entry, &handler.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));

	CuAssertIntEquals (test, 0, status);

	handler.context.action = CMD_BACKGROUND_HANDLER_ACTION_DEBUG_LOG_CLEAR;
	handler.context.buffer_length = 0;

	handler.test.base_event.execute (&handler.test.base_event, handler.context_ptr, &reset);
	CuAssertIntEquals (test, 0, reset);

	cmd_background_handler_testing_validate_and_release (test, &handler);
}

static void cmd_background_handler_test_execute_debug_log_clear_failure (CuTest *test)
{
	struct cmd_background_handler_testing handler;
	int status;
	bool reset = false;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_CMD_INTERFACE,
		.msg_index = CMD_LOGGING_DEBUG_LOG_CLEAR_FAIL,
		.arg1 = LOGGING_CLEAR_FAILED,
		.arg2 = 0
	};

	TEST_START;

	cmd_background_handler_testing_init (test, &handler);

	status = mock_expect (&handler.log.mock, handler.log.base.clear, &handler.log,
		LOGGING_CLEAR_FAILED);

	status |= mock_expect (&handler.log.mock, handler.log.base.create_entry, &handler.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));

	CuAssertIntEquals (test, 0, status);

	handler.context.action = CMD_BACKGROUND_HANDLER_ACTION_DEBUG_LOG_CLEAR;
	handler.context.buffer_length = 0;

	handler.test.base_event.execute (&handler.test.base_event, handler.context_ptr, &reset);
	CuAssertIntEquals (test, 0, reset);

	cmd_background_handler_testing_validate_and_release (test, &handler);
}

static void cmd_background_handler_test_execute_debug_log_clear_static_init (CuTest *test)
{
	struct cmd_background_handler_testing handler;
	struct cmd_background_handler test_static = cmd_background_handler_static_init (&handler.state,
		&handler.attestation.base, &handler.hash.base, &handler.keys.riot, &handler.task.base);
	int status;
	bool reset = false;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_INFO,
		.component = DEBUG_LOG_COMPONENT_CMD_INTERFACE,
		.msg_index = CMD_LOGGING_DEBUG_LOG_CLEARED,
		.arg1 = 0,
		.arg2 = 0
	};

	TEST_START;

	cmd_background_handler_testing_init_static (test, &handler, &test_static);

	status = mock_expect (&handler.log.mock, handler.log.base.clear, &handler.log, 0);

	status |= mock_expect (&handler.log.mock, handler.log.base.create_entry, &handler.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));

	CuAssertIntEquals (test, 0, status);

	handler.context.action = CMD_BACKGROUND_HANDLER_ACTION_DEBUG_LOG_CLEAR;
	handler.context.buffer_length = 0;

	test_static.base_event.execute (&test_static.base_event, handler.context_ptr, &reset);
	CuAssertIntEquals (test, 0, reset);

	cmd_background_handler_testing_release_dependencies (test, &handler);
	cmd_background_handler_release (&test_static);
}

#ifdef CMD_SUPPORT_DEBUG_COMMANDS
static void cmd_background_handler_test_execute_debug_log_fill (CuTest *test)
{
	struct cmd_background_handler_testing handler;
	int status;
	bool reset = false;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_INFO,
		.component = DEBUG_LOG_COMPONENT_DEVICE_SPECIFIC,
		.msg_index = 0,
		.arg1 = 0,
		.arg2 = 0
	};
	int i;
	int count = (FLASH_SECTOR_SIZE / sizeof (struct debug_log_entry)) * LOGGING_FLASH_SECTORS;

	TEST_START;

	cmd_background_handler_testing_init (test, &handler);

	status = mock_expect (&handler.log.mock, handler.log.base.clear, &handler.log, 0);

	for (i = 0; i < count; i++) {
		status |= mock_expect (&handler.log.mock, handler.log.base.create_entry, &handler.log, 0,
			MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
			MOCK_ARG (sizeof (entry)));
	}

	CuAssertIntEquals (test, 0, status);

	handler.context.action = CMD_BACKGROUND_HANDLER_ACTION_DEBUG_LOG_FILL;
	handler.context.buffer_length = 0;

	handler.test.base_event.execute (&handler.test.base_event, handler.context_ptr, &reset);
	CuAssertIntEquals (test, 0, reset);

	cmd_background_handler_testing_validate_and_release (test, &handler);
}

static void cmd_background_handler_test_execute_debug_log_fill_static_init (CuTest *test)
{
	struct cmd_background_handler_testing handler;
	struct cmd_background_handler test_static = cmd_background_handler_static_init (&handler.state,
		&handler.attestation.base, &handler.hash.base, &handler.keys.riot, &handler.task.base);
	int status;
	bool reset = false;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_INFO,
		.component = DEBUG_LOG_COMPONENT_DEVICE_SPECIFIC,
		.msg_index = 0,
		.arg1 = 0,
		.arg2 = 0
	};
	int i;
	int count = (FLASH_SECTOR_SIZE / sizeof (struct debug_log_entry)) * LOGGING_FLASH_SECTORS;

	TEST_START;

	cmd_background_handler_testing_init_static (test, &handler, &test_static);

	status = mock_expect (&handler.log.mock, handler.log.base.clear, &handler.log, 0);

	for (i = 0; i < count; i++) {
		status |= mock_expect (&handler.log.mock, handler.log.base.create_entry, &handler.log, 0,
			MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
			MOCK_ARG (sizeof (entry)));
	}

	CuAssertIntEquals (test, 0, status);

	handler.context.action = CMD_BACKGROUND_HANDLER_ACTION_DEBUG_LOG_FILL;
	handler.context.buffer_length = 0;

	test_static.base_event.execute (&test_static.base_event, handler.context_ptr, &reset);
	CuAssertIntEquals (test, 0, reset);

	cmd_background_handler_testing_release_dependencies (test, &handler);
	cmd_background_handler_release (&test_static);
}
#endif
#endif

static void cmd_background_handler_test_execute_authenticate_riot_certs (CuTest *test)
{
	struct cmd_background_handler_testing handler;
	int status;
	bool reset = false;
	uint8_t *dev_id_der = NULL;
	uint8_t *ca_der = NULL;
	uint8_t *int_der = NULL;

	TEST_START;

	cmd_background_handler_testing_init (test, &handler);

	dev_id_der = platform_malloc (RIOT_CORE_DEVID_SIGNED_CERT_LEN);
	CuAssertPtrNotNull (test, dev_id_der);

	ca_der = platform_malloc (X509_CERTSS_ECC_CA_NOPL_DER_LEN);
	CuAssertPtrNotNull (test, ca_der);

	memcpy (dev_id_der, RIOT_CORE_DEVID_SIGNED_CERT, RIOT_CORE_DEVID_SIGNED_CERT_LEN);
	memcpy (ca_der, X509_CERTSS_ECC_CA_NOPL_DER, X509_CERTSS_ECC_CA_NOPL_DER_LEN);

	status = mock_expect (&handler.keys.riot_keystore.mock,
		handler.keys.riot_keystore.base.load_key, &handler.keys.riot_keystore, 0, MOCK_ARG (0),
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&handler.keys.riot_keystore.mock, 1, &dev_id_der,
		sizeof (dev_id_der), -1);
	status |= mock_expect_output (&handler.keys.riot_keystore.mock, 2,
		&RIOT_CORE_DEVID_SIGNED_CERT_LEN, sizeof (RIOT_CORE_DEVID_SIGNED_CERT_LEN), -1);

	status |= mock_expect (&handler.keys.riot_keystore.mock,
		handler.keys.riot_keystore.base.load_key, &handler.keys.riot_keystore, 0, MOCK_ARG (1),
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&handler.keys.riot_keystore.mock, 1, &ca_der, sizeof (ca_der),
		-1);
	status |= mock_expect_output (&handler.keys.riot_keystore.mock, 2,
		&X509_CERTSS_ECC_CA_NOPL_DER_LEN, sizeof (X509_CERTSS_ECC_CA_NOPL_DER_LEN), -1);

	status |= mock_expect (&handler.keys.riot_keystore.mock,
		handler.keys.riot_keystore.base.load_key, &handler.keys.riot_keystore, KEYSTORE_NO_KEY,
		MOCK_ARG (2), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&handler.keys.riot_keystore.mock, 1, &int_der, sizeof (int_der),
		-1);

	/* Lock for state update: 0 */
	status |= mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	handler.context.action = CMD_BACKGROUND_HANDLER_ACTION_AUTH_RIOT;
	handler.context.buffer_length = 0;

	handler.test.base_event.execute (&handler.test.base_event, handler.context_ptr, &reset);
	CuAssertIntEquals (test, 0, reset);

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_cmd.get_riot_cert_chain_state (&handler.test.base_cmd);
	CuAssertIntEquals (test, 0, status);

	cmd_background_handler_testing_validate_and_release (test, &handler);
}

static void cmd_background_handler_test_execute_authenticate_riot_certs_failure (CuTest *test)
{
	struct cmd_background_handler_testing handler;
	int status;
	bool reset = false;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_WARNING,
		.component = DEBUG_LOG_COMPONENT_RIOT,
		.msg_index = RIOT_LOGGING_DEVID_AUTH_STATUS,
		.arg1 = RIOT_KEY_MANAGER_NO_SIGNED_DEVICE_ID,
		.arg2 = 0
	};
	uint8_t *dev_id_der = NULL;

	TEST_START;

	cmd_background_handler_testing_init (test, &handler);

	status = mock_expect (&handler.keys.riot_keystore.mock,
		handler.keys.riot_keystore.base.load_key, &handler.keys.riot_keystore, KEYSTORE_NO_KEY,
		MOCK_ARG (0), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&handler.keys.riot_keystore.mock, 1, &dev_id_der,
		sizeof (dev_id_der), -1);

	status |= mock_expect (&handler.log.mock, handler.log.base.create_entry, &handler.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));

	/* Lock for state update: RIOT_CERT_STATE_CHAIN_INVALID */
	status |= mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	handler.context.action = CMD_BACKGROUND_HANDLER_ACTION_AUTH_RIOT;
	handler.context.buffer_length = 0;

	handler.test.base_event.execute (&handler.test.base_event, handler.context_ptr, &reset);
	CuAssertIntEquals (test, 0, reset);

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_cmd.get_riot_cert_chain_state (&handler.test.base_cmd);
	CuAssertIntEquals (test, (((RIOT_KEY_MANAGER_NO_SIGNED_DEVICE_ID & 0x00ffffff) << 8) |
			RIOT_CERT_STATE_CHAIN_INVALID), status);

	cmd_background_handler_testing_validate_and_release (test, &handler);
}

static void cmd_background_handler_test_execute_authenticate_riot_certs_static_init (CuTest *test)
{
	struct cmd_background_handler_testing handler;
	struct cmd_background_handler test_static = cmd_background_handler_static_init (&handler.state,
		&handler.attestation.base, &handler.hash.base, &handler.keys.riot, &handler.task.base);
	int status;
	bool reset = false;
	uint8_t *dev_id_der = NULL;
	uint8_t *ca_der = NULL;
	uint8_t *int_der = NULL;

	TEST_START;

	cmd_background_handler_testing_init_static (test, &handler, &test_static);

	dev_id_der = platform_malloc (RIOT_CORE_DEVID_SIGNED_CERT_LEN);
	CuAssertPtrNotNull (test, dev_id_der);

	ca_der = platform_malloc (X509_CERTSS_ECC_CA_NOPL_DER_LEN);
	CuAssertPtrNotNull (test, ca_der);

	memcpy (dev_id_der, RIOT_CORE_DEVID_SIGNED_CERT, RIOT_CORE_DEVID_SIGNED_CERT_LEN);
	memcpy (ca_der, X509_CERTSS_ECC_CA_NOPL_DER, X509_CERTSS_ECC_CA_NOPL_DER_LEN);

	status = mock_expect (&handler.keys.riot_keystore.mock,
		handler.keys.riot_keystore.base.load_key, &handler.keys.riot_keystore, 0, MOCK_ARG (0),
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&handler.keys.riot_keystore.mock, 1, &dev_id_der,
		sizeof (dev_id_der), -1);
	status |= mock_expect_output (&handler.keys.riot_keystore.mock, 2,
		&RIOT_CORE_DEVID_SIGNED_CERT_LEN, sizeof (RIOT_CORE_DEVID_SIGNED_CERT_LEN), -1);

	status |= mock_expect (&handler.keys.riot_keystore.mock,
		handler.keys.riot_keystore.base.load_key, &handler.keys.riot_keystore, 0, MOCK_ARG (1),
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&handler.keys.riot_keystore.mock, 1, &ca_der, sizeof (ca_der),
		-1);
	status |= mock_expect_output (&handler.keys.riot_keystore.mock, 2,
		&X509_CERTSS_ECC_CA_NOPL_DER_LEN, sizeof (X509_CERTSS_ECC_CA_NOPL_DER_LEN), -1);

	status |= mock_expect (&handler.keys.riot_keystore.mock,
		handler.keys.riot_keystore.base.load_key, &handler.keys.riot_keystore, KEYSTORE_NO_KEY,
		MOCK_ARG (2), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&handler.keys.riot_keystore.mock, 1, &int_der, sizeof (int_der),
		-1);

	/* Lock for state update: 0 */
	status |= mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	handler.context.action = CMD_BACKGROUND_HANDLER_ACTION_AUTH_RIOT;
	handler.context.buffer_length = 0;

	test_static.base_event.execute (&test_static.base_event, handler.context_ptr, &reset);
	CuAssertIntEquals (test, 0, reset);

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = test_static.base_cmd.get_riot_cert_chain_state (&test_static.base_cmd);
	CuAssertIntEquals (test, 0, status);

	cmd_background_handler_testing_release_dependencies (test, &handler);
	cmd_background_handler_release (&test_static);
}

static void cmd_background_handler_test_execute_reboot_device (CuTest *test)
{
	struct cmd_background_handler_testing handler;
	bool reset = false;

	TEST_START;

	cmd_background_handler_testing_init (test, &handler);

	handler.context.action = CMD_BACKGROUND_HANDLER_ACTION_REBOOT_DEVICE;
	handler.context.buffer_length = 0;

	handler.test.base_event.execute (&handler.test.base_event, handler.context_ptr, &reset);
	CuAssertIntEquals (test, true, reset);

	cmd_background_handler_testing_validate_and_release (test, &handler);
}

static void cmd_background_handler_test_execute_reboot_device_static_init (CuTest *test)
{
	struct cmd_background_handler_testing handler;
	struct cmd_background_handler test_static = cmd_background_handler_static_init (&handler.state,
		&handler.attestation.base, &handler.hash.base, &handler.keys.riot, &handler.task.base);
	bool reset = false;

	TEST_START;

	cmd_background_handler_testing_init (test, &handler);

	handler.context.action = CMD_BACKGROUND_HANDLER_ACTION_REBOOT_DEVICE;
	handler.context.buffer_length = 0;

	test_static.base_event.execute (&test_static.base_event, handler.context_ptr, &reset);
	CuAssertIntEquals (test, true, reset);

	cmd_background_handler_testing_release_dependencies (test, &handler);
	cmd_background_handler_release (&test_static);
}

#ifdef ATTESTATION_SUPPORT_RSA_UNSEAL
static void cmd_background_handler_test_execute_generate_aux_key (CuTest *test)
{
	struct cmd_background_handler_testing handler;
	int status;
	bool reset = false;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_INFO,
		.component = DEBUG_LOG_COMPONENT_CMD_INTERFACE,
		.msg_index = CMD_LOGGING_AUX_KEY,
		.arg1 = 0,
		.arg2 = 0
	};
	struct aux_attestation *aux_ptr = &handler.keys.aux;
	uint8_t *key_der = NULL;

	TEST_START;

	cmd_background_handler_testing_init_mock_rsa (test, &handler);

	key_der = platform_malloc (RSA3K_PRIVKEY_DER_LEN);
	CuAssertPtrNotNull (test, key_der);

	memcpy (key_der, RSA3K_PRIVKEY_DER, RSA3K_PRIVKEY_DER_LEN);

	status = mock_expect (&handler.rsa_mock.mock, handler.rsa_mock.base.generate_key,
		&handler.rsa_mock, 0, MOCK_ARG_NOT_NULL, MOCK_ARG (3072));
	status |= mock_expect_save_arg (&handler.rsa_mock.mock, 0, 0);

	status |= mock_expect (&handler.rsa_mock.mock, handler.rsa_mock.base.get_private_key_der,
		&handler.rsa_mock, 0, MOCK_ARG_SAVED_ARG (0), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&handler.rsa_mock.mock, 1, &key_der, sizeof (key_der), -1);
	status |= mock_expect_output (&handler.rsa_mock.mock, 2, &RSA3K_PRIVKEY_DER_LEN,
		sizeof (RSA3K_PRIVKEY_DER_LEN), -1);

	status |= mock_expect (&handler.keys.aux_keystore.mock, handler.keys.aux_keystore.base.save_key,
		&handler.keys.aux_keystore, 0, MOCK_ARG (0),
		MOCK_ARG_PTR_CONTAINS (RSA3K_PRIVKEY_DER, RSA3K_PRIVKEY_DER_LEN),
		MOCK_ARG (RSA3K_PRIVKEY_DER_LEN));

	status |= mock_expect (&handler.rsa_mock.mock, handler.rsa_mock.base.release_key,
		&handler.rsa_mock, 0, MOCK_ARG_SAVED_ARG (0));

	status |= mock_expect (&handler.log.mock, handler.log.base.create_entry, &handler.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));

	CuAssertIntEquals (test, 0, status);

	handler.context.action = CMD_BACKGROUND_HANDLER_ACTION_AUX_KEY_GEN;
	handler.context.buffer_length = sizeof (aux_ptr);
	memcpy (handler.context.event_buffer, (uint8_t*) &aux_ptr, sizeof (aux_ptr));

	handler.test.base_event.execute (&handler.test.base_event, handler.context_ptr, &reset);
	CuAssertIntEquals (test, 0, reset);

	cmd_background_handler_testing_validate_and_release (test, &handler);
}

static void cmd_background_handler_test_execute_generate_aux_key_failure (CuTest *test)
{
	struct cmd_background_handler_testing handler;
	int status;
	bool reset = false;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_CMD_INTERFACE,
		.msg_index = CMD_LOGGING_AUX_KEY,
		.arg1 = RSA_ENGINE_GENERATE_KEY_FAILED,
		.arg2 = 0
	};
	struct aux_attestation *aux_ptr = &handler.keys.aux;

	TEST_START;

	cmd_background_handler_testing_init_mock_rsa (test, &handler);

	status = mock_expect (&handler.rsa_mock.mock, handler.rsa_mock.base.generate_key,
		&handler.rsa_mock, RSA_ENGINE_GENERATE_KEY_FAILED, MOCK_ARG_NOT_NULL, MOCK_ARG (3072));

	status |= mock_expect (&handler.log.mock, handler.log.base.create_entry, &handler.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));

	CuAssertIntEquals (test, 0, status);

	handler.context.action = CMD_BACKGROUND_HANDLER_ACTION_AUX_KEY_GEN;
	handler.context.buffer_length = sizeof (aux_ptr);
	memcpy (handler.context.event_buffer, (uint8_t*) &aux_ptr, sizeof (aux_ptr));

	handler.test.base_event.execute (&handler.test.base_event, handler.context_ptr, &reset);
	CuAssertIntEquals (test, 0, reset);

	cmd_background_handler_testing_validate_and_release (test, &handler);
}

static void cmd_background_handler_test_execute_generate_aux_key_static_init (CuTest *test)
{
	struct cmd_background_handler_testing handler;
	struct cmd_background_handler test_static = cmd_background_handler_static_init (&handler.state,
		&handler.attestation.base, &handler.hash.base, &handler.keys.riot, &handler.task.base);
	int status;
	bool reset = false;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_INFO,
		.component = DEBUG_LOG_COMPONENT_CMD_INTERFACE,
		.msg_index = CMD_LOGGING_AUX_KEY,
		.arg1 = 0,
		.arg2 = 0
	};
	struct aux_attestation *aux_ptr = &handler.keys.aux;
	uint8_t *key_der = NULL;

	TEST_START;

	cmd_background_handler_testing_init_static_mock_rsa (test, &handler, &test_static);

	key_der = platform_malloc (RSA3K_PRIVKEY_DER_LEN);
	CuAssertPtrNotNull (test, key_der);

	memcpy (key_der, RSA3K_PRIVKEY_DER, RSA3K_PRIVKEY_DER_LEN);

	status = mock_expect (&handler.rsa_mock.mock, handler.rsa_mock.base.generate_key,
		&handler.rsa_mock, 0, MOCK_ARG_NOT_NULL, MOCK_ARG (3072));
	status |= mock_expect_save_arg (&handler.rsa_mock.mock, 0, 0);

	status |= mock_expect (&handler.rsa_mock.mock, handler.rsa_mock.base.get_private_key_der,
		&handler.rsa_mock, 0, MOCK_ARG_SAVED_ARG (0), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&handler.rsa_mock.mock, 1, &key_der, sizeof (key_der), -1);
	status |= mock_expect_output (&handler.rsa_mock.mock, 2, &RSA3K_PRIVKEY_DER_LEN,
		sizeof (RSA3K_PRIVKEY_DER_LEN), -1);

	status |= mock_expect (&handler.keys.aux_keystore.mock, handler.keys.aux_keystore.base.save_key,
		&handler.keys.aux_keystore, 0, MOCK_ARG (0),
		MOCK_ARG_PTR_CONTAINS (RSA3K_PRIVKEY_DER, RSA3K_PRIVKEY_DER_LEN),
		MOCK_ARG (RSA3K_PRIVKEY_DER_LEN));

	status |= mock_expect (&handler.rsa_mock.mock, handler.rsa_mock.base.release_key,
		&handler.rsa_mock, 0, MOCK_ARG_SAVED_ARG (0));

	status |= mock_expect (&handler.log.mock, handler.log.base.create_entry, &handler.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));

	CuAssertIntEquals (test, 0, status);

	handler.context.action = CMD_BACKGROUND_HANDLER_ACTION_AUX_KEY_GEN;
	handler.context.buffer_length = sizeof (aux_ptr);
	memcpy (handler.context.event_buffer, (uint8_t*) &aux_ptr, sizeof (aux_ptr));

	test_static.base_event.execute (&test_static.base_event, handler.context_ptr, &reset);
	CuAssertIntEquals (test, 0, reset);

	cmd_background_handler_testing_release_dependencies (test, &handler);
	cmd_background_handler_release (&test_static);
}
#endif

static void cmd_background_handler_test_execute_unknown_action (CuTest *test)
{
	struct cmd_background_handler_testing handler;
	int status;
	bool reset = false;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_WARNING,
		.component = DEBUG_LOG_COMPONENT_CMD_INTERFACE,
		.msg_index = CMD_LOGGING_NOTIFICATION_ERROR,
		.arg1 = 0x100,
		.arg2 = 0
	};
	uint8_t key[AES256_KEY_LENGTH];
	size_t key_length = sizeof (key);
	uint32_t result;

	TEST_START;

	cmd_background_handler_testing_init (test, &handler);

	handler.context.action = 0x100;

	status = mock_expect (&handler.log.mock, handler.log.base.create_entry, &handler.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));

	CuAssertIntEquals (test, 0, status);

	handler.test.base_event.execute (&handler.test.base_event, handler.context_ptr, &reset);
	CuAssertIntEquals (test, 0, reset);

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_cmd.unseal_result (&handler.test.base_cmd, key, &key_length,
		&result);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, ATTESTATION_CMD_STATUS_NONE_STARTED, result);
	CuAssertIntEquals (test, 0, key_length);

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_cmd.get_authorized_operation_status (&handler.test.base_cmd);
	CuAssertIntEquals (test, CONFIG_RESET_STATUS_NONE_STARTED, status);

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_cmd.get_riot_cert_chain_state (&handler.test.base_cmd);
	CuAssertIntEquals (test, RIOT_CERT_STATE_CHAIN_INVALID, status);

	cmd_background_handler_testing_validate_and_release (test, &handler);
}

#ifdef CMD_ENABLE_UNSEAL
static void cmd_background_handler_test_execute_unknown_action_unseal_active (CuTest *test)
{
	struct cmd_background_handler_testing handler;
	int status;
	bool reset = false;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_WARNING,
		.component = DEBUG_LOG_COMPONENT_CMD_INTERFACE,
		.msg_index = CMD_LOGGING_NOTIFICATION_ERROR,
		.arg1 = 0x100,
		.arg2 = 0
	};
	uint8_t unseal_data[] = {0x11, 0x12, 0x13, 0x14, 0x15};
	uint8_t key[AES256_KEY_LENGTH];
	size_t key_length = sizeof (key);
	uint32_t result;

	TEST_START;

	cmd_background_handler_testing_init (test, &handler);

	status = mock_expect (&handler.task.mock, handler.task.base.get_event_context, &handler.task, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&handler.task.mock, 0, &handler.context_ptr,
		sizeof (handler.context_ptr), -1);

	status |= mock_expect (&handler.task.mock, handler.task.base.notify, &handler.task, 0,
		MOCK_ARG_PTR (&handler.test.base_event));

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_cmd.unseal_start (&handler.test.base_cmd, unseal_data,
		sizeof (unseal_data));
	CuAssertIntEquals (test, 0, status);

	/* Corrupt the action. */
	handler.context.action = 0x100;

	status = mock_expect (&handler.log.mock, handler.log.base.create_entry, &handler.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));

	/* Lock for state update: ATTESTATION_CMD_STATUS_INTERNAL_ERROR */
	status |= mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	handler.test.base_event.execute (&handler.test.base_event, handler.context_ptr, &reset);
	CuAssertIntEquals (test, 0, reset);

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_cmd.unseal_result (&handler.test.base_cmd, key, &key_length,
		&result);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, (((CMD_BACKGROUND_UNSUPPORTED_OP & 0x00ffffff) << 8) |
			ATTESTATION_CMD_STATUS_INTERNAL_ERROR), result);
	CuAssertIntEquals (test, 0, key_length);

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_cmd.get_authorized_operation_status (&handler.test.base_cmd);
	CuAssertIntEquals (test, CONFIG_RESET_STATUS_NONE_STARTED, status);

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_cmd.get_riot_cert_chain_state (&handler.test.base_cmd);
	CuAssertIntEquals (test, RIOT_CERT_STATE_CHAIN_INVALID, status);

	cmd_background_handler_testing_validate_and_release (test, &handler);
}
#endif

#ifdef CMD_ENABLE_RESET_CONFIG
static void cmd_background_handler_test_execute_unknown_action_config_reset_active (CuTest *test)
{
	struct cmd_background_handler_testing handler;
	int status;
	bool reset = false;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_WARNING,
		.component = DEBUG_LOG_COMPONENT_CMD_INTERFACE,
		.msg_index = CMD_LOGGING_NOTIFICATION_ERROR,
		.arg1 = 0x100,
		.arg2 = 0
	};
	uint8_t key[AES256_KEY_LENGTH];
	size_t key_length = sizeof (key);
	uint32_t result;

	TEST_START;

	cmd_background_handler_testing_init (test, &handler);

	status = mock_expect (&handler.task.mock, handler.task.base.get_event_context, &handler.task, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&handler.task.mock, 0, &handler.context_ptr,
		sizeof (handler.context_ptr), -1);

	status |= mock_expect (&handler.task.mock, handler.task.base.notify, &handler.task, 0,
		MOCK_ARG_PTR (&handler.test.base_event));

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_cmd.execute_authorized_operation (&handler.test.base_cmd,
		&handler.execution.base);

	/* Corrupt the action. */
	handler.context.action = 0x100;

	status = mock_expect (&handler.log.mock, handler.log.base.create_entry, &handler.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));

	/* Lock for state update: CONFIG_RESET_STATUS_INTERNAL_ERROR */
	status |= mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	handler.test.base_event.execute (&handler.test.base_event, handler.context_ptr, &reset);
	CuAssertIntEquals (test, 0, reset);

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_cmd.unseal_result (&handler.test.base_cmd, key, &key_length,
		&result);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, ATTESTATION_CMD_STATUS_NONE_STARTED, result);
	CuAssertIntEquals (test, 0, key_length);

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_cmd.get_authorized_operation_status (&handler.test.base_cmd);
	CuAssertIntEquals (test,
		(((CMD_BACKGROUND_UNSUPPORTED_OP & 0x00ffffff) << 8) | CONFIG_RESET_STATUS_INTERNAL_ERROR),
		status);

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_cmd.get_riot_cert_chain_state (&handler.test.base_cmd);
	CuAssertIntEquals (test, RIOT_CERT_STATE_CHAIN_INVALID, status);

	cmd_background_handler_testing_validate_and_release (test, &handler);
}
#endif

static void cmd_background_handler_test_execute_unknown_action_riot_auth_active (CuTest *test)
{
	struct cmd_background_handler_testing handler;
	int status;
	bool reset = false;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_WARNING,
		.component = DEBUG_LOG_COMPONENT_CMD_INTERFACE,
		.msg_index = CMD_LOGGING_NOTIFICATION_ERROR,
		.arg1 = 0x100,
		.arg2 = 0
	};
	uint8_t key[AES256_KEY_LENGTH];
	size_t key_length = sizeof (key);
	uint32_t result;

	TEST_START;

	cmd_background_handler_testing_init (test, &handler);

	status = mock_expect (&handler.task.mock, handler.task.base.get_event_context, &handler.task, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&handler.task.mock, 0, &handler.context_ptr,
		sizeof (handler.context_ptr), -1);

	status |= mock_expect (&handler.task.mock, handler.task.base.notify, &handler.task, 0,
		MOCK_ARG_PTR (&handler.test.base_event));

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_cmd.authenticate_riot_certs (&handler.test.base_cmd);
	CuAssertIntEquals (test, 0, status);

	/* Corrupt the action. */
	handler.context.action = 0x100;

	status = mock_expect (&handler.log.mock, handler.log.base.create_entry, &handler.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));

	/* Lock for state update: RIOT_CERT_STATE_CHAIN_INVALID */
	status |= mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	handler.test.base_event.execute (&handler.test.base_event, handler.context_ptr, &reset);
	CuAssertIntEquals (test, 0, reset);

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_cmd.unseal_result (&handler.test.base_cmd, key, &key_length,
		&result);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, ATTESTATION_CMD_STATUS_NONE_STARTED, result);
	CuAssertIntEquals (test, 0, key_length);

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_cmd.get_authorized_operation_status (&handler.test.base_cmd);
	CuAssertIntEquals (test, CONFIG_RESET_STATUS_NONE_STARTED, status);

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_cmd.get_riot_cert_chain_state (&handler.test.base_cmd);
	CuAssertIntEquals (test,
		(((CMD_BACKGROUND_UNSUPPORTED_OP & 0x00ffffff) << 8) | RIOT_CERT_STATE_CHAIN_INVALID),
		status);

	cmd_background_handler_testing_validate_and_release (test, &handler);
}

static void cmd_background_handler_test_execute_unknown_action_static_init (CuTest *test)
{
	struct cmd_background_handler_testing handler;
	struct cmd_background_handler test_static = cmd_background_handler_static_init (&handler.state,
		&handler.attestation.base, &handler.hash.base, &handler.keys.riot, &handler.task.base);
	int status;
	bool reset = false;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_WARNING,
		.component = DEBUG_LOG_COMPONENT_CMD_INTERFACE,
		.msg_index = CMD_LOGGING_NOTIFICATION_ERROR,
		.arg1 = 0x200,
		.arg2 = 0
	};
	uint8_t key[AES256_KEY_LENGTH];
	size_t key_length = sizeof (key);
	uint32_t result;

	TEST_START;

	cmd_background_handler_testing_init_static (test, &handler, &test_static);

	handler.context.action = 0x200;

	status = mock_expect (&handler.log.mock, handler.log.base.create_entry, &handler.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));

	CuAssertIntEquals (test, 0, status);

	test_static.base_event.execute (&test_static.base_event, handler.context_ptr, &reset);
	CuAssertIntEquals (test, 0, reset);

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = test_static.base_cmd.unseal_result (&test_static.base_cmd, key, &key_length, &result);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, ATTESTATION_CMD_STATUS_NONE_STARTED, result);
	CuAssertIntEquals (test, 0, key_length);

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = test_static.base_cmd.get_authorized_operation_status (&test_static.base_cmd);
	CuAssertIntEquals (test, CONFIG_RESET_STATUS_NONE_STARTED, status);

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = test_static.base_cmd.get_riot_cert_chain_state (&test_static.base_cmd);
	CuAssertIntEquals (test, RIOT_CERT_STATE_CHAIN_INVALID, status);

	cmd_background_handler_testing_release_dependencies (test, &handler);
	cmd_background_handler_release (&test_static);
}


// *INDENT-OFF*
TEST_SUITE_START (cmd_background_handler);

TEST (cmd_background_handler_test_init);
TEST (cmd_background_handler_test_init_null);
TEST (cmd_background_handler_test_static_init);
TEST (cmd_background_handler_test_static_init_null);
TEST (cmd_background_handler_test_release_null);
#ifdef CMD_ENABLE_UNSEAL
TEST (cmd_background_handler_test_unseal_result);
TEST (cmd_background_handler_test_unseal_result_static_init);
TEST (cmd_background_handler_test_unseal_result_null);
TEST (cmd_background_handler_test_unseal_result_no_unseal_support);
#endif
#ifdef CMD_ENABLE_RESET_CONFIG
TEST (cmd_background_handler_test_get_authorized_operation_status);
TEST (cmd_background_handler_test_get_authorized_operation_status_static_init);
TEST (cmd_background_handler_test_get_authorized_operation_status_null);
#endif
TEST (cmd_background_handler_test_get_riot_cert_chain_state);
TEST (cmd_background_handler_test_get_riot_cert_chain_state_valid_certs);
TEST (cmd_background_handler_test_get_riot_cert_chain_state_static_init);
TEST (cmd_background_handler_test_get_riot_cert_chain_state_static_init_valid_certs);
TEST (cmd_background_handler_test_get_riot_cert_chain_state_null);
#ifdef CMD_ENABLE_UNSEAL
TEST (cmd_background_handler_test_unseal_start);
TEST (cmd_background_handler_test_unseal_start_max_message);
TEST (cmd_background_handler_test_unseal_start_static_init);
TEST (cmd_background_handler_test_unseal_start_null);
TEST (cmd_background_handler_test_unseal_start_no_unseal_support);
TEST (cmd_background_handler_test_unseal_start_data_too_long);
TEST (cmd_background_handler_test_unseal_start_no_task);
TEST (cmd_background_handler_test_unseal_start_task_busy);
TEST (cmd_background_handler_test_unseal_start_get_context_error);
TEST (cmd_background_handler_test_unseal_start_notify_error);
#endif
#ifdef CMD_ENABLE_RESET_CONFIG
TEST (cmd_background_handler_test_execute_authorized_operation);
TEST (cmd_background_handler_test_execute_authorized_operation_static_init);
TEST (cmd_background_handler_test_execute_authorized_operation_null);
TEST (cmd_background_handler_test_execute_authorized_operation_no_task);
TEST (cmd_background_handler_test_execute_authorized_operation_task_busy);
TEST (cmd_background_handler_test_execute_authorized_operation_get_context_error);
TEST (cmd_background_handler_test_execute_authorized_operation_notify_error);
#endif
#ifdef CMD_ENABLE_DEBUG_LOG
TEST (cmd_background_handler_test_debug_log_clear);
TEST (cmd_background_handler_test_debug_log_clear_static_init);
TEST (cmd_background_handler_test_debug_log_clear_null);
TEST (cmd_background_handler_test_debug_log_clear_no_task);
TEST (cmd_background_handler_test_debug_log_clear_task_busy);
TEST (cmd_background_handler_test_debug_log_clear_get_context_error);
TEST (cmd_background_handler_test_debug_log_clear_notify_error);
#ifdef CMD_SUPPORT_DEBUG_COMMANDS
TEST (cmd_background_handler_test_debug_log_fill);
TEST (cmd_background_handler_test_debug_log_fill_static_init);
TEST (cmd_background_handler_test_debug_log_fill_null);
TEST (cmd_background_handler_test_debug_log_fill_no_task);
TEST (cmd_background_handler_test_debug_log_fill_task_busy);
TEST (cmd_background_handler_test_debug_log_fill_get_context_error);
TEST (cmd_background_handler_test_debug_log_fill_notify_error);
#endif
#endif
TEST (cmd_background_handler_test_authenticate_riot_certs);
TEST (cmd_background_handler_test_authenticate_riot_certs_static_init);
TEST (cmd_background_handler_test_authenticate_riot_certs_null);
TEST (cmd_background_handler_test_authenticate_riot_certs_no_task);
TEST (cmd_background_handler_test_authenticate_riot_certs_task_busy);
TEST (cmd_background_handler_test_authenticate_riot_certs_get_context_error);
TEST (cmd_background_handler_test_authenticate_riot_certs_notify_error);
TEST (cmd_background_handler_test_reboot_device);
TEST (cmd_background_handler_test_reboot_device_static_init);
TEST (cmd_background_handler_test_reboot_device_null);
TEST (cmd_background_handler_test_reboot_device_no_task);
TEST (cmd_background_handler_test_reboot_device_task_busy);
TEST (cmd_background_handler_test_reboot_device_get_context_error);
TEST (cmd_background_handler_test_reboot_device_notify_error);
TEST (cmd_background_handler_test_generate_aux_key);
TEST (cmd_background_handler_test_generate_aux_key_static_init);
#ifdef ATTESTATION_SUPPORT_RSA_UNSEAL
TEST (cmd_background_handler_test_generate_aux_key_null);
TEST (cmd_background_handler_test_generate_aux_key_no_task);
TEST (cmd_background_handler_test_generate_aux_key_task_busy);
TEST (cmd_background_handler_test_generate_aux_key_get_context_error);
TEST (cmd_background_handler_test_generate_aux_key_notify_error);
#endif
#ifdef CMD_ENABLE_UNSEAL
TEST (cmd_background_handler_test_execute_unseal_rsa);
TEST (cmd_background_handler_test_execute_unseal_ecc);
TEST (cmd_background_handler_test_execute_unseal_result_buffer_too_small);
TEST (cmd_background_handler_test_execute_unseal_failure);
TEST (cmd_background_handler_test_execute_unseal_static_init);
#endif
#ifdef CMD_ENABLE_RESET_CONFIG
TEST (cmd_background_handler_test_execute_execute_authorized_operation);
TEST (cmd_background_handler_test_execute_execute_authorized_operation_failure);
TEST (cmd_background_handler_test_execute_execute_authorized_operation_failure_bypass_error);
TEST (cmd_background_handler_test_execute_execute_authorized_operation_static_init);
#endif
#ifdef CMD_ENABLE_DEBUG_LOG
TEST (cmd_background_handler_test_execute_debug_log_clear);
TEST (cmd_background_handler_test_execute_debug_log_clear_failure);
TEST (cmd_background_handler_test_execute_debug_log_clear_static_init);
#ifdef CMD_SUPPORT_DEBUG_COMMANDS
TEST (cmd_background_handler_test_execute_debug_log_fill);
TEST (cmd_background_handler_test_execute_debug_log_fill_static_init);
#endif
#endif
TEST (cmd_background_handler_test_execute_authenticate_riot_certs);
TEST (cmd_background_handler_test_execute_authenticate_riot_certs_failure);
TEST (cmd_background_handler_test_execute_authenticate_riot_certs_static_init);
TEST (cmd_background_handler_test_execute_reboot_device);
TEST (cmd_background_handler_test_execute_reboot_device_static_init);
#ifdef ATTESTATION_SUPPORT_RSA_UNSEAL
TEST (cmd_background_handler_test_execute_generate_aux_key);
TEST (cmd_background_handler_test_execute_generate_aux_key_failure);
TEST (cmd_background_handler_test_execute_generate_aux_key_static_init);
#endif
TEST (cmd_background_handler_test_execute_unknown_action);
#ifdef CMD_ENABLE_UNSEAL
TEST (cmd_background_handler_test_execute_unknown_action_unseal_active);
#endif
#ifdef CMD_ENABLE_RESET_CONFIG
TEST (cmd_background_handler_test_execute_unknown_action_config_reset_active);
#endif
TEST (cmd_background_handler_test_execute_unknown_action_riot_auth_active);
TEST (cmd_background_handler_test_execute_unknown_action_static_init);

TEST_SUITE_END;
// *INDENT-ON*
