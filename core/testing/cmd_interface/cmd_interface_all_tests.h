// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef CMD_INTERFACE_ALL_TESTS_H_
#define CMD_INTERFACE_ALL_TESTS_H_

#include "testing.h"
#include "platform_all_tests.h"
#include "common/unused.h"


/**
 * Add all tests for components in the 'cmd_interface' directory.
 *
 * Be sure to keep the test suites in alphabetical order for easier management.
 *
 * @param suite Suite to add the tests to.
 */
static void add_all_cmd_interface_tests (CuSuite *suite)
{
	/* This is unused when no tests will be executed. */
	UNUSED (suite);

#if (defined TESTING_RUN_CERBERUS_PROTOCOL_DEBUG_COMMANDS_SUITE || \
		defined TESTING_RUN_ALL_TESTS || defined TESTING_RUN_ALL_CORE_TESTS || \
		(!defined TESTING_SKIP_ALL_TESTS && !defined TESTING_SKIP_ALL_CORE_TESTS)) && \
	!defined TESTING_SKIP_CERBERUS_PROTOCOL_DEBUG_COMMANDS_SUITE
	TESTING_RUN_SUITE (cerberus_protocol_debug_commands);
#endif
#if (defined TESTING_RUN_CERBERUS_PROTOCOL_DIAGNOSTIC_COMMANDS_SUITE || \
		defined TESTING_RUN_ALL_TESTS || defined TESTING_RUN_ALL_CORE_TESTS || \
		(!defined TESTING_SKIP_ALL_TESTS && !defined TESTING_SKIP_ALL_CORE_TESTS)) && \
	!defined TESTING_SKIP_CERBERUS_PROTOCOL_DIAGNOSTIC_COMMANDS_SUITE
	TESTING_RUN_SUITE (cerberus_protocol_diagnostic_commands);
#endif
#if (defined TESTING_RUN_CERBERUS_PROTOCOL_MASTER_COMMANDS_SUITE || \
		defined TESTING_RUN_ALL_TESTS || defined TESTING_RUN_ALL_CORE_TESTS || \
		(!defined TESTING_SKIP_ALL_TESTS && !defined TESTING_SKIP_ALL_CORE_TESTS)) && \
	!defined TESTING_SKIP_CERBERUS_PROTOCOL_MASTER_COMMANDS_SUITE
	TESTING_RUN_SUITE (cerberus_protocol_master_commands);
#endif
#if (defined TESTING_RUN_CERBERUS_PROTOCOL_OPTIONAL_COMMANDS_SUITE || \
		defined TESTING_RUN_ALL_TESTS || defined TESTING_RUN_ALL_CORE_TESTS || \
		(!defined TESTING_SKIP_ALL_TESTS && !defined TESTING_SKIP_ALL_CORE_TESTS)) && \
	!defined TESTING_SKIP_CERBERUS_PROTOCOL_OPTIONAL_COMMANDS_SUITE
	TESTING_RUN_SUITE (cerberus_protocol_optional_commands);
#endif
#if (defined TESTING_RUN_CERBERUS_PROTOCOL_REQUIRED_COMMANDS_SUITE || \
		defined TESTING_RUN_ALL_TESTS || defined TESTING_RUN_ALL_CORE_TESTS || \
		(!defined TESTING_SKIP_ALL_TESTS && !defined TESTING_SKIP_ALL_CORE_TESTS)) && \
	!defined TESTING_SKIP_CERBERUS_PROTOCOL_REQUIRED_COMMANDS_SUITE
	TESTING_RUN_SUITE (cerberus_protocol_required_commands);
#endif
#if (defined TESTING_RUN_CMD_AUTHORIZATION_SUITE || \
		defined TESTING_RUN_ALL_TESTS || defined TESTING_RUN_ALL_CORE_TESTS || \
		(!defined TESTING_SKIP_ALL_TESTS && !defined TESTING_SKIP_ALL_CORE_TESTS)) && \
	!defined TESTING_SKIP_CMD_AUTHORIZATION_SUITE
	TESTING_RUN_SUITE (cmd_authorization);
#endif
#if (defined TESTING_RUN_CMD_CHANNEL_SUITE || \
		defined TESTING_RUN_ALL_TESTS || defined TESTING_RUN_ALL_CORE_TESTS || \
		(!defined TESTING_SKIP_ALL_TESTS && !defined TESTING_SKIP_ALL_CORE_TESTS)) && \
	!defined TESTING_SKIP_CMD_CHANNEL_SUITE
	TESTING_RUN_SUITE (cmd_channel);
#endif
#if (defined TESTING_RUN_CMD_INTERFACE_DUAL_CMD_SET_SUITE || \
		defined TESTING_RUN_ALL_TESTS || defined TESTING_RUN_ALL_CORE_TESTS || \
		(!defined TESTING_SKIP_ALL_TESTS && !defined TESTING_SKIP_ALL_CORE_TESTS)) && \
	!defined TESTING_SKIP_CMD_INTERFACE_DUAL_CMD_SET_SUITE
	TESTING_RUN_SUITE (cmd_interface_dual_cmd_set);
#endif
#if (defined TESTING_RUN_CMD_INTERFACE_SLAVE_SUITE || \
		defined TESTING_RUN_ALL_TESTS || defined TESTING_RUN_ALL_CORE_TESTS || \
		(!defined TESTING_SKIP_ALL_TESTS && !defined TESTING_SKIP_ALL_CORE_TESTS)) && \
	!defined TESTING_SKIP_CMD_INTERFACE_SLAVE_SUITE
	TESTING_RUN_SUITE (cmd_interface_slave);
#endif
#if (defined TESTING_RUN_CMD_INTERFACE_SYSTEM_SUITE || \
		defined TESTING_RUN_ALL_TESTS || defined TESTING_RUN_ALL_CORE_TESTS || \
		(!defined TESTING_SKIP_ALL_TESTS && !defined TESTING_SKIP_ALL_CORE_TESTS)) && \
	!defined TESTING_SKIP_CMD_INTERFACE_SYSTEM_SUITE
	TESTING_RUN_SUITE (cmd_interface_system);
#endif
#if (defined TESTING_RUN_CONFIG_RESET_SUITE || \
		defined TESTING_RUN_ALL_TESTS || defined TESTING_RUN_ALL_CORE_TESTS || \
		(!defined TESTING_SKIP_ALL_TESTS && !defined TESTING_SKIP_ALL_CORE_TESTS)) && \
	!defined TESTING_SKIP_CONFIG_RESET_SUITE
	TESTING_RUN_SUITE (config_reset);
#endif
#if (defined TESTING_RUN_COUNTER_MANAGER_REGISTERS_SUITE || \
		defined TESTING_RUN_ALL_TESTS || defined TESTING_RUN_ALL_CORE_TESTS || \
		(!defined TESTING_SKIP_ALL_TESTS && !defined TESTING_SKIP_ALL_CORE_TESTS)) && \
	!defined TESTING_SKIP_COUNTER_MANAGER_REGISTERS_SUITE
	TESTING_RUN_SUITE (counter_manager_registers);
#endif
#if (defined TESTING_RUN_DEVICE_MANAGER_SUITE || \
		defined TESTING_RUN_ALL_TESTS || defined TESTING_RUN_ALL_CORE_TESTS || \
		(!defined TESTING_SKIP_ALL_TESTS && !defined TESTING_SKIP_ALL_CORE_TESTS)) && \
	!defined TESTING_SKIP_DEVICE_MANAGER_SUITE
	TESTING_RUN_SUITE (device_manager);
#endif
#if (defined TESTING_RUN_SESSION_MANAGER_ECC_SUITE || \
		defined TESTING_RUN_ALL_TESTS || defined TESTING_RUN_ALL_CORE_TESTS || \
		(!defined TESTING_SKIP_ALL_TESTS && !defined TESTING_SKIP_ALL_CORE_TESTS)) && \
	!defined TESTING_SKIP_SESSION_MANAGER_ECC_SUITE
	TESTING_RUN_SUITE (session_manager_ecc);
#endif
}


#endif /* CMD_INTERFACE_ALL_TESTS_H_ */
