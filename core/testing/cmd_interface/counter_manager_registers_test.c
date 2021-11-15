// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <string.h>
#include "testing.h"
#include "cmd_interface/counter_manager_registers.h"
#include "cmd_interface/cerberus_protocol_required_commands.h"


TEST_SUITE_LABEL ("counter_manager_registers");


/*******************
 * Test cases
 *******************/

static void counter_manager_registers_test_init (CuTest *test)
{
	struct counter_manager_registers manager;
	uint32_t reg1;
	uint32_t reg2;
	int status;

	TEST_START;

	status = counter_manager_registers_init (&manager, &reg1, &reg2);
	CuAssertIntEquals (test, 0, status);

	counter_manager_registers_release (&manager);
}

static void counter_manager_registers_test_init_null (CuTest *test)
{
	struct counter_manager_registers manager;
	uint32_t reg1;
	uint32_t reg2;
	int status;

	TEST_START;

	status = counter_manager_registers_init (NULL, &reg1, &reg2);
	CuAssertIntEquals (test, COUNTER_MANAGER_INVALID_ARGUMENT, status);

	status = counter_manager_registers_init (&manager, NULL, &reg2);
	CuAssertIntEquals (test, COUNTER_MANAGER_INVALID_ARGUMENT, status);

	status = counter_manager_registers_init (&manager, &reg1, NULL);
	CuAssertIntEquals (test, 0, status);

	counter_manager_registers_release (&manager);
}

static void counter_manager_registers_test_release_null (CuTest *test)
{
	TEST_START;

	counter_manager_registers_release (NULL);
}

static void counter_manager_registers_test_get_counter (CuTest *test)
{
	struct counter_manager_registers manager;
	uint32_t reg1;
	uint32_t reg2;
	int status;

	TEST_START;

	reg1 = 0x20001;
	reg2 = 3;

	status = counter_manager_registers_init (&manager, &reg1, &reg2);
	CuAssertIntEquals (test, 0, status);

	status = counter_manager_registers_get_counter (&manager, CERBERUS_PROTOCOL_CERBERUS_RESET, 0);
	CuAssertIntEquals (test, 1, status);

	status = counter_manager_registers_get_counter (&manager, CERBERUS_PROTOCOL_COMPONENT_RESET, 0);
	CuAssertIntEquals (test, 2, status);

	status = counter_manager_registers_get_counter (&manager, CERBERUS_PROTOCOL_COMPONENT_RESET, 1);
	CuAssertIntEquals (test, 3, status);

	counter_manager_registers_release (&manager);
}

static void counter_manager_registers_test_get_counter_null (CuTest *test)
{
	struct counter_manager_registers manager;
	uint32_t reg1;
	uint32_t reg2;
	int status;

	TEST_START;

	status = counter_manager_registers_init (&manager, &reg1, &reg2);
	CuAssertIntEquals (test, 0, status);

	status = counter_manager_registers_get_counter (NULL, CERBERUS_PROTOCOL_CERBERUS_RESET, 0);
	CuAssertIntEquals (test, COUNTER_MANAGER_INVALID_ARGUMENT, status);

	counter_manager_registers_release (&manager);
}

static void counter_manager_registers_test_get_counter_unknown_type (CuTest *test)
{
	struct counter_manager_registers manager;
	uint32_t reg1;
	uint32_t reg2;
	int status;

	TEST_START;

	status = counter_manager_registers_init (&manager, &reg1, &reg2);
	CuAssertIntEquals (test, 0, status);

	status = counter_manager_registers_get_counter (&manager, 2, 0);
	CuAssertIntEquals (test, COUNTER_MANAGER_UNKNOWN_COUNTER, status);

	counter_manager_registers_release (&manager);
}

static void counter_manager_registers_test_get_counter_unknown_port (CuTest *test)
{
	struct counter_manager_registers manager;
	uint32_t reg1;
	uint32_t reg2;
	int status;

	TEST_START;

	status = counter_manager_registers_init (&manager, &reg1, &reg2);
	CuAssertIntEquals (test, 0, status);

	status = counter_manager_registers_get_counter (&manager, CERBERUS_PROTOCOL_COMPONENT_RESET, 2);
	CuAssertIntEquals (test, COUNTER_MANAGER_UNKNOWN_COUNTER, status);

	counter_manager_registers_release (&manager);
}

static void counter_manager_registers_test_get_counter_no_port1_counter (CuTest *test)
{
	struct counter_manager_registers manager;
	uint32_t reg1 = 0;
	int status;

	TEST_START;

	status = counter_manager_registers_init (&manager, &reg1, NULL);
	CuAssertIntEquals (test, 0, status);

	status = counter_manager_registers_get_counter (&manager, CERBERUS_PROTOCOL_COMPONENT_RESET, 1);
	CuAssertIntEquals (test, COUNTER_MANAGER_UNKNOWN_COUNTER, status);

	counter_manager_registers_release (&manager);
}

static void counter_manager_registers_test_increment (CuTest *test)
{
	struct counter_manager_registers manager;
	uint32_t reg1 = 0;
	uint32_t reg2 = 0;
	int status;

	TEST_START;

	status = counter_manager_registers_init (&manager, &reg1, &reg2);
	CuAssertIntEquals (test, 0, status);

	status = counter_manager_registers_increment (&manager, CERBERUS_PROTOCOL_CERBERUS_RESET, 0);
	CuAssertIntEquals (test, 0, status);

	status = counter_manager_registers_increment (&manager, CERBERUS_PROTOCOL_COMPONENT_RESET, 0);
	CuAssertIntEquals (test, 0, status);

	status = counter_manager_registers_increment (&manager, CERBERUS_PROTOCOL_COMPONENT_RESET, 1);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, 1,
		counter_manager_registers_get_counter (&manager, CERBERUS_PROTOCOL_CERBERUS_RESET, 0));
	CuAssertIntEquals (test, 1,
		counter_manager_registers_get_counter (&manager, CERBERUS_PROTOCOL_COMPONENT_RESET, 0));
	CuAssertIntEquals (test, 1,
		counter_manager_registers_get_counter (&manager, CERBERUS_PROTOCOL_COMPONENT_RESET, 1));

	counter_manager_registers_release (&manager);
}

static void counter_manager_registers_test_increment_after_clear (CuTest *test)
{
	struct counter_manager_registers manager;
	uint32_t reg1 = 0;
	int status;

	TEST_START;

	status = counter_manager_registers_init (&manager, &reg1, NULL);
	CuAssertIntEquals (test, 0, status);

	status = counter_manager_registers_increment (&manager, CERBERUS_PROTOCOL_CERBERUS_RESET, 0);
	CuAssertIntEquals (test, 0, status);

	status = counter_manager_registers_increment (&manager, CERBERUS_PROTOCOL_COMPONENT_RESET, 0);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, 1,
		counter_manager_registers_get_counter (&manager, CERBERUS_PROTOCOL_CERBERUS_RESET, 0));
	CuAssertIntEquals (test, 1,
		counter_manager_registers_get_counter (&manager, CERBERUS_PROTOCOL_COMPONENT_RESET, 0));

	status = counter_manager_registers_clear (&manager, CERBERUS_PROTOCOL_CERBERUS_RESET, 0);
	CuAssertIntEquals (test, 0, status);

	status = counter_manager_registers_clear (&manager, CERBERUS_PROTOCOL_COMPONENT_RESET, 0);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, 0,
		counter_manager_registers_get_counter (&manager, CERBERUS_PROTOCOL_CERBERUS_RESET, 0));
	CuAssertIntEquals (test, 0,
		counter_manager_registers_get_counter (&manager, CERBERUS_PROTOCOL_COMPONENT_RESET, 0));

	status = counter_manager_registers_increment (&manager, CERBERUS_PROTOCOL_CERBERUS_RESET, 0);
	CuAssertIntEquals (test, 0, status);

	status = counter_manager_registers_increment (&manager, CERBERUS_PROTOCOL_COMPONENT_RESET, 0);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, 1,
		counter_manager_registers_get_counter (&manager, CERBERUS_PROTOCOL_CERBERUS_RESET, 0));
	CuAssertIntEquals (test, 1,
		counter_manager_registers_get_counter (&manager, CERBERUS_PROTOCOL_COMPONENT_RESET, 0));

	counter_manager_registers_release (&manager);
}

static void counter_manager_registers_test_increment_null (CuTest *test)
{
	struct counter_manager_registers manager;
	uint32_t reg1 = 0;
	uint32_t reg2 = 0;
	int status;

	TEST_START;

	status = counter_manager_registers_init (&manager, &reg1, &reg2);
	CuAssertIntEquals (test, 0, status);

	status = counter_manager_registers_increment (NULL, CERBERUS_PROTOCOL_CERBERUS_RESET, 0);
	CuAssertIntEquals (test, COUNTER_MANAGER_INVALID_ARGUMENT, status);

	CuAssertIntEquals (test, 0,
		counter_manager_registers_get_counter (&manager, CERBERUS_PROTOCOL_CERBERUS_RESET, 0));
	CuAssertIntEquals (test, 0,
		counter_manager_registers_get_counter (&manager, CERBERUS_PROTOCOL_COMPONENT_RESET, 0));
	CuAssertIntEquals (test, 0,
		counter_manager_registers_get_counter (&manager, CERBERUS_PROTOCOL_COMPONENT_RESET, 1));

	counter_manager_registers_release (&manager);
}

static void counter_manager_registers_test_increment_multiple (CuTest *test)
{
	struct counter_manager_registers manager;
	uint32_t reg1 = 0;
	uint32_t reg2 = 0;
	int status;

	TEST_START;

	status = counter_manager_registers_init (&manager, &reg1, &reg2);
	CuAssertIntEquals (test, 0, status);

	status = counter_manager_registers_increment (&manager, CERBERUS_PROTOCOL_CERBERUS_RESET, 0);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, 1,
		counter_manager_registers_get_counter (&manager, CERBERUS_PROTOCOL_CERBERUS_RESET, 0));
	CuAssertIntEquals (test, 0,
		counter_manager_registers_get_counter (&manager, CERBERUS_PROTOCOL_COMPONENT_RESET, 0));
	CuAssertIntEquals (test, 0,
		counter_manager_registers_get_counter (&manager, CERBERUS_PROTOCOL_COMPONENT_RESET, 1));

	status = counter_manager_registers_increment (&manager, CERBERUS_PROTOCOL_CERBERUS_RESET, 0);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, 2,
		counter_manager_registers_get_counter (&manager, CERBERUS_PROTOCOL_CERBERUS_RESET, 0));
	CuAssertIntEquals (test, 0,
		counter_manager_registers_get_counter (&manager, CERBERUS_PROTOCOL_COMPONENT_RESET, 0));
	CuAssertIntEquals (test, 0,
		counter_manager_registers_get_counter (&manager, CERBERUS_PROTOCOL_COMPONENT_RESET, 1));

	status = counter_manager_registers_increment (&manager, CERBERUS_PROTOCOL_COMPONENT_RESET, 0);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, 2,
		counter_manager_registers_get_counter (&manager, CERBERUS_PROTOCOL_CERBERUS_RESET, 0));
	CuAssertIntEquals (test, 1,
		counter_manager_registers_get_counter (&manager, CERBERUS_PROTOCOL_COMPONENT_RESET, 0));
	CuAssertIntEquals (test, 0,
		counter_manager_registers_get_counter (&manager, CERBERUS_PROTOCOL_COMPONENT_RESET, 1));

	status = counter_manager_registers_increment (&manager, CERBERUS_PROTOCOL_COMPONENT_RESET, 0);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, 2,
		counter_manager_registers_get_counter (&manager, CERBERUS_PROTOCOL_CERBERUS_RESET, 0));
	CuAssertIntEquals (test, 2,
		counter_manager_registers_get_counter (&manager, CERBERUS_PROTOCOL_COMPONENT_RESET, 0));
	CuAssertIntEquals (test, 0,
		counter_manager_registers_get_counter (&manager, CERBERUS_PROTOCOL_COMPONENT_RESET, 1));

	status = counter_manager_registers_increment (&manager, CERBERUS_PROTOCOL_COMPONENT_RESET, 1);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, 2,
		counter_manager_registers_get_counter (&manager, CERBERUS_PROTOCOL_CERBERUS_RESET, 0));
	CuAssertIntEquals (test, 2,
		counter_manager_registers_get_counter (&manager, CERBERUS_PROTOCOL_COMPONENT_RESET, 0));
	CuAssertIntEquals (test, 1,
		counter_manager_registers_get_counter (&manager, CERBERUS_PROTOCOL_COMPONENT_RESET, 1));

	status = counter_manager_registers_increment (&manager, CERBERUS_PROTOCOL_COMPONENT_RESET, 1);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, 2,
		counter_manager_registers_get_counter (&manager, CERBERUS_PROTOCOL_CERBERUS_RESET, 0));
	CuAssertIntEquals (test, 2,
		counter_manager_registers_get_counter (&manager, CERBERUS_PROTOCOL_COMPONENT_RESET, 0));
	CuAssertIntEquals (test, 2,
		counter_manager_registers_get_counter (&manager, CERBERUS_PROTOCOL_COMPONENT_RESET, 1));

	counter_manager_registers_release (&manager);
}

static void counter_manager_registers_test_increment_unknown_type (CuTest *test)
{
	struct counter_manager_registers manager;
	uint32_t reg1 = 0;
	int status;

	TEST_START;

	status = counter_manager_registers_init (&manager, &reg1, NULL);
	CuAssertIntEquals (test, 0, status);

	status = counter_manager_registers_increment (&manager, 2, 0);
	CuAssertIntEquals (test, COUNTER_MANAGER_UNKNOWN_COUNTER, status);

	CuAssertIntEquals (test, 0,
		counter_manager_registers_get_counter (&manager, CERBERUS_PROTOCOL_CERBERUS_RESET, 0));
	CuAssertIntEquals (test, 0,
		counter_manager_registers_get_counter (&manager, CERBERUS_PROTOCOL_COMPONENT_RESET, 0));

	counter_manager_registers_release (&manager);
}

static void counter_manager_registers_test_increment_unknown_port (CuTest *test)
{
	struct counter_manager_registers manager;
	uint32_t reg1 = 0;
	int status;

	TEST_START;

	status = counter_manager_registers_init (&manager, &reg1, NULL);
	CuAssertIntEquals (test, 0, status);

	status = counter_manager_registers_increment (&manager, CERBERUS_PROTOCOL_COMPONENT_RESET, 2);
	CuAssertIntEquals (test, COUNTER_MANAGER_UNKNOWN_COUNTER, status);

	CuAssertIntEquals (test, 0,
		counter_manager_registers_get_counter (&manager, CERBERUS_PROTOCOL_CERBERUS_RESET, 0));
	CuAssertIntEquals (test, 0,
		counter_manager_registers_get_counter (&manager, CERBERUS_PROTOCOL_COMPONENT_RESET, 0));

	counter_manager_registers_release (&manager);
}

static void counter_manager_registers_test_increment_no_port1_counter (CuTest *test)
{
	struct counter_manager_registers manager;
	uint32_t reg1 = 0;
	int status;

	TEST_START;

	status = counter_manager_registers_init (&manager, &reg1, NULL);
	CuAssertIntEquals (test, 0, status);

	status = counter_manager_registers_increment (&manager, CERBERUS_PROTOCOL_COMPONENT_RESET, 1);
	CuAssertIntEquals (test, COUNTER_MANAGER_UNKNOWN_COUNTER, status);

	CuAssertIntEquals (test, 0,
		counter_manager_registers_get_counter (&manager, CERBERUS_PROTOCOL_CERBERUS_RESET, 0));
	CuAssertIntEquals (test, 0,
		counter_manager_registers_get_counter (&manager, CERBERUS_PROTOCOL_COMPONENT_RESET, 0));

	counter_manager_registers_release (&manager);
}

static void counter_manager_registers_test_increment_overflow (CuTest *test)
{
	struct counter_manager_registers manager;
	uint32_t reg1;
	uint32_t reg2;
	int status;

	TEST_START;

	reg1 = 0xffff;
	reg2 = 0;

	status = counter_manager_registers_init (&manager, &reg1, &reg2);
	CuAssertIntEquals (test, 0, status);

	status = counter_manager_registers_increment (&manager, CERBERUS_PROTOCOL_CERBERUS_RESET, 0);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, 0,
		counter_manager_registers_get_counter (&manager, CERBERUS_PROTOCOL_CERBERUS_RESET, 0));
	CuAssertIntEquals (test, 0,
		counter_manager_registers_get_counter (&manager, CERBERUS_PROTOCOL_COMPONENT_RESET, 0));
	CuAssertIntEquals (test, 0,
		counter_manager_registers_get_counter (&manager, CERBERUS_PROTOCOL_COMPONENT_RESET, 1));

	status = counter_manager_registers_increment (&manager, CERBERUS_PROTOCOL_CERBERUS_RESET, 0);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, 1,
		counter_manager_registers_get_counter (&manager, CERBERUS_PROTOCOL_CERBERUS_RESET, 0));
	CuAssertIntEquals (test, 0,
		counter_manager_registers_get_counter (&manager, CERBERUS_PROTOCOL_COMPONENT_RESET, 0));
	CuAssertIntEquals (test, 0,
		counter_manager_registers_get_counter (&manager, CERBERUS_PROTOCOL_COMPONENT_RESET, 1));

	counter_manager_registers_release (&manager);
}

static void counter_manager_registers_test_increment_overflow_port0 (CuTest *test)
{
	struct counter_manager_registers manager;
	uint32_t reg1;
	uint32_t reg2;
	int status;

	TEST_START;

	reg1 = 0xffff0000;
	reg2 = 0;

	status = counter_manager_registers_init (&manager, &reg1, &reg2);
	CuAssertIntEquals (test, 0, status);

	status = counter_manager_registers_increment (&manager, CERBERUS_PROTOCOL_COMPONENT_RESET, 0);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, 0,
		counter_manager_registers_get_counter (&manager, CERBERUS_PROTOCOL_CERBERUS_RESET, 0));
	CuAssertIntEquals (test, 0,
		counter_manager_registers_get_counter (&manager, CERBERUS_PROTOCOL_COMPONENT_RESET, 0));
	CuAssertIntEquals (test, 0,
		counter_manager_registers_get_counter (&manager, CERBERUS_PROTOCOL_COMPONENT_RESET, 1));

	status = counter_manager_registers_increment (&manager, CERBERUS_PROTOCOL_COMPONENT_RESET, 0);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, 0,
		counter_manager_registers_get_counter (&manager, CERBERUS_PROTOCOL_CERBERUS_RESET, 0));
	CuAssertIntEquals (test, 1,
		counter_manager_registers_get_counter (&manager, CERBERUS_PROTOCOL_COMPONENT_RESET, 0));
	CuAssertIntEquals (test, 0,
		counter_manager_registers_get_counter (&manager, CERBERUS_PROTOCOL_COMPONENT_RESET, 1));

	counter_manager_registers_release (&manager);
}

static void counter_manager_registers_test_increment_overflow_port1 (CuTest *test)
{
	struct counter_manager_registers manager;
	uint32_t reg1;
	uint32_t reg2;
	int status;

	TEST_START;

	reg1 = 0;
	reg2 = 0xffff;

	status = counter_manager_registers_init (&manager, &reg1, &reg2);
	CuAssertIntEquals (test, 0, status);

	status = counter_manager_registers_increment (&manager, CERBERUS_PROTOCOL_COMPONENT_RESET, 1);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, 0,
		counter_manager_registers_get_counter (&manager, CERBERUS_PROTOCOL_CERBERUS_RESET, 0));
	CuAssertIntEquals (test, 0,
		counter_manager_registers_get_counter (&manager, CERBERUS_PROTOCOL_COMPONENT_RESET, 0));
	CuAssertIntEquals (test, 0,
		counter_manager_registers_get_counter (&manager, CERBERUS_PROTOCOL_COMPONENT_RESET, 1));

	status = counter_manager_registers_increment (&manager, CERBERUS_PROTOCOL_COMPONENT_RESET, 1);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, 0,
		counter_manager_registers_get_counter (&manager, CERBERUS_PROTOCOL_CERBERUS_RESET, 0));
	CuAssertIntEquals (test, 0,
		counter_manager_registers_get_counter (&manager, CERBERUS_PROTOCOL_COMPONENT_RESET, 0));
	CuAssertIntEquals (test, 1,
		counter_manager_registers_get_counter (&manager, CERBERUS_PROTOCOL_COMPONENT_RESET, 1));

	counter_manager_registers_release (&manager);
}

static void counter_manager_registers_test_clear (CuTest *test)
{
	struct counter_manager_registers manager;
	uint32_t reg1;
	uint32_t reg2;
	int status;

	TEST_START;

	reg1 = 0x20001;
	reg2 = 0x3;

	status = counter_manager_registers_init (&manager, &reg1, &reg2);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, 1,
		counter_manager_registers_get_counter (&manager, CERBERUS_PROTOCOL_CERBERUS_RESET, 0));
	CuAssertIntEquals (test, 2,
		counter_manager_registers_get_counter (&manager, CERBERUS_PROTOCOL_COMPONENT_RESET, 0));
	CuAssertIntEquals (test, 3,
		counter_manager_registers_get_counter (&manager, CERBERUS_PROTOCOL_COMPONENT_RESET, 1));

	status = counter_manager_registers_clear (&manager, CERBERUS_PROTOCOL_CERBERUS_RESET, 0);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, 0,
		counter_manager_registers_get_counter (&manager, CERBERUS_PROTOCOL_CERBERUS_RESET, 0));
	CuAssertIntEquals (test, 2,
		counter_manager_registers_get_counter (&manager, CERBERUS_PROTOCOL_COMPONENT_RESET, 0));
	CuAssertIntEquals (test, 3,
		counter_manager_registers_get_counter (&manager, CERBERUS_PROTOCOL_COMPONENT_RESET, 1));

	status = counter_manager_registers_clear (&manager, CERBERUS_PROTOCOL_COMPONENT_RESET, 0);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, 0,
		counter_manager_registers_get_counter (&manager, CERBERUS_PROTOCOL_CERBERUS_RESET, 0));
	CuAssertIntEquals (test, 0,
		counter_manager_registers_get_counter (&manager, CERBERUS_PROTOCOL_COMPONENT_RESET, 0));
	CuAssertIntEquals (test, 3,
		counter_manager_registers_get_counter (&manager, CERBERUS_PROTOCOL_COMPONENT_RESET, 1));

	status = counter_manager_registers_clear (&manager, CERBERUS_PROTOCOL_COMPONENT_RESET, 1);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, 0,
		counter_manager_registers_get_counter (&manager, CERBERUS_PROTOCOL_CERBERUS_RESET, 0));
	CuAssertIntEquals (test, 0,
		counter_manager_registers_get_counter (&manager, CERBERUS_PROTOCOL_COMPONENT_RESET, 0));
	CuAssertIntEquals (test, 0,
		counter_manager_registers_get_counter (&manager, CERBERUS_PROTOCOL_COMPONENT_RESET, 1));

	counter_manager_registers_release (&manager);
}

static void counter_manager_registers_test_clear_multiple (CuTest *test)
{
	struct counter_manager_registers manager;
	uint32_t reg1;
	int status;

	TEST_START;

	reg1 = 0x20001;

	status = counter_manager_registers_init (&manager, &reg1, NULL);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, 1,
		counter_manager_registers_get_counter (&manager, CERBERUS_PROTOCOL_CERBERUS_RESET, 0));
	CuAssertIntEquals (test, 2,
		counter_manager_registers_get_counter (&manager, CERBERUS_PROTOCOL_COMPONENT_RESET, 0));

	status = counter_manager_registers_clear (&manager, CERBERUS_PROTOCOL_CERBERUS_RESET, 0);
	CuAssertIntEquals (test, 0, status);

	status = counter_manager_registers_clear (&manager, CERBERUS_PROTOCOL_CERBERUS_RESET, 0);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, 0,
		counter_manager_registers_get_counter (&manager, CERBERUS_PROTOCOL_CERBERUS_RESET, 0));
	CuAssertIntEquals (test, 2,
		counter_manager_registers_get_counter (&manager, CERBERUS_PROTOCOL_COMPONENT_RESET, 0));

	counter_manager_registers_release (&manager);
}

static void counter_manager_registers_test_clear_null (CuTest *test)
{
	struct counter_manager_registers manager;
	uint32_t reg1;
	uint32_t reg2;
	int status;

	TEST_START;

	status = counter_manager_registers_init (&manager, &reg1, &reg2);
	CuAssertIntEquals (test, 0, status);

	status = counter_manager_registers_clear (NULL, CERBERUS_PROTOCOL_CERBERUS_RESET, 0);
	CuAssertIntEquals (test, COUNTER_MANAGER_INVALID_ARGUMENT, status);

	counter_manager_registers_release (&manager);
}

static void counter_manager_registers_test_clear_unknown_type (CuTest *test)
{
	struct counter_manager_registers manager;
	uint32_t reg1;
	uint32_t reg2;
	int status;

	TEST_START;

	reg1 = 0x20001;
	reg2 = 0x3;

	status = counter_manager_registers_init (&manager, &reg1, &reg2);
	CuAssertIntEquals (test, 0, status);

	status = counter_manager_registers_clear (&manager, 2, 0);
	CuAssertIntEquals (test, COUNTER_MANAGER_UNKNOWN_COUNTER, status);

	CuAssertIntEquals (test, 1,
		counter_manager_registers_get_counter (&manager, CERBERUS_PROTOCOL_CERBERUS_RESET, 0));
	CuAssertIntEquals (test, 2,
		counter_manager_registers_get_counter (&manager, CERBERUS_PROTOCOL_COMPONENT_RESET, 0));
	CuAssertIntEquals (test, 3,
		counter_manager_registers_get_counter (&manager, CERBERUS_PROTOCOL_COMPONENT_RESET, 1));

	counter_manager_registers_release (&manager);
}

static void counter_manager_registers_test_clear_unknown_port (CuTest *test)
{
	struct counter_manager_registers manager;
	uint32_t reg1;
	uint32_t reg2;
	int status;

	TEST_START;

	reg1 = 0x20001;
	reg2 = 0x3;

	status = counter_manager_registers_init (&manager, &reg1, &reg2);
	CuAssertIntEquals (test, 0, status);

	status = counter_manager_registers_clear (&manager, CERBERUS_PROTOCOL_COMPONENT_RESET, 2);
	CuAssertIntEquals (test, COUNTER_MANAGER_UNKNOWN_COUNTER, status);

	CuAssertIntEquals (test, 1,
		counter_manager_registers_get_counter (&manager, CERBERUS_PROTOCOL_CERBERUS_RESET, 0));
	CuAssertIntEquals (test, 2,
		counter_manager_registers_get_counter (&manager, CERBERUS_PROTOCOL_COMPONENT_RESET, 0));
	CuAssertIntEquals (test, 3,
		counter_manager_registers_get_counter (&manager, CERBERUS_PROTOCOL_COMPONENT_RESET, 1));

	counter_manager_registers_release (&manager);
}

static void counter_manager_registers_test_clear_no_port1_counter (CuTest *test)
{
	struct counter_manager_registers manager;
	uint32_t reg1;
	int status;

	TEST_START;

	reg1 = 0x20001;

	status = counter_manager_registers_init (&manager, &reg1, NULL);
	CuAssertIntEquals (test, 0, status);

	status = counter_manager_registers_clear (&manager, CERBERUS_PROTOCOL_COMPONENT_RESET, 2);
	CuAssertIntEquals (test, COUNTER_MANAGER_UNKNOWN_COUNTER, status);

	CuAssertIntEquals (test, 1,
		counter_manager_registers_get_counter (&manager, CERBERUS_PROTOCOL_CERBERUS_RESET, 0));
	CuAssertIntEquals (test, 2,
		counter_manager_registers_get_counter (&manager, CERBERUS_PROTOCOL_COMPONENT_RESET, 0));

	counter_manager_registers_release (&manager);
}


TEST_SUITE_START (counter_manager_registers);

TEST (counter_manager_registers_test_init);
TEST (counter_manager_registers_test_init_null);
TEST (counter_manager_registers_test_release_null);
TEST (counter_manager_registers_test_get_counter);
TEST (counter_manager_registers_test_get_counter_null);
TEST (counter_manager_registers_test_get_counter_unknown_type);
TEST (counter_manager_registers_test_get_counter_unknown_port);
TEST (counter_manager_registers_test_get_counter_no_port1_counter);
TEST (counter_manager_registers_test_increment);
TEST (counter_manager_registers_test_increment_after_clear);
TEST (counter_manager_registers_test_increment_null);
TEST (counter_manager_registers_test_increment_multiple);
TEST (counter_manager_registers_test_increment_after_clear);
TEST (counter_manager_registers_test_increment_unknown_type);
TEST (counter_manager_registers_test_increment_unknown_port);
TEST (counter_manager_registers_test_increment_no_port1_counter);
TEST (counter_manager_registers_test_increment_overflow);
TEST (counter_manager_registers_test_increment_overflow_port0);
TEST (counter_manager_registers_test_increment_overflow_port1);
TEST (counter_manager_registers_test_clear);
TEST (counter_manager_registers_test_clear_multiple);
TEST (counter_manager_registers_test_clear_null);
TEST (counter_manager_registers_test_clear_unknown_type);
TEST (counter_manager_registers_test_clear_unknown_port);
TEST (counter_manager_registers_test_clear_no_port1_counter);

TEST_SUITE_END;
