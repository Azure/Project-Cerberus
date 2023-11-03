// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "testing.h"
#include "cmd_interface/cmd_interface.h"


TEST_SUITE_LABEL ("cmd_interface");


/*******************
 * Test cases
 *******************/

static void cmd_interface_test_msg_new_message (CuTest *test)
{
	uint8_t data[16];
	struct cmd_interface_msg msg = {
		.data = data,
		.length = sizeof (data),
		.max_response = sizeof (data) - 2,
		.payload = &data[8],
		.payload_length = 4,
		.source_eid = 0x55,
		.source_addr = 0xaa,
		.target_eid = 0x66,
		.is_encrypted = true,
		.crypto_timeout = true,
		.channel_id = 100
	};

	TEST_START;

	cmd_interface_msg_new_message (&msg, 0x11, 0x22, 0x33, 50);
	CuAssertPtrEquals (test, data, msg.data);
	CuAssertIntEquals (test, 0, msg.length);
	CuAssertIntEquals (test, sizeof (data) - 2, msg.max_response);
	CuAssertPtrEquals (test, data, msg.payload);
	CuAssertIntEquals (test, 0, msg.payload_length);
	CuAssertIntEquals (test, 0x11, msg.source_eid);
	CuAssertIntEquals (test, 0x22, msg.source_addr);
	CuAssertIntEquals (test, 0x33, msg.target_eid);
	CuAssertIntEquals (test, false, msg.is_encrypted);
	CuAssertIntEquals (test, false, msg.crypto_timeout);
	CuAssertIntEquals (test, 50, msg.channel_id);
}

static void cmd_interface_test_msg_new_message_null (CuTest *test)
{
	TEST_START;

	cmd_interface_msg_new_message (NULL, 0x11, 0x22, 0x33, 50);
}

static void cmd_interface_test_msg_add_payload_data (CuTest *test)
{
	uint8_t data[16] = {0};
	struct cmd_interface_msg msg = {
		.data = data,
	};
	uint8_t new[5] = {1, 2, 3, 4, 5};
	int status;

	TEST_START;

	cmd_interface_msg_new_message (&msg, 0x11, 0x22, 0x33, 50);
	CuAssertIntEquals (test, 0, msg.length);
	CuAssertIntEquals (test, 0, msg.payload_length);

	cmd_interface_msg_add_payload_data (&msg, new, sizeof (new));
	CuAssertPtrEquals (test, data, msg.data);
	CuAssertIntEquals (test, sizeof (new), msg.length);
	CuAssertPtrEquals (test, data, msg.payload);
	CuAssertIntEquals (test, sizeof (new), msg.payload_length);

	status = testing_validate_array (new, data, sizeof (new));
	CuAssertIntEquals (test, 0, status);
}

static void cmd_interface_test_msg_add_payload_data_multiple (CuTest *test)
{
	uint8_t data[16] = {0};
	struct cmd_interface_msg msg = {
		.data = data,
	};
	uint8_t new1[5] = {1, 2, 3, 4, 5};
	uint8_t new2[2] = {6, 7};
	uint8_t new3[4] = {8, 9, 10, 11};
	uint8_t expected[11] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11};
	int status;

	TEST_START;

	cmd_interface_msg_new_message (&msg, 0x11, 0x22, 0x33, 50);
	CuAssertIntEquals (test, 0, msg.length);
	CuAssertIntEquals (test, 0, msg.payload_length);

	cmd_interface_msg_add_payload_data (&msg, new1, sizeof (new1));
	cmd_interface_msg_add_payload_data (&msg, new2, sizeof (new2));
	cmd_interface_msg_add_payload_data (&msg, new3, sizeof (new3));

	CuAssertPtrEquals (test, data, msg.data);
	CuAssertIntEquals (test, sizeof (expected), msg.length);
	CuAssertPtrEquals (test, data, msg.payload);
	CuAssertIntEquals (test, sizeof (expected), msg.payload_length);

	status = testing_validate_array (expected, data, sizeof (expected));
	CuAssertIntEquals (test, 0, status);
}

static void cmd_interface_test_msg_add_payload_data_null (CuTest *test)
{
	uint8_t data[16] = {0};
	struct cmd_interface_msg msg = {
		.data = data,
	};
	uint8_t new[5] = {1, 2, 3, 4, 5};
	int status;

	TEST_START;

	cmd_interface_msg_new_message (&msg, 0x11, 0x22, 0x33, 50);
	CuAssertIntEquals (test, 0, msg.length);
	CuAssertIntEquals (test, 0, msg.payload_length);

	cmd_interface_msg_add_payload_data (&msg, new, sizeof (new));

	cmd_interface_msg_add_payload_data (NULL, new, sizeof (new));
	cmd_interface_msg_add_payload_data (&msg, NULL, sizeof (new));
	cmd_interface_msg_add_payload_data (&msg, new, 0);

	CuAssertPtrEquals (test, data, msg.data);
	CuAssertIntEquals (test, sizeof (new), msg.length);
	CuAssertPtrEquals (test, data, msg.payload);
	CuAssertIntEquals (test, sizeof (new), msg.payload_length);

	status = testing_validate_array (new, data, sizeof (new));
	CuAssertIntEquals (test, 0, status);
}

static void cmd_interface_test_msg_set_message_payload_length (CuTest *test)
{
	uint8_t data[16] = {0};
	struct cmd_interface_msg msg = {
		.data = data,
	};

	TEST_START;

	cmd_interface_msg_new_message (&msg, 0x11, 0x22, 0x33, 50);
	CuAssertIntEquals (test, 0, msg.length);
	CuAssertIntEquals (test, 0, msg.payload_length);

	msg.payload = &data[10];

	cmd_interface_msg_set_message_payload_length (&msg, 4);
	CuAssertPtrEquals (test, data, msg.data);
	CuAssertIntEquals (test, 4, msg.length);
	CuAssertPtrEquals (test, &data[10], msg.payload);
	CuAssertIntEquals (test, 4, msg.payload_length);
}

static void cmd_interface_test_msg_set_message_payload_length_null (CuTest *test)
{
	uint8_t data[16] = {0};
	struct cmd_interface_msg msg = {
		.data = data,
	};

	TEST_START;

	cmd_interface_msg_new_message (&msg, 0x11, 0x22, 0x33, 50);
	CuAssertIntEquals (test, 0, msg.length);
	CuAssertIntEquals (test, 0, msg.payload_length);

	msg.payload = &data[10];

	cmd_interface_msg_set_message_payload_length (NULL, 4);
	CuAssertPtrEquals (test, data, msg.data);
	CuAssertIntEquals (test, 0, msg.length);
	CuAssertPtrEquals (test, &data[10], msg.payload);
	CuAssertIntEquals (test, 0, msg.payload_length);
}

static void cmd_interface_test_msg_remove_protocol_header (CuTest *test)
{
	uint8_t data[16];
	struct cmd_interface_msg msg = {
		.data = data,
	};
	uint8_t msg_data[16];

	TEST_START;

	cmd_interface_msg_new_message (&msg, 0x11, 0x22, 0x33, 50);
	cmd_interface_msg_add_payload_data (&msg, msg_data, sizeof (msg_data));
	msg.max_response = sizeof (data) - 2;

	cmd_interface_msg_remove_protocol_header (&msg, 3);
	CuAssertPtrEquals (test, &data[3], msg.payload);
	CuAssertIntEquals (test, sizeof (data) - 3, msg.payload_length);

	cmd_interface_msg_remove_protocol_header (&msg, 7);
	CuAssertPtrEquals (test, &data[10], msg.payload);
	CuAssertIntEquals (test, sizeof (data) - 10, msg.payload_length);

	cmd_interface_msg_remove_protocol_header (&msg, 0);
	CuAssertPtrEquals (test, &data[10], msg.payload);
	CuAssertIntEquals (test, sizeof (data) - 10, msg.payload_length);
}

static void cmd_interface_test_msg_remove_protocol_header_more_than_data (CuTest *test)
{
	uint8_t data[16];
	struct cmd_interface_msg msg = {
		.data = data,
	};
	uint8_t msg_data[10];

	TEST_START;

	cmd_interface_msg_new_message (&msg, 0x11, 0x22, 0x33, 50);
	cmd_interface_msg_add_payload_data (&msg, msg_data, sizeof (msg_data));
	msg.max_response = sizeof (data) - 2;

	cmd_interface_msg_remove_protocol_header (&msg, sizeof (msg_data) + 1);
	CuAssertPtrEquals (test, &data[10], msg.payload);
	CuAssertIntEquals (test, 0, msg.payload_length);
}

static void cmd_interface_test_msg_remove_protocol_header_more_than_payload (CuTest *test)
{
	uint8_t data[16];
	struct cmd_interface_msg msg = {
		.data = data,
	};
	uint8_t msg_data[10];

	TEST_START;

	cmd_interface_msg_new_message (&msg, 0x11, 0x22, 0x33, 50);
	cmd_interface_msg_add_payload_data (&msg, msg_data, sizeof (msg_data));
	msg.max_response = sizeof (data) - 2;

	cmd_interface_msg_remove_protocol_header (&msg, 3);
	CuAssertPtrEquals (test, &data[3], msg.payload);
	CuAssertIntEquals (test, sizeof (msg_data) - 3, msg.payload_length);

	cmd_interface_msg_remove_protocol_header (&msg, 9);
	CuAssertPtrEquals (test, &data[10], msg.payload);
	CuAssertIntEquals (test, 0, msg.payload_length);
}

static void cmd_interface_test_msg_remove_protocol_header_null (CuTest *test)
{
	uint8_t data[16];
	struct cmd_interface_msg msg = {
		.data = data,
	};
	uint8_t msg_data[16];

	TEST_START;

	cmd_interface_msg_new_message (&msg, 0x11, 0x22, 0x33, 50);
	cmd_interface_msg_add_payload_data (&msg, msg_data, sizeof (msg_data));
	msg.max_response = sizeof (data) - 2;

	cmd_interface_msg_remove_protocol_header (NULL, 3);
	CuAssertPtrEquals (test, data, msg.payload);
	CuAssertIntEquals (test, sizeof (data), msg.payload_length);
}

static void cmd_interface_test_msg_add_protocol_header (CuTest *test)
{
	uint8_t data[16];
	struct cmd_interface_msg msg = {
		.data = data,
	};

	TEST_START;

	cmd_interface_msg_new_message (&msg, 0x11, 0x22, 0x33, 50);
	msg.max_response = sizeof (data);
	msg.payload = &data[12];
	msg.payload_length = 4;
	msg.length = 4;

	cmd_interface_msg_add_protocol_header (&msg, 3);
	CuAssertPtrEquals (test, &data[9], msg.payload);
	CuAssertIntEquals (test, 7, msg.payload_length);
	CuAssertIntEquals (test, 7, msg.length);

	cmd_interface_msg_add_protocol_header (&msg, 7);
	CuAssertPtrEquals (test, &data[2], msg.payload);
	CuAssertIntEquals (test, 14, msg.payload_length);
	CuAssertIntEquals (test, 14, msg.length);

	cmd_interface_msg_add_protocol_header (&msg, 0);
	CuAssertPtrEquals (test, &data[2], msg.payload);
	CuAssertIntEquals (test, 14, msg.payload_length);
	CuAssertIntEquals (test, 14, msg.length);
}

static void cmd_interface_test_msg_add_protocol_header_more_than_buffer_space (CuTest *test)
{
	uint8_t data[16];
	struct cmd_interface_msg msg = {
		.data = data,
	};

	TEST_START;

	cmd_interface_msg_new_message (&msg, 0x11, 0x22, 0x33, 50);
	msg.max_response = sizeof (data) - 2;
	msg.payload = &data[12];
	msg.payload_length = 4;
	msg.length = 4;

	cmd_interface_msg_add_protocol_header (&msg, 13);
	CuAssertPtrEquals (test, data, msg.payload);
	CuAssertIntEquals (test, sizeof (data), msg.payload_length);
	CuAssertIntEquals (test, sizeof (data), msg.length);
}

static void cmd_interface_test_msg_add_protocol_header_null (CuTest *test)
{
	uint8_t data[16];
	struct cmd_interface_msg msg = {
		.data = data,
	};

	TEST_START;

	cmd_interface_msg_new_message (&msg, 0x11, 0x22, 0x33, 50);
	msg.max_response = sizeof (data) - 2;
	msg.payload = &data[12];
	msg.payload_length = 4;
	msg.length = 4;

	cmd_interface_msg_add_protocol_header (NULL, 13);
	CuAssertPtrEquals (test, &data[12], msg.payload);
	CuAssertIntEquals (test, 4, msg.payload_length);
	CuAssertIntEquals (test, 4, msg.length);
}

static void cmd_interface_test_msg_get_protocol_length (CuTest *test)
{
	uint8_t data[16];
	struct cmd_interface_msg msg = {
		.data = data,
		.length = sizeof (data)
	};
	size_t length;

	TEST_START;

	msg.payload = data;
	msg.payload_length = sizeof (data);

	length = cmd_interface_msg_get_protocol_length (&msg);
	CuAssertIntEquals (test, 0, length);

	msg.payload += 5;
	msg.payload_length -= 5;

	length = cmd_interface_msg_get_protocol_length (&msg);
	CuAssertIntEquals (test, 5, length);

	msg.payload += 3;
	msg.payload_length -= 3;

	length = cmd_interface_msg_get_protocol_length (&msg);
	CuAssertIntEquals (test, 8, length);
}

static void cmd_interface_test_msg_get_protocol_length_null (CuTest *test)
{
	size_t length;

	TEST_START;

	length = cmd_interface_msg_get_protocol_length (NULL);
	CuAssertIntEquals (test, 0, length);
}

static void cmd_interface_test_msg_get_protocol_length_payload_null (CuTest *test)
{
	uint8_t data[16];
	struct cmd_interface_msg msg = {
		.data = data,
		.length = sizeof (data)
	};
	size_t length;

	TEST_START;

	msg.payload = NULL;
	msg.payload_length = 0;

	length = cmd_interface_msg_get_protocol_length (&msg);
	CuAssertIntEquals (test, 0, length);
}

static void cmd_interface_test_msg_get_protocol_length_payload_before_data (CuTest *test)
{
	uint8_t data[16];
	struct cmd_interface_msg msg = {
		.data = &data[8],
		.length = sizeof (data) - 8
	};
	size_t length;

	TEST_START;

	msg.payload = data;
	msg.payload_length = sizeof (data);

	length = cmd_interface_msg_get_protocol_length (&msg);
	CuAssertIntEquals (test, 0, length);
}

static void cmd_interface_test_msg_get_protocol_length_payload_after_data (CuTest *test)
{
	uint8_t data[16];
	struct cmd_interface_msg msg = {
		.data = data,
		.length = sizeof (data) - 8
	};
	size_t length;

	TEST_START;

	msg.payload = &data[8];
	msg.payload_length = sizeof (data) - 8;

	length = cmd_interface_msg_get_protocol_length (&msg);
	CuAssertIntEquals (test, 0, length);
}

static void cmd_interface_test_msg_get_max_response (CuTest *test)
{
	uint8_t data[16];
	struct cmd_interface_msg msg = {
		.data = data,
		.length = sizeof (data),
		.max_response = sizeof (data) - 2
	};
	size_t expected = sizeof (data) - 2;
	size_t length;

	TEST_START;

	msg.payload = data;
	msg.payload_length = sizeof (data);

	length = cmd_interface_msg_get_max_response (&msg);
	CuAssertIntEquals (test, expected, length);

	msg.payload += 5;
	msg.payload_length -= 5;
	expected -= 5;

	length = cmd_interface_msg_get_max_response (&msg);
	CuAssertIntEquals (test, expected, length);

	msg.payload += 3;
	msg.payload_length -= 3;
	expected -= 3;

	length = cmd_interface_msg_get_max_response (&msg);
	CuAssertIntEquals (test, expected, length);
}

static void cmd_interface_test_msg_get_max_response_null (CuTest *test)
{
	size_t length;

	TEST_START;

	length = cmd_interface_msg_get_max_response (NULL);
	CuAssertIntEquals (test, 0, length);
}


TEST_SUITE_START (cmd_interface);

TEST (cmd_interface_test_msg_new_message);
TEST (cmd_interface_test_msg_new_message_null);
TEST (cmd_interface_test_msg_add_payload_data);
TEST (cmd_interface_test_msg_add_payload_data_multiple);
TEST (cmd_interface_test_msg_add_payload_data_null);
TEST (cmd_interface_test_msg_set_message_payload_length);
TEST (cmd_interface_test_msg_set_message_payload_length_null);
TEST (cmd_interface_test_msg_remove_protocol_header);
TEST (cmd_interface_test_msg_remove_protocol_header_more_than_data);
TEST (cmd_interface_test_msg_remove_protocol_header_more_than_payload);
TEST (cmd_interface_test_msg_remove_protocol_header_null);
TEST (cmd_interface_test_msg_add_protocol_header);
TEST (cmd_interface_test_msg_add_protocol_header_more_than_buffer_space);
TEST (cmd_interface_test_msg_add_protocol_header_null);
TEST (cmd_interface_test_msg_get_protocol_length);
TEST (cmd_interface_test_msg_get_protocol_length_null);
TEST (cmd_interface_test_msg_get_protocol_length_payload_null);
TEST (cmd_interface_test_msg_get_protocol_length_payload_before_data);
TEST (cmd_interface_test_msg_get_protocol_length_payload_after_data);
TEST (cmd_interface_test_msg_get_max_response);
TEST (cmd_interface_test_msg_get_max_response_null);

TEST_SUITE_END;
