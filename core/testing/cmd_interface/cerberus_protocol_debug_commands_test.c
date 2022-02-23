// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include "testing.h"
#include "cmd_interface/cerberus_protocol.h"
#include "cmd_interface/cerberus_protocol_debug_commands.h"
#include "testing/mock/crypto/ecc_mock.h"
#include "testing/mock/crypto/rsa_mock.h"
#include "testing/mock/crypto/rng_mock.h"
#include "testing/mock/crypto/x509_mock.h"
#include "testing/cmd_interface/cerberus_protocol_debug_commands_testing.h"
#include "testing/crypto/x509_testing.h"


// TEST_SUITE_LABEL ("cerberus_protocol_debug_commands");


void cerberus_protocol_debug_commands_testing_process_debug_fill_log (CuTest *test,
	struct cmd_interface *cmd, struct cmd_background_mock *background)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_header header = {0};
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header.command = CERBERUS_PROTOCOL_DEBUG_FILL_LOG;

	memcpy (request.data, &header, sizeof (header));
	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	status = mock_expect (&background->mock, background->base.debug_log_fill, background, 0);
	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0, request.length);
	CuAssertIntEquals (test, false, request.crypto_timeout);
}


/*******************
 * Test cases
 *******************/


TEST_SUITE_START (cerberus_protocol_debug_commands);

TEST_SUITE_END;
