// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "platform_api.h"
#include "testing.h"
#include "spdm/spdm_certificate_chain.h"


TEST_SUITE_LABEL ("spdm_certificate_chain");


/*******************
 * Test cases
 *******************/

static void spdm_certificate_chain_test_certificate_chain_header_format (CuTest *test)
{
	uint8_t raw_buffer[] = {
		0x01, 0x02, 0x03, 0x04,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
		0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
		0x20, 0x12, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
		0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
		0x30, 0x13, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
		0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
		0x40, 0x14, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
		0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f
	};
	struct spdm_certificate_chain_header *header;

	TEST_START;

	CuAssertIntEquals (test, sizeof (raw_buffer), sizeof (struct spdm_certificate_chain_header));

	header = (struct spdm_certificate_chain_header*) raw_buffer;
	CuAssertIntEquals (test, 0x0201, header->min_hdr.length);
	CuAssertIntEquals (test, 0x0403, header->min_hdr.reserved);
	CuAssertPtrEquals (test, &raw_buffer[4], header->root_hash);
}


// *INDENT-OFF*
TEST_SUITE_START (spdm_certificate_chain);

TEST (spdm_certificate_chain_test_certificate_chain_header_format);

TEST_SUITE_END;
// *INDENT-ON*
