// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "acvp_proto_tester_adapter.h"
#include "platform_api.h"
#include "backend_interfaces/protobuf/backend_protobuf.h"
#include "common/unused.h"
#include "parser/common.h"
#include "proto/proto.h"


/**
 * The current implementation identifier for the ACVP backend.  This global variable allows the
 * backend to determine the algorithm implementation selected in the current ACVP test.
 */
uint32_t acvp_implementation = 0;


int acvp_proto_tester_adapter_check_input_length (const struct acvp_proto_tester *tester,
	size_t in_len)
{
	if (tester == NULL) {
		return ACVP_PROTO_TESTER_INVALID_ARGUMENT;
	}

	if (in_len <= PB_BUF_WRITE_HEADER_SZ) {
		return ACVP_PROTO_TESTER_LENGTH_TOO_SMALL;
	}

	if (in_len > (PB_BUF_WRITE_HEADER_SZ + ACVP_MAXDATA)) {
		return ACVP_PROTO_TESTER_LENGTH_TOO_LARGE;
	}

	return 0;
}

int acvp_proto_tester_adapter_proto_test_algo (const struct acvp_proto_tester *tester,
	const uint8_t *in, size_t in_len, uint8_t **out, size_t *out_length)
{
	const struct acvp_proto_tester_adapter *adapter =
		(const struct acvp_proto_tester_adapter*) tester;
	struct buffer in_buf;
	struct buffer out_buf = {NULL, 0};
	pb_header_t header;
	int status;

	if ((adapter == NULL) || (in == NULL) || (out == NULL) || (out_length == NULL)) {
		return ACVP_PROTO_TESTER_INVALID_ARGUMENT;
	}

	status = tester->check_input_length (tester, in_len);
	if (status != 0) {
		return status;
	}

	memcpy (&header, in, PB_BUF_WRITE_HEADER_SZ);

	acvp_implementation = header.implementation;

	in_buf.buf = (unsigned char*) &in[PB_BUF_WRITE_HEADER_SZ];
	in_buf.len = in_len - PB_BUF_WRITE_HEADER_SZ;

	status = proto_test_algo (&in_buf, &out_buf, &header);
	if (status != 0) {
		return ACVP_PROTO_TESTER_TEST_FAILED;
	}

	*out = out_buf.buf;
	*out_length = out_buf.len;

	return 0;
}

/**
 * Initialize the ACVP Proto tester adapter.
 *
 * @param tester_adapter The ACVP Proto tester adapter to initialize.
 *
 * @return 0 if the ACVP Proto tester adapter was initialized successfully or an error code.
 */
int acvp_proto_tester_adapter_init (struct acvp_proto_tester_adapter *tester_adapter)
{
	if (tester_adapter == NULL) {
		return ACVP_PROTO_TESTER_INVALID_ARGUMENT;
	}

	tester_adapter->base.check_input_length = acvp_proto_tester_adapter_check_input_length;
	tester_adapter->base.proto_test_algo = acvp_proto_tester_adapter_proto_test_algo;

	return 0;
}

/**
 * Release the resources used by the ACVP Proto tester adapter.
 *
 * @param tester_adapter The ACVP Proto tester adapter to release.
 */
void acvp_proto_tester_adapter_release (const struct acvp_proto_tester_adapter *tester_adapter)
{
	UNUSED (tester_adapter);
}
