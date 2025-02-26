// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef ACVP_PROTO_TESTER_ADAPTER_STATIC_H_
#define ACVP_PROTO_TESTER_ADAPTER_STATIC_H_

#include "acvp_proto_tester_adapter.h"


/* Internal functions declared to allow for static initialization. */
int acvp_proto_tester_adapter_check_input_length (const struct acvp_proto_tester *tester,
	size_t in_len);
int acvp_proto_tester_adapter_proto_test_algo (const struct acvp_proto_tester *tester,
	const uint8_t *in, size_t in_len, uint8_t **out, size_t *out_length);


/**
 * Constant initializer for the ACVP Proto tester adapter.
 */
#define	ACVP_PROTO_TESTER_ADAPTER_API_INIT { \
		.check_input_length = acvp_proto_tester_adapter_check_input_length, \
		.proto_test_algo = acvp_proto_tester_adapter_proto_test_algo, \
	}


/**
 * Initialize a static protocol handler for the ACVP Proto tester adapter.
 */
#define	acvp_proto_tester_adapter_static_init { \
		.base = ACVP_PROTO_TESTER_ADAPTER_API_INIT, \
	}


#endif	/* ACVP_PROTO_TESTER_ADAPTER_STATIC_H_ */
