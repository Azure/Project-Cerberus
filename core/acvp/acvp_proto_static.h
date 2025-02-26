// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef ACVP_PROTO_STATIC_H_
#define ACVP_PROTO_STATIC_H_

#include "acvp/acvp_proto.h"


/* Internal functions declared to allow for static initialization. */
int acvp_proto_init_test (const struct acvp_proto_interface *intf, size_t total_size);
int acvp_proto_add_test_data (const struct acvp_proto_interface *intf, size_t offset,
	const uint8_t *data, size_t length);
int acvp_proto_execute_test (const struct acvp_proto_interface *intf, size_t *out_length);
int acvp_proto_get_test_results (const struct acvp_proto_interface *intf, size_t offset,
	uint8_t *results, size_t length, size_t *out_length);


/**
 * Constant initializer for the ACVP Proto API.
 */
#define	ACVP_PROTO_API_INIT  { \
		.init_test = acvp_proto_init_test, \
		.add_test_data = acvp_proto_add_test_data, \
		.execute_test = acvp_proto_execute_test, \
		.get_test_results = acvp_proto_get_test_results \
	}


/**
 * Initialize a static ACVP Proto instance.
 *
 * There is no validation done on the arguments.
 *
 * @param state_ptr Variable context for the ACVP Proto implementation.
 * @param tester_ptr Interface to ACVP Proto tester library.
 */
#define	acvp_proto_static_init(state_ptr, tester_ptr)	{ \
		.base = ACVP_PROTO_API_INIT, \
		.state = state_ptr, \
		.tester = tester_ptr, \
	}


#endif	/* ACVP_PROTO_STATIC_H_ */
