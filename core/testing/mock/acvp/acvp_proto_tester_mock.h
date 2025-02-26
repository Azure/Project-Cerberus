// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef ACVP_PROTO_TESTER_MOCK_H_
#define ACVP_PROTO_TESTER_MOCK_H_

#include <stddef.h>
#include <stdint.h>
#include "mock.h"
#include "acvp/acvp_proto_tester.h"


/**
 * Mock for an ACVP Proto tester interface.
 */
struct acvp_proto_tester_mock {
	struct acvp_proto_tester base;	/**< Base ACVP Proto tester API. */
	struct mock mock;				/**< Mock interface. */
};


int acvp_proto_tester_mock_init (struct acvp_proto_tester_mock *mock);
void acvp_proto_tester_mock_release (struct acvp_proto_tester_mock *mock);

int acvp_proto_tester_mock_validate_and_release (struct acvp_proto_tester_mock *mock);


#endif	/* ACVP_PROTO_TESTER_MOCK_H_ */
