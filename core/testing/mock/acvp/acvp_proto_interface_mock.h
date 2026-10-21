// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef ACVP_PROTO_INTERFACE_MOCK_H_
#define ACVP_PROTO_INTERFACE_MOCK_H_

#include <stddef.h>
#include <stdint.h>
#include "mock.h"
#include "acvp/acvp_proto_interface.h"


/**
 * Mock for an ACVP Proto interface.
 */
struct acvp_proto_interface_mock {
	struct acvp_proto_interface base;	/**< Base ACVP Proto API. */
	struct mock mock;					/**< Mock interface. */
};


int acvp_proto_interface_mock_init (struct acvp_proto_interface_mock *mock);
void acvp_proto_interface_mock_release (struct acvp_proto_interface_mock *mock);

int acvp_proto_interface_mock_validate_and_release (struct acvp_proto_interface_mock *mock);


#endif	/* ACVP_PROTO_INTERFACE_MOCK_H_ */
