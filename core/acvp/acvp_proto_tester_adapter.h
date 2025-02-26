// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef ACVP_PROTO_TESTER_ADAPTER_H_
#define ACVP_PROTO_TESTER_ADAPTER_H_

#include "acvp/acvp_proto_tester.h"


/**
 * ACVP Proto tester adapter implementation.
 */
struct acvp_proto_tester_adapter {
	struct acvp_proto_tester base;	/**< Base API implementation. */
};


int acvp_proto_tester_adapter_init (struct acvp_proto_tester_adapter *tester_adapter);
void acvp_proto_tester_adapter_release (const struct acvp_proto_tester_adapter *tester_adapter);


#endif	/* ACVP_PROTO_TESTER_ADAPTER_H_ */
