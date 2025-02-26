// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef ACVP_PROTO_H_
#define ACVP_PROTO_H_

#include "acvp_proto_interface.h"
#include "acvp_proto_tester.h"


/**
 * Variable context for the ACVP Proto implementation.
 */
struct acvp_proto_state {
	uint8_t *buffer;		/**< Buffer for ACVP test data and test results. */
	size_t buffer_length;	/**< Length of buffer. */
};

/**
 * ACVP Proto interface implementation.
 */
struct acvp_proto {
	struct acvp_proto_interface base;		/**< Base API implementation. */
	struct acvp_proto_state *state;			/**< Variable context for the implementation. */
	const struct acvp_proto_tester *tester;	/**< Interface to ACVP Proto tester library. */
};


int acvp_proto_init (struct acvp_proto *acvp, struct acvp_proto_state *state,
	const struct acvp_proto_tester *tester);
int acvp_proto_init_state (const struct acvp_proto *acvp);
void acvp_proto_release (const struct acvp_proto *acvp);


#endif	/* ACVP_PROTO_H_ */
