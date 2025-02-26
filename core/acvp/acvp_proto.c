// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <string.h>
#include "platform_api.h"
#include "acvp/acvp_proto.h"
#include "common/buffer_util.h"
#include "common/common_math.h"


int acvp_proto_init_test (const struct acvp_proto_interface *intf, size_t total_size)
{
	struct acvp_proto *acvp = (struct acvp_proto*) intf;
	int status;

	if (acvp == NULL) {
		return ACVP_PROTO_INVALID_ARGUMENT;
	}

	if (acvp->state->buffer != NULL) {
		platform_free (acvp->state->buffer);
		acvp->state->buffer = NULL;
	}

	status = acvp->tester->check_input_length (acvp->tester, total_size);
	if (status != 0) {
		return status;
	}

	acvp->state->buffer = (uint8_t*) platform_calloc (total_size, sizeof (uint8_t));
	if (acvp->state->buffer == NULL) {
		return ACVP_PROTO_NO_MEMORY;
	}

	acvp->state->buffer_length = total_size;

	return 0;
}

int acvp_proto_add_test_data (const struct acvp_proto_interface *intf, size_t offset,
	const uint8_t *data, size_t length)
{
	struct acvp_proto *acvp = (struct acvp_proto*) intf;

	if ((acvp == NULL) || (data == NULL)) {
		return ACVP_PROTO_INVALID_ARGUMENT;
	}

	if (acvp->state->buffer == NULL) {
		return ACVP_PROTO_INVALID_STATE;
	}

	if ((offset > acvp->state->buffer_length) || (length > (acvp->state->buffer_length - offset))) {
		return ACVP_PROTO_ADD_TEST_DATA_OFFSET_OUT_OF_RANGE;
	}

	memcpy (&acvp->state->buffer[offset], data, length);

	return 0;
}

int acvp_proto_execute_test (const struct acvp_proto_interface *intf, size_t *out_length)
{
	struct acvp_proto *acvp = (struct acvp_proto*) intf;
	uint8_t *test_out = NULL;
	size_t test_out_len;
	int status;

	if ((acvp == NULL) || (out_length == NULL)) {
		return ACVP_PROTO_INVALID_ARGUMENT;
	}

	if (acvp->state->buffer == NULL) {
		return ACVP_PROTO_INVALID_STATE;
	}

	status = acvp->tester->proto_test_algo (acvp->tester, acvp->state->buffer,
		acvp->state->buffer_length,	&test_out, &test_out_len);
	if (status != 0) {
		return status;
	}

	// Update the state buffer to store the test output
	platform_free (acvp->state->buffer);

	acvp->state->buffer = test_out;
	acvp->state->buffer_length = test_out_len;
	*out_length = test_out_len;

	return 0;
}

int acvp_proto_get_test_results (const struct acvp_proto_interface *intf, size_t offset,
	uint8_t *results, size_t length, size_t *out_length)
{
	struct acvp_proto *acvp = (struct acvp_proto*) intf;

	if ((acvp == NULL) || (results == NULL) || (out_length == NULL)) {
		return ACVP_PROTO_INVALID_ARGUMENT;
	}

	if (acvp->state->buffer == NULL) {
		return ACVP_PROTO_INVALID_STATE;
	}

	*out_length = buffer_copy (acvp->state->buffer, acvp->state->buffer_length, &offset, &length,
		results);

	return 0;
}

/**
 * Initialize the ACVP Proto interface.
 *
 * @param acvp ACVP Proto interface instance.
 * @param state Variable context for the implementation.
 * @param tester Interface to ACVP Proto tester executor.
 *
 * @return 0 if the interface was initialized successfully or an error code.
 */
int acvp_proto_init (struct acvp_proto *acvp, struct acvp_proto_state *state,
	const struct acvp_proto_tester *tester)
{
	if ((acvp == NULL) || (state == NULL) || (tester == NULL)) {
		return ACVP_PROTO_INVALID_ARGUMENT;
	}

	memset (acvp, 0, sizeof (struct acvp_proto));

	acvp->base.init_test = acvp_proto_init_test;
	acvp->base.add_test_data = acvp_proto_add_test_data;
	acvp->base.execute_test = acvp_proto_execute_test;
	acvp->base.get_test_results = acvp_proto_get_test_results;

	acvp->tester = tester;

	acvp->state = state;

	return acvp_proto_init_state (acvp);
}

/**
 * Initialize the ACVP Proto interface state.
 *
 * @param acvp ACVP Proto interface instance.
 *
 * @return 0 if the state was initialized successfully or an error code.
 */
int acvp_proto_init_state (const struct acvp_proto *acvp)
{
	if ((acvp == NULL) || (acvp->state == NULL) || (acvp->tester == NULL)) {
		return ACVP_PROTO_INVALID_ARGUMENT;
	}

	memset (acvp->state, 0, sizeof (struct acvp_proto_state));

	return 0;
}

/**
 * Release the resources used by the ACVP Proto interface.
 *
 * @param acvp ACVP Proto interface instance.
 */
void acvp_proto_release (const struct acvp_proto *acvp)
{
	if ((acvp == NULL) || (acvp->state == NULL)) {
		return;
	}

	if (acvp->state->buffer != NULL) {
		platform_free (acvp->state->buffer);
		acvp->state->buffer = NULL;
	}
}
