// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <string.h>
#include <stdint.h>
#include "attestation_master_mock.h"


static int attestation_master_mock_generate_challenge_request (
	struct attestation_master *attestation, uint8_t eid, uint8_t slot_num, 
	struct attestation_challenge *challenge)
{
	struct attestation_master_mock *mock = (struct attestation_master_mock*) attestation;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, attestation_master_mock_generate_challenge_request, attestation,
		MOCK_ARG_CALL (eid), MOCK_ARG_CALL (slot_num), MOCK_ARG_CALL (challenge));
}

static int attestation_master_mock_compare_digests (struct attestation_master *attestation,
	uint8_t eid, struct attestation_chain_digest *digests)
{
	struct attestation_master_mock *mock = (struct attestation_master_mock*) attestation;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, attestation_master_mock_compare_digests, attestation,
		MOCK_ARG_CALL (eid), MOCK_ARG_CALL (digests));
}

static int attestation_master_mock_store_certificate (struct attestation_master *attestation,
	uint8_t eid, uint8_t slot_num, uint8_t cert_num, const uint8_t *buf, size_t buf_len)
{
	struct attestation_master_mock *mock = (struct attestation_master_mock*) attestation;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, attestation_master_mock_store_certificate, attestation,
		MOCK_ARG_CALL (eid), MOCK_ARG_CALL (slot_num), MOCK_ARG_CALL (cert_num),
		MOCK_ARG_CALL (buf), MOCK_ARG_CALL (buf_len));
}

static int attestation_master_mock_process_challenge_response (
	struct attestation_master *attestation, uint8_t *buf, size_t buf_len, uint8_t eid)
{
	struct attestation_master_mock *mock = (struct attestation_master_mock*) attestation;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, attestation_master_mock_process_challenge_response, attestation,
		MOCK_ARG_CALL (buf), MOCK_ARG_CALL (buf_len), MOCK_ARG_CALL (eid));
}

static int attestation_master_mock_func_arg_count (void *func)
{
	if (func == attestation_master_mock_compare_digests) {
		return 2;
	}
	else if ((func == attestation_master_mock_process_challenge_response) || 
		(func == attestation_master_mock_generate_challenge_request)) {
		return 3;
	}
	else if (func == attestation_master_mock_store_certificate) {
		return 5;
	}
	else {
		return 0;
	}
}

static const char* attestation_master_mock_func_name_map (void *func)
{
	if (func == attestation_master_mock_generate_challenge_request) {
		return "generate_challenge_request";
	}
	else if (func == attestation_master_mock_compare_digests) {
		return "compare_digests";
	}
	else if (func == attestation_master_mock_store_certificate) {
		return "store_certificate";
	}
	else if (func == attestation_master_mock_process_challenge_response) {
		return "process_challenge_process";
	}
	else {
		return "unknown";
	}
}

static const char* attestation_master_mock_arg_name_map (void *func, int arg)
{
	if (func == attestation_master_mock_generate_challenge_request) {
		switch (arg) {
			case 0:
				return "eid";

			case 1:
				return "slot_num";

			case 2:
				return "challenge";

			default:
				return "unknown";
		}
	}
	else if (func == attestation_master_mock_compare_digests) {
		switch (arg) {
			case 0:
				return "eid";

			case 1:
				return "digests";

			default:
				return "unknown";
		}
	}
	else if (func == attestation_master_mock_store_certificate) {
		switch (arg) {
			case 0:
				return "eid";

			case 1:
				return "slot_num";

			case 2:
				return "cert_num";

			case 3:
				return "buf";

			case 4:
				return "buf_len";

			default:
				return "unknown";
		}
	}
	else if (func == attestation_master_mock_process_challenge_response) {
		switch (arg) {
			case 0:
				return "buf";

			case 1:
				return "buf_len";

			case 2:
				return "eid";

			default:
				return "unknown";
		}
	}
	else {
		return "unknown";
	}
}

/**
 * Initialize mock interface instance
 *
 * @param mock Mock interface instance to initialize
 *
 * @return Initialization status, 0 if success or an error code.
 */
int attestation_master_mock_init (struct attestation_master_mock *mock)
{
	int status;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	memset (mock, 0, sizeof (struct attestation_master_mock));

	status = mock_init (&mock->mock);

	if (status != 0) {
		return status;
	}

	mock_set_name (&mock->mock, "attestation");

	mock->base.generate_challenge_request = attestation_master_mock_generate_challenge_request;
	mock->base.compare_digests = attestation_master_mock_compare_digests;
	mock->base.store_certificate = attestation_master_mock_store_certificate;
	mock->base.process_challenge_response = attestation_master_mock_process_challenge_response;

	mock->mock.func_arg_count = attestation_master_mock_func_arg_count;
	mock->mock.func_name_map = attestation_master_mock_func_name_map;
	mock->mock.arg_name_map = attestation_master_mock_arg_name_map;

	return 0;
}

/**
 * Release resources used by a master attestation manager mock instance
 *
 * @param mock Mock interface instance to release
 */
void attestation_master_mock_release (struct attestation_master_mock *mock)
{
	if (mock != NULL) {
		mock_release (&mock->mock);
	}
}

/**
 * Validate that all expectations were met then release the mock instance
 *
 * @param mock The master attestation manager mock interface to validate and release
 *
 * @return Validation status, 0 if expectations met or an error code.
 */
int attestation_master_mock_validate_and_release (struct attestation_master_mock *mock)
{
	int status = 1;

	if (mock != NULL) {
		status = mock_validate (&mock->mock);
		attestation_master_mock_release (mock);
	}

	return status;
}
