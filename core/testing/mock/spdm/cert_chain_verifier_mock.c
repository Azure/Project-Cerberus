// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "cert_chain_verifier_mock.h"


static int cert_chain_verifier_mock_start_verification (const struct cert_chain_verifier *verifier)
{
	struct cert_chain_verifier_mock *mock = (struct cert_chain_verifier_mock*) verifier;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN_NO_ARGS (&mock->mock, cert_chain_verifier_mock_start_verification, verifier);
}

static int cert_chain_verifier_mock_process_cert (const struct cert_chain_verifier *verifier,
	const uint8_t *cert, size_t length)
{
	struct cert_chain_verifier_mock *mock = (struct cert_chain_verifier_mock*) verifier;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, cert_chain_verifier_mock_process_cert, verifier,
		MOCK_ARG_PTR_CALL (cert), MOCK_ARG_CALL (length));
}

static int cert_chain_verifier_mock_finalize_verification (
	const struct cert_chain_verifier *verifier, struct cert_chain_verifier_result *result)
{
	struct cert_chain_verifier_mock *mock = (struct cert_chain_verifier_mock*) verifier;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, cert_chain_verifier_mock_finalize_verification, verifier,
		MOCK_ARG_PTR_CALL (result));
}

// *INDENT-OFF*
MOCK_FUNCTION_TABLE_BEGIN (cert_chain_verifier, 2)
	MOCK_FUNCTION (
		cert_chain_verifier,
		start_verification,
		0,
		MOCK_FUNCTION_ARGS ())
	MOCK_FUNCTION (
		cert_chain_verifier,
		process_cert,
		2,
		MOCK_FUNCTION_ARGS ("cert", "length"))
	MOCK_FUNCTION (
		cert_chain_verifier,
		finalize_verification,
		1,
		MOCK_FUNCTION_ARGS ("result"))
MOCK_FUNCTION_TABLE_END (cert_chain_verifier)
// *INDENT-ON*

/**
 * Initialize a mock for a certificate chain verifier.
 *
 * @param mock The mock to initialize.
 *
 * @return 0 if the mock was initialized successfully or an error code.
 */
int cert_chain_verifier_mock_init (struct cert_chain_verifier_mock *mock)
{
	int status;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	memset (mock, 0, sizeof (struct cert_chain_verifier_mock));

	status = mock_init (&mock->mock);
	if (status != 0) {
		return status;
	}

	mock_set_name (&mock->mock, "cert_chain_verifier");

	mock->base.start_verification = cert_chain_verifier_mock_start_verification;
	mock->base.process_cert = cert_chain_verifier_mock_process_cert;
	mock->base.finalize_verification = cert_chain_verifier_mock_finalize_verification;

	MOCK_INTERFACE_INIT (mock->mock, cert_chain_verifier);

	return 0;
}

/**
 * Release a mock certificate chain verifier.
 *
 * @param mock The mock to release.
 */
void cert_chain_verifier_mock_release (struct cert_chain_verifier_mock *mock)
{
	if (mock != NULL) {
		mock_release (&mock->mock);
	}
}

/**
 * Verify the mock was called as expected and release the instance.
 *
 * @param mock The mock to validate.
 *
 * @return 0 if all expectations were met or 1 if not.
 */
int cert_chain_verifier_mock_validate_and_release (struct cert_chain_verifier_mock *mock)
{
	int status = 1;

	if (mock != NULL) {
		status = mock_validate (&mock->mock);
		cert_chain_verifier_mock_release (mock);
	}

	return status;
}
