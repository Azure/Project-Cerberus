// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "spdm_certificate_chain_mock.h"


static int spdm_certificate_chain_mock_get_digest (const struct spdm_certificate_chain *chain,
	const struct hash_engine *hash, enum hash_type hash_type, uint8_t *digest, size_t length)
{
	struct spdm_certificate_chain_mock *mock = (struct spdm_certificate_chain_mock*) chain;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, spdm_certificate_chain_mock_get_digest, chain,
		MOCK_ARG_PTR_CALL (hash), MOCK_ARG_CALL (hash_type), MOCK_ARG_PTR_CALL (digest),
		MOCK_ARG_CALL (length));
}

static int spdm_certificate_chain_mock_get_certificate_chain (
	const struct spdm_certificate_chain *chain, const struct hash_engine *hash,
	enum hash_type root_ca_hash, size_t offset, uint8_t *buffer, size_t *length,
	size_t *total_length)
{
	struct spdm_certificate_chain_mock *mock = (struct spdm_certificate_chain_mock*) chain;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, spdm_certificate_chain_mock_get_certificate_chain, chain,
		MOCK_ARG_PTR_CALL (hash), MOCK_ARG_CALL (root_ca_hash), MOCK_ARG_CALL (offset),
		MOCK_ARG_PTR_CALL (buffer), MOCK_ARG_PTR_CALL (length), MOCK_ARG_PTR_CALL (total_length));
}

static int spdm_certificate_chain_mock_sign_message (const struct spdm_certificate_chain *chain,
	const struct ecc_engine *ecc, const struct hash_engine *hash, enum hash_type hash_algo,
	const uint8_t *message, size_t msg_length, uint8_t *signature, size_t sig_length)
{
	struct spdm_certificate_chain_mock *mock = (struct spdm_certificate_chain_mock*) chain;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, spdm_certificate_chain_mock_sign_message, chain,
		MOCK_ARG_PTR_CALL (ecc), MOCK_ARG_PTR_CALL (hash), MOCK_ARG_CALL (hash_algo),
		MOCK_ARG_PTR_CALL (message), MOCK_ARG_CALL (msg_length), MOCK_ARG_PTR_CALL (signature),
		MOCK_ARG_CALL (sig_length));
}

// *INDENT-OFF*
MOCK_FUNCTION_TABLE_BEGIN (spdm_certificate_chain, 7)
	MOCK_FUNCTION (
		spdm_certificate_chain,
		get_digest,
		4,
		MOCK_FUNCTION_ARGS ("hash", "hash_type", "digest", "length"))
	MOCK_FUNCTION (
		spdm_certificate_chain,
		get_certificate_chain,
		6,
		MOCK_FUNCTION_ARGS ("hash", "root_ca_hash", "offset", "buffer", "length", "total_length"))
	MOCK_FUNCTION (
		spdm_certificate_chain,
		sign_message,
		7,
		MOCK_FUNCTION_ARGS ("ecc", "hash", "hash_algo", "message", "msg_length", "signature",
			"sig_length"))
MOCK_FUNCTION_TABLE_END (spdm_certificate_chain)
// *INDENT-ON*

/**
 * Initialize a mock for a SPDM certificate chain.
 *
 * @param mock The mock to initialize.
 *
 * @return 0 if the mock was successfully initialized or an error code.
 */
int spdm_certificate_chain_mock_init (struct spdm_certificate_chain_mock *mock)
{
	int status;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	memset (mock, 0, sizeof (struct spdm_certificate_chain_mock));

	status = mock_init (&mock->mock);
	if (status != 0) {
		return status;
	}

	mock_set_name (&mock->mock, "spdm_certificate_chain");

	mock->base.get_digest = spdm_certificate_chain_mock_get_digest;
	mock->base.get_certificate_chain = spdm_certificate_chain_mock_get_certificate_chain;
	mock->base.sign_message = spdm_certificate_chain_mock_sign_message;

	MOCK_INTERFACE_INIT (mock->mock, spdm_certificate_chain);

	return 0;
}

/**
 * Release a mock SPDM certificate chain.
 *
 * @param mock The mock to release.
 */
void spdm_certificate_chain_mock_release (struct spdm_certificate_chain_mock *mock)
{
	if (mock) {
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
int spdm_certificate_chain_mock_validate_and_release (struct spdm_certificate_chain_mock *mock)
{
	int status = 1;

	if (mock != NULL) {
		status = mock_validate (&mock->mock);
		spdm_certificate_chain_mock_release (mock);
	}

	return status;
}
