// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <string.h>
#include "authorized_data_token_only.h"
#include "common/unused.h"


int authorized_data_token_only_get_token_offset (const struct authorized_data *auth,
	const uint8_t *data, size_t length, size_t *token_offset)
{
	if ((auth == NULL) || (data == NULL) || (token_offset == NULL)) {
		return AUTH_DATA_INVALID_ARGUMENT;
	}

	if (length == 0) {
		return AUTH_DATA_NO_AUTH_TOKEN;
	}

	/* The token is always at the beginning of the payload. */
	*token_offset = 0;

	return 0;
}

int authorized_data_token_only_get_authenticated_data (const struct authorized_data *auth,
	const uint8_t *data, size_t length, const uint8_t **aad, size_t *aad_length)
{
	if ((auth == NULL) || (data == NULL) || (length == 0) || (aad == NULL) ||
		(aad_length == NULL)) {
		return AUTH_DATA_INVALID_ARGUMENT;
	}

	/* The authorized data never contains any AAD. */
	*aad = NULL;
	*aad_length = 0;

	return 0;
}

int authorized_data_token_only_get_authenticated_data_length (const struct authorized_data *auth,
	const uint8_t *data, size_t length, size_t *aad_length)
{
	if ((auth == NULL) || (data == NULL) || (length == 0) || (aad_length == NULL)) {
		return AUTH_DATA_INVALID_ARGUMENT;
	}

	*aad_length = 0;

	return 0;
}

/**
 * Initialize an authorized data parser for payloads that only contain a signed authorization token.
 *
 * @param auth The authorized data parser to initialize.
 *
 * @return 0 if the parser was initialized successfully or an error code.
 */
int authorized_data_token_only_init (struct authorized_data_token_only *auth)
{
	if (auth == NULL) {
		return AUTH_DATA_INVALID_ARGUMENT;
	}

	memset (auth, 0, sizeof (*auth));

	auth->base.get_token_offset = authorized_data_token_only_get_token_offset;
	auth->base.get_authenticated_data = authorized_data_token_only_get_authenticated_data;
	auth->base.get_authenticated_data_length =
		authorized_data_token_only_get_authenticated_data_length;

	return 0;
}

/**
 * Release the resources used for parsing token-only authorized data.
 *
 * @param auth The authorized data parser to release.
 */
void authorized_data_token_only_release (const struct authorized_data_token_only *auth)
{
	UNUSED (auth);
}
