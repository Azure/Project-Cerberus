// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <string.h>
#include "authorized_data_with_aad.h"
#include "common/buffer_util.h"
#include "common/unused.h"


#pragma pack(push, 1)
/**
 * Header that will be applied to every authorized data payload.
 */
struct authorized_data_with_aad_header {
	uint16_t token_length;	/**< Total length of the authorizing token. */
	uint16_t aad_length;	/**< Total length of the additional authenticated data. */
};

#pragma pack(pop)


/**
 * Get the header on the authorized data payload and check it for validity.
 *
 * @param data The authorized data payload.
 * @param length Length of the payload.
 * @param header Output for the payload header.
 *
 * @return 0 if the header is valid or an error code.
 */
static int authorized_data_with_aad_get_header (const uint8_t *data, size_t length,
	const struct authorized_data_with_aad_header **header)
{
	*header = (struct authorized_data_with_aad_header*) data;

	/* Check for enough bytes to have a header. */
	if (length < sizeof (**header)) {
		return AUTH_DATA_BAD;
	}

	/* Check for enough bytes based on the header contents. */
	if ((sizeof (**header) + buffer_unaligned_read16 (&(*header)->token_length) +
		buffer_unaligned_read16 (&(*header)->aad_length)) > length) {
		return AUTH_DATA_BAD;
	}

	return 0;
}

int authorized_data_with_aad_get_token_offset (const struct authorized_data *auth,
	const uint8_t *data, size_t length, size_t *token_offset)
{
	const struct authorized_data_with_aad_header *header;
	int status;

	if ((auth == NULL) || (data == NULL) || (token_offset == NULL)) {
		return AUTH_DATA_INVALID_ARGUMENT;
	}

	status = authorized_data_with_aad_get_header (data, length, &header);
	if (status != 0) {
		return status;
	}

	if (buffer_unaligned_read16 (&header->token_length) != 0) {
		*token_offset = sizeof (*header);
	}
	else {
		/* This payload does not contain an authorization token. */
		return AUTH_DATA_NO_AUTH_TOKEN;
	}

	return 0;
}

int authorized_data_with_aad_get_authenticated_data (const struct authorized_data *auth,
	const uint8_t *data, size_t length, const uint8_t **aad, size_t *aad_length)
{
	const struct authorized_data_with_aad_header *header;
	int status;

	if ((auth == NULL) || (data == NULL) || (aad == NULL) || (aad_length == NULL)) {
		return AUTH_DATA_INVALID_ARGUMENT;
	}

	status = authorized_data_with_aad_get_header (data, length, &header);
	if (status != 0) {
		return status;
	}

	if ((buffer_unaligned_read16 (&header->aad_length) != 0)) {
		*aad = &data[sizeof (*header) + buffer_unaligned_read16 (&header->token_length)];
		*aad_length = buffer_unaligned_read16 (&header->aad_length);
	}
	else {
		/* This payload does not contain any AAD. */
		*aad = NULL;
		*aad_length = 0;
	}

	return 0;
}

int authorized_data_with_aad_get_authenticated_data_length (const struct authorized_data *auth,
	const uint8_t *data, size_t length, size_t *aad_length)
{
	const struct authorized_data_with_aad_header *header;
	int status;

	if ((auth == NULL) || (data == NULL) || (aad_length == NULL)) {
		return AUTH_DATA_INVALID_ARGUMENT;
	}

	status = authorized_data_with_aad_get_header (data, length, &header);
	if (status != 0) {
		return status;
	}

	*aad_length = buffer_unaligned_read16 (&header->aad_length);

	return 0;
}

int authorized_data_with_aad_get_signature (const struct authorizing_signature *auth,
	const uint8_t *data, size_t length, const uint8_t **signature, size_t *sig_length)
{
	const struct authorized_data_with_aad_header *header;
	size_t offset;
	int status;

	if ((auth == NULL) || (data == NULL) || (signature == NULL) || (sig_length == NULL)) {
		return AUTH_SIGNATURE_INVALID_ARGUMENT;
	}

	status = authorized_data_with_aad_get_header (data, length, &header);
	if (status != 0) {
		return status;
	}

	offset = sizeof (*header) + buffer_unaligned_read16 (&header->token_length) +
		buffer_unaligned_read16 (&header->aad_length);
	if (length == offset) {
		return AUTH_SIGNATURE_NO_SIGNATURE;
	}

	*signature = &data[offset];
	*sig_length = length - offset;

	return 0;
}

int authorized_data_with_aad_get_signature_length (const struct authorizing_signature *auth,
	const uint8_t *data, size_t length, size_t *sig_length)
{
	const uint8_t *signature;

	return authorized_data_with_aad_get_signature (auth, data, length, &signature, sig_length);
}

/**
 * Initialize an authorized data parser for payloads that can contain either an authorization token,
 * authenticated data, or both.
 *
 * @param auth The authorized data parser to initialize.
 *
 * @return 0 if the parser was initialized successfully or an error code.
 */
int authorized_data_with_aad_init (struct authorized_data_with_aad *auth)
{
	if (auth == NULL) {
		return AUTH_DATA_INVALID_ARGUMENT;
	}

	memset (auth, 0, sizeof (*auth));

	auth->base_data.get_token_offset = authorized_data_with_aad_get_token_offset;
	auth->base_data.get_authenticated_data = authorized_data_with_aad_get_authenticated_data;
	auth->base_data.get_authenticated_data_length =
		authorized_data_with_aad_get_authenticated_data_length;

	auth->base_sig.get_signature = authorized_data_with_aad_get_signature;
	auth->base_sig.get_signature_length = authorized_data_with_aad_get_signature_length;

	return 0;
}

/**
 * Release the resources used for parsing authorized data.
 *
 * @param auth The authorized data parser to release.
 */
void authorized_data_with_aad_release (const struct authorized_data_with_aad *auth)
{
	UNUSED (auth);
}
