// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "device_unlock_token.h"
#include "platform_api.h"
#include "asn1/asn1_util.h"
#include "common/buffer_util.h"
#include "common/unused.h"


/**
 * Authorized data structure:
 * - uint16_t:      token length
 * - <var>:         token data
 *   - <var>:       OID
 *   - uint16_t:    format version
 *   - uint8_t[16]: UUID
 *   - uint8_t:     counter length
 *   - <var>:       counter
 *   - uint8_t[32]: nonce
 *   - <var>:       token signature
 * - uint16_t:      policy length
 * - <var>:         policy data
 * - <var>:         data signature
 *
 * This provides pointers to the fields in this variable length structure.
 */
struct device_unlock_token_auth_data {
	const uint16_t *token_length;	/**< The unlock token data length. */
	const uint8_t *token_data;		/**< The unlock token data. */
	const uint8_t *oid;				/**< The device type OID in the unlock token. */
	const uint16_t *format_version;	/**< Version identifier for the token. */
	const uint8_t *uuid;			/**< UUID for the device that generated the token. */
	const uint8_t *counter_length;	/**< Length of the unlock counter. */
	const uint8_t *counter;			/**< Unlock counter value in the token. */
	const uint8_t *nonce;			/**< Token nonce. */
	const uint8_t *token_signature;	/**< Signature for the token data. */
	const uint16_t *policy_length;	/**< The unlock policy data length. */
	const uint8_t *policy_data;		/**< The authorized unlock policy data. */
	const uint8_t *data_signature;	/**< Signature for the authorized data. */
};

/**
 * Version number for the unlock token format.
 */
#define	DEVICE_UNLOCK_TOKEN_FORMAT			1


/**
 * Extract a single field from the authorized data.
 *
 * @param data Buffer containing the raw authorized data.
 * @param length Total length of the authorized data.
 * @param offset Offset in the buffer where the field is located.
 * @param field The field pointer in the parsed auth data structure to save.
 * @param field_length Length of the field in the authorized data.  The offset will be updated by
 * this amount after the field has been saved.
 */
#define	device_unlock_token_parse_auth_data_field(data, length, offset, field, field_length) \
	{ \
		size_t temp_off = offset; \
		uint16_t temp_len = field_length; \
        \
		if (length < (temp_off + (temp_len))) { \
			return DEVICE_UNLOCK_TOKEN_BAD_AUTH_DATA; \
		} \
        \
		field = (void*) &data[temp_off]; \
		temp_off += (temp_len); \
		offset = temp_off; \
	}

/**
 * Parse authorized unlock data to determine where each component exists in the data buffer.  Only
 * the top-level container will be parsed.  No token information will be populated.
 *
 * @param auth_data The raw authorized unlock data buffer to parse.
 * @param length Length of the authorized unlock data.
 * @param parsed Output for the parsed information containing pointers to locations in the data
 * buffer.
 *
 * @return 0 if the data was parsed successfully or an error code.
 */
static int device_unlock_token_parse_authorized_data (const uint8_t *auth_data, size_t length,
	struct device_unlock_token_auth_data *parsed)
{
	size_t offset = 0;

	device_unlock_token_parse_auth_data_field (auth_data, length, offset, parsed->token_length,
		sizeof (*parsed->token_length));
	device_unlock_token_parse_auth_data_field (auth_data, length, offset, parsed->token_data,
		buffer_unaligned_read16 (parsed->token_length));

	device_unlock_token_parse_auth_data_field (auth_data, length, offset, parsed->policy_length,
		sizeof (*parsed->policy_length));
	device_unlock_token_parse_auth_data_field (auth_data, length, offset, parsed->policy_data,
		buffer_unaligned_read16 (parsed->policy_length));

	// parsed->data_signature = &auth_data[offset];

	return 0;
}

/**
 * Parse authorized unlock data to determine where each component exists in the data buffer.  Both
 * the top-level container and the token embedded in the authorized data will be parsed.
 *
 * @param auth_data The raw authorized unlock data buffer to parse.
 * @param length Length of the authorized unlock data.
 * @param parsed Output for the parsed information containing pointers to locations in the data
 * buffer.
 *
 * @return 0 if the data was parsed successfully or an error code.
 */
static int device_unlock_token_parse_authorized_data_and_token (const uint8_t *auth_data,
	size_t length, struct device_unlock_token_auth_data *parsed)
{
	size_t offset = 0;
	int oid_length;
	int status;

	/* Parse the authorized data container. */
	status = device_unlock_token_parse_authorized_data (auth_data, length, parsed);
	if (status != 0) {
		return status;
	}

	/* Parse token contents. */
	auth_data = parsed->token_data;
	length = buffer_unaligned_read16 (parsed->token_length);

	oid_length = asn1_get_der_item_len (&auth_data[offset], length - offset);
	if ((oid_length == ASN1_UTIL_NOT_VALID) || (length < (size_t) oid_length)) {
		return DEVICE_UNLOCK_TOKEN_BAD_AUTH_DATA;
	}

	device_unlock_token_parse_auth_data_field (auth_data, length, offset, parsed->oid, oid_length);
	device_unlock_token_parse_auth_data_field (auth_data, length, offset, parsed->format_version,
		sizeof (*parsed->format_version));
	device_unlock_token_parse_auth_data_field (auth_data, length, offset, parsed->uuid,
		DEVICE_UNLOCK_TOKEN_UUID_LENGTH);
	device_unlock_token_parse_auth_data_field (auth_data, length, offset, parsed->counter_length,
		sizeof (*parsed->counter_length));
	device_unlock_token_parse_auth_data_field (auth_data, length, offset, parsed->counter,
		*parsed->counter_length);
	device_unlock_token_parse_auth_data_field (auth_data, length, offset, parsed->nonce,
		DEVICE_UNLOCK_TOKEN_NONCE_LENGTH);

	// parsed->token_signature = &auth_data[offset];

	return 0;
}

/**
 * Initialize a handler for device unlock tokens.
 *
 * @param token The unlock token handler to initialize.
 * @param auth Authorization token manager to use for unlock tokens.  This must have been
 * initialized to require additional token data of DEVICE_UNLOCK_TOKEN_SIZEOF_EXTRA_DATA bytes.
 * @param uuid Interface for retrieving the device UUID.
 * @param oid The OID indicating the type of device generating the tokens.  This must be a base128
 * encoded value.
 * @param oid_length Length of the device type OID.
 * @param counter_length Length of the anti-replay unlock counter that will be present in the
 * tokens.
 * @param auth_hash Hash algorithm to use for signature verification of authorized unlock data.
 *
 * @return 0 if the unlock token handler was initialized successfully or an error code.
 */
int device_unlock_token_init (struct device_unlock_token *token, const struct auth_token *auth,
	const struct cmd_device *uuid, const uint8_t *oid, size_t oid_length, size_t counter_length,
	enum hash_type auth_hash)
{
	if ((token == NULL) || (auth == NULL) || (uuid == NULL) || (oid == NULL) || (oid_length == 0) ||
		(counter_length == 0)) {
		return DEVICE_UNLOCK_TOKEN_INVALID_ARGUMENT;
	}

	memset (token, 0, sizeof (struct device_unlock_token));

	token->auth = auth;
	token->uuid = uuid;
	token->oid = oid;
	token->oid_length = oid_length;
	token->counter_length = counter_length;
	token->data_length = DEVICE_UNLOCK_TOKEN_SIZEOF_EXTRA_DATA (oid_length, counter_length);
	token->auth_hash = auth_hash;

	return 0;
}

/**
 * Release the resources used for device unlock token handling.
 *
 * @param token The unlock token handler to release.
 */
void device_unlock_token_release (const struct device_unlock_token *token)
{
	UNUSED (token);
}

/**
 * Get the length of the anti-replay unlock counter expected by this token handler.
 *
 * @param token The unlock token handler to query.
 *
 * @return Length of the unlock counter data.  This will be 0 if the token handler is null.
 */
size_t device_unlock_token_get_counter_length (const struct device_unlock_token *token)
{
	if (token == NULL) {
		return 0;
	}

	return token->counter_length;
}

/**
 * Generate a new device unlock token.  There can only be one valid unlock token at a time, so this
 * operation will invalidate any previously generated token.
 *
 * @param token The unlock token handler to use for token generation.
 * @param unlock_counter The value of the anti-replay unlock counter to include in the token.  The
 * length of this counter is constant and specified during initialization of the token handler.
 * @param counter_length Length of the unlock counter data.  This must match the counter length
 * specified during initialization of the token handler.
 * @param data Output buffer for the token data.
 * @param length Length of the token buffer.
 *
 * @return Length of the generated unlock token or an error code.  Use ROT_IS_ERROR to check the
 * status.
 */
int device_unlock_token_generate (const struct device_unlock_token *token,
	const uint8_t *unlock_counter, size_t counter_length, uint8_t *data, size_t length)
{
	uint8_t *pos;
	const uint8_t *unlock_token;
	size_t token_length;
	int status;

	if ((token == NULL) || (unlock_counter == NULL) || (data == NULL)) {
		return DEVICE_UNLOCK_TOKEN_INVALID_ARGUMENT;
	}

	if (counter_length != token->counter_length) {
		return DEVICE_UNLOCK_TOKEN_INVALID_COUNTER;
	}

	/* If the output buffer isn't large enough for the extra context for the token, throw an error
	 * without doing anything else.  This ensures a new token is not generated unnecessarily and
	 * that the output buffer can be used to build the token context. */
	if (length < token->data_length) {
		return DEVICE_UNLOCK_TOKEN_SMALL_BUFFER;
	}

	/* Use the user-provided buffer as a temp location for building the token context data.
	 * - <var>:       OID
	 * - uint16_t:    format version
	 * - uint8_t[16]: UUID
	 * - uint8_t:     counter length
	 * - <var>:       counter */
	status = asn1_encode_base128_oid (token->oid, token->oid_length, data, token->data_length);
	if (ROT_IS_ERROR (status)) {
		return status;
	}

	pos = &data[status];

	buffer_unaligned_write16 ((uint16_t*) pos, DEVICE_UNLOCK_TOKEN_FORMAT);
	pos += sizeof (uint16_t);

	/* The UUID size in the token is fixed, regardless of how much data is provided by the device.
	 * Pad zeros for devices that have smaller UUID values. */
	memset (pos, 0, DEVICE_UNLOCK_TOKEN_UUID_LENGTH);
	status = token->uuid->get_uuid (token->uuid, pos, DEVICE_UNLOCK_TOKEN_UUID_LENGTH);
	if (ROT_IS_ERROR (status)) {
		return status;
	}

	pos += DEVICE_UNLOCK_TOKEN_UUID_LENGTH;

	*pos++ = token->counter_length;
	memcpy (pos, unlock_counter, token->counter_length);

	/* Generate a new unlock token with the token context. */
	status = token->auth->new_token (token->auth, data, token->data_length, &unlock_token,
		&token_length);
	if (status != 0) {
		return status;
	}

	/* Before copying the final token data, be sure the buffer is large enough. */
	if (length < token_length) {
		return DEVICE_UNLOCK_TOKEN_SMALL_BUFFER;
	}

	memcpy (data, unlock_token, token_length);

	return token_length;
}

/**
 * Authenticate authorized unlock data against the current active unlock token.
 *
 * @param token The unlock token handler to use for authentication.
 * @param data The authorized unlock data to authenticate.
 * @param length Length of the authorized unlock data.
 *
 * @return 0 if the unlock data was authenticated successfully or an error code.
 */
int device_unlock_token_authenicate (const struct device_unlock_token *token, const uint8_t *data,
	size_t length)
{
	struct device_unlock_token_auth_data parsed;
	int status;

	if ((token == NULL) || (data == NULL)) {
		return DEVICE_UNLOCK_TOKEN_INVALID_ARGUMENT;
	}

	status = device_unlock_token_parse_authorized_data (data, length, &parsed);
	if (status != 0) {
		return status;
	}

	return token->auth->verify_data (token->auth, data, length, sizeof (*parsed.token_length),
		sizeof (*parsed.policy_length) + buffer_unaligned_read16 (parsed.policy_length),
		token->auth_hash);
}

/**
 * Invalidate the current unlock token, if one exists.  Any future requests using that token will
 * fail authentication.
 *
 * @param token The unlock token handler to use for token invalidation.
 *
 * @return 0 if the unlock token was invalidated successfully or an error code.
 */
int device_unlock_token_invalidate (const struct device_unlock_token *token)
{
	if (token == NULL) {
		return DEVICE_UNLOCK_TOKEN_INVALID_ARGUMENT;
	}

	return token->auth->invalidate (token->auth);
}

/**
 * Parse an authorized device unlock token and extract the unlock counter value.
 *
 * @param auth_data The authorized unlock data to parse.  This does not support raw, unauthorized
 * tokens.
 * @param length Length of the authorized unlock data.
 * @param counter Output for the unlock counter value contained in the unlock token.  This will be a
 * pointer to a location in the authorized unlock data.
 * @param counter_length Output for the length of the unlock counter.
 *
 * @return 0 if the unlock counter was extracted successfully or an error code.
 */
int device_unlock_token_get_unlock_counter (const uint8_t *auth_data, size_t length,
	const uint8_t **counter, size_t *counter_length)
{
	struct device_unlock_token_auth_data parsed;
	int status;

	if ((auth_data == NULL) || (counter == NULL) || (counter_length == NULL)) {
		return DEVICE_UNLOCK_TOKEN_INVALID_ARGUMENT;
	}

	status = device_unlock_token_parse_authorized_data_and_token (auth_data, length, &parsed);
	if (status != 0) {
		return status;
	}

	*counter = parsed.counter;
	*counter_length = *parsed.counter_length;

	return 0;
}

/**
 * Parse an authorized device unlock token and extract the nonce.
 *
 * @param auth_data The authorized unlock data to parse.  This does not support raw, unauthorized
 * tokens.
 * @param length Length of the authorized unlock data.
 * @param nonce Output for the nonce contained in the unlock token.  This will be a pointer to a
 * location in the authorized unlock data.
 * @param nonce_length Output for the length of the nonce.
 *
 * @return 0 if the nonce was extracted successfully or an error code.
 */
int device_unlock_token_get_nonce (const uint8_t *auth_data, size_t length, const uint8_t **nonce,
	size_t *nonce_length)
{
	struct device_unlock_token_auth_data parsed;
	int status;

	if ((auth_data == NULL) || (nonce == NULL) || (nonce_length == NULL)) {
		return DEVICE_UNLOCK_TOKEN_INVALID_ARGUMENT;
	}

	status = device_unlock_token_parse_authorized_data_and_token (auth_data, length, &parsed);
	if (status != 0) {
		return status;
	}

	*nonce = parsed.nonce;
	*nonce_length = DEVICE_UNLOCK_TOKEN_NONCE_LENGTH;

	return 0;
}

/**
 * Parse authorized device unlock data and extract the unlock policy.
 *
 * @param auth_data The authorized unlock data to parse.
 * @param length Length of the authorized unlock data.
 * @param policy Output for the unlock policy contained in the authorized data.  This will be a
 * pointer to a location in the authorized unlock data.
 * @param policy_length Output for the length of the unlock policy.
 *
 * @return 0 if the unlock policy was extracted successfully or an error code.
 */
int device_unlock_token_get_unlock_policy (const uint8_t *auth_data, size_t length,
	const uint8_t **policy, size_t *policy_length)
{
	struct device_unlock_token_auth_data parsed;
	int status;

	if ((auth_data == NULL) || (policy == NULL) || (policy_length == NULL)) {
		return DEVICE_UNLOCK_TOKEN_INVALID_ARGUMENT;
	}

	status = device_unlock_token_parse_authorized_data (auth_data, length, &parsed);
	if (status != 0) {
		return status;
	}

	*policy = parsed.policy_data;
	*policy_length = buffer_unaligned_read16 (parsed.policy_length);

	return 0;
}
