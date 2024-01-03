// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include "rma_unlock_token.h"
#include "asn1/asn1_util.h"
#include "common/buffer_util.h"
#include "common/unused.h"


/**
 * Version number for the RMA token format.
 */
#define	RMA_UNLOCK_TOKEN_FORMAT				1

/**
 * Magic number identifier for an RMA token structure.
 */
#define	RMA_UNLOCK_TOKEN_MAGIC_NUMBER		0x52545354

/**
 * Length of the UUID field in the unlock token.
 */
#define	RMA_UNLOCK_TOKEN_UUID_LENGTH		16


int rma_unlock_token_authenticate (const struct rma_unlock_token *handler, const uint8_t *data,
	size_t length)
{
	uint8_t uuid[RMA_UNLOCK_TOKEN_UUID_LENGTH] = {0};
	const uint8_t *oid;
	size_t oid_length;
	uint8_t token_digest[HASH_MAX_HASH_LEN];
	int digest_length;
	size_t offset;
	int status;

	if ((handler == NULL) || (data == NULL)) {
		return RMA_UNLOCK_TOKEN_INVALID_ARGUMENT;
	}

	status = handler->uuid->get_uuid (handler->uuid, uuid, sizeof (uuid));
	if (ROT_IS_ERROR (status)) {
		return status;
	}

	/* Parse and validate the RMA token fields against the device context.
	 * - <var>:       OID
	 * - uint16_t:    format version
	 * - uint32_t:    magic number
	 * - uint8_t[16]: UUID
	 * - <var>:       digest of DICE Device ID public key
	 * - <var>:       token signature */

	/* OID */
	status = asn1_decode_base128_oid (data, length, &oid, &oid_length);
	if (status != 0) {
		return RMA_UNLOCK_TOKEN_BAD_TOKEN_DATA;
	}

	if (handler->oid_length != oid_length) {
		return RMA_UNLOCK_TOKEN_DEVICE_MISMATCH;
	}

	status = buffer_compare (handler->oid, oid, oid_length);
	if (status != 0) {
		return RMA_UNLOCK_TOKEN_DEVICE_MISMATCH;
	}

	offset = &oid[oid_length] - data;

	/* format version */
	if (length < (offset + sizeof (uint16_t))) {
		return RMA_UNLOCK_TOKEN_BAD_TOKEN_DATA;
	}

	if (buffer_unaligned_read16 ((uint16_t*) &data[offset]) != RMA_UNLOCK_TOKEN_FORMAT) {
		return RMA_UNLOCK_TOKEN_BAD_TOKEN_DATA;
	}

	offset += sizeof (uint16_t);

	/* magic number */
	if (length < (offset + sizeof (uint32_t))) {
		return RMA_UNLOCK_TOKEN_BAD_TOKEN_DATA;
	}

	if (buffer_unaligned_read32 ((uint32_t*) &data[offset]) != RMA_UNLOCK_TOKEN_MAGIC_NUMBER) {
		return RMA_UNLOCK_TOKEN_BAD_TOKEN_DATA;
	}

	offset += sizeof (uint32_t);

	/* UUID */
	if (length < (offset + RMA_UNLOCK_TOKEN_UUID_LENGTH)) {
		return RMA_UNLOCK_TOKEN_BAD_TOKEN_DATA;
	}

	status = buffer_compare (uuid, &data[offset], RMA_UNLOCK_TOKEN_UUID_LENGTH);
	if (status != 0) {
		return RMA_UNLOCK_TOKEN_DEVICE_MISMATCH;
	}

	offset += RMA_UNLOCK_TOKEN_UUID_LENGTH;

	/* Device ID hash */
	if (length < (offset + handler->dice_length)) {
		return RMA_UNLOCK_TOKEN_BAD_TOKEN_DATA;
	}

	status = buffer_compare (handler->dice_hash, &data[offset], handler->dice_length);
	if (status != 0) {
		return RMA_UNLOCK_TOKEN_DEVICE_MISMATCH;
	}

	offset += handler->dice_length;

	/* token signature */
	digest_length = hash_calculate (handler->hash, handler->auth_hash, data, offset, token_digest,
		sizeof (token_digest));
	if (ROT_IS_ERROR (digest_length)) {
		return digest_length;
	}

	status = handler->authority->set_verification_key (handler->authority, handler->authority_key,
		handler->auth_key_length);
	if (status != 0) {
		return status;
	}

	return handler->authority->verify_signature (handler->authority, token_digest, digest_length,
		&data[offset], length - offset);
}

/**
 * Initialize a handler for authorizing RMA unlock tokens.
 *
 * @param handler The RMA token handler to initialize.
 * @param authority_key The public key for entity that will be generating RMA tokens.
 * @param key_length Length of the authority public key.
 * @param authority Verification handler for the authority public key.  This does not need to be
 * pre-loaded with the authority key since the verification flow will reload the key each time.
 * @param hash The hash engine to use for token digests.
 * @param auth_hash Hash algorithm to use for signature verification of the token.
 * @param uuid Interface for retrieving the device UUID.
 * @param oid The OID indicating the type of device generating the tokens.  This must be a base128
 * encoded value.
 * @param oid_length Length of the device type OID.
 * @param dice_hash Digest of the DICE Device ID public key.  This would typically be available
 * through the DME structure.
 * @param hash_length Length of the Device ID digest.
 *
 * @return 0 if the RMA token handler was initialized successfully or an error code.
 */
int rma_unlock_token_init (struct rma_unlock_token *handler, const uint8_t *authority_key,
	size_t key_length, const struct signature_verification *authority, struct hash_engine *hash,
	enum hash_type auth_hash, const struct cmd_device *uuid, const uint8_t *oid, size_t oid_length,
	const uint8_t *dice_hash, size_t hash_length)
{
	if ((handler == NULL) || (authority_key == NULL) || (key_length == 0) || (authority == NULL) ||
		(hash == NULL) || (uuid == NULL) || (oid == NULL) || (oid_length == 0) ||
		(dice_hash == NULL) || (hash_length == 0)) {
		return RMA_UNLOCK_TOKEN_INVALID_ARGUMENT;
	}

	memset (handler, 0, sizeof (struct rma_unlock_token));

	handler->authenticate = rma_unlock_token_authenticate;

	handler->hash = hash;
	handler->authority = authority;
	handler->authority_key = authority_key;
	handler->auth_key_length = key_length;
	handler->auth_hash = auth_hash;
	handler->uuid = uuid;
	handler->oid = oid;
	handler->oid_length = oid_length;
	handler->dice_hash = dice_hash;
	handler->dice_length = hash_length;

	return 0;
}

/**
 * Release the resources used for RMA token authentication.
 *
 * @param handler The RMA token handler to release.
 */
void rma_unlock_token_release (const struct rma_unlock_token *handler)
{
	UNUSED (handler);
}
