// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <string.h>
#include "hkdf.h"
#include "kdf.h"
#include "common/buffer_util.h"
#include "common/unused.h"


/**
 * Zeroize the current PRK, preventing any additional HKDF-Expand operations until a new PRK is
 * extracted.
 *
 * @param hkdf_impl The HKDF instance to zeroize.
 */
static void hkdf_reset_key_derivation_context (const struct hkdf *hkdf_impl)
{
	buffer_zeroize (hkdf_impl->state->prk, sizeof (hkdf_impl->state->prk));
	hkdf_impl->state->hmac_type = HMAC_INVALID;
}

int hkdf_extract (const struct hkdf_interface *hkdf, enum hash_type hash_algo, const uint8_t *ikm,
	size_t length, const uint8_t *salt, size_t salt_length)
{
	const struct hkdf *hkdf_impl = (const struct hkdf*) hkdf;
	enum hmac_hash hmac_type = (enum hmac_hash) hash_algo;
	int status;

	if ((hkdf == NULL) || (ikm == NULL) || (length == 0)) {
		return HKDF_INVALID_ARGUMENT;
	}

	hkdf_reset_key_derivation_context (hkdf_impl);

	/* There is no special case needed when the salt is not provided.  There is no difference to the
	 * HMAC implementation whether the input is all zeros or null. */
	status = hash_generate_hmac (hkdf_impl->hash, salt, salt_length, ikm, length, hmac_type,
		hkdf_impl->state->prk, sizeof (hkdf_impl->state->prk));
	if (status == 0) {
		hkdf_impl->state->hmac_type = hmac_type;
	}
	else {
		/* Ensure the PRK state is cleared. */
		hkdf_reset_key_derivation_context (hkdf_impl);
	}

	return status;
}

int hkdf_expand (const struct hkdf_interface *hkdf, const uint8_t *info, size_t info_length,
	uint8_t *key_out, size_t key_length)
{
	const struct hkdf *hkdf_impl = (const struct hkdf*) hkdf;

	if ((hkdf == NULL) || (key_out == NULL)) {
		return HKDF_INVALID_ARGUMENT;
	}

	if (hkdf_impl->state->hmac_type == HMAC_INVALID) {
		return HKDF_NO_PRK_AVAILABLE;
	}

	return kdf_hkdf_expand (hkdf_impl->hash, hkdf_impl->state->hmac_type, hkdf_impl->state->prk,
		hash_hmac_get_hmac_length (hkdf_impl->state->hmac_type), info, info_length, key_out,
		key_length);
}

int hkdf_update_prk (const struct hkdf_interface *hkdf, const uint8_t *info, size_t info_length)
{
	int status;
	const struct hkdf *hkdf_impl = (const struct hkdf*) hkdf;
	uint8_t new_prk[HASH_MAX_HASH_LEN];

	status = hkdf_expand (hkdf, info, info_length, new_prk, sizeof (new_prk));
	if (status == 0) {
		memcpy (hkdf_impl->state->prk, new_prk,
			hash_hmac_get_hmac_length (hkdf_impl->state->hmac_type));
	}

	buffer_zeroize (new_prk, sizeof (new_prk));

	return status;
}

int hkdf_clear_prk (const struct hkdf_interface *hkdf)
{
	const struct hkdf *hkdf_impl = (const struct hkdf*) hkdf;

	if (hkdf == NULL) {
		return HKDF_INVALID_ARGUMENT;
	}

	hkdf_reset_key_derivation_context (hkdf_impl);

	return 0;
}

/**
 * Initialize an instance for driving keys using HKDF.
 *
 * @param hkdf The HKDF instance to initialize.
 * @param state Variable context for HKDF execution.  This must be uninitialized.
 * @param hash Hash engine to use for HMAC operations.
 *
 * @return 0 if the HKDF was initialized successfully or an error code.
 */
int hkdf_init (struct hkdf *hkdf, struct hkdf_state *state, const struct hash_engine *hash)
{
	if (hkdf == NULL) {
		return HKDF_INVALID_ARGUMENT;
	}

	memset (hkdf, 0, sizeof (*hkdf));

	hkdf->base.extract = hkdf_extract;
	hkdf->base.expand = hkdf_expand;
	hkdf->base.update_prk = hkdf_update_prk;
	hkdf->base.clear_prk = hkdf_clear_prk;

	hkdf->state = state;
	hkdf->hash = hash;

	return hkdf_init_state (hkdf);
}

/**
 * Initialize only the variable state of an HKDF instance.  The rest of the instance is assumed to
 * already have been initialized.
 *
 * This would generally be used with a statically initialized instance.
 *
 * @param hkdf The HKDF instance that contains the state to initialize.
 *
 * @return 0 if the state was successfully initialized or an error code.
 */
int hkdf_init_state (const struct hkdf *hkdf)
{
	if ((hkdf == NULL) || (hkdf->state == NULL) || (hkdf->hash == NULL)) {
		return HKDF_INVALID_ARGUMENT;
	}

	hkdf_reset_key_derivation_context (hkdf);

	return 0;
}

/**
 * Release the resources used for HKDF.
 *
 * @param hkdf The HKDF instance to release.
 */
void hkdf_release (const struct hkdf *hkdf)
{
	UNUSED (hkdf);
}
