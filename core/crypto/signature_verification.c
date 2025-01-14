// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <string.h>
#include "signature_verification.h"
#include "common/buffer_util.h"


/**
 * Verify a specified message with a digital signature.
 *
 * @param sig_verify The context to use for signature verification.
 * @param hash The hash engine that will be used to calculate the message digest.
 * @param hash_algo Algorithm to use for message hashing.
 * @param message The raw message data that should be verified.
 * @param msg_length Length of the message.
 * @param key Optional public key to use for signature verification.  If this is provided, the
 * verification context will be loaded with this key prior to verification.  This key will be erased
 * from the verification context prior to returning.  If this is null, the key currently present in
 * the verification context will be used for verification and will be left unchanged upon returning.
 * @param key_length Length of the optional public key.  This should be 0 if no key is provided.
 * @param signature The digital signature for the message data.
 * @param sig_length Length of the digital signature.
 *
 * @return 0 if the message was verified successfully or an error code.
 */
int signature_verification_verify_message (const struct signature_verification *sig_verify,
	const struct hash_engine *hash, enum hash_type hash_algo, const uint8_t *message,
	size_t msg_length, const uint8_t *key, size_t key_length, const uint8_t *signature,
	size_t sig_length)
{
	int status;

	if ((sig_verify == NULL) || (hash == NULL) || (signature == NULL) || (sig_length == 0)) {
		return SIG_VERIFICATION_INVALID_ARGUMENT;
	}

	status = hash_start_new_hash (hash, hash_algo);
	if (status != 0) {
		return status;
	}

	status = hash->update (hash, message, msg_length);
	if (status != 0) {
		hash->cancel (hash);

		return status;
	}

	return signature_verification_verify_hash_and_finish (sig_verify, hash, key, key_length,
		signature, sig_length);
}

/**
 * Verify a calculated digest against the provided digital signature.
 *
 * @param sig_verify The context to use for signature verification.
 * @param digest The digest to verify.
 * @param digest_length Length of the digest to verify.
 * @param key Optional public key to use for signature verification.  If this is provided, the
 * verification context will be loaded with this key prior to verification.  This key will be erased
 * from the verification context prior to returning.  If this is null, the key currently present in
 * the verification context will be used for verification and will be left unchanged upon returning.
 * @param key_length Length of the optional public key.  This should be 0 if no key is provided.
 * @param signature The digital signature for the digest.
 * @param sig_length Length of the digital signature.
 *
 * @return 0 if the digest was verified successfully or an error code.
 */
static int signature_verification_verify_digest (const struct signature_verification *sig_verify,
	uint8_t digest[HASH_MAX_HASH_LEN], size_t digest_length, const uint8_t *key, size_t key_length,
	const uint8_t *signature, size_t sig_length)
{
	int status;

	if (((key != NULL) && (key_length == 0)) || ((key == NULL) && (key_length != 0))) {
		return SIG_VERIFICATION_INCONSISTENT_KEY;
	}

	if (key != NULL) {
		status = sig_verify->set_verification_key (sig_verify, key, key_length);
		if (status != 0) {
			return status;
		}
	}

	status = sig_verify->verify_signature (sig_verify, digest, digest_length, signature,
		sig_length);

	if (key != NULL) {
		/* Wipe the public key from the verification context.  Errors here are ignored. */
		sig_verify->set_verification_key (sig_verify, NULL, 0);
	}

	return status;
}

/**
 * Verify an active hash context with a digital signature.
 *
 * The hash context will remain active after signature verification, allowing additional updates to
 * be made.  Not all hash implementations support this type of behavior, so it should only be used
 * in scenarios which require it.  Most scenarios should use dsa_verify_hash_and_finish instead.
 *
 * @param sig_verify The context to use for signature verification.
 * @param hash The hash engine that will be used to calculate the message digest.
 * @param key Optional public key to use for signature verification.  If this is provided, the
 * verification context will be loaded with this key prior to verification.  This key will be erased
 * from the verification context prior to returning.  If this is null, the key currently present in
 * the verification context will be used for verification and will be left unchanged upon returning.
 * @param key_length Length of the optional public key.  This should be 0 if no key is provided.
 * @param signature The digital signature for the hash context
 * @param sig_length Length of the digital signature.
 *
 * @return 0 if the hash was verified successfully or an error code.
 */
int signature_verification_verify_hash (const struct signature_verification *sig_verify,
	const struct hash_engine *hash, const uint8_t *key, size_t key_length, const uint8_t *signature,
	size_t sig_length)
{
	uint8_t digest[HASH_MAX_HASH_LEN] = {0};
	size_t digest_length;
	int status;

	if ((sig_verify == NULL) || (hash == NULL) || (signature == NULL) || (sig_length == 0)) {
		return SIG_VERIFICATION_INVALID_ARGUMENT;
	}

	digest_length = hash_get_active_hash_length (hash);
	if (digest_length == 0) {
		return SIG_VERIFICATION_NO_ACTVE_HASH;
	}

	status = hash->get_hash (hash, digest, sizeof (digest));
	if (status != 0) {
		goto exit;
	}

	status = signature_verification_verify_digest (sig_verify, digest, digest_length, key,
		key_length, signature, sig_length);

exit:
	buffer_zeroize (digest, HASH_MAX_HASH_LEN);

	return status;
}

/**
 * Verify an active hash context with a digital signature.
 *
 * The hash context will be finished as part of signature verification.  No additional updates can
 * be made to the hash context, regardless of whether the signature verification was successful or
 * not.
 *
 * @param sig_verify The context to use for signature verification.
 * @param hash The hash engine that will be used to calculate the message digest.  The active
 * context will always be terminated upon returning from this call.
 * @param key Optional public key to use for signature verification.  If this is provided, the
 * verification context will be loaded with this key prior to verification.  This key will be erased
 * from the verification context prior to returning.  If this is null, the key currently present in
 * the verification context will be used for verification and will be left unchanged upon returning.
 * @param key_length Length of the optional public key.  This should be 0 if no key is provided.
 * @param signature The digital signature for the hash context.
 * @param sig_length Length of the digital signature.
 *
 * @return 0 if the hash was verified successfully or an error code.
 */
int signature_verification_verify_hash_and_finish (const struct signature_verification *sig_verify,
	const struct hash_engine *hash, const uint8_t *key, size_t key_length, const uint8_t *signature,
	size_t sig_length)
{
	uint8_t digest[HASH_MAX_HASH_LEN] = {0};
	int status;

	status = signature_verification_verify_hash_and_finish_save_digest (sig_verify, hash, key,
		key_length, signature, sig_length, digest, sizeof (digest), NULL);

	buffer_zeroize (digest, sizeof (digest));

	return status;
}

/**
 * Verify an active hash context with a digital signature.  The digest that was calculated for
 * verification will be returned.
 *
 * The hash context will be finished as part of signature verification.  No additional updates can
 * be made to the hash context, regardless of whether the signature verification was successful or
 * not.
 *
 * @param sig_verify The context to use for signature verification.
 * @param hash The hash engine that will be used to calculate the message digest.  The active
 * context will always be terminated upon returning from this call.
 * @param key Optional public key to use for signature verification.  If this is provided, the
 * verification context will be loaded with this key prior to verification.  This key will be erased
 * from the verification context prior to returning.  If this is null, the key currently present in
 * the verification context will be used for verification and will be left unchanged upon returning.
 * @param key_length Length of the optional public key.  This should be 0 if no key is provided.
 * @param signature The digital signature for the hash context.
 * @param sig_length Length of the digital signature.
 * @param digest Output buffer for the calculated digest used for signature verification.  The
 * caller is expected to know the length of the generated digest.  This may contain valid data even
 * if the verification operation overall was not successful.
 * @param digest_length Length of the output digest buffer.
 * @param digest_valid Optional output to indicate if the digest output buffer contains valid data.
 * This could be used to determine situations where the hash finish completed successfully but the
 * verification of the digest did not.  This can be null if this information is not needed.
 *
 * @return 0 if the hash was verified successfully or an error code.
 */
int signature_verification_verify_hash_and_finish_save_digest (
	const struct signature_verification *sig_verify, const struct hash_engine *hash,
	const uint8_t *key, size_t key_length, const uint8_t *signature, size_t sig_length,
	uint8_t *digest, size_t digest_length, bool *digest_valid)
{
	size_t active_length;
	int status;

	if (digest_valid != NULL) {
		*digest_valid = false;
	}

	if (hash == NULL) {
		return SIG_VERIFICATION_INVALID_ARGUMENT;
	}

	active_length = hash_get_active_hash_length (hash);
	if (active_length == 0) {
		return SIG_VERIFICATION_NO_ACTVE_HASH;
	}

	if ((sig_verify == NULL) || (signature == NULL) || (sig_length == 0) || (digest == NULL)) {
		status = SIG_VERIFICATION_INVALID_ARGUMENT;
		goto hash_cancel;
	}

	status = hash->finish (hash, digest, digest_length);
	if (status != 0) {
		goto hash_cancel;
	}

	if (digest_valid != NULL) {
		*digest_valid = true;
	}

	return signature_verification_verify_digest (sig_verify, digest, active_length, key, key_length,
		signature, sig_length);

hash_cancel:
	hash->cancel (hash);

	return status;
}
