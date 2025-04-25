// Copyright (c) Microsoft Corporation. All rights reserved.

#include <stdint.h>
#include "backend_ecdsa.h"
#include "platform_api.h"
#include "acvp/acvp_logging.h"
#include "asn1/ecc_der_util.h"
#include "common/unused.h"
#include "crypto/ecc_mbedtls.h"
#include "crypto/ecdsa.h"
#include "crypto/signature_verification.h"
#include "logging/debug_log.h"
#include "parser/cipher_definitions.h"

/**
 * The current implementation identifier for the ACVP backend.
 */
extern uint32_t acvp_implementation;


/**
 * Execute an ECDSA key generation ACVP test on the provided data.  This test performs the key
 * generation with testing candidates according to FIPS 186-4 B.4.2.
 *
 * @param data The container for the parsed test input and test output.  The test output is stored
 * in data.d.buf, data.Qx.buf, and data.Qy.buf and must be freed by the caller.
 * @param parsed_flags Flags parsed from the ACVP request.
 *
 * @return 0 if the test was executed successfully, else -1.
 */
static int backend_ecdsa_keygen (struct ecdsa_keygen_data *data, flags_t parsed_flags);

/**
 * Execute an ECDSA key generation ACVP test on the provided data.  This test performs the key
 * generation with extra entropy according to FIPS 186-4 B.4.1.
 *
 * @param data The container for the parsed test input and test output.  The test output is stored
 * in data.d.buf, data.Qx.buf, and data.Qy.buf and must be freed by the caller.
 * @param parsed_flags Flags parsed from the ACVP request.
 *
 * @return 0 if the test was executed successfully, else -1.
 */
static int backend_ecdsa_keygen_extra (struct ecdsa_keygen_extra_data *data, flags_t parsed_flags);

/**
 * Execute an ECDSA signature generation ACVP test on the provided data.
 *
 * @param data The container for the parsed test input and test output.  The test output is stored
 * in data.R.buf and data.S.buf and must be freed by the caller.
 * @param parsed_flags Flags parsed from the ACVP request.
 *
 * @return 0 if the test was executed successfully, else -1.
 */
static int backend_ecdsa_siggen (struct ecdsa_siggen_data *data, flags_t parsed_flags);

/**
 * Execute an ECDSA signature verification ACVP test on the provided data.
 *
 * @param data The container for the parsed test input and test output.
 * @param parsed_flags Flags parsed from the ACVP request.
 *
 * @return 0 if the test was executed successfully, else -1.
 */
static int backend_ecdsa_sigver (struct ecdsa_sigver_data *data, flags_t parsed_flags);

/**
 * Generate an ECDSA key pair and store it in the current state.
 *
 * @param curve The ECC curve type to use for key generation.  This is a bitmask of the curve type
 * defined in cipher_definitions.h.
 * @param qx Output for the X-coordinate of the public key.  The contained buffer must be freed by
 * the caller.
 * @param qy Output for the Y-coordinate of the public key.  The contained buffer must be freed by
 * the caller.
 * @param privkey Output for the private key.  This buffer must be freed by the caller using
 * backend_ecdsa_free_key.
 *
 * @return 0 if the key pair was generated successfully, else -1.
 */
static int backend_ecdsa_keygen_en (uint64_t curve, struct buffer *qx, struct buffer *qy,
	void **privkey);

/**
 * Free the given private key.
 *
 * @param privkey The private key to free.
 */
static void backend_ecdsa_free_key (void *privkey);

/**
 * List of registered ECDSA engines.
 */
static const struct backend_ecdsa_engine *ecdsa_engines = NULL;

/**
 * Number of registered ECDSA engines.
 */
static size_t ecdsa_engines_cnt = 0;

/**
 * ECDSA backend callback structure.
 */
static const struct ecdsa_backend ecdsa_impl = {
	.ecdsa_keygen = backend_ecdsa_keygen,
	.ecdsa_keygen_extra = backend_ecdsa_keygen_extra,
	.ecdsa_pkvver = NULL,
	.ecdsa_siggen = backend_ecdsa_siggen,
	.ecdsa_sigver = backend_ecdsa_sigver,
	.ecdsa_keygen_en = backend_ecdsa_keygen_en,
	.ecdsa_free_key = backend_ecdsa_free_key
};


/**
 * Get the ECDSA backend callback structure containing the ECDSA implementations.
 *
 * @return The ECDSA backend callback structure.
 */
const struct ecdsa_backend* backend_ecdsa_get_impl ()
{
	return &ecdsa_impl;
}

/**
 * Register a list of ECDSA engines with the ECDSA backend.  If any ECDSA engines were previously
 * registered, they will be replaced by the new list of ECDSA engines.  The engines must remain valid
 * for the lifetime of the ECDSA backend.
 *
 * @param ecdsa The list of ECDSA engines to register.
 * @param num_engines The number of ECDSA engines in the list.
 */
void backend_ecdsa_register_engines (const struct backend_ecdsa_engine *ecdsa, size_t num_engines)
{
	ecdsa_engines = ecdsa;
	ecdsa_engines_cnt = num_engines;
}

/**
 * Retrieve the ECDSA engine for the specified implementation identifier.
 *
 * @param impl_id The implementation identifier to search for.
 * @param engine Output for the ECDSA engine associated with the given implentation identifier.
 *
 * @return 0 if the ECDSA engine was found or an error code.
 */
static int backend_ecdsa_get_engine (int impl_id, const struct backend_ecdsa_engine **engine)
{
	size_t i;

	if (engine == NULL) {
		return BACKEND_ECDSA_INVALID_ARGUMENT;
	}

	if (ecdsa_engines == NULL) {
		return BACKEND_ECDSA_NO_ENGINE;
	}

	for (i = 0; i < ecdsa_engines_cnt; i++) {
		if (ecdsa_engines[i].impl_id == impl_id) {
			*engine = &ecdsa_engines[i];

			return 0;
		}
	}

	return BACKEND_ECDSA_ENGINE_NOT_FOUND;
}

/**
 * Get the hash type from the specified cipher.
 *
 * @param cipher The cipher to get the hash type for.  The cipher is expected to be a bitmask
 * including the hash type to use as defined in cipher_definitions.h.
 * @param hash_type Output for the hash type specified by the cipher.
 *
 * @return 0 if the hash type was determined or an error code.
 */
static int backend_ecdsa_get_hash_type (uint64_t cipher, enum hash_type *hash_type)
{
	if (hash_type == NULL) {
		return BACKEND_ECDSA_INVALID_ARGUMENT;
	}

	switch (cipher & ACVP_HASHMASK) {
		case ACVP_SHA1:
			*hash_type = HASH_TYPE_SHA1;
			break;

		case ACVP_SHA256:
			*hash_type = HASH_TYPE_SHA256;
			break;

		case ACVP_SHA384:
			*hash_type = HASH_TYPE_SHA384;
			break;

		case ACVP_SHA512:
			*hash_type = HASH_TYPE_SHA512;
			break;

		default:
			return BACKEND_ECDSA_HASH_TYPE_UNSUPPORTED;
	}

	return 0;
}

/**
 * Get the ECC key lengths from the specified cipher.
 *
 * @param cipher The cipher to get the key length for.  The cipher is expected to be a bitmask
 * including the ECC curve type to use as defined in cipher_definitions.h.
 * @param key_length Output for the raw key length specified by the cipher's ECC curve type.
 *
 * @return 0 if the hash type was determined or an error code.
 */
static int backend_ecdsa_get_ecc_key_length (uint64_t cipher, size_t *key_length)
{
	if (key_length == NULL) {
		return BACKEND_ECDSA_INVALID_ARGUMENT;
	}

	switch (cipher & ACVP_CURVEMASK) {
		case ACVP_NISTP256:
			*key_length = ECC_KEY_LENGTH_256;
			break;

		case ACVP_NISTP384:
			*key_length = ECC_KEY_LENGTH_384;
			break;

		case ACVP_NISTP521:
			*key_length = ECC_KEY_LENGTH_521;
			break;

		default:
			return BACKEND_ECDSA_CURVE_TYPE_UNSUPPORTED;
	}

	return 0;
}

/**
 * Helper function to generate an ECDSA key pair.
 *
 * @param engine The ECDSA engine to use for key generation.
 * @param cipher The cipher to use for key generation.  The cipher is expected to be a bitmask
 * including the ECC curve type to use as defined in cipher_definitions.h.
 * @param d Output for the private key.  The contained buffer must be freed by the caller.
 * @param Qx Output for the x-coordinate of the public key.  The contained buffer must be freed by
 * the caller.
 * @param Qy Output for the y-coordinate of the public key.  The contained buffer must be freed by
 * the caller.
 *
 * @return 0 if the key pair was generated successfully or an error code.
 */
static int backend_ecdsa_keygen_helper (const struct backend_ecdsa_engine *engine, uint64_t cipher,
	struct buffer *d, struct buffer *Qx, struct buffer *Qy)
{
	size_t key_length;
	int status;

	uint8_t *priv_key_der = NULL;
	uint8_t *pub_key_der = NULL;
	size_t priv_key_der_length;
	size_t pub_key_der_length;

	union {
		struct ecc_raw_private_key hw;
		struct ecc_private_key eng;
	} priv_key;
	union {
		struct ecc_point_public_key hw;
		struct ecc_public_key eng;
	} pub_key;

	status = backend_ecdsa_get_ecc_key_length (cipher, &key_length);
	if (status != 0) {
		return status;
	}

	// Create output buffers for generated key pair components.
	d->buf = platform_malloc (key_length);
	if (d->buf == NULL) {
		return BACKEND_ECDSA_NO_MEMORY;
	}
	d->len = key_length;

	Qx->buf = platform_malloc (key_length);
	if (Qx->buf == NULL) {
		platform_free (d->buf);

		return BACKEND_ECDSA_NO_MEMORY;
	}
	Qx->len = key_length;

	Qy->buf = platform_malloc (key_length);
	if (Qy->buf == NULL) {
		platform_free (d->buf);
		platform_free (Qx->buf);

		return BACKEND_ECDSA_NO_MEMORY;
	}
	Qy->len = key_length;

	if (engine->is_hw) {
		status = ecdsa_ecc_hw_generate_random_key (engine->ecc.hw, engine->hash, key_length,
			&priv_key.hw, &pub_key.hw);
		if (status != 0) {
			goto release;
		}

		memcpy (d->buf, priv_key.hw.d, key_length);
		memcpy (Qx->buf, pub_key.hw.x, key_length);
		memcpy (Qy->buf, pub_key.hw.y, key_length);
	}
	else {
		status = ecdsa_generate_random_key (engine->ecc.engine, engine->hash, key_length,
			&priv_key.eng, &pub_key.eng);
		if (status != 0) {
			goto release;
		}

		// Convert generated key to DER, then write raw components to output buffers.
		status = engine->ecc.engine->get_private_key_der (engine->ecc.engine, &priv_key.eng,
			&priv_key_der, &priv_key_der_length);
		if (status != 0) {
			goto release;
		}

		status = engine->ecc.engine->get_public_key_der (engine->ecc.engine, &pub_key.eng,
			&pub_key_der, &pub_key_der_length);
		if (status != 0) {
			goto release;
		}

		status = ecc_der_decode_private_key ((const uint8_t*) priv_key_der, priv_key_der_length,
			d->buf, key_length);
		if (ROT_IS_ERROR (status)) {
			goto release;
		}

		status = ecc_der_decode_public_key ((const uint8_t*) pub_key_der, pub_key_der_length,
			Qx->buf, Qy->buf, key_length);
		if (!(ROT_IS_ERROR (status))) {
			status = 0;
		}
	}

release:
	// Release output buffers if an error occurred.
	if (ROT_IS_ERROR (status)) {
		if (d->buf != NULL) {
			platform_free (d->buf);
			d->buf = NULL;
		}

		if (Qx->buf != NULL) {
			platform_free (Qx->buf);
			Qx->buf = NULL;
		}

		if (Qy->buf != NULL) {
			platform_free (Qy->buf);
			Qy->buf = NULL;
		}
	}

	if (priv_key_der != NULL) {
		platform_free (priv_key_der);
	}

	if (pub_key_der != NULL) {
		platform_free (pub_key_der);
	}

	if (!engine->is_hw) {
		engine->ecc.engine->release_key_pair (engine->ecc.engine, &priv_key.eng, &pub_key.eng);
	}

	return status;
}

static int backend_ecdsa_keygen (struct ecdsa_keygen_data *data, flags_t parsed_flags)
{
	const struct backend_ecdsa_engine *engine;
	int status;

	UNUSED (parsed_flags);

	if (data == NULL) {
		status = BACKEND_ECDSA_INVALID_ARGUMENT;
		goto exit;
	}

	if (ecdsa_engines == NULL) {
		status = BACKEND_ECDSA_NO_ENGINE;
		goto exit;
	}

	status = backend_ecdsa_get_engine (acvp_implementation, &engine);
	if (status != 0) {
		goto exit;
	}

	if (engine->keygen_type != BACKEND_ECDSA_KEYGEN_TYPE_TESTING_CANDIDATES) {
		status = BACKEND_ECDSA_KEYGEN_TYPE_UNSUPPORTED;
		goto exit;
	}

	status = backend_ecdsa_keygen_helper (engine, data->cipher, &data->d, &data->Qx, &data->Qy);

exit:
	if (ROT_IS_ERROR (status)) {
		// On failure, set status to -1 to trigger test failure handling in Acvpparser library. Log
		// error to give more information about the failure.
		debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_ACVP,
			ACVP_LOGGING_TEST_FAILURE, status, 0);

		status = -1;
	}

	return status;
}

static int backend_ecdsa_keygen_extra (struct ecdsa_keygen_extra_data *data, flags_t parsed_flags)
{
	const struct backend_ecdsa_engine *engine;
	int status;

	UNUSED (parsed_flags);

	if (data == NULL) {
		status = BACKEND_ECDSA_INVALID_ARGUMENT;
		goto exit;
	}

	if (ecdsa_engines == NULL) {
		status = BACKEND_ECDSA_NO_ENGINE;
		goto exit;
	}

	status = backend_ecdsa_get_engine (acvp_implementation, &engine);
	if (status != 0) {
		goto exit;
	}

	if (engine->keygen_type != BACKEND_ECDSA_KEYGEN_TYPE_EXTRA_ENTROPY) {
		status = BACKEND_ECDSA_KEYGEN_TYPE_UNSUPPORTED;
		goto exit;
	}

	status = backend_ecdsa_keygen_helper (engine, data->cipher, &data->d, &data->Qx, &data->Qy);

exit:
	if (ROT_IS_ERROR (status)) {
		// On failure, set status to -1 to trigger test failure handling in Acvpparser library. Log
		// error to give more information about the failure.
		debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_ACVP,
			ACVP_LOGGING_TEST_FAILURE, status, 0);

		status = -1;
	}

	return status;
}

static int backend_ecdsa_siggen (struct ecdsa_siggen_data *data, flags_t parsed_flags)
{
	const struct backend_ecdsa_engine *engine;
	enum hash_type hash_type;
	size_t key_length;
	uint8_t key_der[ECC_DER_MAX_PRIVATE_LENGTH];
	size_t key_der_len;
	size_t sig_der_len;
	int status;

	union {
		uint8_t eng[ECC_DER_ECDSA_MAX_LENGTH];
		struct ecc_ecdsa_signature hw;
	} signature;

	UNUSED (parsed_flags);

	if ((data == NULL) || (data->component != BACKEND_ECDSA_COMPONENT_TYPE_FULL) ||
		(data->privkey == NULL) || (data->msg.buf == NULL) ||
		(data->Qx.buf == NULL) || (data->Qy.buf == NULL)) {
		status = BACKEND_ECDSA_INVALID_ARGUMENT;
		goto exit;
	}

	if (ecdsa_engines == NULL) {
		status = BACKEND_ECDSA_NO_ENGINE;
		goto exit;
	}

	status = backend_ecdsa_get_engine (acvp_implementation, &engine);
	if (status != 0) {
		goto exit;
	}

	status = backend_ecdsa_get_hash_type (data->cipher, &hash_type);
	if (status != 0) {
		goto exit;
	}

	status = backend_ecdsa_get_ecc_key_length (data->cipher, &key_length);
	if (status != 0) {
		goto exit;
	}

	// Prepare R and S signature output buffers.
	data->R.buf = platform_malloc (key_length);
	if (data->R.buf == NULL) {
		status = BACKEND_ECDSA_NO_MEMORY;
		goto exit;
	}
	data->R.len = key_length;

	data->S.buf = platform_malloc (key_length);
	if (data->S.buf == NULL) {
		platform_free (data->R.buf);

		status = BACKEND_ECDSA_NO_MEMORY;
		goto exit;
	}
	data->S.len = key_length;

	// Sign message and write to signature output buffers.
	if (engine->is_hw) {
		if (engine->api_type == BACKEND_ECDSA_API_TYPE_MESSAGE) {
			status = ecdsa_ecc_hw_sign_message (engine->ecc.hw, engine->hash, hash_type, NULL,
				data->privkey, key_length, data->msg.buf, data->msg.len, &signature.hw);
		}
		else {
			status = hash_start_new_hash (engine->hash, hash_type);
			if (status != 0) {
				goto release;
			}

			status = engine->hash->update (engine->hash, data->msg.buf, data->msg.len);
			if (status != 0) {
				engine->hash->cancel (engine->hash);

				goto release;
			}

			status = ecdsa_ecc_hw_sign_hash_and_finish (engine->ecc.hw, engine->hash, NULL,
				data->privkey, key_length, &signature.hw);
		}

		if (status != 0) {
			goto release;
		}

		memcpy (data->R.buf, signature.hw.r, key_length);
		memcpy (data->S.buf, signature.hw.s, key_length);
	}
	else {
		status = ecc_der_encode_private_key (data->privkey, data->Qx.buf, data->Qy.buf, key_length,
			key_der, ECC_DER_MAX_PRIVATE_LENGTH);
		if (ROT_IS_ERROR (status)) {
			goto release;
		}

		key_der_len = status;

		if (engine->api_type == BACKEND_ECDSA_API_TYPE_MESSAGE) {
			status = ecdsa_sign_message (engine->ecc.engine, engine->hash, hash_type, NULL,	key_der,
				key_der_len, data->msg.buf, data->msg.len, (uint8_t*) signature.eng,
				sizeof (signature.eng));
		}
		else {
			status = hash_start_new_hash (engine->hash, hash_type);
			if (status != 0) {
				goto exit;
			}

			status = engine->hash->update (engine->hash, data->msg.buf, data->msg.len);
			if (status != 0) {
				engine->hash->cancel (engine->hash);

				goto exit;
			}

			status = ecdsa_sign_hash_and_finish (engine->ecc.engine, engine->hash, NULL, key_der,
				key_der_len, (uint8_t*) signature.eng, sizeof (signature.eng));
		}

		if (ROT_IS_ERROR (status)) {
			goto release;
		}

		sig_der_len = status;

		status = ecc_der_decode_ecdsa_signature ((uint8_t*) signature.eng, sig_der_len, data->R.buf,
			data->S.buf, key_length);
	}

release:
	if (ROT_IS_ERROR (status)) {
		if (data->R.buf != NULL) {
			platform_free (data->R.buf);
			data->R.buf = NULL;
		}

		if (data->S.buf != NULL) {
			platform_free (data->S.buf);
			data->S.buf = NULL;
		}
	}

exit:
	if (ROT_IS_ERROR (status)) {
		// On failure, set status to -1 to trigger test failure handling in Acvpparser library. Log
		// error to give more information about the failure.
		debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_ACVP,
			ACVP_LOGGING_TEST_FAILURE, status, 0);

		status = -1;
	}

	return status;
}

static int backend_ecdsa_sigver (struct ecdsa_sigver_data *data, flags_t parsed_flags)
{
	const struct backend_ecdsa_engine *engine;
	enum hash_type hash_type;
	size_t key_length;
	uint8_t sig_der[ECC_DER_ECDSA_MAX_LENGTH];
	size_t sig_der_length;
	uint8_t pub_key_der[ECC_DER_MAX_PUBLIC_LENGTH];
	size_t pub_key_der_length;
	struct ecc_point_public_key pub_key_point;
	struct ecc_ecdsa_signature sig;
	int status = 0;

	UNUSED (parsed_flags);

	if ((data == NULL) || (data->component != BACKEND_ECDSA_COMPONENT_TYPE_FULL) ||
		(data->R.buf == NULL) || (data->S.buf == NULL) ||
		(data->Qx.buf == NULL) || (data->Qy.buf == NULL) || (data->msg.buf == NULL)) {
		status = BACKEND_ECDSA_INVALID_ARGUMENT;
		goto exit;
	}

	if (ecdsa_engines == NULL) {
		status = BACKEND_ECDSA_NO_ENGINE;
		goto exit;
	}

	status = backend_ecdsa_get_engine (acvp_implementation, &engine);
	if (status != 0) {
		goto exit;
	}

	status = backend_ecdsa_get_hash_type (data->cipher, &hash_type);
	if (status != 0) {
		goto exit;
	}

	status = backend_ecdsa_get_ecc_key_length (data->cipher, &key_length);
	if (status != 0) {
		goto exit;
	}

	if (engine->is_hw) {
		memcpy (pub_key_point.x, data->Qx.buf, key_length);
		memcpy (pub_key_point.y, data->Qy.buf, key_length);
		pub_key_point.key_length = key_length;

		memcpy (sig.r, data->R.buf, key_length);
		memcpy (sig.s, data->S.buf, key_length);
		sig.length = key_length;

		if (engine->api_type == BACKEND_ECDSA_API_TYPE_MESSAGE) {
			status = ecdsa_ecc_hw_verify_message (engine->ecc.hw, engine->hash, hash_type,
				data->msg.buf, data->msg.len, &pub_key_point, &sig);
		}
		else {
			status = hash_start_new_hash (engine->hash, hash_type);
			if (status != 0) {
				goto exit;
			}

			status = engine->hash->update (engine->hash, data->msg.buf, data->msg.len);
			if (status != 0) {
				engine->hash->cancel (engine->hash);

				goto exit;
			}

			status = ecdsa_ecc_hw_verify_hash_and_finish (engine->ecc.hw, engine->hash,
				&pub_key_point, &sig);
		}
	}
	else {
		status = ecc_der_encode_ecdsa_signature (data->R.buf, data->S.buf, key_length, sig_der,
			ECC_DER_ECDSA_MAX_LENGTH);
		if (ROT_IS_ERROR (status)) {
			goto exit;
		}

		sig_der_length = status;

		status = ecc_der_encode_public_key (data->Qx.buf, data->Qy.buf, key_length,	pub_key_der,
			ECC_DER_MAX_PUBLIC_LENGTH);
		if (ROT_IS_ERROR (status)) {
			goto exit;
		}

		pub_key_der_length = status;

		if (engine->api_type == BACKEND_ECDSA_API_TYPE_MESSAGE) {
			status = ecdsa_verify_message (engine->ecc.engine, engine->hash, hash_type,
				data->msg.buf, data->msg.len, pub_key_der, pub_key_der_length, sig_der,
				sig_der_length);
		}
		else {
			status = hash_start_new_hash (engine->hash, hash_type);
			if (status != 0) {
				goto exit;
			}

			status = engine->hash->update (engine->hash, data->msg.buf, data->msg.len);
			if (status != 0) {
				engine->hash->cancel (engine->hash);

				goto exit;
			}

			status = ecdsa_verify_hash_and_finish (engine->ecc.engine, engine->hash, pub_key_der,
				pub_key_der_length, sig_der, sig_der_length);
		}
	}

	// If signature verification fails, the returned status should be 0. ECC_ENGINE_BAD_SIGNATURE
	if ((status == SIG_VERIFICATION_BAD_SIGNATURE) || (status == ECC_ENGINE_BAD_SIGNATURE) ||
		(status == ECC_HW_ECDSA_BAD_SIGNATURE)) {
		data->sigver_success = 0;
		status = 0;
	}
	else if (status == 0) {
		data->sigver_success = 1;
	}

exit:
	if (ROT_IS_ERROR (status)) {
		// On failure, set status to -1 to trigger test failure handling in Acvpparser library. Log
		// error to give more information about the failure.
		debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_ACVP,
			ACVP_LOGGING_TEST_FAILURE, status, 0);

		status = -1;
	}

	return status;
}

static int backend_ecdsa_keygen_en (uint64_t curve, struct buffer *qx, struct buffer *qy,
	void **privkey)
{
	const struct backend_ecdsa_engine *engine;
	struct buffer d;
	int status;

	if ((qx == NULL) || (qy == NULL) || (privkey == NULL)) {
		status = BACKEND_ECDSA_INVALID_ARGUMENT;
		goto exit;
	}

	if (ecdsa_engines == NULL) {
		status = BACKEND_ECDSA_NO_ENGINE;
		goto exit;
	}

	status = backend_ecdsa_get_engine (acvp_implementation, &engine);
	if (status != 0) {
		goto exit;
	}

	status = backend_ecdsa_keygen_helper (engine, curve, &d, qx, qy);
	if (status != 0) {
		goto exit;
	}

	*privkey = d.buf;

exit:
	if (ROT_IS_ERROR (status)) {
		// On failure, set status to -1 to trigger failure handling in Acvpparser library. Log error
		// to give more information about the failure.
		debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_ACVP,
			ACVP_LOGGING_TEST_FAILURE, status, 0);

		status = -1;
	}

	return status;
}

static void backend_ecdsa_free_key (void *privkey)
{
	if (privkey != NULL) {
		platform_free (privkey);
	}
}

/**
 * Register the ECDSA backend implementation with the ACVP backend.
 */
void backend_ecdsa_register_impl (void)
{
	register_ecdsa_impl ((struct ecdsa_backend*) &ecdsa_impl);
}
