// Copyright (c) Microsoft Corporation. All rights reserved.

#include <stdint.h>
#include "backend_ecdh.h"
#include "platform_api.h"
#include "acvp/acvp_logging.h"
#include "asn1/ecc_der_util.h"
#include "common/buffer_util.h"
#include "common/unused.h"
#include "logging/debug_log.h"
#include "parser/cipher_definitions.h"

/**
 * The current implementation identifier for the ACVP backend.
 */
extern uint32_t acvp_implementation;


/**
 * Execute an ECDH shared secret generation ACVP test on the provided data.
 *
 * @param data The container for the parsed test input and test output.  The test output is stored
 * in data.Qxloc.buf, data.Qyloc.buf, and data.hashzz.buf and must be freed by the caller.
 * @param parsed_flags Flags parsed from the ACVP request.
 *
 * @return 0 if the test was executed successfully, else -1.
 */
static int backend_ecdh_ecdh_ss (struct ecdh_ss_data *data, flags_t parsed_flags);

/**
 * Execute an ECDH shared secret verification ACVP test on the provided data.
 *
 * @param data The container for the parsed test input and test output.
 * @param parsed_flags Flags parsed from the ACVP request.
 *
 * @return 0 if the test was executed successfully, else -1.
 */
static int backend_ecdh_ecdh_ss_ver (struct ecdh_ss_ver_data *data, flags_t parsed_flags);

/**
 * List of registered ECDH engines.
 */
static const struct backend_ecdh_engine *ecdh_engines = NULL;

/**
 * Number of registered ECDH engines.
 */
static size_t ecdh_engines_cnt = 0;

/**
 * ECDH backend callback structure.
 */
static const struct ecdh_backend ecdh_impl = {
	.ecdh_ss = backend_ecdh_ecdh_ss,
	.ecdh_ss_ver = backend_ecdh_ecdh_ss_ver
};


/**
 * Get the ECDH backend callback structure containing the ECDH implementations.
 *
 * @return The ECDH backend callback structure.
 */
const struct ecdh_backend* backend_ecdh_get_impl ()
{
	return &ecdh_impl;
}

/**
 * Register a list of ECDH engines with the ECDH backend.  If any ECDH engines were previously
 * registered, they will be replaced by the new list of ECDH engines.  The engines must remain valid
 * for the lifetime of the ECDH backend.
 *
 * @param ecdh The list of ECDH engines to register.
 * @param num_engines The number of ECDH engines in the list.
 */
void backend_ecdh_register_engines (const struct backend_ecdh_engine *ecdh, size_t num_engines)
{
	ecdh_engines = ecdh;
	ecdh_engines_cnt = num_engines;
}

/**
 * Retrieve the ECDH engine for the specified implementation identifier.
 *
 * @param impl_id The implementation identifier to search for.
 * @param engine Output for the ECDH engine associated with the given implentation identifier.
 *
 * @return 0 if the ECDH engine was found or an error code.
 */
static int backend_ecdh_get_engine (int impl_id, const struct backend_ecdh_engine **engine)
{
	size_t i;

	if (engine == NULL) {
		return BACKEND_ECDH_INVALID_ARGUMENT;
	}

	if (ecdh_engines == NULL) {
		return BACKEND_ECDH_NO_ENGINE;
	}

	for (i = 0; i < ecdh_engines_cnt; i++) {
		if (ecdh_engines[i].impl_id == impl_id) {
			*engine = &ecdh_engines[i];

			return 0;
		}
	}

	return BACKEND_ECDH_ENGINE_NOT_FOUND;
}

/**
 * Get the ECC key length from the specified cipher.
 *
 * @param cipher The cipher to get the key length for.  The cipher is expected to be a bitmask
 * including the ECC curve type to use as defined in cipher_definitions.h.
 * @param key_length Output for the raw key length specified by the cipher's ECC curve type.
 *
 * @return 0 if the key length was determined or an error code.
 */
static int backend_ecdh_get_ecc_key_length (uint64_t cipher, size_t *key_length)
{
	if (key_length == NULL) {
		return BACKEND_ECDH_INVALID_ARGUMENT;
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
			return BACKEND_ECDH_CURVE_TYPE_UNSUPPORTED;
	}

	return 0;
}

/**
 * Helper to free allocated parameters used during testing.  If any of the given parameters are
 * null, they will be ignored.
 *
 * @param hashzz The shared secret to free.
 * @param Qxloc The X coordinate of the public key to free.
 * @param Qyloc The Y coordinate of the public key to free.
 */
static void backend_ecdh_free_helper (unsigned char **hashzz, unsigned char **Qxloc,
	unsigned char **Qyloc)
{
	if ((hashzz != NULL) && (*hashzz != NULL)) {
		platform_free (*hashzz);
		*hashzz = NULL;
	}

	if ((Qxloc != NULL) && (*Qxloc != NULL)) {
		platform_free (*Qxloc);
		*Qxloc = NULL;
	}

	if ((Qyloc != NULL) && (*Qyloc != NULL)) {
		platform_free (*Qyloc);
		*Qyloc = NULL;
	}
}

/**
 * Helper to generate an ECDH shared secret using an ECC engine.
 *
 * @param engine The ECC engine to use for the operation.
 * @param key_length Length of the private key.  This will determine the curve to use.
 * @param privkey The private key to use for the operation.
 * @param pubkey_x The X coordinate of the public key to use for the operation.
 * @param pubkey_y The Y coordinate of the public key to use for the operation.
 * @param shared_secret Output for the shared secret.
 *
 * @return 0 if the operation was successful or an error code.
 */
static int backend_ecdh_ss_common (const struct ecc_engine *engine, size_t key_length,
	const struct ecc_private_key *privkey, const uint8_t *pubkey_x, const uint8_t *pubkey_y,
	uint8_t *shared_secret)
{
	uint8_t pubkey_der[ECC_DER_MAX_PUBLIC_LENGTH];
	struct ecc_public_key pubkey;
	int status;

	status = ecc_der_encode_public_key (pubkey_x, pubkey_y, key_length, (uint8_t*) pubkey_der,
		ECC_DER_MAX_PUBLIC_LENGTH);
	if (ROT_IS_ERROR (status)) {
		return status;
	}

	status = engine->init_public_key (engine, pubkey_der, status, &pubkey);
	if (status != 0) {
		return status;
	}

	status = engine->compute_shared_secret (engine, privkey, &pubkey, shared_secret, key_length);
	engine->release_key_pair (engine, NULL, &pubkey);
	if (ROT_IS_ERROR (status)) {
		return status;
	}

	return 0;
}

/**
 * Helper to generate an ECDH shared secret using ECC HW.
 *
 * @param hw The ECC HW engine to use for the operation.
 * @param key_length Length of the private key.  This will determine the curve to use.
 * @param privkey The private key to use for the operation.
 * @param pubkey_x The X coordinate of the public key to use for the operation.
 * @param pubkey_y The Y coordinate of the public key to use for the operation.
 * @param shared_secret Output for the the shared secret.
 *
 * @return 0 if the operation was successful or an error code.
 */
static int backend_ecdh_ss_hw_common (const struct ecc_hw *hw, size_t key_length,
	const uint8_t *privkey,	const uint8_t *pubkey_x, const uint8_t *pubkey_y,
	uint8_t *shared_secret)
{
	struct ecc_point_public_key pubkey_rem;
	int status;

	memcpy (&pubkey_rem.x, pubkey_x, key_length);
	memcpy (&pubkey_rem.y, pubkey_y, key_length);
	pubkey_rem.key_length = key_length;

	status = hw->ecdh_compute (hw, privkey, key_length, &pubkey_rem, shared_secret, key_length);
	if (status != 0) {
		return status;
	}

	return 0;
}

static int backend_ecdh_ecdh_ss (struct ecdh_ss_data *data, flags_t parsed_flags)
{
	const struct backend_ecdh_engine *engine;
	size_t key_length;
	struct ecc_public_key pubkey_eng;
	struct ecc_point_public_key pubkey_hw;
	uint8_t *pubkey_der = NULL;
	size_t pubkey_der_len;
	struct ecc_private_key privkey_eng;
	uint8_t privkey_hw[ECC_MAX_KEY_LENGTH];
	int status;

	UNUSED (parsed_flags);

	if ((data == NULL) || (data->Qxrem.buf == NULL) || (data->Qxrem.len == 0) ||
		(data->Qyrem.buf == NULL) || (data->Qyrem.len == 0)) {
		status = BACKEND_ECDH_INVALID_ARGUMENT;
		goto exit;
	}

	status = backend_ecdh_get_engine (acvp_implementation, &engine);
	if (status != 0) {
		goto exit;
	}

	status = backend_ecdh_get_ecc_key_length (data->cipher, &key_length);
	if (status != 0) {
		goto exit;
	}

	data->hashzz.buf = platform_malloc (key_length);
	if (data->hashzz.buf == NULL) {
		status = BACKEND_ECDH_NO_MEMORY;
		goto exit;
	}
	data->hashzz.len = key_length;

	if (engine->is_hw) {
		status = engine->ecc.hw->generate_ecc_key_pair (engine->ecc.hw, key_length,	privkey_hw,
			&pubkey_hw);
		if (status != 0) {
			backend_ecdh_free_helper (&data->hashzz.buf, NULL, NULL);

			goto exit;
		}

		status = backend_ecdh_ss_hw_common (engine->ecc.hw, key_length, privkey_hw,	data->Qxrem.buf,
			data->Qyrem.buf, data->hashzz.buf);
	}
	else {
		status = engine->ecc.engine->generate_key_pair (engine->ecc.engine, key_length,
			&privkey_eng, &pubkey_eng);
		if (status != 0) {
			backend_ecdh_free_helper (&data->hashzz.buf, NULL, NULL);

			goto exit;
		}

		status = engine->ecc.engine->get_public_key_der (engine->ecc.engine, &pubkey_eng,
			&pubkey_der, &pubkey_der_len);
		if (status != 0) {
			backend_ecdh_free_helper (&data->hashzz.buf, NULL, NULL);

			goto exit;
		}

		status = backend_ecdh_ss_common (engine->ecc.engine, key_length, &privkey_eng,
			data->Qxrem.buf, data->Qyrem.buf, data->hashzz.buf);
		engine->ecc.engine->release_key_pair (engine->ecc.engine, &privkey_eng, &pubkey_eng);
	}

	if (status != 0) {
		goto exit;
	}

	// Write local public key to output buffers.
	data->Qxloc.buf = platform_malloc (key_length);
	if (data->Qxloc.buf == NULL) {
		backend_ecdh_free_helper (&data->hashzz.buf, NULL, NULL);

		status = BACKEND_ECDH_NO_MEMORY;
		goto exit;
	}
	data->Qxloc.len = key_length;

	data->Qyloc.buf = platform_malloc (key_length);
	if (data->Qyloc.buf == NULL) {
		backend_ecdh_free_helper (&data->hashzz.buf, &data->Qyloc.buf, NULL);

		status = BACKEND_ECDH_NO_MEMORY;
		goto exit;
	}
	data->Qyloc.len = key_length;

	if (engine->is_hw) {
		memcpy (data->Qxloc.buf, pubkey_hw.x, key_length);
		memcpy (data->Qyloc.buf, pubkey_hw.y, key_length);
	}
	else {
		status = ecc_der_decode_public_key (pubkey_der, pubkey_der_len, data->Qxloc.buf,
			data->Qyloc.buf, key_length);
		if (ROT_IS_ERROR (status)) {
			backend_ecdh_free_helper (&data->hashzz.buf, &data->Qyloc.buf, &data->Qxloc.buf);

			goto exit;
		}
	}

	status = 0;

exit:
	if (pubkey_der != NULL) {
		platform_free (pubkey_der);
	}

	if (ROT_IS_ERROR (status)) {
		// On failure, set status to -1 to trigger test failure handling in Acvpparser library. Log
		// error to give more information about the failure.
		debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_ACVP,
			ACVP_LOGGING_TEST_FAILURE, status, ACVP_ALGORITHM_ECDH);

		status = -1;
	}

	return status;
}

static int backend_ecdh_ecdh_ss_ver (struct ecdh_ss_ver_data *data, flags_t parsed_flags)
{
	const struct backend_ecdh_engine *engine;
	size_t key_length;
	struct ecc_private_key privkey;
	uint8_t privkey_der[ECC_DER_MAX_PRIVATE_LENGTH];
	uint8_t shared_secret[ECC_MAX_KEY_LENGTH];
	uint8_t *shared_secret_ptr = shared_secret;
	int status;

	UNUSED (parsed_flags);

	if ((data == NULL) || (data->Qxrem.buf == NULL) || (data->Qxrem.len == 0) ||
		(data->Qyrem.buf == NULL) || (data->Qyrem.len == 0) || (data->privloc.buf == NULL) ||
		(data->privloc.len == 0) || (data->hashzz.buf == NULL) || (data->hashzz.len == 0)) {
		status = BACKEND_ECDH_INVALID_ARGUMENT;
		goto exit;
	}

	status = backend_ecdh_get_engine (acvp_implementation, &engine);
	if (status != 0) {
		goto exit;
	}

	status = backend_ecdh_get_ecc_key_length (data->cipher, &key_length);
	if (status != 0) {
		goto exit;
	}

	if (engine->is_hw) {
		status = backend_ecdh_ss_hw_common (engine->ecc.hw, key_length, data->privloc.buf,
			data->Qxrem.buf, data->Qyrem.buf, shared_secret_ptr);
	}
	else {
		status = ecc_der_encode_private_key (data->privloc.buf, NULL, NULL, key_length,
			(uint8_t*) privkey_der, ECC_DER_MAX_PRIVATE_LENGTH);
		if (ROT_IS_ERROR (status)) {
			goto exit;
		}

		status = engine->ecc.engine->init_key_pair (engine->ecc.engine, (uint8_t*) privkey_der,
			status,	&privkey, NULL);
		if (status != 0) {
			goto exit;
		}

		status = backend_ecdh_ss_common (engine->ecc.engine, key_length, &privkey, data->Qxrem.buf,
			data->Qyrem.buf, shared_secret_ptr);
		engine->ecc.engine->release_key_pair (engine->ecc.engine, &privkey, NULL);
	}

	if (status != 0) {
		goto exit;
	}

	status = buffer_compare (data->hashzz.buf, shared_secret, data->hashzz.len);
	if (status == BUFFER_UTIL_DATA_MISMATCH) {
		data->validity_success = 0;
		status = 0;
	}
	else if (status == 0) {
		data->validity_success = 1;
	}

exit:
	if (ROT_IS_ERROR (status)) {
		// On failure, set status to -1 to trigger test failure handling in Acvpparser library. Log
		// error to give more information about the failure.
		debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_ACVP,
			ACVP_LOGGING_TEST_FAILURE, status, ACVP_ALGORITHM_ECDH);

		status = -1;
	}

	return status;
}

/**
 * Register the ECDH backend implementation with the ACVP backend.
 */
void backend_ecdh_register_impl (void)
{
	register_ecdh_impl ((struct ecdh_backend*) &ecdh_impl);
}
