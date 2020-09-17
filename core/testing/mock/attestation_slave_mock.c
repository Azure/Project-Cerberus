// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <string.h>
#include <stdint.h>
#include "attestation_slave_mock.h"


static int attestation_slave_mock_get_digests (struct attestation_slave *attestation,
	uint8_t slot_num, uint8_t *buf, size_t buf_len, uint8_t *num_cert)
{
	struct attestation_slave_mock *mock = (struct attestation_slave_mock*) attestation;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, attestation_slave_mock_get_digests, attestation,
		MOCK_ARG_CALL (slot_num), MOCK_ARG_CALL (buf), MOCK_ARG_CALL (buf_len),
		MOCK_ARG_CALL (num_cert));
}

static int attestation_slave_mock_get_certificate (struct attestation_slave *attestation,
	uint8_t slot_num, uint8_t cert_num, struct der_cert *cert)
{
	struct attestation_slave_mock *mock = (struct attestation_slave_mock*) attestation;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, attestation_slave_mock_get_certificate, attestation,
		MOCK_ARG_CALL (slot_num), MOCK_ARG_CALL (cert_num), MOCK_ARG_CALL (cert));
}

static int attestation_slave_mock_challenge_response (struct attestation_slave *attestation,
	uint8_t *buf, size_t buf_len)
{
	struct attestation_slave_mock *mock = (struct attestation_slave_mock*) attestation;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, attestation_slave_mock_challenge_response, attestation,
		MOCK_ARG_CALL (buf), MOCK_ARG_CALL (buf_len));
}

static int attestation_slave_mock_aux_attestation_unseal (struct attestation_slave *attestation,
	struct hash_engine *hash, enum aux_attestation_key_length key_type, const uint8_t *seed,
	size_t seed_length, enum aux_attestation_seed_type seed_type,
	enum aux_attestation_seed_param seed_param, const uint8_t *hmac, enum hmac_hash hmac_type,
	const uint8_t *ciphertext, size_t cipher_length, const uint8_t sealing[][64], size_t pcr_count,
	uint8_t *key, size_t key_length)
{
	struct attestation_slave_mock *mock = (struct attestation_slave_mock*) attestation;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, attestation_slave_mock_aux_attestation_unseal, attestation,
		MOCK_ARG_CALL (hash), MOCK_ARG_CALL (key_type), MOCK_ARG_CALL (seed),
		MOCK_ARG_CALL (seed_length), MOCK_ARG_CALL (seed_type), MOCK_ARG_CALL (seed_param),
		MOCK_ARG_CALL (hmac), MOCK_ARG_CALL (hmac_type), MOCK_ARG_CALL (ciphertext),
		MOCK_ARG_CALL (cipher_length), MOCK_ARG_CALL (sealing), MOCK_ARG_CALL (pcr_count),
		MOCK_ARG_CALL (key), MOCK_ARG_CALL (key_length));
}

static int attestation_slave_mock_aux_decrypt (struct attestation_slave *attestation,
	const uint8_t *encrypted, size_t len_encrypted, const uint8_t *label, size_t len_label,
	enum hash_type pad_hash, uint8_t *decrypted, size_t len_decrypted)
{
	struct attestation_slave_mock *mock = (struct attestation_slave_mock*) attestation;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, attestation_slave_mock_aux_decrypt, attestation,
		MOCK_ARG_CALL (encrypted), MOCK_ARG_CALL (len_encrypted), MOCK_ARG_CALL (label),
		MOCK_ARG_CALL (len_label), MOCK_ARG_CALL (pad_hash), MOCK_ARG_CALL (decrypted),
		MOCK_ARG_CALL (len_decrypted));
}

static int attestation_slave_mock_generate_ecdh_seed (struct attestation_slave *attestation,
	const uint8_t *pub_key, size_t key_length, bool hash_seed, uint8_t *seed, size_t seed_length)
{
	struct attestation_slave_mock *mock = (struct attestation_slave_mock*) attestation;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, attestation_slave_mock_generate_ecdh_seed, attestation,
		MOCK_ARG_CALL (pub_key), MOCK_ARG_CALL (key_length), MOCK_ARG_CALL (hash_seed),
		MOCK_ARG_CALL (seed), MOCK_ARG_CALL (seed_length));
}

static int attestation_slave_mock_func_arg_count (void *func)
{
	if (func == attestation_slave_mock_aux_attestation_unseal) {
		return 14;
	}
	else if (func == attestation_slave_mock_aux_decrypt) {
		return 7;
	}
	else if (func == attestation_slave_mock_generate_ecdh_seed) {
		return 5;
	}
	else if (func == attestation_slave_mock_get_digests) {
		return 4;
	}
	else if (func == attestation_slave_mock_get_certificate) {
		return 3;
	}
	else if (func == attestation_slave_mock_challenge_response) {
		return 2;
	}
	else {
		return 0;
	}
}

static const char* attestation_slave_mock_func_name_map (void *func)
{
	if (func == attestation_slave_mock_get_digests) {
		return "get_digests";
	}
	else if (func == attestation_slave_mock_get_certificate) {
		return "get_certificate";
	}
	else if (func == attestation_slave_mock_challenge_response) {
		return "challenge_response";
	}
	else if (func == attestation_slave_mock_aux_attestation_unseal) {
		return "aux_attestation_unseal";
	}
	else if (func == attestation_slave_mock_aux_decrypt) {
		return "aux_decrypt";
	}
	else if (func == attestation_slave_mock_generate_ecdh_seed) {
		return "generate_ecdh_seed";
	}
	else {
		return "unknown";
	}
}

static const char* attestation_slave_mock_arg_name_map (void *func, int arg)
{
	if (func == attestation_slave_mock_get_digests) {
		switch (arg) {
			case 0:
				return "slot_num";

			case 1:
				return "buf";

			case 2:
				return "buf_len";

			case 3:
				return "num_cert";

			default:
				return "unknown";
		}
	}
	else if (func == attestation_slave_mock_get_certificate) {
		switch (arg) {
			case 0:
				return "slot_num";

			case 1:
				return "cert_num";

			case 2:
				return "cert";

			default:
				return "unknown";
		}
	}
	else if (func == attestation_slave_mock_challenge_response) {
		switch (arg) {
			case 0:
				return "buf";

			case 1:
				return "buf_len";

			default:
				return "unknown";
		}
	}
	else if (func == attestation_slave_mock_aux_attestation_unseal) {
		switch (arg) {
			case 0:
				return "hash";

			case 1:
				return "key_type";

			case 2:
				return "seed";

			case 3:
				return "seed_length";

			case 4:
				return "seed_type";

			case 5:
				return "seed_param";

			case 6:
				return "hmac";

			case 7:
				return "hmac_type";

			case 8:
				return "ciphertext";

			case 9:
				return "cipher_length";

			case 10:
				return "sealing";

			case 11:
				return "pcr_count";

			case 12:
				return "key";

			case 13:
				return "key_length";

			default:
				return "unknown";
		}
	}
	else if (func == attestation_slave_mock_aux_decrypt) {
		switch (arg) {
			case 0:
				return "ecrypted";

			case 1:
				return "len_encrypted";

			case 2:
				return "label";

			case 3:
				return "len_label";

			case 4:
				return "pad_hash";

			case 5:
				return "decrypted";

			case 6:
				return "len_decrypted";

			default:
				return "unknown";
		}
	}
	else if (func == attestation_slave_mock_generate_ecdh_seed) {
		switch (arg) {
			case 0:
				return "pub_key";

			case 1:
				return "key_length";

			case 2:
				return "hash_seed";

			case 3:
				return "seed";

			case 4:
				return "seed_length";

			default:
				return "unknown";
		}
	}
	else {
		return "unknown";
	}
}

/**
 * Initialize mock interface instance
 *
 * @param mock Mock interface instance to initialize
 *
 * @return Initialization status, 0 if success or an error code.
 */
int attestation_slave_mock_init (struct attestation_slave_mock *mock)
{
	int status;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	memset (mock, 0, sizeof (struct attestation_slave_mock));

	status = mock_init (&mock->mock);

	if (status != 0) {
		return status;
	}

	mock_set_name (&mock->mock, "attestation");

	mock->base.get_digests = attestation_slave_mock_get_digests;
	mock->base.get_certificate = attestation_slave_mock_get_certificate;
	mock->base.challenge_response = attestation_slave_mock_challenge_response;
	mock->base.aux_attestation_unseal = attestation_slave_mock_aux_attestation_unseal;
	mock->base.aux_decrypt = attestation_slave_mock_aux_decrypt;
	mock->base.generate_ecdh_seed = attestation_slave_mock_generate_ecdh_seed;

	mock->mock.func_arg_count = attestation_slave_mock_func_arg_count;
	mock->mock.func_name_map = attestation_slave_mock_func_name_map;
	mock->mock.arg_name_map = attestation_slave_mock_arg_name_map;

	return 0;
}

/**
 * Release resources used by an attestation manager mock instance
 *
 * @param mock Mock interface instance to release
 */
void attestation_slave_mock_release (struct attestation_slave_mock *mock)
{
	if (mock != NULL) {
		mock_release (&mock->mock);
	}
}

/**
 * Validate that all expectations were met then release the mock instance
 *
 * @param mock The attestation manager mock interface to validate and release
 *
 * @return Validation status, 0 if expectations met or an error code.
 */
int attestation_slave_mock_validate_and_release (struct attestation_slave_mock *mock)
{
	int status = 1;

	if (mock != NULL) {
		status = mock_validate (&mock->mock);
		attestation_slave_mock_release (mock);
	}

	return status;
}
