// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include "platform_api.h"
#include "riot_core_common.h"
#include "crypto/kdf.h"


/**
 * The label to use for the Device ID KDF from the CDI hash.
 */
static const char DEVICE_ID_KDF_LABEL[] = "DEVICE ID";

/**
 * The label to use for the Alias KDF from the FWID HMAC.
 */
static const char ALIAS_KDF_LABEL[] = "ALIAS KEY";

/**
 * The context to use for DICE KDFs.
 */
static const char DICE_KDF_CONTEXT[] = "DICE";


/**
 * Create the self-signed X.509 certificate for the Device ID key.  Before the certificate can be
 * generated the following must be initialized:
 * - state->tcb needs to have the layer 0 TcbInfo structure.
 * - state->cdi_hash needs to contain the hash of the CDI.
 * - state->dev_id needs to have an initialized ECC private key context.
 *
 * @param riot The DICE layer 0 handler to use for cert creation.
 *
 * @return 0 if the certificate was created successfully or an error code.
 */
int riot_core_common_create_device_id_certificate (const struct riot_core_common *riot)
{
	uint8_t serial_num[HASH_MAX_HASH_LEN];
	char common_name[BASE64_LENGTH (SHA512_HASH_LENGTH)];
	int status;

	riot->state->dev_id_valid = true;
	status = riot->ecc->get_private_key_der (riot->ecc, &riot->state->dev_id,
		&riot->state->dev_id_der, &riot->state->dev_id_length);
	if (status != 0) {
		return status;
	}

	status = hash_generate_hmac (riot->hash, riot->state->cdi_hash, riot->state->digest_length,
		RIOT_CORE_SERIAL_NUM_KDF_DATA, RIOT_CORE_SERIAL_NUM_KDF_DATA_LENGTH, riot->state->kdf_algo,
		serial_num, sizeof (serial_num));
	if (status != 0) {
		return status;
	}

	status = riot->base64->encode (riot->base64, serial_num, riot->state->digest_length,
		(uint8_t*) common_name, sizeof (common_name));
	if (status != 0) {
		return status;
	}

	if (strlen (common_name) > X509_MAX_COMMON_NAME) {
		memcpy (riot->state->dev_id_name, common_name, X509_MAX_COMMON_NAME);
		riot->state->dev_id_name[X509_MAX_COMMON_NAME] = '\0';
	}
	else {
		strcpy (riot->state->dev_id_name, common_name);
	}

	status = riot->x509->create_self_signed_certificate (riot->x509, &riot->state->dev_id_cert,
		riot->state->dev_id_der, riot->state->dev_id_length, riot->state->hash_algo, serial_num, 8,
		riot->state->dev_id_name, X509_CERT_CA, riot->dev_id_ext, riot->dev_id_ext_count);
	if (status != 0) {
		return status;
	}

	riot->state->dev_id_cert_valid = true;
	return 0;
}

int riot_core_common_generate_device_id (const struct riot_core *riot, const uint8_t *cdi,
	size_t length)
{
	const struct riot_core_common *core = (const struct riot_core_common*) riot;
	uint8_t cdi_kdf[ECC_MAX_KEY_LENGTH];
	int status;
	uint8_t first;

	if ((core == NULL) || (length == 0)) {
		return RIOT_CORE_INVALID_ARGUMENT;
	}

	/* In order to accommodate CDI buffers that are at address 0, we can't just directly hash the
	 * buffer pointer.  Instead, we copy the first byte locally and add it to the hash, then add
	 * the rest of the buffer.  This removes the need to copy the CDI locally, which could be
	 * dangerous since the CDI length is a parameter. */
	status = hash_start_new_hash (core->hash, core->state->hash_algo);
	if (status != 0) {
		return status;
	}

	first = *cdi;
	status = core->hash->update (core->hash, &first, 1);
	if (status != 0) {
		goto cdi_error;
	}
	riot_core_clear (&first, 1);

	status = core->hash->update (core->hash, cdi + 1, length - 1);
	if (status != 0) {
		goto cdi_error;
	}

	status = core->hash->finish (core->hash, core->state->cdi_hash, sizeof (core->state->cdi_hash));
	if (status != 0) {
		goto cdi_error;
	}

	status = kdf_nist800_108_counter_mode (core->hash, core->state->kdf_algo, core->state->cdi_hash,
		core->state->digest_length, (uint8_t*) DEVICE_ID_KDF_LABEL,
		sizeof (DEVICE_ID_KDF_LABEL) - 1, (uint8_t*) DICE_KDF_CONTEXT,
		sizeof (DICE_KDF_CONTEXT) - 1, cdi_kdf, core->key_length);
	if (status != 0) {
		return status;
	}

	if (core->key_length == ECC_KEY_LENGTH_521) {
		/* For ECC-521 keys, 528 bits of key data is generated.  The upper 7 bits need to be masked
		 * off. */
		cdi_kdf[0] &= 0x01;
	}

	status = core->ecc->generate_derived_key_pair (core->ecc, cdi_kdf, core->key_length,
		&core->state->dev_id, NULL);
	if (status != 0) {
		return status;
	}

	riot_core_clear (cdi_kdf, sizeof (cdi_kdf));

	return riot_core_common_create_device_id_certificate (core);

cdi_error:
	core->hash->cancel (core->hash);
	return status;
}

int riot_core_common_get_device_id_csr (const struct riot_core *riot, const uint8_t *oid,
	size_t oid_length, uint8_t **csr, size_t *length)
{
	const struct riot_core_common *core = (const struct riot_core_common*) riot;

	if ((core == NULL) || (csr == NULL) || (length == NULL)) {
		return RIOT_CORE_INVALID_ARGUMENT;
	}

	if (core->state->dev_id_der == NULL) {
		return RIOT_CORE_NO_DEVICE_ID;
	}

	return core->x509->create_csr (core->x509, core->state->dev_id_der, core->state->dev_id_length,
		core->state->hash_algo, core->state->dev_id_name, X509_CERT_CA, oid, oid_length,
		core->dev_id_ext, core->dev_id_ext_count, csr, length);
}

int riot_core_common_get_device_id_cert (const struct riot_core *riot, uint8_t **device_id,
	size_t *length)
{
	const struct riot_core_common *core = (const struct riot_core_common*) riot;

	if ((core == NULL) || (device_id == NULL) || (length == NULL)) {
		return RIOT_CORE_INVALID_ARGUMENT;
	}

	if (!core->state->dev_id_cert_valid) {
		return RIOT_CORE_NO_DEVICE_ID;
	}

	return core->x509->get_certificate_der (core->x509, &core->state->dev_id_cert, device_id,
		length);
}

int riot_core_common_generate_alias_key (const struct riot_core *riot, const uint8_t *fwid,
	size_t length)
{
	const struct riot_core_common *core = (const struct riot_core_common*) riot;
	uint8_t fwid_hmac[HASH_MAX_HASH_LEN];
	uint8_t alias_kdf[ECC_MAX_KEY_LENGTH];
	char common_name[BASE64_LENGTH (SHA512_HASH_LENGTH)];
	int status;

	if ((riot == NULL) || (fwid == NULL) || (length == 0)) {
		return RIOT_CORE_INVALID_ARGUMENT;
	}

	if (!core->state->dev_id_cert_valid) {
		return RIOT_CORE_NO_DEVICE_ID;
	}

	status = hash_generate_hmac (core->hash, core->state->cdi_hash, core->state->digest_length,
		fwid, length, core->state->kdf_algo, fwid_hmac, sizeof (fwid_hmac));
	if (status != 0) {
		return status;
	}

	status = kdf_nist800_108_counter_mode (core->hash, core->state->kdf_algo, fwid_hmac,
		core->state->digest_length, (uint8_t*) ALIAS_KDF_LABEL, sizeof (ALIAS_KDF_LABEL) - 1,
		(uint8_t*) DICE_KDF_CONTEXT, sizeof (DICE_KDF_CONTEXT) - 1, alias_kdf, core->key_length);
	if (status != 0) {
		return status;
	}

	if (core->key_length == ECC_KEY_LENGTH_521) {
		/* For ECC-521 keys, 528 bits of key data is generated.  The upper 7 bits need to be masked
		 * off. */
		alias_kdf[0] &= 0x01;
	}

	status = core->ecc->generate_derived_key_pair (core->ecc, alias_kdf, core->key_length,
		&core->state->alias_key, NULL);
	if (status != 0) {
		return status;
	}

	core->state->alias_key_valid = true;
	status = core->ecc->get_private_key_der (core->ecc, &core->state->alias_key,
		&core->state->alias_der, &core->state->alias_length);
	if (status != 0) {
		return status;
	}

	status = hash_generate_hmac (core->hash, fwid_hmac, core->state->digest_length,
		RIOT_CORE_SERIAL_NUM_KDF_DATA, RIOT_CORE_SERIAL_NUM_KDF_DATA_LENGTH, core->state->kdf_algo,
		alias_kdf, sizeof (alias_kdf));
	if (status != 0) {
		return status;
	}

	status = core->base64->encode (core->base64, alias_kdf, core->state->digest_length,
		(uint8_t*) common_name, sizeof (common_name));
	if (status != 0) {
		return status;
	}

	if (strlen (common_name) > X509_MAX_COMMON_NAME) {
		common_name[X509_MAX_COMMON_NAME] = '\0';
	}

	status = core->x509->create_ca_signed_certificate (core->x509, &core->state->alias_cert,
		core->state->alias_der, core->state->alias_length, alias_kdf, 8, common_name,
		X509_CERT_END_ENTITY, core->state->dev_id_der, core->state->dev_id_length,
		core->state->hash_algo, &core->state->dev_id_cert, core->alias_ext, core->alias_ext_count);
	if (status != 0) {
		return status;
	}

	core->state->alias_cert_valid = true;
	return 0;
}

int riot_core_common_get_alias_key (const struct riot_core *riot, uint8_t **key, size_t *length)
{
	const struct riot_core_common *core = (const struct riot_core_common*) riot;

	if ((core == NULL) || (key == NULL) || (length == NULL)) {
		return RIOT_CORE_INVALID_ARGUMENT;
	}

	if (core->state->alias_der == NULL) {
		return RIOT_CORE_NO_ALIAS_KEY;
	}

	*key = platform_malloc (core->state->alias_length);
	if (*key == NULL) {
		return RIOT_CORE_NO_MEMORY;
	}

	memcpy (*key, core->state->alias_der, core->state->alias_length);
	*length = core->state->alias_length;

	return 0;
}

int riot_core_common_get_alias_key_cert (const struct riot_core *riot, uint8_t **alias_key,
	size_t *length)
{
	const struct riot_core_common *core = (const struct riot_core_common*) riot;

	if ((core == NULL) || (alias_key == NULL) || (length == NULL)) {
		return RIOT_CORE_INVALID_ARGUMENT;
	}

	if (!core->state->alias_cert_valid) {
		return RIOT_CORE_NO_ALIAS_KEY;
	}

	return core->x509->get_certificate_der (core->x509, &core->state->alias_cert, alias_key,
		length);
}

/**
 * Initialize RIoT Core to be ready for RIoT operations.
 *
 * @param riot RIoT Core instance to initialize.
 * @param state Variable context for the DICE handler.  This must be uninitialized.
 * @param hash The hash engine to use with RIoT Core.
 * @param ecc The ECC engine to use with RIoT Core.
 * @param x509 The X.509 certificate engine to use with RIoT Core.
 * @param base64 The base64 encoding engine to use with RIoT Core.
 * @param key_length Length of the DICE keys that should be created.
 * @param device_id_ext A list of additional, custom extensions that should be added to the
 * Device ID certificate and CSR.  At minimum, this should include the DICE TcbInfo extension for
 * layer 0.
 * @param device_id_ext_count The number of custom extensions to add to the Device ID certificate
 * and CSR.
 * @param alias_ext A list of additional, custom extensions that should be added to the
 * Alias certificate.  At minimum, this should include the DICE TcbInfo extension for layer 1.
 * @param alias_ext_count The number of custom extensions to add to the Alias certificate.
 *
 * @return 0 if RIoT Core was been initialize successfully or an error code.
 */
int riot_core_common_init (struct riot_core_common *riot, struct riot_core_common_state *state,
	struct hash_engine *hash, struct ecc_engine *ecc, struct x509_engine *x509,
	struct base64_engine *base64, size_t key_length,
	const struct x509_extension_builder *const *device_id_ext, size_t device_id_ext_count,
	const struct x509_extension_builder *const *alias_ext, size_t alias_ext_count)
{
	if ((riot == NULL) || (state == NULL) || (hash == NULL) || (ecc == NULL) || (x509 == NULL) ||
		(base64 == NULL)) {
		return RIOT_CORE_INVALID_ARGUMENT;
	}

	memset (riot, 0, sizeof (struct riot_core_common));

	riot->state = state;
	riot->hash = hash;
	riot->ecc = ecc;
	riot->base64 = base64;
	riot->x509 = x509;
	riot->dev_id_ext = device_id_ext;
	riot->dev_id_ext_count = device_id_ext_count;
	riot->alias_ext = alias_ext;
	riot->alias_ext_count = alias_ext_count;
	riot->key_length = key_length;

	riot->base.generate_device_id = riot_core_common_generate_device_id;
	riot->base.get_device_id_csr = riot_core_common_get_device_id_csr;
	riot->base.get_device_id_cert = riot_core_common_get_device_id_cert;
	riot->base.generate_alias_key = riot_core_common_generate_alias_key;
	riot->base.get_alias_key = riot_core_common_get_alias_key;
	riot->base.get_alias_key_cert = riot_core_common_get_alias_key_cert;

	return riot_core_common_init_state (riot);
}

/**
 * Initialize only the variable state of a DICE layer 0 handler.  The rest of the DICE handler
 * is assumed to have already been initialized.
 *
 * This would generally be used with a statically initialized instance.
 *
 * @param riot The DICE handler that contains the state to initialize.
 *
 * @return 0 if the DICE state was successfully initialized or an error code.
 */
int riot_core_common_init_state (const struct riot_core_common *riot)
{
	if ((riot == NULL) || (riot->state == NULL) || (riot->hash == NULL) || (riot->ecc == NULL) ||
		(riot->x509 == NULL) || (riot->base64 == NULL)) {
		return RIOT_CORE_INVALID_ARGUMENT;
	}

	/* These cases should also be caught by the X.509 engine, but check it here to fail fast. */
	if (((riot->dev_id_ext_count != 0) && (riot->dev_id_ext == NULL)) ||
		((riot->alias_ext_count != 0) && (riot->alias_ext == NULL))) {
		return RIOT_CORE_INVALID_ARGUMENT;
	}

	memset (riot->state, 0, sizeof (struct riot_core_common_state));

	switch (riot->key_length) {
		case ECC_KEY_LENGTH_256:
			riot->state->hash_algo = HASH_TYPE_SHA256;
			riot->state->kdf_algo = HMAC_SHA256;
			break;

#if (ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_384) && defined HASH_ENABLE_SHA384
		case ECC_KEY_LENGTH_384:
			riot->state->hash_algo = HASH_TYPE_SHA384;
			riot->state->kdf_algo = HMAC_SHA384;
			break;
#endif

#if (ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_521) && defined HASH_ENABLE_SHA512
		case ECC_KEY_LENGTH_521:
			riot->state->hash_algo = HASH_TYPE_SHA512;
			riot->state->kdf_algo = HMAC_SHA512;
			break;
#endif

		default:
			return RIOT_CORE_UNSUPPORTED_KEY_LENGTH;
	}

	/* The hash algorithm is known to be good, so this won't fail. */
	riot->state->digest_length = hash_get_hash_length (riot->state->hash_algo);

	return 0;
}

/**
 * Release RIoT core and zeroize all internal state with private data.
 *
 * It is imperative that all RIoT Core instances be released before starting the next application
 * stage, even if it's not necessary from a resource management perspective.  Releasing the RIoT
 * Core instance ensures that private data in memory is zeroized.
 *
 * @param riot The RIoT Core to release.
 */
void riot_core_common_release (const struct riot_core_common *riot)
{
	if (riot != NULL) {
		if (riot->state->dev_id_der) {
			riot_core_clear (riot->state->dev_id_der, riot->state->dev_id_length);
			platform_free (riot->state->dev_id_der);
		}

		if (riot->state->dev_id_valid) {
			riot->ecc->release_key_pair (riot->ecc, &riot->state->dev_id, NULL);
		}

		if (riot->state->dev_id_cert_valid) {
			riot->x509->release_certificate (riot->x509, &riot->state->dev_id_cert);
		}

		if (riot->state->alias_der) {
			platform_free (riot->state->alias_der);
		}

		if (riot->state->alias_key_valid) {
			riot->ecc->release_key_pair (riot->ecc, &riot->state->alias_key, NULL);
		}

		if (riot->state->alias_cert_valid) {
			riot->x509->release_certificate (riot->x509, &riot->state->alias_cert);
		}

		riot_core_clear (riot->state, sizeof (struct riot_core_common_state));
	}
}
