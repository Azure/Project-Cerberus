// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include "platform.h"
#include "riot_core_common.h"


/**
 * The serial number derivation data to use for certificate serial numbers.  Serial numbers are
 * are derived using NIST SP800-108, Counter Mode.  This data sets Label="SERIAL", Context="RIOT",
 * and L=8.
 */
static const uint8_t SERIAL_NUM_KDF_DATA[] = {
	0x00,0x00,0x00,0x01,0x53,0x45,0x52,0x49,0x41,0x4c,0x00,0x52,0x49,0x4f,0x54,0x00,
	0x00,0x00,0x40
};


static int riot_core_common_generate_device_id (struct riot_core *riot, const uint8_t *cdi,
	size_t length, const struct x509_dice_tcbinfo *riot_tcb)
{
	struct riot_core_common *core = (struct riot_core_common*) riot;
	uint8_t serial_num[SHA256_HASH_LENGTH];
	int status;
	uint8_t first;

	if ((core == NULL) || (length == 0) || (riot_tcb == NULL)) {
		return RIOT_CORE_INVALID_ARGUMENT;
	}

	core->tcb = riot_tcb;

	/* In order to accommodate CDI buffers that are at address 0, we can't just directly hash the
	 * buffer pointer.  Instead, we copy the first byte locally and add it to the hash, then add
	 * the rest of the buffer.  This removes the need to copy the CDI locally, which could be
	 * dangerous since the CDI length is a parameter. */
	status = core->hash->start_sha256 (core->hash);
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

	status = core->hash->finish (core->hash, core->cdi_hash, sizeof (core->cdi_hash));
	if (status != 0) {
		goto cdi_error;
	}

	status = core->ecc->generate_derived_key_pair (core->ecc, core->cdi_hash, SHA256_HASH_LENGTH,
		&core->dev_id, NULL);
	if (status != 0) {
		return status;
	}

	core->dev_id_valid = true;
	status = core->ecc->get_private_key_der (core->ecc, &core->dev_id, &core->dev_id_der,
		&core->dev_id_length);
	if (status != 0) {
		return status;
	}

	status = hash_generate_hmac (core->hash, core->cdi_hash, SHA256_HASH_LENGTH,
		SERIAL_NUM_KDF_DATA, sizeof (SERIAL_NUM_KDF_DATA), HMAC_SHA256, serial_num,
		sizeof (serial_num));
	if (status != 0) {
		return status;
	}

	status = core->base64->encode (core->base64, serial_num, SHA256_HASH_LENGTH,
		(uint8_t*) core->dev_id_name, sizeof (core->dev_id_name));
	if (status != 0) {
		return status;
	}

	status = core->x509->create_self_signed_certificate (core->x509, &core->dev_id_cert,
		core->dev_id_der, core->dev_id_length, serial_num, 8, core->dev_id_name, X509_CERT_CA,
		core->tcb);
	if (status != 0) {
		return status;
	}

	core->dev_id_cert_valid = true;
	return 0;

cdi_error:
	core->hash->cancel (core->hash);
	return status;
}

static int riot_core_common_get_device_id_csr (struct riot_core *riot, const char *oid,
	uint8_t **csr, size_t *length)
{
	struct riot_core_common *core = (struct riot_core_common*) riot;

	if ((core == NULL) || (csr == NULL) || (length == NULL)) {
		return RIOT_CORE_INVALID_ARGUMENT;
	}

	if (core->dev_id_der == NULL) {
		return RIOT_CORE_NO_DEVICE_ID;
	}

	return core->x509->create_csr (core->x509, core->dev_id_der, core->dev_id_length,
		core->dev_id_name, X509_CERT_CA, oid, core->tcb, csr, length);
}

static int riot_core_common_get_device_id_cert (struct riot_core *riot, uint8_t **device_id,
	size_t *length)
{
	struct riot_core_common *core = (struct riot_core_common*) riot;

	if ((core == NULL) || (device_id == NULL) || (length == NULL)) {
		return RIOT_CORE_INVALID_ARGUMENT;
	}

	if (!core->dev_id_cert_valid) {
		return RIOT_CORE_NO_DEVICE_ID;
	}

	return core->x509->get_certificate_der (core->x509, &core->dev_id_cert, device_id, length);
}

static int riot_core_common_generate_alias_key (struct riot_core *riot,
	const struct x509_dice_tcbinfo *alias_tcb)
{
	struct riot_core_common *core = (struct riot_core_common*) riot;
	uint8_t alias_kdf[SHA256_HASH_LENGTH];
	uint8_t serial_num[SHA256_HASH_LENGTH];
	uint8_t subject[BASE64_LENGTH (SHA256_HASH_LENGTH)];
	int status;

	if ((riot == NULL) || (alias_tcb == NULL) || (alias_tcb->fw_id == NULL)) {
		return RIOT_CORE_INVALID_ARGUMENT;
	}

	if (alias_tcb->fw_id_hash != HASH_TYPE_SHA256) {
		return RIOT_CORE_BAD_FWID_LENGTH;
	}

	if (!core->dev_id_cert_valid) {
		return RIOT_CORE_NO_DEVICE_ID;
	}

	status = hash_generate_hmac (core->hash, core->cdi_hash, SHA256_HASH_LENGTH, alias_tcb->fw_id,
		SHA256_HASH_LENGTH, HMAC_SHA256, alias_kdf, sizeof (alias_kdf));
	if (status != 0) {
		return status;
	}

	status = core->ecc->generate_derived_key_pair (core->ecc, alias_kdf, SHA256_HASH_LENGTH,
		&core->alias_key, NULL);
	if (status != 0) {
		return status;
	}

	core->alias_key_valid = true;
	status = core->ecc->get_private_key_der (core->ecc, &core->alias_key, &core->alias_der,
		&core->alias_length);
	if (status != 0) {
		return status;
	}

	status = hash_generate_hmac (core->hash, alias_kdf, SHA256_HASH_LENGTH, SERIAL_NUM_KDF_DATA,
		sizeof (SERIAL_NUM_KDF_DATA), HMAC_SHA256, serial_num, sizeof (serial_num));
	if (status != 0) {
		return status;
	}

	status = core->base64->encode (core->base64, serial_num, SHA256_HASH_LENGTH, subject,
		sizeof (subject));
	if (status != 0) {
		return status;
	}

	status = core->x509->create_ca_signed_certificate (core->x509, &core->alias_cert,
		core->alias_der, core->alias_length, serial_num, 8, (char*) subject, X509_CERT_END_ENTITY,
		core->dev_id_der, core->dev_id_length, &core->dev_id_cert, alias_tcb);
	if (status != 0) {
		return status;
	}

	core->alias_cert_valid = true;
	return 0;
}

static int riot_core_common_get_alias_key (struct riot_core *riot, uint8_t **key, size_t *length)
{
	struct riot_core_common *core = (struct riot_core_common*) riot;

	if ((core == NULL) || (key == NULL) || (length == NULL)) {
		return RIOT_CORE_INVALID_ARGUMENT;
	}

	if (core->alias_der == NULL) {
		return RIOT_CORE_NO_ALIAS_KEY;
	}

	*key = platform_malloc (core->alias_length);
	if (*key == NULL) {
		return RIOT_CORE_NO_MEMORY;
	}

	memcpy (*key, core->alias_der, core->alias_length);
	*length = core->alias_length;

	return 0;
}

static int riot_core_common_get_alias_key_cert (struct riot_core *riot, uint8_t **alias_key,
	size_t *length)
{
	struct riot_core_common *core = (struct riot_core_common*) riot;

	if ((core == NULL) || (alias_key == NULL) || (length == NULL)) {
		return RIOT_CORE_INVALID_ARGUMENT;
	}

	if (!core->alias_cert_valid) {
		return RIOT_CORE_NO_ALIAS_KEY;
	}

	return core->x509->get_certificate_der (core->x509, &core->alias_cert, alias_key, length);
}

/**
 * Initialize RIoT Core to be ready for RIoT operations.
 *
 * @param riot RIoT Core instance to initialize.
 * @param hash The hash engine to use with RIoT Core.
 * @param ecc The ECC engine to use with RIoT Core.
 * @param x509 The X.509 certificate engine to use with RIoT Core.
 * @param base64 The base64 encoding engine to use with RIoT Core.
 *
 * @return 0 if RIoT Core was been initialize successfully or an error code.
 */
int riot_core_common_init (struct riot_core_common *riot, struct hash_engine *hash,
	struct ecc_engine *ecc, struct x509_engine *x509, struct base64_engine *base64)
{
	if ((riot == NULL) || (hash == NULL) || (ecc == NULL) || (x509 == NULL) || (base64 == NULL)) {
		return RIOT_CORE_INVALID_ARGUMENT;
	}

	memset (riot, 0, sizeof (struct riot_core_common));

	riot->hash = hash;
	riot->ecc = ecc;
	riot->x509 = x509;
	riot->base64 = base64;

	riot->base.generate_device_id = riot_core_common_generate_device_id;
	riot->base.get_device_id_csr = riot_core_common_get_device_id_csr;
	riot->base.get_device_id_cert = riot_core_common_get_device_id_cert;
	riot->base.generate_alias_key = riot_core_common_generate_alias_key;
	riot->base.get_alias_key = riot_core_common_get_alias_key;
	riot->base.get_alias_key_cert = riot_core_common_get_alias_key_cert;

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
void riot_core_common_release (struct riot_core_common *riot)
{
	if (riot != NULL) {
		if (riot->dev_id_der) {
			riot_core_clear (riot->dev_id_der, riot->dev_id_length);
			platform_free (riot->dev_id_der);
		}

		if (riot->dev_id_valid) {
			riot->ecc->release_key_pair (riot->ecc, &riot->dev_id, NULL);
		}

		if (riot->dev_id_cert_valid) {
			riot->x509->release_certificate (riot->x509, &riot->dev_id_cert);
		}

		if (riot->alias_der) {
			platform_free (riot->alias_der);
		}

		if (riot->alias_key_valid) {
			riot->ecc->release_key_pair (riot->ecc, &riot->alias_key, NULL);
		}

		if (riot->alias_cert_valid) {
			riot->x509->release_certificate (riot->x509, &riot->alias_cert);
		}

		riot_core_clear (riot, sizeof (struct riot_core_common));
	}
}
