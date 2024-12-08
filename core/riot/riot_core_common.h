// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef RIOT_CORE_COMMON_H_
#define RIOT_CORE_COMMON_H_

#include <stdbool.h>
#include "riot_core.h"
#include "asn1/base64.h"
#include "asn1/x509.h"
#include "asn1/x509_extension_builder.h"
#include "crypto/ecc.h"
#include "crypto/hash.h"


/**
 * Variable context for the general DICE layer 0 handler.
 */
struct riot_core_common_state {
	enum hash_type hash_algo;					/**< Hash algorithm for key generation and signatures. */
	enum hmac_hash kdf_algo;					/**< HMAC type to use for KDFs. */
	size_t digest_length;						/**< Length of all digests during key generation. */
	uint8_t cdi_hash[HASH_MAX_HASH_LEN];		/**< Buffer for the hash of the CDI. */
	char dev_id_name[X509_MAX_COMMON_NAME + 1];	/**< The name for the Device ID cert. */
	struct ecc_private_key dev_id;				/**< The Device ID key pair. */
	uint8_t *dev_id_der;						/**< DER formatted Device ID private key. */
	size_t dev_id_length;						/**< The length of the Device ID private key. */
	struct x509_certificate dev_id_cert;		/**< The X.509 certificate for the Device ID. */
	struct ecc_private_key alias_key;			/**< The Alias key pair. */
	uint8_t *alias_der;							/**< DER formatted Alias private key. */
	size_t alias_length;						/**< The length of the Alias private key. */
	struct x509_certificate alias_cert;			/**< The X.509 certificate for the Alias key. */
	bool dev_id_valid;							/**< Flag indicating validity of the Device ID. */
	bool dev_id_cert_valid;						/**< Flag indicating validity of the Device ID cert. */
	bool alias_key_valid;						/**< Flag indicating validity of the Alias key. */
	bool alias_cert_valid;						/**< Flag indicating validity of the Alias key cert. */
};

/**
 * A common implementation of DICE layer 0 using generic abstractions for cryptographic
 * implementations.
 */
struct riot_core_common {
	struct riot_core base;									/**< The base RIoT core instance. */
	struct riot_core_common_state *state;					/**< Variable context for RIoT Core. */
	const struct hash_engine *hash;							/**< The hash engine for RIoT Core operations. */
	const struct ecc_engine *ecc;							/**< The ECC engine for RIoT Core operations. */
	const struct base64_engine *base64;						/**< The base64 engine for RIoT Core operations. */
	const struct x509_engine *x509;							/**< The X.509 engine for RIoT Core operations. */
	const struct x509_extension_builder *const *dev_id_ext;	/**< List of custom extensions added to the Device ID certificate. */
	size_t dev_id_ext_count;								/**< Number of custom extensions in the Device ID certificate. */
	const struct x509_extension_builder *const *alias_ext;	/**< List of custom extensions added to the Alias certificate. */
	size_t alias_ext_count;									/**< Number of custom extensions in the Alias certificate. */
	size_t key_length;										/**< Length of the ECC keys to generate. */
};


int riot_core_common_init (struct riot_core_common *riot, struct riot_core_common_state *state,
	const struct hash_engine *hash, const struct ecc_engine *ecc, const struct x509_engine *x509,
	const struct base64_engine *base64, size_t key_length,
	const struct x509_extension_builder *const *device_id_ext, size_t device_id_ext_count,
	const struct x509_extension_builder *const *alias_ext, size_t alias_ext_count);
int riot_core_common_init_state (const struct riot_core_common *riot);
void riot_core_common_release (const struct riot_core_common *riot);

/* Internal functions for use by derived types. */
int riot_core_common_create_device_id_certificate (const struct riot_core_common *riot);


#endif	/* RIOT_CORE_COMMON_H_ */
