// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef RIOT_CORE_COMMON_H_
#define RIOT_CORE_COMMON_H_

#include <stdbool.h>
#include "riot_core.h"
#include "crypto/hash.h"
#include "crypto/ecc.h"
#include "crypto/x509.h"
#include "crypto/base64.h"


/**
 * A common implementation of RIoT core using generic abstractions for cryptographic
 * implementations.
 */
struct riot_core_common {
	struct riot_core base;					/**< The base RIoT core instance. */
	struct hash_engine *hash;				/**< The hash engine for RIoT Core operations. */
	struct ecc_engine *ecc;					/**< The ECC engine for RIoT Core operations. */
	struct x509_engine *x509;				/**< The X.509 engine for RIoT Core operations. */
	struct base64_engine *base64;			/**< The base64 engine for RIoT Core operations. */
	uint8_t cdi_hash[SHA256_HASH_LENGTH];	/**< Buffer for the hash of the CDI. */
	char dev_id_name[BASE64_LENGTH (SHA256_HASH_LENGTH)];	/**< The name for the Device ID cert. */
	struct ecc_private_key dev_id;			/**< The Device ID key pair. */
	uint8_t *dev_id_der;					/**< DER formatted Device ID private key. */
	size_t dev_id_length;					/**< The length of the Device ID private key. */
	const struct x509_dice_tcbinfo *tcb;	/**< TCB information for the Device ID certificate. */
	struct x509_certificate dev_id_cert;	/**< The X.509 certificate for the Device ID. */
	struct ecc_private_key alias_key;		/**< The Alias key pair. */
	uint8_t *alias_der;						/**< DER formatted Alias private key. */
	size_t alias_length;					/**< The length of the Alias private key. */
	struct x509_certificate alias_cert;		/**< The X.509 certificate for the Alias key. */
	bool dev_id_valid;						/**< Flag indicating validity of the Device ID. */
	bool dev_id_cert_valid;					/**< Flag indicating validity of the Device ID cert. */
	bool alias_key_valid;					/**< Flag indicating validity of the Alias key. */
	bool alias_cert_valid;					/**< Flag indicating validity of the Alias key cert. */
};


int riot_core_common_init (struct riot_core_common *riot, struct hash_engine *hash,
	struct ecc_engine *ecc, struct x509_engine *x509, struct base64_engine *base64);
void riot_core_common_release (struct riot_core_common *riot);


#endif /* RIOT_CORE_COMMON_H_ */
