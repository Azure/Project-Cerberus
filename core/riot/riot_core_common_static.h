// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef RIOT_CORE_COMMON_STATIC_H_
#define RIOT_CORE_COMMON_STATIC_H_

#include "riot_core_common.h"


/* Internal functions declared to allow for static initialization. */
int riot_core_common_generate_device_id (const struct riot_core *riot, const uint8_t *cdi,
	size_t length, const struct x509_dice_tcbinfo *riot_tcb);
int riot_core_common_get_device_id_csr (const struct riot_core *riot, const char *oid,
	uint8_t **csr, size_t *length);
int riot_core_common_get_device_id_cert (const struct riot_core *riot, uint8_t **device_id,
	size_t *length);
int riot_core_common_generate_alias_key (const struct riot_core *riot,
	const struct x509_dice_tcbinfo *alias_tcb);
int riot_core_common_get_alias_key (const struct riot_core *riot, uint8_t **key, size_t *length);
int riot_core_common_get_alias_key_cert (const struct riot_core *riot, uint8_t **alias_key,
	size_t *length);


/**
 * Constant initializer for the RIoT core API.
 */
#define	RIOT_CORE_COMMON_API_INIT  { \
		.generate_device_id = riot_core_common_generate_device_id, \
		.get_device_id_csr = riot_core_common_get_device_id_csr, \
		.get_device_id_cert = riot_core_common_get_device_id_cert, \
		.generate_alias_key = riot_core_common_generate_alias_key, \
		.get_alias_key = riot_core_common_get_alias_key, \
		.get_alias_key_cert = riot_core_common_get_alias_key_cert \
	}


/**
 * Initialize a static instance for DICE layer 0 handling.  This can be a constant instance.
 *
 * There is no validation done on the arguments.
 *
 * @param state_ptr Variable context for DICE handling.
 * @param hash_ptr The hash engine to use with RIoT Core.
 * @param ecc_ptr The ECC engine to use with RIoT Core.
 * @param x509_ptr The X.509 certificate engine to use with RIoT Core.
 * @param base64_ptr The base64 encoding engine to use with RIoT Core.
 * @param key_len Length of the DICE keys that should be created.
 */
#define	riot_core_common_static_init(state_ptr, hash_ptr, ecc_ptr, x509_ptr, base64_ptr, key_len) \
	{ \
		.base = RIOT_CORE_COMMON_API_INIT, \
		.state = state_ptr, \
		.hash = hash_ptr, \
		.ecc = ecc_ptr, \
		.x509 = x509_ptr, \
		.base64 = base64_ptr, \
		.key_length = key_len, \
	}


#endif /* RIOT_CORE_COMMON_STATIC_H_ */
