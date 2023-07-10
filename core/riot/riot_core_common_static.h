// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef RIOT_CORE_COMMON_STATIC_H_
#define RIOT_CORE_COMMON_STATIC_H_

#include "riot_core_common.h"


/* Internal functions declared to allow for static initialization. */
int riot_core_common_generate_device_id (const struct riot_core *riot, const uint8_t *cdi,
	size_t length);
int riot_core_common_get_device_id_csr (const struct riot_core *riot, const uint8_t *oid,
	size_t oid_length, uint8_t **csr, size_t *length);
int riot_core_common_get_device_id_cert (const struct riot_core *riot, uint8_t **device_id,
	size_t *length);
int riot_core_common_generate_alias_key (const struct riot_core *riot, const uint8_t *fwid,
	size_t length);
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
 * @param hash_ptr The hash engine to use with DICE.
 * @param ecc_ptr The ECC engine to use with DICE.
 * @param x509_ptr The X.509 certificate engine to use with DICE.
 * @param base64_ptr The base64 encoding engine to use with DICE.
 * @param key_len Length of the DICE keys that should be created.
 * @param device_id_ext_ptr A list of additional, custom extensions that should be added to the
 * Device ID certificate and CSR.  At minimum, this should include the DICE TcbInfo extension for
 * layer 0.
 * @param device_id_ext_cnt The number of custom extensions to add to the Device ID certificate
 * and CSR.
 * @param alias_ext_ptr A list of additional, custom extensions that should be added to the
 * Alias certificate.  At minimum, this should include the DICE TcbInfo extension for layer 1.
 * @param alias_ext_cnt The number of custom extensions to add to the Alias certificate.
 */
#define	riot_core_common_static_init(state_ptr, hash_ptr, ecc_ptr, x509_ptr, base64_ptr, key_len, \
	device_id_ext_ptr, device_id_ext_cnt, alias_ext_ptr, alias_ext_cnt) \
	{ \
		.base = RIOT_CORE_COMMON_API_INIT, \
		.state = state_ptr, \
		.hash = hash_ptr, \
		.ecc = ecc_ptr, \
		.base64 = base64_ptr, \
		.x509 = x509_ptr, \
		.dev_id_ext = device_id_ext_ptr, \
		.dev_id_ext_count = device_id_ext_cnt, \
		.alias_ext = alias_ext_ptr, \
		.alias_ext_count = alias_ext_cnt, \
		.key_length = key_len, \
	}


#endif /* RIOT_CORE_COMMON_STATIC_H_ */
