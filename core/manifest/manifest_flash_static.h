// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef MANIFEST_FLASH_STATIC_H_
#define MANIFEST_FLASH_STATIC_H_

#include "manifest_flash.h"


/**
 * Initialize a static instance for the common handling for manifests stored on flash.  Both version
 * 1 and version 2 style manifests can be supported.
 *
 * There is no validation done on the arguments.
 *
 * @param state_ptr Variable context for the manifest.
 * @param flash_ptr The flash device that contains the manifest.
 * @param hash_ptr A hash engine to use for validating run-time access of manifest elements.
 * @param base_addr_arg The starting address in flash of the manifest.
 * @param magic_num_v1_arg The magic number that identifies version 1 of the manifest.
 * @param magic_num_v2_arg The magic number that identifies version 2 of the manifest.
 * @param signature_cache_ptr Buffer to hold the manifest signature.
 * @param max_signature_arg The maximum supported length for a manifest signature.
 * @param platform_id_cache_ptr Buffer to hold the manifest platform ID.
 * @param max_platform_id_arg The maximum platform ID length supported, including the NULL
 * terminator.
 */
#define	manifest_flash_v2_static_init(state_ptr, flash_ptr, hash_ptr, base_addr_arg, \
	magic_num_v1_arg, magic_num_v2_arg, signature_cache_ptr, max_signature_arg, \
	platform_id_cache_ptr, max_platform_id_arg)	{ \
		.state = state_ptr, \
		.flash = flash_ptr, \
		.hash = hash_ptr, \
		.addr = base_addr_arg, \
		.magic_num_v1 = magic_num_v1_arg, \
		.magic_num_v2 = magic_num_v2_arg, \
		.signature = signature_cache_ptr, \
		.max_signature = max_signature_arg, \
		.platform_id = (char*) platform_id_cache_ptr, \
		.max_platform_id = max_platform_id_arg - 1, \
		.free_signature = false, \
	}


#endif	/* MANIFEST_FLASH_STATIC_H_ */
