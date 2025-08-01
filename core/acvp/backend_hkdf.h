// Copyright (c) Microsoft Corporation. All rights reserved.

#ifndef BACKEND_HKDF_H_
#define BACKEND_HKDF_H_

#include <stddef.h>
#include "crypto/hkdf_interface.h"
#include "parser/parser_kda_hkdf.h"
#include "status/rot_status.h"


/**
 * Backend HKDF engine structure used for ACVP test handling.
 */
struct backend_hkdf_engine {
	int impl_id;						/**< Implementation identifier. */
	const struct hkdf_interface *intf;	/**< Interface to the HKDF instance use. */
};


const struct hkdf_backend* backend_hkdf_get_impl ();


void backend_hkdf_register_engines (const struct backend_hkdf_engine *hkdf,	size_t num_engines);
void backend_hkdf_register_impl (void);


#define BACKEND_HKDF_ERROR(code)		ROT_ERROR (ROT_MODULE_BACKEND_HKDF, code)

/**
 * Error codes that can be generated by backend HKDF handling.
 */
enum {
	BACKEND_HKDF_INVALID_ARGUMENT = BACKEND_HKDF_ERROR (0x00),	/**< Input parameter is null or not valid. */
	BACKEND_HKDF_NO_MEMORY = BACKEND_HKDF_ERROR (0x01),			/**< Memory allocation failed. */
	BACKEND_HKDF_NO_ENGINE = BACKEND_HKDF_ERROR (0x02),			/**< No HKDF engine is available. */
	BACKEND_HKDF_ENGINE_NOT_FOUND = BACKEND_HKDF_ERROR (0x03),	/**< No HKDF engine found for the specified implementation. */
	BACKEND_HKDF_HKDF_FAILED = BACKEND_HKDF_ERROR (0x04),		/**< HKDF operation failed. */
};


#endif	/* BACKEND_HKDF_H_ */
