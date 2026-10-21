// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <string.h>
#include "cert_chain_verifier_interface.h"
#include "platform_api.h"


/**
 * Release the buffers a successful finalize_verification transferred to a result, and clear the
 * struct.  Safe to call on a zeroed or already-released result.
 *
 * @param result The result whose owned buffers should be freed.  This can be null.
 */
void cert_chain_verifier_result_release (struct cert_chain_verifier_result *result)
{
	if (result != NULL) {
		platform_free ((void*) result->alias_key);
		platform_free ((void*) result->root_cert.cert);
		memset (result, 0, sizeof (*result));
	}
}
