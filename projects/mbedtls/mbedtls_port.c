// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <string.h>
#include "platform_port.h"
#include "common/unused.h"
#include "mbedtls/entropy.h"


/* mbedTLS hardware entropy callback function. */
int mbedtls_hardware_poll (void *data, unsigned char *output, size_t len, size_t *out_len)
{
	size_t copy_len;
	uint32_t val;

	UNUSED (data);

	if ((output == NULL) || (out_len == NULL)) {
		return MBEDTLS_ERR_ENTROPY_SOURCE_FAILED;
	}

	*out_len = len;
	while (len > 0) {
		val = platform_port_get_random_data ();

		/* Use memcpy in case the destination buffer is not 32-bit aligned. */
		copy_len = min (len, sizeof (uint32_t));
		memcpy (output, &val, copy_len);

		output += copy_len;
		len -= copy_len;
	}

	return 0;
}
