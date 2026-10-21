// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "aes_key_wrap.h"
#include "aes_key_wrap_with_padding.h"
#include "platform_api.h"
#include "common/buffer_util.h"
#include "common/common_math.h"
#include "common/unused.h"


/**
 * Constant portion of the IV to use for key wrapping.
 */
static const uint8_t AES_KEY_WRAP_WITH_PADDING_IV[] = {
	0xa6, 0x59, 0x59, 0xa6
};

/**
 * The maximum length supported for data to be wrapped.  The full 2^32 bytes can't be supported
 * since the aligned length of such data can't be represented in size_t on a 32-bit system.  Only
 * support up to the last 64-bit aligned length that can be represented in 32 bits.
 */
#define	AES_KEY_WRAP_WITH_PADDING_MAX_LENGTH				(0xffffffff & ~0x7)


int aes_key_wrap_with_padding_wrap (const struct aes_key_wrap_interface *aes_kw,
	const uint8_t *data, size_t length, uint8_t *wrapped, size_t out_length)
{
	const struct aes_key_wrap_with_padding *aes_kwp =
		(const struct aes_key_wrap_with_padding*) aes_kw;
	uint8_t initial_value[AES_KEY_WRAP_INTERFACE_BLOCK_SIZE];
	uint32_t mli = platform_htonl (length);
	size_t aligned_length = AES_KEY_WRAP_INTERFACE_ALIGNED_LENGTH (length);
	int status;

	if ((aes_kw == NULL) || (data == NULL) || (wrapped == NULL)) {
		return AES_KEY_WRAP_INVALID_ARGUMENT;
	}

	if (length == 0) {
		return AES_KEY_WRAP_NOT_ENOUGH_DATA;
	}

	if (length > AES_KEY_WRAP_WITH_PADDING_MAX_LENGTH) {
		return AES_KEY_WRAP_TOO_MUCH_DATA;
	}

	if (out_length < (aligned_length + AES_KEY_WRAP_INTERFACE_BLOCK_SIZE)) {
		return AES_KEY_WRAP_SMALL_OUTPUT_BUFFER;
	}

	memcpy (initial_value, AES_KEY_WRAP_WITH_PADDING_IV, sizeof (AES_KEY_WRAP_WITH_PADDING_IV));
	memcpy (&initial_value[sizeof (AES_KEY_WRAP_WITH_PADDING_IV)], &mli, sizeof (mli));

	if (&wrapped[AES_KEY_WRAP_INTERFACE_BLOCK_SIZE] != data) {
		/* If the input and output buffers are different, copy the data to the wrapped buffer. */
		memmove (&wrapped[AES_KEY_WRAP_INTERFACE_BLOCK_SIZE], data, length);
	}

	/* Add zero bytes as padding to align the data to 64-bit blocks. */
	memset (&wrapped[AES_KEY_WRAP_INTERFACE_BLOCK_SIZE + length], 0, aligned_length - length);

	if (aligned_length > AES_KEY_WRAP_INTERFACE_BLOCK_SIZE) {
		status = aes_key_wrap_data_wrap (&aes_kwp->base, initial_value, wrapped, aligned_length);
	}
	else {
		memcpy (wrapped, initial_value, AES_KEY_WRAP_INTERFACE_BLOCK_SIZE);

		status = aes_kwp->base.ecb->encrypt_data (aes_kwp->base.ecb, wrapped, AES_ECB_BLOCK_SIZE,
			wrapped, AES_ECB_BLOCK_SIZE);
	}

	if (status != 0) {
		buffer_zeroize (wrapped, out_length);
	}

	return status;
}

int aes_key_wrap_with_padding_unwrap (const struct aes_key_wrap_interface *aes_kw,
	const uint8_t *wrapped, size_t length, uint8_t *data, size_t *out_length)
{
	const struct aes_key_wrap_with_padding *aes_kwp =
		(const struct aes_key_wrap_with_padding*) aes_kw;
	uint8_t integrity_check[AES_KEY_WRAP_INTERFACE_BLOCK_SIZE];
	uint32_t *mli = (uint32_t*) &integrity_check[sizeof (AES_KEY_WRAP_WITH_PADDING_IV)];
	uint32_t data_length;
	size_t i;
	int status;

	if ((aes_kw == NULL) || (wrapped == NULL) || (data == NULL) || (out_length == NULL)) {
		return AES_KEY_WRAP_INVALID_ARGUMENT;
	}

	if (AES_KEY_WRAP_INTERFACE_ALIGNED_LENGTH (length) != length) {
		/* While the wrapped data doesn't need to be aligned, the unwrapped data must always be
		 * aligned to the AES key wrap block size. */
		return AES_KEY_WRAP_NOT_BLOCK_ALIGNED;
	}

	if (length < (AES_KEY_WRAP_INTERFACE_BLOCK_SIZE * 2)) {
		return AES_KEY_WRAP_NOT_ENOUGH_DATA;
	}

	if (*out_length < (length - AES_KEY_WRAP_INTERFACE_BLOCK_SIZE)) {
		return AES_KEY_WRAP_SMALL_OUTPUT_BUFFER;
	}

	if (length > AES_ECB_BLOCK_SIZE) {
		status = aes_key_wrap_data_unwrap (&aes_kwp->base, wrapped, length, data, integrity_check);
	}
	else {
		uint8_t b[AES_ECB_BLOCK_SIZE] = {0};

		memcpy (b, wrapped, length);

		status = aes_kwp->base.ecb->decrypt_data (aes_kwp->base.ecb, b, sizeof (b), b, sizeof (b));
		if (status == 0) {
			memcpy (data, &b[AES_KEY_WRAP_INTERFACE_BLOCK_SIZE], AES_KEY_WRAP_INTERFACE_BLOCK_SIZE);
			memcpy (integrity_check, b, AES_KEY_WRAP_INTERFACE_BLOCK_SIZE);
		}

		buffer_zeroize (b, sizeof (b));
	}

	if (status == 0) {
		if (buffer_compare (integrity_check, AES_KEY_WRAP_WITH_PADDING_IV,
			sizeof (AES_KEY_WRAP_WITH_PADDING_IV)) == 0) {
			data_length = platform_ntohl (*mli);

			/* Ensure the MIL falls within the expected range based on the length of the wrapped
			 * data.  It should always fall within one block size of the input length, after
			 * accounting for the 8-byte integrity check that is added to the wrapped data. */
			if ((length - (AES_KEY_WRAP_INTERFACE_BLOCK_SIZE * 2)) >= data_length) {
				status = AES_KEY_WRAP_LENGTH_CHECK_FAIL;
			}
			else if (data_length > (length - AES_KEY_WRAP_INTERFACE_BLOCK_SIZE)) {
				status = AES_KEY_WRAP_LENGTH_CHECK_FAIL;
			}
			else {
				/* If the length is valid, check any added padding bytes to ensure they are all
				 * zero.  Non-zero padding is a failure. */
				for (i = data_length; i < (length - AES_KEY_WRAP_INTERFACE_BLOCK_SIZE); i++) {
					if (data[i] != 0) {
						status = AES_KEY_WRAP_PADDING_CHECK_FAIL;
					}
				}
			}
		}
		else {
			status = AES_KEY_WRAP_INTEGRITY_CHECK_FAIL;
		}
	}

	if (status != 0) {
		buffer_zeroize (data, *out_length);
	}
	else {
		*out_length = data_length;
	}

	return status;
}

/**
 * Initialize a instance for encrypting data using the AES Key Wrap with Padding algorithm defined
 * in RFC 5649.
 *
 * @param aes_kwp The AES key wrap instance to initialize.
 * @param ecb AES engine to use for encrypting the data.
 *
 * @return 0 if the instance was initialized successfully or an error code.
 */
int aes_key_wrap_with_padding_init (struct aes_key_wrap_with_padding *aes_kwp,
	const struct aes_ecb_engine *ecb)
{
	if ((aes_kwp == NULL) || (ecb == NULL)) {
		return AES_KEY_WRAP_INVALID_ARGUMENT;
	}

	memset (aes_kwp, 0, sizeof (*aes_kwp));

	aes_kwp->base.base.set_kek = aes_key_wrap_set_kek;
	aes_kwp->base.base.clear_kek = aes_key_wrap_clear_kek;
	aes_kwp->base.base.wrap = aes_key_wrap_with_padding_wrap;
	aes_kwp->base.base.unwrap = aes_key_wrap_with_padding_unwrap;

	aes_kwp->base.ecb = ecb;

	return 0;
}

/**
 * Release the resources used for AES key wrap.
 *
 * @param aes_kwp The AES key wrap instance to release.
 */
void aes_key_wrap_with_padding_release (const struct aes_key_wrap_with_padding *aes_kwp)
{
	UNUSED (aes_kwp);
}
