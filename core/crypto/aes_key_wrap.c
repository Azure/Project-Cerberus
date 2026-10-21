// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "aes_key_wrap.h"
#include "platform_api.h"
#include "common/buffer_util.h"
#include "common/common_math.h"
#include "common/unused.h"


/**
 * Constant IV to use for key wrapping.
 */
static const uint8_t AES_KEY_WRAP_IV[AES_KEY_WRAP_INTERFACE_BLOCK_SIZE] = {
	0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6
};

/**
 * The number of data blocks present in the input data.
 *
 * @param length Length of the input data
 */
#define	AES_KEY_WRAP_BLOCK_COUNT(length)		((length) / AES_KEY_WRAP_INTERFACE_BLOCK_SIZE)

/**
 * The number of iterations to run the wrapping over the entire data.
 */
#define	AES_KEY_WRAP_ITERATIONS					6


int aes_key_wrap_set_kek (const struct aes_key_wrap_interface *aes_kw, const uint8_t *kek,
	size_t length)
{
	const struct aes_key_wrap *key_wrap = (const struct aes_key_wrap*) aes_kw;

	if (aes_kw == NULL) {
		return AES_KEY_WRAP_INVALID_ARGUMENT;
	}

	return key_wrap->ecb->set_key (key_wrap->ecb, kek, length);
}

int aes_key_wrap_clear_kek (const struct aes_key_wrap_interface *aes_kw)
{
	const struct aes_key_wrap *key_wrap = (const struct aes_key_wrap*) aes_kw;

	if (aes_kw == NULL) {
		return AES_KEY_WRAP_INVALID_ARGUMENT;
	}

	return key_wrap->ecb->clear_key (key_wrap->ecb);
}

/**
 * Execute AES key wrapping over the entire set of data.
 *
 * @param key_wrap The AES key wrap instance to use.
 * @param initial_value The initial value to assign to A[0] for the wrapping process.
 * @param wrapped Input/output buffer that holds the data being wrapped.  This should point to the
 * beginning of the wrapped buffer, not the beginning of the data.  The first 64-bits will be used
 * to store the resulting integrity check value.  Data will be wrapped in place.
 * @param length Length of the data being wrapped.  This is just the length of the data, not the
 * total length of the wrapped buffer.  It's assumed the buffer is at least length + 8 bytes.
 *
 * @return 0 if the wrapping was successful or an error code.
 */
int aes_key_wrap_data_wrap (const struct aes_key_wrap *key_wrap,
	const uint8_t initial_value[AES_KEY_WRAP_INTERFACE_BLOCK_SIZE], uint8_t *wrapped, size_t length)
{
	uint8_t b[AES_ECB_BLOCK_SIZE] = {0};
	uint64_t *a = (uint64_t*) b;
	uint8_t *r = &b[AES_KEY_WRAP_INTERFACE_BLOCK_SIZE];
	int n = AES_KEY_WRAP_BLOCK_COUNT (length);
	uint64_t t = 0;
	int i;
	int j;
	int status;

	memcpy (a, initial_value, AES_KEY_WRAP_INTERFACE_BLOCK_SIZE);

	for (j = 0; j < AES_KEY_WRAP_ITERATIONS; j++) {
		for (i = 1; i <= n; i++) {
			memcpy (r, &wrapped[i * AES_KEY_WRAP_INTERFACE_BLOCK_SIZE],
				AES_KEY_WRAP_INTERFACE_BLOCK_SIZE);

			status = key_wrap->ecb->encrypt_data (key_wrap->ecb, b, sizeof (b), b, sizeof (b));
			if (status != 0) {
				goto exit;
			}

			/* This call cannot fail as the counter will never roll over. */
			common_math_increment_byte_array ((uint8_t*) &t, sizeof (t), false);

			*a ^= t;
			memcpy (&wrapped[i * AES_KEY_WRAP_INTERFACE_BLOCK_SIZE], r,
				AES_KEY_WRAP_INTERFACE_BLOCK_SIZE);
		}
	}

	/* Save the integrity check value to the beginning of the wrapped data. */
	memcpy (wrapped, a, AES_KEY_WRAP_INTERFACE_BLOCK_SIZE);

exit:
	buffer_zeroize (b, sizeof (b));

	return status;
}

int aes_key_wrap_wrap (const struct aes_key_wrap_interface *aes_kw, const uint8_t *data,
	size_t length, uint8_t *wrapped, size_t out_length)
{
	const struct aes_key_wrap *key_wrap = (const struct aes_key_wrap*) aes_kw;
	int status;

	if ((aes_kw == NULL) || (data == NULL) || (wrapped == NULL)) {
		return AES_KEY_WRAP_INVALID_ARGUMENT;
	}

	if (AES_KEY_WRAP_INTERFACE_NOT_BLOCK_ALGINED (length)) {
		return AES_KEY_WRAP_NOT_BLOCK_ALIGNED;
	}

	if (length < (AES_KEY_WRAP_INTERFACE_BLOCK_SIZE * 2)) {
		return AES_KEY_WRAP_NOT_ENOUGH_DATA;
	}

	if (out_length < (length + AES_KEY_WRAP_INTERFACE_BLOCK_SIZE)) {
		return AES_KEY_WRAP_SMALL_OUTPUT_BUFFER;
	}

	if (&wrapped[AES_KEY_WRAP_INTERFACE_BLOCK_SIZE] != data) {
		/* If the input and output buffers are different, copy the data to the wrapped buffer. */
		memmove (&wrapped[AES_KEY_WRAP_INTERFACE_BLOCK_SIZE], data, length);
	}

	status = aes_key_wrap_data_wrap (key_wrap, AES_KEY_WRAP_IV, wrapped, length);
	if (status != 0) {
		buffer_zeroize (wrapped, out_length);
	}

	return status;
}

/**
 * Execute AES key unwrapping over the entire set of data.
 *
 * @param key_wrap The AES key wrap instance to use.
 * @param wrapped Wrapped data that will be unwrapped.
 * @param length Length of the wrapped data.
 * @param data Output buffer for the data being unwrapped.  This can overlap the wrapped buffer.
 * @param integrity_check Output for the value of A[0] to serve as an integrity check of the
 * unwrapped data.
 *
 * @return 0 if the unwrapping round was successful or an error code.
 */
int aes_key_wrap_data_unwrap (const struct aes_key_wrap *key_wrap, const uint8_t *wrapped,
	size_t length, uint8_t *data, uint8_t integrity_check[AES_KEY_WRAP_INTERFACE_BLOCK_SIZE])
{
	uint8_t b[AES_ECB_BLOCK_SIZE] = {0};
	uint64_t *a = (uint64_t*) b;
	uint8_t *r = &b[AES_KEY_WRAP_INTERFACE_BLOCK_SIZE];
	int n = AES_KEY_WRAP_BLOCK_COUNT (length - AES_KEY_WRAP_INTERFACE_BLOCK_SIZE);
	uint64_t t = platform_htonll ((uint64_t) (n * AES_KEY_WRAP_ITERATIONS));
	int i;
	int j;
	int status = 0;

	memcpy (a, wrapped, AES_KEY_WRAP_INTERFACE_BLOCK_SIZE);
	if (data != &wrapped[AES_KEY_WRAP_INTERFACE_BLOCK_SIZE]) {
		/* If the input and output buffers are different, copy the wrapped data to the output
		 * buffer. */
		memmove (data, &wrapped[AES_KEY_WRAP_INTERFACE_BLOCK_SIZE],
			length - AES_KEY_WRAP_INTERFACE_BLOCK_SIZE);
	}

	for (j = 0; j < AES_KEY_WRAP_ITERATIONS; j++) {
		for (i = (n - 1); i >= 0; i--) {
			*a ^= t;
			memcpy (r, &data[i * AES_KEY_WRAP_INTERFACE_BLOCK_SIZE],
				AES_KEY_WRAP_INTERFACE_BLOCK_SIZE);

			status = key_wrap->ecb->decrypt_data (key_wrap->ecb, b, sizeof (b), b, sizeof (b));
			if (status != 0) {
				goto exit;
			}

			/* This call cannot fail as the counter will never roll over. */
			common_math_decrement_byte_array ((uint8_t*) &t, sizeof (t), false);

			memcpy (&data[i * AES_KEY_WRAP_INTERFACE_BLOCK_SIZE], r,
				AES_KEY_WRAP_INTERFACE_BLOCK_SIZE);
		}
	}

	/* Save the value of A[0] for integrity checks executed by the caller. */
	memcpy (integrity_check, a, AES_KEY_WRAP_INTERFACE_BLOCK_SIZE);

exit:
	buffer_zeroize (b, sizeof (b));

	return status;
}

int aes_key_wrap_unwrap (const struct aes_key_wrap_interface *aes_kw, const uint8_t *wrapped,
	size_t length, uint8_t *data, size_t *out_length)
{
	const struct aes_key_wrap *key_wrap = (const struct aes_key_wrap*) aes_kw;
	uint8_t integrity_check[AES_KEY_WRAP_INTERFACE_BLOCK_SIZE];
	int status;

	if ((aes_kw == NULL) || (wrapped == NULL) || (data == NULL) || (out_length == NULL)) {
		return AES_KEY_WRAP_INVALID_ARGUMENT;
	}

	if (AES_KEY_WRAP_INTERFACE_NOT_BLOCK_ALGINED (length)) {
		return AES_KEY_WRAP_NOT_BLOCK_ALIGNED;
	}

	if (length < (AES_KEY_WRAP_INTERFACE_BLOCK_SIZE * 3)) {
		return AES_KEY_WRAP_NOT_ENOUGH_DATA;
	}

	if (*out_length < (length - AES_KEY_WRAP_INTERFACE_BLOCK_SIZE)) {
		return AES_KEY_WRAP_SMALL_OUTPUT_BUFFER;
	}

	status = aes_key_wrap_data_unwrap (key_wrap, wrapped, length, data, integrity_check);
	if (status == 0) {
		if (buffer_compare (integrity_check, AES_KEY_WRAP_IV,
			AES_KEY_WRAP_INTERFACE_BLOCK_SIZE) == 0) {
			*out_length = length - AES_KEY_WRAP_INTERFACE_BLOCK_SIZE;
		}
		else {
			status = AES_KEY_WRAP_INTEGRITY_CHECK_FAIL;
		}
	}

	if (status != 0) {
		buffer_zeroize (data, *out_length);
	}

	return status;
}

/**
 * Initialize a instance for encrypting data using the AES Key Wrap algorithm from RFC 3394.
 *
 * @param aes_kw The AES key wrap instance to initialize.
 * @param ecb AES engine to use for encrypting the data.
 *
 * @return 0 if the instance was initialized successfully or an error code.
 */
int aes_key_wrap_init (struct aes_key_wrap *aes_kw, const struct aes_ecb_engine *ecb)
{
	if ((aes_kw == NULL) || (ecb == NULL)) {
		return AES_KEY_WRAP_INVALID_ARGUMENT;
	}

	memset (aes_kw, 0, sizeof (*aes_kw));

	aes_kw->base.set_kek = aes_key_wrap_set_kek;
	aes_kw->base.clear_kek = aes_key_wrap_clear_kek;
	aes_kw->base.wrap = aes_key_wrap_wrap;
	aes_kw->base.unwrap = aes_key_wrap_unwrap;

	aes_kw->ecb = ecb;

	return 0;
}

/**
 * Release the resources used for AES key wrap.
 *
 * @param aes_kw The AES key wrap instance to release.
 */
void aes_key_wrap_release (const struct aes_key_wrap *aes_kw)
{
	UNUSED (aes_kw);
}
