// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdint.h>
#include "asn1.h"


/**
 * Type tags used in ASN.1 encoding.
 */
enum {
	ASN1_TAG_INTEGER = 0x02			/**< ASN.1 INTEGER value. */
};


/**
 * Get the total length of a ASN.1 item from DER formatted data.
 *
 * @param der The DER formatted ASN.1 data.
 * @param der_len Total length of der buffer.
 *
 * @return The total length of the item, including the header, or ASN1_NOT_VALID if the length
 * cannot be determined.
 */
int asn1_get_der_item_len (const uint8_t *der, size_t der_len)
{
	int header_len;
	int length;

	if (der == NULL) {
		return 0;
	}

	if (der_len < 2) {
		return ASN1_NOT_VALID;
	}

	switch (der[1]) {
		case 0x81:
			if (der_len < 3) {
				return ASN1_NOT_VALID;
			}

			header_len = 3;
			length = der[2];

			break;

		case 0x82:
			if (der_len < 4) {
				return ASN1_NOT_VALID;
			}

			header_len = 4;
			length = (der[2] << 8) | der[3];

			break;

		case 0x83:
			if (der_len < 5) {
				return ASN1_NOT_VALID;
			}

			header_len = 5;
			length = (der[2] << 16) | (der[3] << 8) | der[4];

			break;

		case 0x84:
			if (der_len < 6) {
				return ASN1_NOT_VALID;
			}

			header_len = 6;
			length = (der[2] << 24) | (der[3] << 16) | (der[4] << 8) | der[5];

			break;

		default:
			if (der[1] < 0x80) {
				header_len = 2;
				length = der[1];
			}
			else {
				return ASN1_NOT_VALID;
			}

			break;
	}

	return (length + header_len);
}

/**
 * Inspect DER encoded ASN.1 data to determine the total length of the data.  The length
 * will be returned with the following conditions:
 *	- If the encoded length is less than buffer length, the encoded length will be returned.
 *	- If the encoded length is less than or equal to the buffer length, the buffer length will be
 *		returned.
 *	- If the encoded length cannot be determined, the buffer length will be returned.
 *	- If the DER buffer is null, 0 will be returned.
 *
 * @param der ASN.1/DER encoded data to inspect.
 * @param max_length Length of the data buffer containing the ASN.1/DER data.
 *
 * @return Length of the encoded data contained within the buffer.
 */
size_t asn1_get_der_encoded_length (const uint8_t *der, size_t max_length)
{
	size_t der_length;

	der_length = asn1_get_der_item_len (der, max_length);
	if (max_length <= der_length) {
		return max_length;
	}
	else {
		return der_length;
	}
}

/**
 * Encode an integer value as an DER encoded ASN.1 INTEGER.
 *
 * @param value The value to encode.
 * @param der Output for the DER encoded data.
 * @param length Length of the DER output buffer.
 *
 * @return Length of the encoded data or an error code.
 */
int asn1_encode_integer (uint64_t value, uint8_t *der, size_t length)
{
	size_t i = 56;
	size_t der_length = 0;

	if (der == NULL) {
		return ASN1_INVALID_ARGUMENT;
	}

	if (length < 3) {
		/* Every encoded integer will be at least 3 bytes. */
		return ASN1_SMALL_DER_BUFFER;
	}

	/* Find the first non-zero byte. */
	while (((i > 0) && ((value >> i) & 0xff) == 0)) {
		i -= 8;
	}

	/* Add an extra zero if the sign bit would be negative. */
	if ((value >> i) & 0x80) {
		der[2] = 0;
		der_length++;
	}

	/* Add all bytes after the first non-zero byte, but make sure the LSB is always added. */
	i += 8;
	do {
		i -= 8;

		if (length > (2 + der_length)) {
			der[2 + der_length++] = value >> i;
		}
		else {
			return ASN1_SMALL_DER_BUFFER;
		}
	} while (i > 0);

	/* INTEGER tag and length. */
	der[0] = ASN1_TAG_INTEGER;
	der[1] = der_length;

	return 2 + der_length;
}

/**
 * Decode an integer value that is ASN.1/DER encoded.
 *
 * @param der The DER encoded integer value.
 * @param length Length of the DER buffer.
 * @param value Output for the decoded integer value.
 *
 * @return 0 if the value was decoded successfully or an error code.
 */
int asn1_decode_integer (const uint8_t *der, size_t length, uint64_t *value)
{
	int i;
	int der_length;
	uint64_t tmp = 0;

	if ((der == NULL) || (value == NULL)) {
		return ASN1_INVALID_ARGUMENT;
	}

	der_length = asn1_get_der_item_len (der, length);
	if (der_length == ASN1_NOT_VALID) {
		return der_length;
	}

	if ((size_t) der_length > length) {
		return ASN1_SMALL_DER_BUFFER;
	}

	if (der[0] != ASN1_TAG_INTEGER) {
		return ASN1_UNEXPECTED_TAG;
	}

	der_length -= 2;
	der += 2;

	if (der[0] & 0x80) {
		/* This API does not support negative integers. */
		return ASN1_OUT_OF_RANGE;
	}

	if ((der_length > 9) || ((der_length == 9) && (der[0] != 0))) {
		/* Anything larger than 8 bytes will not fit into a 64-bit integer. */
		return ASN1_OUT_OF_RANGE;
	}

	for (i = 0; i < der_length; i++) {
		tmp = (tmp << 8) + der[i];
	}

	*value = tmp;
	return 0;
}
