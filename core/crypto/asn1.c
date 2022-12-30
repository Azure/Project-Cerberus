// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdint.h>
#include "asn1.h"


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
