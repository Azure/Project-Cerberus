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
 * @return The total length, including header, of the item or error.
 */
int asn1_get_der_item_len (const uint8_t *der, size_t der_len)
{
	int header_len;
	int length;

	if (der == NULL) {
		return 0;
	}

	if (der_len < 3) {
		return ASN1_NOT_VALID;
	}

	switch (der[1]) {
		case 0x81:
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
