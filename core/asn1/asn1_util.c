// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdint.h>
#include <string.h>
#include "asn1_util.h"


/**
 * Type tags used in ASN.1 encoding.
 */
enum {
	ASN1_TAG_INTEGER = 0x02,				/**< ASN.1 INTEGER value. */
	ASN1_TAG_OBJECT_IDENTIFIER = 0x06,		/**< ASN.1 OBJECT IDENTIFIER value. */
};


/**
 * Parse a DER encoded ASN.1 header to determine the encoded item length.
 *
 * @param der The DER formatted data pointing to the beginning of the header to parse.
 * @param der_length Total length of the DER data.
 * @param item_length Output for the length of the encoded item.
 * @param header_length Output for the length ASN.1 header on the item.
 *
 * @return 0 if the header was parse successfully or ASN1_UTIL_NOT_VALID if the length cannot be
 * determined.
 */
static int asn1_parse_der_header (const uint8_t *der, size_t der_length, size_t *item_length,
	size_t *header_length)
{
	if (der_length < 2) {
		return ASN1_UTIL_NOT_VALID;
	}

	switch (der[1]) {
		case 0x81:
			if (der_length < 3) {
				return ASN1_UTIL_NOT_VALID;
			}

			*header_length = 3;
			*item_length = der[2];

			break;

		case 0x82:
			if (der_length < 4) {
				return ASN1_UTIL_NOT_VALID;
			}

			*header_length = 4;
			*item_length = (der[2] << 8) | der[3];

			break;

		case 0x83:
			if (der_length < 5) {
				return ASN1_UTIL_NOT_VALID;
			}

			*header_length = 5;
			*item_length = (der[2] << 16) | (der[3] << 8) | der[4];

			break;

		case 0x84:
			if (der_length < 6) {
				return ASN1_UTIL_NOT_VALID;
			}

			*header_length = 6;
			*item_length = (der[2] << 24) | (der[3] << 16) | (der[4] << 8) | der[5];

			break;

		default:
			if (der[1] < 0x80) {
				*header_length = 2;
				*item_length = der[1];
			}
			else {
				return ASN1_UTIL_NOT_VALID;
			}

			break;
	}

	return 0;
}

/**
 * Get the next item in a DER encoded ASN.1 buffer.
 *
 * @param tag The expected tag for the next item in the buffer.
 * @param der Buffer that contains the DER encoded data.  This must point to the beginning of the
 * header for the next item.  Upon output, this pointer will be updated to point to the item data.
 * @param der_length Total length of the DER buffer.  Upon output, this will be updated with the
 * remaining length of DER data.
 * @param length Output for the length of the encoded item.
 *
 * @return 0 if the item was retrieved successfully or an error code.
 */
static int asn1_get_item (uint8_t tag, const uint8_t **der, size_t *der_length, size_t *length)
{
	size_t header_length;
	int status;

	status = asn1_parse_der_header (*der, *der_length, length, &header_length);
	if (status != 0) {
		return status;
	}

	if ((*der)[0] != tag) {
		return ASN1_UTIL_UNEXPECTED_TAG;
	}

	if ((size_t) (header_length + *length) > *der_length) {
		return ASN1_UTIL_SMALL_DER_BUFFER;
	}

	*der += header_length;
	*der_length -= header_length;

	return 0;
}

/**
 * Get the total length of a ASN.1 item from DER formatted data.
 *
 * @param der The DER formatted ASN.1 data.
 * @param der_len Total length of DER buffer.
 *
 * @return The total length of the item, including the header, or ASN1_UTIL_NOT_VALID if the length
 * cannot be determined.  A null buffer will result in a length of 0.
 */
int asn1_get_der_item_len (const uint8_t *der, size_t der_len)
{
	size_t header_len;
	size_t length;
	int status;

	if (der == NULL) {
		return 0;
	}

	status = asn1_parse_der_header (der, der_len, &length, &header_len);
	if (status == 0) {
		status = length + header_len;
	}

	return status;
}

/**
 * Inspect DER encoded ASN.1 data to determine the total length of the data.  The length
 * will be returned with the following conditions:
 *	- If the encoded length is less than buffer length, the encoded length will be returned.
 *	- If the buffer length is less than or equal to the encoded length, the buffer length will be
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
 * Encode an integer value as a DER encoded ASN.1 INTEGER.
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
		return ASN1_UTIL_INVALID_ARGUMENT;
	}

	if (length < 3) {
		/* Every encoded integer will be at least 3 bytes. */
		return ASN1_UTIL_SMALL_DER_BUFFER;
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
			return ASN1_UTIL_SMALL_DER_BUFFER;
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
	size_t i;
	size_t der_length;
	uint64_t tmp = 0;
	int status;

	if ((der == NULL) || (value == NULL)) {
		return ASN1_UTIL_INVALID_ARGUMENT;
	}

	status = asn1_get_item (ASN1_TAG_INTEGER, &der, &length, &der_length);
	if (status != 0) {
		return status;
	}

	if (der[0] & 0x80) {
		/* This API does not support negative integers. */
		return ASN1_UTIL_OUT_OF_RANGE;
	}

	if ((der_length > 9) || ((der_length == 9) && (der[0] != 0))) {
		/* Anything larger than 8 bytes will not fit into a 64-bit integer. */
		return ASN1_UTIL_OUT_OF_RANGE;
	}

	for (i = 0; i < der_length; i++) {
		tmp = (tmp << 8) + der[i];
	}

	*value = tmp;
	return 0;
}

/**
 * Encode an OID value as a DER encoded ASN.1 OBJECT IDENTIFIER.  The OID value itself must already
 * be base128 encoded per DER rules.  No additional processing of the value will be performed.
 *
 * @param oid The base128 encoded OID to DER encode.
 * @param oid_length Length of the OID data.
 * @param der Output for the DER encoded data.
 * @param length Length of the DER output buffer.
 *
 * @return Length of the encoded data or an error code.
 */
int asn1_encode_base128_oid (const uint8_t *oid, size_t oid_length, uint8_t *der, size_t length)
{
	size_t der_length = 2 + oid_length;

	if ((oid == NULL) || (oid_length == 0) || (der == NULL)) {
		return ASN1_UTIL_INVALID_ARGUMENT;
	}

	if (oid_length > 127) {
		/* Most OIDs are short, so assume there will never be an OID that requires more than one
		 * length byte for encoding. */
		return ASN1_UTIL_OUT_OF_RANGE;
	}

	if (length < der_length) {
		return ASN1_UTIL_SMALL_DER_BUFFER;
	}

	der[0] = 0x06;
	der[1] = oid_length;
	memcpy (&der[2], oid, oid_length);

	return der_length;
}

/**
 * Decode an OID value that is ASN.1/DER encoded.  The OID will remain base128 encoded per DER
 * rules.
 *
 * @param der The DER encoded object identifier.
 * @param length Length of the DER buffer.
 * @param oid Output for the decoded OID.  This will be a pointer to the value in the DER buffer, so
 * is only valid as long as the DER buffer is valid.
 * @param oid_length Output for the length of the OID data.
 *
 * @return 0 if the OID was decoded successfully or an error code.
 */
int asn1_decode_base128_oid (const uint8_t *der, size_t length, const uint8_t **oid,
	size_t *oid_length)
{
	if ((der == NULL) || (oid == NULL) || (oid_length == NULL)) {
		return ASN1_UTIL_INVALID_ARGUMENT;
	}

	*oid = der;
	return asn1_get_item (ASN1_TAG_OBJECT_IDENTIFIER, oid, &length, oid_length);
}
