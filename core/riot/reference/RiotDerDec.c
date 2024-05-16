// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "platform_api.h"
#include "asn1/x509_cert_build.h"
#include "include/RiotDerDec.h"
#include "include/RiotStatus.h"
#include "include/RiotX509Bldr.h"


#define ASRT(_X) if(!(_X))     {goto Error;}
#define CHK(_X) if(((_X)) < 0) {goto Error;}

//
// This file contains basic DER-decoding routines that are sufficient to create
// RIoT X.509 certificates.
//
// Routines in this file encode the following types:
//    SEQUENCE
//    SET
//    INTEGER
//    BIT STRING
//    OCTET STRING
//    OID
//    UTF8String
//
// This file also contains helper DER-decoding routines to create RIoT X.509 certificates.
//
static int read_length (size_t *len, const uint8_t *der, size_t der_len, size_t *position)
{
	size_t length;
	uint8_t header;
	size_t pos = *position;

	if (pos >= der_len) {
		return -1;
	}

	switch (der[pos]) {
		case 0x81:
			header = 2;
			if ((pos + 1) >= der_len) {
				return -1;
			}
			length = (size_t) der[pos + 1];
			break;

		case 0x82:
			header = 3;
			if ((pos + 2) >= der_len) {
				return -1;
			}
			length = (size_t) ((der[pos + 1] << 8) | der[pos + 2]);
			break;

		case 0x83:
			header = 4;
			if ((pos + 3) >= der_len) {
				return -1;
			}
			length = (size_t) ((der[pos + 1] << 16) | (der[pos + 2] << 8) | der[pos + 3]);
			break;

		case 0x84:
			header = 5;
			if ((pos + 4) >= der_len) {
				return -1;
			}
			length = (size_t) ((der[pos + 1] << 24) | (der[pos + 2] << 16) | (der[pos + 3] <<
				8) | der[pos + 4]);
			break;

		default:
			if (der[pos] < 0x80) {
				header = 1;
				length = (size_t) der[pos];
				break;
			}

			return -1;
	}

	if (len != NULL) {
		*len = length;
	}

	(*position) += (uint32_t) header;

	return 0;
}

static int process_asn1_type (size_t *len, size_t *position, const uint8_t *der_buf, size_t der_len,
	uint8_t tag)
{
	if (*position >= der_len) {
		return -1;
	}

	if (der_buf[*position] != tag) {
		return -1;
	}

	(*position) += 1;

	return read_length (len, der_buf, der_len, position);
}

static int process_asn1_explicit_type (size_t *len, size_t *position, const uint8_t *der_buf,
	size_t der_len, uint8_t tag_num)
{
	if (*position >= der_len) {
		return -1;
	}

	if (der_buf[*position] != (0xA0 + tag_num)) {
		return -1;
	}

	(*position) += 1;

	return read_length (len, der_buf, der_len, position);
}

static int read_set (const uint8_t *der_buf, size_t der_len, size_t *position)
{
	return process_asn1_type (NULL, position, der_buf, der_len, 0x31);
}

static int read_integer (const uint8_t *der_buf, size_t der_len, size_t *position)
{
	size_t len;
	int status;

	status = process_asn1_type (&len, position, der_buf, der_len, 0x02);
	if (status != 0) {
		return -1;
	}

	(*position) += len;

	return 0;
}

static int read_explicit_integer (const uint8_t *der_buf, size_t der_len, size_t *position,
	uint8_t tag_num)
{
	size_t len;
	int status;

	status = process_asn1_explicit_type (&len, position, der_buf, der_len, tag_num);
	if (status != 0) {
		return -1;
	}

	return read_integer (der_buf, der_len, position);
}

static int read_explicit_type (const uint8_t *der_buf, size_t der_len, size_t *position,
	uint8_t tag_num)
{
	size_t len;
	int status;

	status = process_asn1_explicit_type (&len, position, der_buf, der_len, tag_num);
	if (status != 0) {
		return -1;
	}

	(*position) += len;

	return 0;
}

static int decode_bit_string (const uint8_t **bit_str, size_t *out_len, const uint8_t *der_buf,
	size_t der_len, size_t *position)
{
	size_t bstr_len;
	int status;

	status = process_asn1_type (&bstr_len, position, der_buf, der_len, 0x03);
	if ((status != 0) || ((*position + bstr_len) > der_len)) {
		return -1;
	}

	*bit_str = &der_buf[*position];

	if (out_len) {
		*out_len = bstr_len;
	}

	return 0;
}

static int decode_explicit_bit_string (const uint8_t **bit_str, size_t *out_len,
	const uint8_t *der_buf, size_t der_len, size_t *position, uint8_t tag_num)
{
	size_t len;
	int status;

	status = process_asn1_explicit_type (&len, position, der_buf, der_len, tag_num);
	if (status != 0) {
		return -1;
	}

	status = decode_bit_string (bit_str, out_len, der_buf, der_len, position);
	if (status != 0) {
		return -1;
	}

	return 0;
}

static int decode_octet_string (uint8_t *oct_str, size_t *out_len, size_t max_buf_len,
	const uint8_t *der_buf, size_t der_len, size_t *position)
{
	size_t len;
	int status;

	status = process_asn1_type (&len, position, der_buf, der_len, 0x04);
	if ((status != 0) || ((*position + len) > der_len)) {
		return -1;
	}

	if (len > max_buf_len) {
		return -2;
	}

	memcpy (oct_str, &der_buf[*position], len);
	(*position) += len;

	if (out_len) {
		*out_len = len;
	}

	return 0;
}

static int read_octet_string (size_t *len, const uint8_t *der_buf, size_t der_len, size_t *position)
{
	return process_asn1_type (len, position, der_buf, der_len, 0x04);
}

static int read_oid (size_t *len, const uint8_t *der_buf, size_t der_len, size_t *position)
{
	return process_asn1_type (len, position, der_buf, der_len, 0x06);
}

static int read_utf8String (size_t *len, const uint8_t *der_buf, size_t der_len, size_t *position)
{
	return process_asn1_type (len, position, der_buf, der_len, 0xc);
}

static int read_sequence (size_t *len, const uint8_t *der_buf, size_t der_len, size_t *position)
{
	return process_asn1_type (len, position, der_buf, der_len, 0x30);
}

static int read_cert_subject_name (size_t *len, size_t *position, const uint8_t *der,
	size_t der_len)
{
	CHK (read_sequence (NULL, der, der_len, position));
	CHK (read_sequence (NULL, der, der_len, position));
	CHK (read_explicit_integer (der, der_len, position, 0));
	CHK (read_integer (der, der_len, position));
	CHK (read_sequence (len, der, der_len, position));
	(*position) += (*len);
	CHK (read_sequence (NULL, der, der_len, position));
	CHK (read_set (der, der_len, position));
	CHK (read_sequence (NULL, der, der_len, position));
	CHK (read_oid (len, der, der_len, position));
	(*position) += (*len);
	CHK (read_utf8String (len, der, der_len, position));
	(*position) += (*len);
	CHK (read_sequence (len, der, der_len, position));
	(*position) += (*len);
	CHK (read_sequence (NULL, der, der_len, position));
	CHK (read_set (der, der_len, position));
	CHK (read_sequence (NULL, der, der_len, position));
	CHK (read_oid (len, der, der_len, position));
	(*position) += (*len);
	CHK (read_utf8String (len, der, der_len, position));

	return 0;
Error:

	return -1;
}

RIOT_STATUS DERDECReadSequence (size_t *len, const uint8_t *der_buf, size_t der_len,
	size_t *position)
{
	CHK (read_sequence (len, der_buf, der_len, position));

	return RIOT_SUCCESS;
Error:

	return RIOT_FAILURE;
}

RIOT_STATUS DERDECGetPrivKey (uint8_t *private_key, size_t *key_len, const uint8_t *private_key_der,
	const size_t key_der_len)
{
	size_t position = 0;
	int status;

	if ((private_key == NULL) || (private_key_der == NULL)) {
		goto Error;
	}

	ASRT (key_der_len <= RIOT_X509_MAX_KEY_LEN);

	CHK (read_sequence (NULL, private_key_der, key_der_len, &position));
	CHK (read_integer (private_key_der, key_der_len, &position));
	status = decode_octet_string (private_key, key_len, RIOT_ECC_PRIVATE_BYTES, private_key_der,
		key_der_len, &position);
	if (status == -2) {
		return RIOT_INVALID_PARAMETER;
	}
	else if (status < 0) {
		goto Error;
	}

	if (key_len) {
		ASRT (*key_len <= RIOT_ECC_PRIVATE_BYTES);
	}

	return RIOT_SUCCESS;
Error:

	return RIOT_FAILURE;
}

RIOT_STATUS DERDECGetPubKey (const uint8_t **public_key, size_t *key_len,
	const uint8_t *public_key_der, const size_t key_der_len)
{
	size_t position = 0;
	size_t len;

	if ((public_key == NULL) || (public_key_der == NULL)) {
		goto Error;
	}

	CHK (read_sequence (NULL, public_key_der, key_der_len, &position));
	CHK (read_sequence (&len, public_key_der, key_der_len, &position));
	position += len;
	CHK (decode_bit_string (public_key, key_len, public_key_der, key_der_len, &position));

	(*public_key)++;
	(*key_len)--;

	return RIOT_SUCCESS;
Error:

	return RIOT_FAILURE;
}

RIOT_STATUS DERDECGetPubKeyFromPrivKey (const uint8_t **public_key, size_t *key_len,
	const uint8_t *private_key_der, const size_t key_der_len)
{
	size_t position = 0;
	size_t len;

	if ((public_key == NULL) || (private_key_der == NULL)) {
		goto Error;
	}

	ASRT (key_der_len <= RIOT_X509_MAX_KEY_LEN);

	CHK (read_sequence (NULL, private_key_der, key_der_len, &position));
	CHK (read_integer (private_key_der, key_der_len, &position));
	CHK (read_octet_string (&len, private_key_der, key_der_len, &position));
	position += len;
	CHK (read_explicit_type (private_key_der, key_der_len, &position, 0));
	CHK (decode_explicit_bit_string (public_key, key_len, private_key_der, key_der_len, &position,
		1));

	return RIOT_SUCCESS;
Error:

	return RIOT_FAILURE;
}

RIOT_STATUS DERDECGetSubjectName (char **name, const uint8_t *der, const size_t length)
{
	size_t position = 0;
	size_t len;
	int status;

	if ((name == NULL) || (der == NULL)) {
		goto Error;
	}

	*name = NULL;

	status = read_cert_subject_name (&len, &position, der, length);
	if ((status != 0) || ((position + len) > length)) {
		goto Error;
	}

	*name = platform_malloc (len + 1);
	if (*name == NULL) {
		goto Error;
	}
	memcpy (*name, &der[position], len);
	(*name)[len] = '\0';

	return RIOT_SUCCESS;
Error:

	return RIOT_FAILURE;
}

RIOT_STATUS DERDECVerifyCert (const uint8_t *der, const size_t length)
{
	size_t position = 0;
	size_t len;
	int status;

	ASRT (der != NULL);

	status = read_cert_subject_name (&len, &position, der, length);
	if ((status != 0) || ((position + len) > length)) {
		goto Error;
	}

	return RIOT_SUCCESS;
Error:

	return RIOT_FAILURE;
}
