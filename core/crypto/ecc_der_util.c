// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <string.h>
#include "ecc_der_util.h"


/**
 * The ASN.1 encoded OID for the P256 ECC curve.
 */
static const uint8_t ECC_DER_P256_OID[] = {
	0x2a,0x86,0x48,0xce,0x3d,0x03,0x01,0x07
};

#if ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_384
/**
 * The ASN.1 encoded OID for the P384 ECC curve.
 */
static const uint8_t ECC_DER_P384_OID[] = {
	0x2b,0x81,0x04,0x00,0x22
};
#endif

#if ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_521
/**
 * The ASN.1 encoded OID for the P521 ECC curve.
 */
static const uint8_t ECC_DER_P521_OID[] = {
	0x2b,0x81,0x04,0x00,0x23
};
#endif

/**
 * The ASN.1 encoded OID for an ECC public key.
 */
static const uint8_t ECC_DER_EC_PUBLIC_KEY_OID[] = {
	0x2a,0x86,0x48,0xce,0x3d,0x02,0x01
};


/**
 * Get the next tag in an ASN.1 buffer and determine basic information about it.
 *
 * @param type The expected type for the next tag in the buffer.
 * @param der The ASN.1 buffer to parse.  This must be pointing to the start of a new tag.  Upon
 * returning, this will be moved past the tag header bytes.
 * @param length The total length remaining in the data buffer.  Upon output, this will be updated
 * based on the length of the header.
 * @param type_len Output for the data length described by the tag.
 *
 * @return 0 if the next tag was successfully parsed or an error code.
 */
static int ecc_der_get_next_tag (uint8_t type, const uint8_t **der, size_t *length,
	size_t *type_len)
{
	const uint8_t *pos = *der;
	uint8_t header_len;

	if ((*length < 3) || (pos[0] != type)) {
		/* While 2 bytes is enough for the short length representation, we will always have more
		 * data overall after a tag, so even in the case of a 2 byte header, not enough space for
		 * more data is an error.  Just check the length once here to avoid needing repeated length
		 * checks. */
		return ECC_DER_UTIL_MALFORMED;
	}

	if (pos[1] < 0x80) {
		*type_len = pos[1];
		header_len = 2;
	}
	else if (pos[1] == 0x81) {
		*type_len = pos[2];
		header_len = 3;
	}
	else {
		/* We will never get an ASN.1 sequence that needs for that a single length byte.  If we do,
		 * there is no point parsing it any further since it does not represent an ECC private
		 * key.
		 *
		 * This same error will trigger if any sub-tag has more than one length byte.  In that case,
		 * the encoding is technically malformed. */
		return ECC_DER_UTIL_UNKNOWN_SEQUENCE;
	}

	if (*length < (header_len + *type_len)) {
		return ECC_DER_UTIL_MALFORMED;
	}

	*der = pos + header_len;
	*length -= header_len;
	return 0;
}

/**
 * Add the next tag in an ASN.1 buffer.
 *
 * @param type The type for the next tag to be added in the buffer.
 * @param type_len Data length to specify in the tag.
 * @param data Buffer for the data to add to the tag.  Set to null if no data should be added.
 * @param der Input the current position in the ASN.1 buffer.  Output the buffer position after the
 * tag has been added.
 * @param length Input the length of the ASN.1 buffer.  Output the remaining buffer length after the
 * tag has been added.
 *
 * @return 0 if the tag was added successfully or an error code.
 */
static int ecc_der_add_next_tag (uint8_t type, size_t type_len, const uint8_t *data, uint8_t **der,
	size_t *length)
{
	uint8_t *pos = *der;

	if (*length < 3) {
		/* Technically we may be able to fit a 2 byte header, but there is no scenario where a 2
		 * byte header would not be followed by another byte.  So, just check against 3 bytes here
		 * to remove the need for additional checks. */
		return ECC_DER_UTIL_SMALL_DER_BUFFER;
	}

	*pos++ = type;
	if (type_len >= 0x80) {
		*pos++ = 0x81;
		(*length)--;
	}
	*pos++ = type_len;
	*length -= 2;

	if (data) {
		if (*length < type_len) {
			return ECC_DER_UTIL_SMALL_DER_BUFFER;
		}

		memcpy (pos, data, type_len);
		pos += type_len;
		*length -= type_len;
	}

	*der = pos;
	return 0;
}

/*
 * ECC private key ASN.1 structure:  https://www.secg.org/sec1-v2.pdf
 *
 * CPrivateKey ::= SEQUENCE {
 *		version INTEGER { ecPrivkeyVer1(1) } (ecPrivkeyVer1),
 *		privateKey OCTET STRING,
 *		parameters [0] ECDomainParameters {{ SECGCurveNames }} OPTIONAL,
 *		publicKey [1] BIT STRING OPTIONAL
 * }
 *
 * parameters and publicKey are EXPLICIT.
 */

/**
 * Encode the public key into an ASN.1 BIT STRING.
 *
 * @param pub_key_x X coordinate of the ECC public key.
 * @param pub_key_y Y coordinate of the ECC public key.
 * @param key_length Length of the ECC key.
 * @param der Output buffer for the encoded BIT STRING.  The buffer pointer will be moved to the end
 * of the encoded value.
 * @param length Length of the output buffer.  This will be updated on output based on the length of
 * the encoded value.
 *
 * @return 0 if the BIT STRING was successfully encoded or an error code.
 */
static int ecc_der_encode_public_key_bit_string (const uint8_t *pub_key_x, const uint8_t *pub_key_y,
	size_t key_length, uint8_t **der, size_t *length)
{
	uint8_t *pos = *der;
	uint8_t pub_key_hdr[] = {0x00, 0x04};
	int status;

	status = ecc_der_add_next_tag (0x03, (key_length * 2) + 2, NULL, &pos, length);
	if (status != 0) {
		return status;
	}

	if (*length < (sizeof (pub_key_hdr) + (key_length * 2))) {
		return ECC_DER_UTIL_SMALL_DER_BUFFER;
	}

	memcpy (pos, pub_key_hdr, sizeof (pub_key_hdr));
	pos += sizeof (pub_key_hdr);

	memcpy (pos, pub_key_x, key_length);
	pos += key_length;

	memcpy (pos, pub_key_y, key_length);
	pos += key_length;

	*der = pos;
	*length -= (sizeof (pub_key_hdr) + (key_length * 2));
	return 0;
}

/**
 * Extract an ECC private key from ASN.1/DER encoded data.  If the DER data also contains a public
 * key, this value is ignored.
 *
 * Only P256, P384, and P521 curves are supported.
 *
 * @param der An ASN.1/DER encoded ECC private key.
 * @param length Length of the DER data.
 * @param priv_key Output buffer for the raw private key.
 * @param key_length Length of the private key buffer.  The actual key length is determined by the
 * encoded data.
 *
 * @return Length of the private key or an error code.
 */
int ecc_der_decode_private_key (const uint8_t *der, size_t length, uint8_t *priv_key,
	size_t key_length)
{
	const uint8_t *pos = der;
	size_t type_len;
	int key_len;
	size_t oid_len;
	const uint8_t *oid;
	int status;

	if ((der == NULL) || (priv_key == NULL)) {
		return ECC_DER_UTIL_INVALID_ARGUMENT;
	}

	status = ecc_der_get_next_tag (0x30, &pos, &length, &type_len);
	if (status != 0) {
		return status;
	}

	status = ecc_der_get_next_tag (0x02, &pos, &length, &type_len);
	if (status != 0) {
		return status;
	}

	if ((type_len != 1) || (*pos != 1)) {
		/* If this is not a version 1 structure, we don't know what it is. */
		return ECC_DER_UTIL_UNKNOWN_SEQUENCE;
	}

	pos += type_len;
	length -= type_len;

	status = ecc_der_get_next_tag (0x04, &pos, &length, &type_len);
	if (status != 0) {
		return status;
	}

	/* Make sure the private key is a supported key length. */
	key_len = type_len;
	switch (key_len) {
		case ECC_KEY_LENGTH_256:
			oid = ECC_DER_P256_OID;
			oid_len = sizeof (ECC_DER_P256_OID);
			break;

#if ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_384
		case ECC_KEY_LENGTH_384:
			oid = ECC_DER_P384_OID;
			oid_len = sizeof (ECC_DER_P384_OID);
			break;
#endif

#if ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_521
		case ECC_KEY_LENGTH_521 - 1:
			/* Some encoders drop the first byte of private key if it is 0, so accept one less byte
			 * than normally expected. */
			key_len++;

			/* fall through */ /* no break */

		case ECC_KEY_LENGTH_521:
			oid = ECC_DER_P521_OID;
			oid_len = sizeof (ECC_DER_P521_OID);
			break;
#endif

		default:
			return ECC_DER_UTIL_UNSUPPORTED_KEY_LENGTH;
	}

	if (key_length >= (size_t) key_len) {
#if ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_521
		if (type_len == (ECC_KEY_LENGTH_521 - 1)) {
			priv_key[0] = 0;
			memcpy (&priv_key[1], pos, type_len);
		}
		else
#endif
		{
			memcpy (priv_key, pos, key_len);
		}
	}
	else {
		return ECC_DER_UTIL_SMALL_KEY_BUFFER;
	}

	/* We have the private key of a valid length, but we need to make sure it is for the expected
	 * curve.  While this field is defined as optional, it is expected to always be present, and
	 * RFC 5915 mandates this. */
	pos += type_len;
	length -= type_len;

	status = ecc_der_get_next_tag (0xa0, &pos, &length, &type_len);
	if (status != 0) {
		return status;
	}

	status = ecc_der_get_next_tag (0x06, &pos, &length, &type_len);
	if (status != 0) {
		return status;
	}

	if ((type_len != oid_len) || (memcmp (pos, oid, oid_len) != 0)) {
		/* Only a single curve is supported for each key length.  If the OID indicates a different
		 * curve, report the key as unsupported. */
		return ECC_DER_UTIL_UNSUPPORTED_CURVE;
	}

	return key_len;
}

/**
 * Encode an ECC private key using ASN.1/DER.
 *
 * Only P256, P384, and P521 curves are supported.
 *
 * @param priv_key The private key to encode.
 * @param pub_key_x Optional X coordinate for the ECC public key.  If this is null, the public key
 * will not be encoded.
 * @param pub_key_y Optional Y coordinate for the ECC public key.  If this is null, the public key
 * will not be encoded.
 * @param key_length Length of the private key.  All key buffers must be the same size.
 * @param der Output buffer for the DER encoded private key.  This will include the optional public
 * key portion if that information was provided.
 * @param length Length of the DER output buffer.  This must be large enough to hold all key
 * information and the encoding overhead.
 *
 * @return Length of the encoded data or an error code.
 */
int ecc_der_encode_private_key (const uint8_t *priv_key, const uint8_t *pub_key_x,
	const uint8_t *pub_key_y, size_t key_length, uint8_t *der, size_t length)
{
	uint8_t *pos = der;
	uint8_t has_pub_key = 0;
	uint8_t seq_hdr_len = 2;
	uint8_t version = 1;
	size_t oid_len;
	const uint8_t *oid;
	int status;

	if ((priv_key == NULL) || (der == NULL)) {
		return ECC_DER_UTIL_INVALID_ARGUMENT;
	}

	if (pub_key_x && pub_key_y) {
		has_pub_key = 0x80;
		if (key_length > ECC_KEY_LENGTH_256) {
			seq_hdr_len = 3;
		}
	}

	switch (key_length) {
		case ECC_KEY_LENGTH_256:
			oid_len = sizeof (ECC_DER_P256_OID);
			oid = ECC_DER_P256_OID;

			status = ecc_der_add_next_tag (0x30, 0, NULL, &pos, &length);
			break;

#if ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_384
		case ECC_KEY_LENGTH_384:
			oid_len = sizeof (ECC_DER_P384_OID);
			oid = ECC_DER_P384_OID;

			status = ecc_der_add_next_tag (0x30, has_pub_key, NULL, &pos, &length);
			break;
#endif

#if ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_521
		case ECC_KEY_LENGTH_521:
			oid_len = sizeof (ECC_DER_P521_OID);
			oid = ECC_DER_P521_OID;

			status = ecc_der_add_next_tag (0x30, has_pub_key, NULL, &pos, &length);
			break;
#endif

		default:
			return ECC_DER_UTIL_UNSUPPORTED_KEY_LENGTH;
	}

	if (status != 0) {
		return status;
	}

	status = ecc_der_add_next_tag (0x02, 1, &version, &pos, &length);
	if (status != 0) {
		return status;
	}

	status = ecc_der_add_next_tag (0x04, key_length, priv_key, &pos, &length);
	if (status != 0) {
		return status;
	}

	status = ecc_der_add_next_tag (0xa0, oid_len + 2, NULL, &pos, &length);
	if (status != 0) {
		return status;
	}

	status = ecc_der_add_next_tag (0x06, oid_len, oid, &pos, &length);
	if (status != 0) {
		return status;
	}

	if (pub_key_x && pub_key_y) {
		if (key_length != ECC_KEY_LENGTH_521) {
			status = ecc_der_add_next_tag (0xa1, (key_length * 2) + 4, NULL, &pos, &length);
		}
		else {
			status = ecc_der_add_next_tag (0xa1, (key_length * 2) + 5, NULL, &pos, &length);
		}
		if (status != 0) {
			return status;
		}

		status = ecc_der_encode_public_key_bit_string (pub_key_x, pub_key_y, key_length, &pos,
			&length);
		if (status != 0) {
			return status;
		}
	}

	der[seq_hdr_len - 1] = (pos - der) - seq_hdr_len;
	return der[seq_hdr_len - 1] + seq_hdr_len;
}

/*
 * ECC public key ASN.1 structure:  https://datatracker.ietf.org/doc/html/rfc5480
 *
 *
 * SubjectPublicKeyInfo  ::=  SEQUENCE  {
 *   algorithm         AlgorithmIdentifier,
 *   subjectPublicKey  BIT STRING
 * }
 *
 * AlgorithmIdentifier  ::=  SEQUENCE  {
 *   algorithm   OBJECT IDENTIFIER,
 *   parameters  ANY DEFINED BY algorithm OPTIONAL
 * }
 *
 * parameters is used to specify the OID for the named curve of the key.
 * subjectPublicKey is the ECPoint for the public key.
 */

/**
 * Extract an ECC public key from ASN.1/DER encoded data.
 *
 * Only P256, P384, and P521 curves are supported.  Only uncompressed public keys will be decoded.
 *
 * @param der An ASN.1/DER encoded ECC public key.
 * @param length Length of the DER data.
 * @param pub_key_x Output buffer for the X coordinate of the public key.
 * @param pub_key_y Output buffer for the Y coordinate of the public key.
 * @param key_length Length of the public key buffers.  Each component of the public key must be the
 * same length.  The actual key length is determined by the encoded data.
 *
 * @return Length of the ECC key or an error code.
 */
int ecc_der_decode_public_key (const uint8_t *der, size_t length, uint8_t *pub_key_x,
	uint8_t *pub_key_y, size_t key_length)
{
	const uint8_t *pos = der;
	size_t type_len;
	size_t oid_len;
	const uint8_t *oid;
	int status;

	if ((der == NULL) || (pub_key_x == NULL) || (pub_key_y == NULL)) {
		return ECC_DER_UTIL_INVALID_ARGUMENT;
	}

	status = ecc_der_get_next_tag (0x30, &pos, &length, &type_len);
	if (status != 0) {
		return status;
	}

	status = ecc_der_get_next_tag (0x30, &pos, &length, &type_len);
	if (status != 0) {
		return status;
	}

	status = ecc_der_get_next_tag (0x06, &pos, &length, &type_len);
	if (status != 0) {
		return status;
	}

	if ((type_len != sizeof (ECC_DER_EC_PUBLIC_KEY_OID) ||
		(memcmp (pos, ECC_DER_EC_PUBLIC_KEY_OID, type_len) != 0))) {
		return ECC_DER_UTIL_UNSUPPORTED_ALGORITHM;
	}

	pos += type_len;
	length -= type_len;

	status = ecc_der_get_next_tag (0x06, &pos, &length, &type_len);
	if (status != 0) {
		return status;
	}

	/* Save the curve OID so we can compare against it once we know the key length. */
	oid_len = type_len;
	oid = pos;

	pos += type_len;
	length -= type_len;

	status = ecc_der_get_next_tag (0x03, &pos, &length, &type_len);
	if (status != 0) {
		return status;
	}

	pos += 2;
	type_len = (type_len - 2) / 2;

	switch (type_len) {
		case ECC_KEY_LENGTH_256:
			if ((oid_len != sizeof (ECC_DER_P256_OID)) ||
				(memcmp (oid, ECC_DER_P256_OID, oid_len) != 0)) {
				return ECC_DER_UTIL_UNSUPPORTED_CURVE;
			}
			break;

#if ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_384
		case ECC_KEY_LENGTH_384:
			if ((oid_len != sizeof (ECC_DER_P384_OID)) ||
				(memcmp (oid, ECC_DER_P384_OID, oid_len) != 0)) {
				return ECC_DER_UTIL_UNSUPPORTED_CURVE;
			}
			break;
#endif

#if ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_521
		case ECC_KEY_LENGTH_521:
			if ((oid_len != sizeof (ECC_DER_P521_OID)) ||
				(memcmp (oid, ECC_DER_P521_OID, oid_len) != 0)) {
				return ECC_DER_UTIL_UNSUPPORTED_CURVE;
			}
			break;
#endif

		default:
			return ECC_DER_UTIL_UNSUPPORTED_KEY_LENGTH;
	}

	if (key_length < type_len) {
		return ECC_DER_UTIL_SMALL_KEY_BUFFER;
	}

	memcpy (pub_key_x, pos, type_len);
	memcpy (pub_key_y, &pos[type_len], type_len);

	return type_len;
}

/**
 * Encode an ECC public key using ASN.1/DER.
 *
 * Only P256, P384, and P521 curves are supported.
 *
 * @param pub_key_x X coordinate of the ECC public key.
 * @param pub_key_y Y coordinate of the ECC public key.
 * @param key_length Length of the ECC key.  Each component of the public key must be the same
 * length.
 * @param der Output buffer for the DER encoded public key.
 * @param length Length of the DER output buffer.  This must be large enough to hold both public key
 * components and the encoding overhead.
 *
 * @return Length of the encoded data or an error code.
 */
int ecc_der_encode_public_key (const uint8_t *pub_key_x, const uint8_t *pub_key_y,
	size_t key_length, uint8_t *der, size_t length)
{
	uint8_t *pos = der;
	uint8_t seq_hdr_len = 2;
	size_t algo_len;
	size_t oid_len;
	const uint8_t *oid;
	int status;

	if ((pub_key_x == NULL) || (pub_key_y == NULL) || (der == NULL)) {
		return ECC_DER_UTIL_INVALID_ARGUMENT;
	}

	switch (key_length) {
		case ECC_KEY_LENGTH_256:
			algo_len = 0x13;
			oid = ECC_DER_P256_OID;
			oid_len = sizeof (ECC_DER_P256_OID);
			break;

#if ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_384
		case ECC_KEY_LENGTH_384:
			algo_len = 0x10;
			oid = ECC_DER_P384_OID;
			oid_len = sizeof (ECC_DER_P384_OID);
			break;
#endif

#if ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_521
		case ECC_KEY_LENGTH_521:
			seq_hdr_len = 3;
			algo_len = 0x10;
			oid = ECC_DER_P521_OID;
			oid_len = sizeof (ECC_DER_P521_OID);
			break;
#endif

		default:
			return ECC_DER_UTIL_UNSUPPORTED_KEY_LENGTH;
	}

	status = ecc_der_add_next_tag (0x30, (seq_hdr_len == 2) ? 0 : 0x80, NULL, &pos, &length);
	if (status != 0) {
		return status;
	}

	status = ecc_der_add_next_tag (0x30, algo_len, NULL, &pos, &length);
	if (status != 0) {
		return status;
	}

	status = ecc_der_add_next_tag (0x06, sizeof (ECC_DER_EC_PUBLIC_KEY_OID),
		ECC_DER_EC_PUBLIC_KEY_OID, &pos, &length);
	if (status != 0) {
		return status;
	}

	status = ecc_der_add_next_tag (0x06, oid_len, oid, &pos, &length);
	if (status != 0) {
		return status;
	}

	status = ecc_der_encode_public_key_bit_string (pub_key_x, pub_key_y, key_length, &pos, &length);
	if (status != 0) {
		return status;
	}

	der[seq_hdr_len - 1] = (pos - der) - seq_hdr_len;
	return der[seq_hdr_len - 1] + seq_hdr_len;
}

/*
 * ECDSA signature ASN.1 structure:  https://datatracker.ietf.org/doc/html/rfc3279
 *
 * Ecdsa-Sig-Value  ::=  SEQUENCE  {
 *   r     INTEGER,
 *   s     INTEGER  }
 */

/**
 * Decode a single INTEGER from an ASN.1 encoded ECDSA signature.
 *
 * @param der The INTEGER to decode.  On output, this will be updated to point past the decoded
 * data.
 * @param length Total length of the encoded data.  Upon return, this will be updated to reflect the
 * remaining data after the decoded INTEGER.
 * @param sig Output buffer for the INTEGER value.
 * @param key_length Length of the INTEGER.  Encoded values that are smaller than this will have the
 * MSBs zero padded.
 *
 * @return 0 if the INTEGER was successfully decoded or an error code.
 */
static int ecc_der_decode_ecdsa_integer (const uint8_t **der, size_t *length, uint8_t *sig,
	size_t key_length)
{
	size_t type_len;
	int status;

	status = ecc_der_get_next_tag (0x02, der, length, &type_len);
	if (status != 0) {
		return status;
	}

	if (type_len > (key_length + 1)) {
		/* A signature can have an additional byte of zero padding to account for negative numbers,
		 * any more than that means this signature does not match the provided key length. */
		return ECC_DER_UTIL_SIG_TOO_LONG;
	}

	if (type_len > key_length) {
		if (**der != 0) {
			/* The extra byte is not zero, which means the integer is too long for the key size. */
			return ECC_DER_UTIL_SIG_TOO_LONG;
		}

		(*der)++;
		(*length)--;
		type_len--;
	}

	memset (sig, 0, key_length);
	memcpy (&sig[key_length - type_len], *der, type_len);
	*der += type_len;
	*length -= type_len;

	return 0;
}

/**
 * Encode a single ECDSA signature value to an ASN.1 INTEGER.
 *
 * @param sig The signature value to encode.
 * @param key_length Length of the value.
 * @param der Output buffer for the encoded INTEGER.  The buffer pointer will be moved to the end of
 * the encoded value.
 * @param length Length of the output buffer.  This will be updated on output based on the length of
 * the encoded value.
 *
 * @return 0 if the signature value was encoded successfully or an error code.
 */
static int ecc_der_encode_ecdsa_integer (const uint8_t *sig, size_t key_length, uint8_t **der,
	size_t *length)
{
	uint8_t *pos = *der;
	uint8_t *int_len = &(*der)[1];
	size_t i = 0;
	int status;

	status = ecc_der_add_next_tag (0x02, 0, NULL, &pos, length);
	if (status != 0) {
		return status;
	}

	/* Trim leading zeros from the signature value. */
	while ((sig[i] == 0) && (key_length > 1)) {
		i++;
		key_length--;
	}

	/* Pad with an extra zero to avoid negative numbers in the encoding.  There will always be
	 * enough buffer space for this padding because of the length check when adding the tag. */
	if (sig[i] & 0x80) {
		*pos++ = 0;
		(*length)--;
		(*int_len)++;
	}

	if (*length < key_length) {
		return ECC_DER_UTIL_SMALL_DER_BUFFER;
	}

	memcpy (pos, &sig[i], key_length);
	pos += key_length;
	*length -= key_length;
	*int_len += key_length;

	*der = pos;
	return 0;
}

/**
 * Extract an ECDSA signature from ASN.1/DER encoded data.
 *
 * @param der An ASN.1/DER encoded ECDSA signature.
 * @param length Length of the DER data.
 * @param sig_r Output buffer for the r value of the signature.
 * @param sig_s Output buffer for the s value of the signature.
 * @param key_length The size of the key used to generate the signature.  The signature output
 * buffers must each be able to hold this much data.  The encoded data cannot be used to reliably
 * determine the key length since INTEGER encoding adds and removes leading zeros.
 *
 * @return 0 if the signature was parse successfully or an error code.
 */
int ecc_der_decode_ecdsa_signature (const uint8_t *der, size_t length, uint8_t *sig_r,
	uint8_t *sig_s, size_t key_length)
{
	const uint8_t *pos = der;
	size_t type_len;
	int status;

	if ((der == NULL) || (sig_r == NULL) || (sig_s == NULL)) {
		return ECC_DER_UTIL_INVALID_ARGUMENT;
	}

	status = ecc_der_get_next_tag (0x30, &pos, &length, &type_len);
	if (status != 0) {
		return status;
	}

	status = ecc_der_decode_ecdsa_integer (&pos, &length, sig_r, key_length);
	if (status != 0) {
		return status;
	}

	return ecc_der_decode_ecdsa_integer (&pos, &length, sig_s, key_length);
}

/**
 * Encode an ECDSA signature using ASN.1/DER.
 *
 * @param sig_r r value for the signature.
 * @param sig_s s value for the signature.
 * @param key_length Length of the signature components.  Both components must be the same length.
 * @param der Output buffer for the DER encoded signature.
 * @param length Length of the DER output buffer.  This must be large enough to hold both signature
 * components and the encoding overhead.
 *
 * @return Length of the encoded signature or an error code.
 */
int ecc_der_encode_ecdsa_signature (const uint8_t *sig_r, const uint8_t *sig_s, size_t key_length,
	uint8_t *der, size_t length)
{
	uint8_t *pos = der;
	int total_len;
	int status;

	if ((sig_r == NULL) || (sig_s == NULL) || (der == NULL) || (key_length == 0)) {
		return ECC_DER_UTIL_INVALID_ARGUMENT;
	}

	status = ecc_der_add_next_tag (0x30, 0, NULL, &pos, &length);
	if (status != 0) {
		return status;
	}

	status = ecc_der_encode_ecdsa_integer (sig_r, key_length, &pos, &length);
	if (status != 0) {
		return status;
	}

	status = ecc_der_encode_ecdsa_integer (sig_s, key_length, &pos, &length);
	if (status != 0) {
		return status;
	}

	total_len = (pos - der) - 2;

#if ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_521
	/* For P521 signatures, the resulting structure could require 3 header bytes.  Adjust here, if
	 * necessary. */
	der[1] = total_len;
	if (total_len >= 0x80) {
		if (length == 0) {
			return ECC_DER_UTIL_SMALL_DER_BUFFER;
		}

		memmove (&der[2], &der[1], total_len + 1);
		der[1] = 0x81;
		total_len++;
	}
#endif

	return total_len + 2;
}
