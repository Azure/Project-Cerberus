/*
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See LICENSE in the project root.
 */
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#ifdef WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>	// TODO: REMOVE THIS
#else
#include "platform_api.h"

#endif

#include "include/RiotBase64.h"
#include "include/RiotDerEnc.h"

//
// This file contains basic DER-encoding routines that are sufficient to create
// RIoT X.509 certificates. A few corners are cut (and noted) in the interests
// of small code footprint and simplicity.
//
// Routines in this file encode the following types:
//    SEQUENCE
//    SET
//    INTEGER
//    OID
//    BOOL
//    PrintableString
//    UTF8String
//    UTCTime
//    GeneralizedTime
//

// Assert-less assert
#define ASRT(_X) if(!(_X)) {goto Error;}

// The encoding routines need to check that the encoded data will fit in the
// buffer. The following macros do (conservative) checks because it's hard to
// properly test low-buffer situations. CHECK_SPACE is appropriate for short
// additions. CHECK_SPACE2 when larger objects are being added (and the length
// is known.)
#define CHECK_SPACE(_X)      if((_X->Length-_X->Position)<32)        {goto Error;}
#define CHECK_SPACE2(_X, _N) if(((_X->Length-_X->Position)+(_N))<32) {goto Error;}

static int GetIntEncodedNumBytes (
	int Val)
// Returns the number of bytes needed to DER encode a number.  If the number
// is less then 127, a single byte is used.  Otherwise the DER rule is first
// byte is 0x80|NumBytes, followed by the number in network byte-order. Note
// that the routines in this library only handle lengths up to 16K Bytes.
{
	ASRT (Val < 166536);
	if (Val < 128) {
		return 1;
	}
	if (Val < 256) {
		return 2;
	}

	return 3;
Error:

	return -1;
}


static int EncodeInt (
	uint8_t *Buffer, int Val)
// DER-encode Val into buffer. Function assumes the caller knows how many
// bytes it will need (e.g., from GetIntEncodedNumBytes).
{
	ASRT (Val < 166536);
	if (Val < 128) {
		Buffer[0] = (uint8_t) Val;

		return 0;
	}
	if (Val < 256) {
		Buffer[0] = 0x81;
		Buffer[1] = (uint8_t) Val;

		return 0;
	}
	Buffer[0] = 0x82;
	Buffer[1] = (uint8_t) (Val / 256);
	Buffer[2] = Val % 256;

	return 0;
Error:

	return -1;
}

void DERInitContext (
	DERBuilderContext *Context, uint8_t *Buffer, size_t Length)
// Intialize the builder context.  The caller manages the encoding buffer.
// Note that the encoding routines do conservative checks that the encoding
// will fit, so approximately 30 extra bytes are needed.  Note that if an
// encoding routine fails because the buffer is too small, the buffer will
// be in an indeterminate state, and the encoding must be restarted.
{
	int j;

	Context->Buffer = Buffer;
	Context->Length = Length;
	Context->Position = 0;
	memset (Buffer, 0, Length);
	for (j = 0; j < DER_MAX_NESTED; j++) {
		Context->CollectionStart[j] = -1;
	}
	Context->CollectionPos = 0;

	return;
}

size_t DERGetEncodedLength (
	DERBuilderContext *Context)
// Get the length of encoded data.
{
	return Context->Position;
}

int DERAddOID (
	DERBuilderContext *Context, const int *Values)
// Add an OID. The OID is an int-array (max 16) terminated with -1
{
	int j, k;
	int lenPos, digitPos = 0;
	int val, digit;
	int numValues = 0;

	for (j = 0; j < 16; j++) {
		if (Values[j] < 0) {
			break;
		}
		numValues++;
	}

	// Sanity check
	ASRT (numValues < 16);

	// Note that we don't know how many bytes the actual encoding will be
	// so we also check as we fill the buffer.
	CHECK_SPACE (Context);
	Context->Buffer[Context->Position++] = 6;

	// Save space for length (only <128 supported)
	lenPos = Context->Position;
	Context->Position++;

	// DER-encode the OID, first octet is special
	val = (numValues == 1) ? 0 : Values[1];
	Context->Buffer[Context->Position++] = (uint8_t) (Values[0] * 40 + val);

	// Others are base-128 encoded with the most significant bit of each byte,
	// apart from the least significant byte, set to 1.
	if (numValues >= 2) {
		uint8_t digits[5] = {0};

		for (j = 2; j < numValues; j++) {
			digitPos = 0;
			val = Values[j];

			// Convert to B128
			while (true) {
				digit = val % 128;
				digits[digitPos++] = (uint8_t) digit;
				val = val / 128;
				if (val == 0) {
					break;
				}
			}

			// Reverse into the buffer, setting the MSB as needed.
			for (k = digitPos - 1; k >= 0; k--) {
				val = digits[k];
				if (k != 0) {
					val += 128;
				}
				Context->Buffer[Context->Position++] = (uint8_t) val;
			}
			CHECK_SPACE (Context);
		}
	}

	Context->Buffer[lenPos] = (uint8_t) (Context->Position - 1 - lenPos);

	return 0;
Error:

	return -1;
}

int DERAddEncodedOID (
	DERBuilderContext *Context, const uint8_t *Oid, size_t OidLength)
{
	uint32_t j;

	ASRT (OidLength < 127);
	CHECK_SPACE2 (Context, OidLength);

	Context->Buffer[Context->Position++] = 0x06;
	Context->Buffer[Context->Position++] = (uint8_t) OidLength;

	for (j = 0; j < OidLength; j++) {
		Context->Buffer[Context->Position++] = Oid[j];
	}

	return 0;
Error:

	return -1;
}

int DERAddString (
	DERBuilderContext *Context, const char *Str, uint8_t Tag)
{
	uint32_t j, numChar = (uint32_t) strlen (Str);

	ASRT (numChar < 127);
	CHECK_SPACE2 (Context, numChar);

	Context->Buffer[Context->Position++] = Tag;
	Context->Buffer[Context->Position++] = (uint8_t) numChar;

	for (j = 0; j < numChar; j++) {
		Context->Buffer[Context->Position++] = Str[j];
	}

	return 0;
Error:

	return -1;
}

int DERAddUTF8String (
	DERBuilderContext *Context, const char *Str)
{
	return DERAddString (Context, Str, 0x0c);
}

int DERAddPrintableString (
	DERBuilderContext *Context, const char *Str)
{
	return DERAddString (Context, Str, 0x13);
}

int DERAddIA5String (
	DERBuilderContext *Context, const char *Str)
{
	return DERAddString (Context, Str, 0x16);
}

int DERAddTime (
	DERBuilderContext *Context, const char *Str)
// Format of time can be UTCTime (YYMMDDhhmmssZ) or GeneralizedTime (YYYYMMDDHHMMSSZ)
{
	uint32_t j, numChar = (uint32_t) strlen (Str);

	ASRT ((numChar == 13) || (numChar == 15));
	CHECK_SPACE (Context);

	if (numChar == 13) {
		Context->Buffer[Context->Position++] = 0x17;	// UTCTime
	}
	else {
		Context->Buffer[Context->Position++] = 0x18;	// GeneralizedTime
	}

	Context->Buffer[Context->Position++] = (uint8_t) numChar;

	for (j = 0; j < numChar; j++) {
		Context->Buffer[Context->Position++] = Str[j];
	}

	return 0;
Error:

	return -1;
}

static int DERAddTaggedIntegerFromArray (
	DERBuilderContext *Context,	const uint8_t *Val,	uint32_t NumBytes, uint8_t Tag)
// Input integer is assumed unsigned with most signficant byte first.
// A leading zero will be added if the most significant input bit is set.
// Leading zeros in the input number will be removed.
{
	uint32_t j, numLeadingZeros = 0;
	bool negative;

	ASRT (NumBytes < 128);
	CHECK_SPACE2 (Context, NumBytes);

	for (j = 0; j < NumBytes; j++) {
		if (Val[j] != 0) {
			break;
		}
		numLeadingZeros++;
	}

	negative = Val[numLeadingZeros] >= 128;
	Context->Buffer[Context->Position++] = Tag;

	if (NumBytes == numLeadingZeros) {	//integer is zero
		Context->Buffer[Context->Position++] = 1;
		Context->Buffer[Context->Position++] = 0;
	}
	else {
		if (negative) {
			Context->Buffer[Context->Position++] = (uint8_t) (NumBytes - numLeadingZeros + 1);
			Context->Buffer[Context->Position++] = 0;
		}
		else {
			Context->Buffer[Context->Position++] = (uint8_t) (NumBytes - numLeadingZeros);
		}

		for (j = numLeadingZeros; j < NumBytes; j++) {
			Context->Buffer[Context->Position++] = Val[j];
		}
	}

	return 0;
Error:

	return -1;
}

int DERAddIntegerFromArray (
	DERBuilderContext *Context,	const uint8_t *Val,	uint32_t NumBytes)
{
	return DERAddTaggedIntegerFromArray (Context, Val, NumBytes, 0x02);
}

int DERAddTaggedInteger (
	DERBuilderContext *Context, int Val, uint8_t Tag)
{
	long valx = platform_htonl (Val);	// TODO: REMOVE USAGE
	int res = DERAddTaggedIntegerFromArray (Context, (uint8_t*) &valx, 4, Tag);

	return res;
}

int DERAddInteger (
	DERBuilderContext *Context, int Val)
{
	return DERAddTaggedInteger (Context, Val, 0x02);
}

int DERAddShortExplicitInteger (
	DERBuilderContext *Context, int Val)
{
	long valx;

	ASRT (Val < 127);

	Context->Buffer[Context->Position++] = 0xA0;
	Context->Buffer[Context->Position++] = 3;

	valx = platform_htonl (Val);

	return (DERAddIntegerFromArray (Context, (uint8_t*) &valx, 4));
Error:

	return -1;
}

int DERAddBoolean (
	DERBuilderContext *Context, bool Val)
{
	CHECK_SPACE (Context);
	Context->Buffer[Context->Position++] = 0x01;
	Context->Buffer[Context->Position++] = 0x01;
	if (Val) {
		Context->Buffer[Context->Position++] = 0xFF;
	}
	else {
		Context->Buffer[Context->Position++] = 0x00;
	}

	return 0;
Error:

	return -1;
}

int DERAddBitString (
	DERBuilderContext *Context,	const uint8_t *BitString, size_t BitStringNumBytes)
{
	return DERAddNamedBitString (Context, BitString, BitStringNumBytes, BitStringNumBytes * 8);
}

int DERAddNamedBitString (
	DERBuilderContext *Context, const uint8_t *BitString, size_t BitStringNumBytes,	size_t bits)
{
	int len = BitStringNumBytes + 1;
	size_t unused_bits = (BitStringNumBytes * 8) - bits;

	if (unused_bits > 7) {
		goto Error;
	}

	CHECK_SPACE2 (Context, BitStringNumBytes);
	Context->Buffer[Context->Position++] = 0x03;
	EncodeInt (Context->Buffer + Context->Position, len);
	Context->Position += GetIntEncodedNumBytes (len);
	Context->Buffer[Context->Position++] = (uint8_t) unused_bits;
	memcpy (Context->Buffer + Context->Position, BitString, BitStringNumBytes);
	Context->Position += BitStringNumBytes;

	return 0;
Error:

	return -1;
}

int DERAddOctetString (
	DERBuilderContext *Context, const uint8_t *OctetString, size_t OctetStringLen)
{
	CHECK_SPACE2 (Context, OctetStringLen);
	Context->Buffer[Context->Position++] = 0x04;
	EncodeInt (Context->Buffer + Context->Position, OctetStringLen);
	Context->Position += GetIntEncodedNumBytes (OctetStringLen);
	memcpy (Context->Buffer + Context->Position, OctetString, OctetStringLen);
	Context->Position += OctetStringLen;

	return 0;
Error:

	return -1;
}

int DERStartConstructed (
	DERBuilderContext *Context, uint8_t Tag)
{
	CHECK_SPACE (Context);
	ASRT (Context->CollectionPos < DER_MAX_NESTED);

	Context->Buffer[Context->Position++] = Tag;

	// Note that no space is left for the length field. The  length field
	// is added at DEREndSequence when we know how many bytes are needed.
	Context->CollectionStart[Context->CollectionPos++] = Context->Position;

	return 0;
Error:

	return -1;
}

int DERStartSequenceOrSet (
	DERBuilderContext *Context, bool Sequence)
{
	uint8_t tp = Sequence ? 0x30 : 0x31;

	return DERStartConstructed (Context, tp);
}

int DERStartExplicit (
	DERBuilderContext *Context, uint32_t Num)
{
	CHECK_SPACE (Context);
	ASRT (Context->CollectionPos < DER_MAX_NESTED);

	Context->Buffer[Context->Position++] = 0xA0 + (uint8_t) Num;
	Context->CollectionStart[Context->CollectionPos++] = Context->Position;

	return 0;
Error:

	return -1;
}

int DERAddAuthKeyBitString (
	DERBuilderContext *Context, const uint8_t *BitString, size_t BitStringLen)
{
	CHECK_SPACE2 (Context, BitStringLen);
	Context->Buffer[Context->Position++] = 0x80;
	EncodeInt (Context->Buffer + Context->Position, BitStringLen);
	Context->Position += GetIntEncodedNumBytes (BitStringLen);
	memcpy (Context->Buffer + Context->Position, BitString, BitStringLen);
	Context->Position += BitStringLen;

	return 0;
Error:

	return -1;
}

int DERStartEnvelopingOctetString (
	DERBuilderContext *Context)
{
	CHECK_SPACE (Context);
	ASRT (Context->CollectionPos < DER_MAX_NESTED);

	Context->Buffer[Context->Position++] = 0x04;
	Context->CollectionStart[Context->CollectionPos++] = Context->Position;

	return 0;
Error:

	return -1;
}

int DERStartEnvelopingBitString (
	DERBuilderContext *Context)
{
	CHECK_SPACE (Context);
	ASRT (Context->CollectionPos < DER_MAX_NESTED);

	Context->Buffer[Context->Position++] = 0x03;

	// The payload includes the numUnusedBits (always zero, for our encodings).
	Context->CollectionStart[Context->CollectionPos++] = Context->Position;

	// No unused bits
	Context->Buffer[Context->Position++] = 0;

	return 0;
Error:

	return -1;
}

int DERPopNesting (
	DERBuilderContext *Context)
{
	int startPos, numBytes, encodedLenSize;

	CHECK_SPACE (Context);
	ASRT (Context->CollectionPos > 0);

	startPos = Context->CollectionStart[--Context->CollectionPos];
	numBytes = Context->Position - startPos;

	// How big is the length field?
	encodedLenSize = GetIntEncodedNumBytes (numBytes);

	// Make space for the length
	memmove (Context->Buffer + startPos + encodedLenSize, Context->Buffer + startPos, numBytes);

	// Fill in the length
	EncodeInt (Context->Buffer + startPos, numBytes);

	// Bump up the next-pointer
	Context->Position += encodedLenSize;

	return 0;
Error:

	return -1;
}

int DERTbsToCert (
	DERBuilderContext *Context)
// This function assumes that Context contains a fully-formed "to be signed"
// region of a certificate. DERTbsToCert copies the existing TBS region into<
// an enclosing SEQUENCE. This prepares the context to receive the signature
// block to make a fully-formed certificate.
{
	ASRT (Context->CollectionPos == 0);
	CHECK_SPACE (Context);

	// Move up one byte to leave room for the SEQUENCE tag.
	// The length is filled in when the sequence is popped.
	memmove (Context->Buffer + 1, Context->Buffer, Context->Position);

	// Fix up the length
	Context->Position++;

	// Add a sequence tag
	Context->Buffer[0] = 0x30;

	// Push the sequence into the collection stack
	Context->CollectionStart[Context->CollectionPos++] = 1;

	// Context now contains a TBS region inside a SEQUENCE. Signature block next.
	return 0;
Error:

	return -1;
}

int DERGetNestingDepth (
	DERBuilderContext *Context)
{
	return Context->CollectionPos;
}

typedef struct {
	uint16_t hLen;
	uint16_t fLen;
	const char *header;
	const char *footer;
} PEMHeadersFooters;

// We only have a small subset of potential PEM encodings
const PEMHeadersFooters PEMhf[LAST_CERT_TYPE] = {
	{28, 26, "-----BEGIN CERTIFICATE-----\n", "-----END CERTIFICATE-----\n"},
	{27, 25, "-----BEGIN PUBLIC KEY-----\n", "-----END PUBLIC KEY-----\n\0"},
	{31, 29, "-----BEGIN EC PRIVATE KEY-----\n", "-----END EC PRIVATE KEY-----\n"},
	{36, 34, "-----BEGIN CERTIFICATE REQUEST-----\n", "-----END CERTIFICATE REQUEST-----\n"}
};


int DERtoPEM (
	DERBuilderContext *Context, uint32_t Type, char *PEM, uint32_t *Length,
	struct base64_engine *base64)
// Note that this function does not support extra header information for
// encrypted keys. Expand the header buffer to ~128 bytes to support this.
{
	uint32_t b64Len, reqLen;
	int status;

	// Parameter validation
	if (!(Context) || !(Type < LAST_CERT_TYPE) || !(PEM) || !(Length)) {
		return -1;
	}

	// Calculate required length for output buffer
	b64Len = Base64Length (Context->Position);
	reqLen = b64Len + PEMhf[Type].hLen + PEMhf[Type].fLen;

	// Validate length of output buffer
	if (*Length < reqLen) {
		*Length = reqLen;

		return -1;
	}

	// Place header
	memcpy (PEM, PEMhf[Type].header, PEMhf[Type].hLen);
	PEM += PEMhf[Type].hLen;

	// Encode bytes
	status = base64->encode (base64, Context->Buffer, Context->Position, (unsigned char*) PEM,
		*Length);
	if (status != 0) {
		return -1;
	}
	PEM += b64Len;

	// Place footer
	memcpy (PEM, PEMhf[Type].footer, PEMhf[Type].fLen);
	PEM += PEMhf[Type].fLen;

	// Output buffer length
	*Length = reqLen;

	return 0;
}

int DERAddNull (
	DERBuilderContext *Context)
{
	CHECK_SPACE (Context);
	Context->Buffer[Context->Position++] = 0x5;
	Context->Buffer[Context->Position++] = 0x0;

	return 0;
Error:

	return -1;
}

int DERAddPublicKey (
	DERBuilderContext *Context,	const uint8_t *key,	size_t key_len)
{
	return DERAddDER (Context, key, key_len);
}

int DERAddDER (
	DERBuilderContext *Context, const uint8_t *der, size_t length)
{
	CHECK_SPACE2 (Context, length);
	memcpy (&Context->Buffer[Context->Position], der, length);
	Context->Position += length;

	return 0;
Error:

	return -1;
}
