/*
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See LICENSE in the project root.
 */

#include <string.h>
#include <stdbool.h>
#include "crypto/base64.h"
#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#define DER_MAX_PEM     0x400
#define DER_MAX_TBS     0x300
#define DER_MAX_NESTED  0x10

//
// Context structure for the DER-encoder. This structure contains a fixed-
// length array for nested SEQUENCES (which imposes a nesting limit).
// The buffer use for encoded data is caller-allocated.
//
typedef struct
{
	uint8_t *Buffer;      // Encoded data
	size_t Length;        // Size, in bytes, of Buffer
	size_t Position;      // Current buffer position

	// SETS, SEQUENCES, etc. can be nested. This array contains the start of
	// the payload for collection types and is set by  DERStartSequenceOrSet().
	// Collections are "popped" using DEREndSequenceOrSet().
	int CollectionStart[DER_MAX_NESTED];
	int CollectionPos;
} DERBuilderContext;

// We only have a small subset of potential PEM encodings
enum CertType {
    CERT_TYPE = 0,
    PUBLICKEY_TYPE,
    ECC_PRIVATEKEY_TYPE,
    CERT_REQ_TYPE,
    LAST_CERT_TYPE
};

void
DERInitContext(
    DERBuilderContext   *Context,
    uint8_t             *Buffer,
    size_t              Length
);

size_t
DERGetEncodedLength(
    DERBuilderContext   *Context
);


int
DERAddOID(
    DERBuilderContext   *Context,
    const int           *Values
);

int
DERAddEncodedOID(
    DERBuilderContext   *Context,
    const char          *Oid
);

int
DERAddString(
    DERBuilderContext   *Context,
    const char          *Str,
    uint8_t              Tag
);

int
DERAddUTF8String(
    DERBuilderContext   *Context,
    const char          *Str
);

int
DERAddPrintableString(
    DERBuilderContext   *Context,
    const char          *Str
);

int
DERAddIA5String(
    DERBuilderContext   *Context,
    const char          *Str
);

int
DERAddTime(
    DERBuilderContext   *Context,
    const char          *Str
);

int
DERAddIntegerFromArray(
    DERBuilderContext   *Context,
    const uint8_t       *Val,
    uint32_t            NumBytes
);

int
DERAddTaggedInteger(
    DERBuilderContext   *Context,
    int                  Val,
    uint8_t              Tag
);

int
DERAddInteger(
    DERBuilderContext   *Context,
    int                 Val
);

int
DERAddShortExplicitInteger(
    DERBuilderContext   *Context,
    int                  Val
);

int
DERAddBoolean(
    DERBuilderContext   *Context,
    bool                 Val
);


int
DERAddBitString(
    DERBuilderContext   *Context,
    const uint8_t       *BitString,
    size_t              BitStringNumBytes
);

int
DERAddNamedBitString(
    DERBuilderContext   *Context,
    const uint8_t       *BitString,
    size_t              BitStringNumBytes,
	size_t				bits
);

int
DERAddOctetString(
    DERBuilderContext   *Context,
    const uint8_t       *OctetString,
    size_t              OctetStringLen
);

int
DERStartConstructed(
    DERBuilderContext   *Context,
    uint8_t              Tag
);

int
DERStartSequenceOrSet(
    DERBuilderContext   *Context,
    bool                 Sequence
);

int
DERStartExplicit(
    DERBuilderContext   *Context,
    uint32_t             Num
);

int
DERAddAuthKeyBitString(
    DERBuilderContext   *Context,
    const uint8_t       *BitString,
    size_t              BitStringLen
);

int
DERStartEnvelopingOctetString(
    DERBuilderContext   *Context
);

int
DERStartEnvelopingBitString(
    DERBuilderContext   *Context
);

int
DERPopNesting(
    DERBuilderContext   *Context
);

int
DERGetNestingDepth(
    DERBuilderContext   *Context
);

int
DERTbsToCert(
    DERBuilderContext   *Context
);

int
DERtoPEM(
	DERBuilderContext	 *Context,
	uint32_t			 Type,
	char				 *PEM,
	uint32_t			 *Length,
	struct base64_engine *base64
);

int
DERAddNull(
    DERBuilderContext   *Context
);

int
DERAddPublicKey(
	DERBuilderContext	*Context,
	const uint8_t		*key,
	size_t				key_len
);

#ifdef __cplusplus
}
#endif
