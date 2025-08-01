// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef X509_EXTENSION_BUILDER_DICE_UEID_H_
#define X509_EXTENSION_BUILDER_DICE_UEID_H_

#include "asn1/x509_extension_builder.h"


/**
 * Extra buffer space to add to keep the DER encoder happy.
 *
 * TODO:  Remove the need for the extra padding with updates to the DER encoder.
 */
#define	X509_EXTENSION_BUILDER_DICE_UEID_BUFFER_PADDING				32

/**
 * Determine the length of the extension data based on the length of the UEID.  This is only valid
 * for UEIDs up to 125 bytes long.
 *
 * @param ueid_len Length of the UEID that will be encoded in the extension.
 */
#define	X509_EXTENSION_BUILDER_DICE_UEID_DATA_LENGTH(ueid_len)      \
	((ueid_len) + 4 + X509_EXTENSION_BUILDER_DICE_UEID_BUFFER_PADDING)


/**
 * Builder for the TCG DICE Ueid extension.  The extension builder does not rely on any external
 * components or libraries.
 */
struct x509_extension_builder_dice_ueid {
	struct x509_extension_builder base;	/**< Base extension builder API. */
	const uint8_t *ueid;				/**< The UEID to encode in the extension. */
	size_t ueid_length;					/**< Length of the UEID. */
	uint8_t *ext_buffer;				/**< Buffer to use for building the extension data. */
	size_t ext_length;					/**< Length of the extension data duffer. */
};


int x509_extension_builder_dice_ueid_init (struct x509_extension_builder_dice_ueid *builder,
	const uint8_t *ueid, size_t length);
int x509_extension_builder_dice_ueid_init_with_buffer (
	struct x509_extension_builder_dice_ueid *builder, const uint8_t *ueid, size_t length,
	uint8_t *ext_buffer, size_t buffer_length);
void x509_extension_builder_dice_ueid_release (
	const struct x509_extension_builder_dice_ueid *builder);


#define	DICE_UEID_EXTENSION_ERROR(code)		ROT_ERROR (ROT_MODULE_DICE_UEID_EXTENSION, code)

/**
 * Error codes that can be generated by a TCG DICE Ueid extension builder.
 */
enum {
	DICE_UEID_EXTENSION_INVALID_ARGUMENT = DICE_UEID_EXTENSION_ERROR (0x00),	/**< Input parameter is null or not valid. */
	DICE_UEID_EXTENSION_NO_MEMORY = DICE_UEID_EXTENSION_ERROR (0x01),			/**< Memory allocation failed. */
	DICE_UEID_EXTENSION_SMALL_EXT_BUFFER = DICE_UEID_EXTENSION_ERROR (0x02),	/**< The extension buffer is too small for the data. */
};


#endif	/* X509_EXTENSION_BUILDER_DICE_UEID_H_ */
