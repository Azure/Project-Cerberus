// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef X509_EXTENSION_BUILDER_DICE_UEID_TESTING_H_
#define X509_EXTENSION_BUILDER_DICE_UEID_TESTING_H_

#include <stdint.h>
#include <stddef.h>
#include "asn1/x509_extension_builder.h"


extern const uint8_t X509_EXTENSION_BUILDER_DICE_UEID_TESTING_OID[];
#define	X509_EXTENSION_BUILDER_DICE_UEID_TESTING_OID_LEN		6

extern const uint8_t X509_EXTENSION_BUILDER_DICE_UEID_TESTING_DATA[];
extern const size_t X509_EXTENSION_BUILDER_DICE_UEID_TESTING_DATA_LEN;

extern const struct x509_extension X509_EXTENSION_BUILDER_DICE_UEID_TESTING_EXTENSION;


#endif /* X509_EXTENSION_BUILDER_DICE_UEID_TESTING_H_ */
