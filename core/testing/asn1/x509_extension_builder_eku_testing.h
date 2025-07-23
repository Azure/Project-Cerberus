// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef X509_EXTENSION_BUILDER_EKU_TESTING_H_
#define X509_EXTENSION_BUILDER_EKU_TESTING_H_

#include <stddef.h>
#include <stdint.h>
#include "asn1/x509_extension_builder.h"


extern const uint8_t X509_EXTENSION_BUILDER_EKU_TESTING_OID[];
#define	X509_EXTENSION_BUILDER_EKU_TESTING_OID_LEN					3


extern const struct x509_extension_builder_eku_oid X509_EXTENSION_BUILDER_EKU_TESTING_SINGLE_OID[];
#define	X509_EXTENSION_BUILDER_EKU_TESTING_SINGLE_OID_COUNT			1

extern const uint8_t X509_EXTENSION_BUILDER_EKU_TESTING_DATA_SINGLE[];
extern const size_t X509_EXTENSION_BUILDER_EKU_TESTING_DATA_SINGLE_LEN;

extern const struct x509_extension X509_EXTENSION_BUILDER_EKU_TESTING_EXTENSION_SINGLE;


extern const struct x509_extension_builder_eku_oid
	X509_EXTENSION_BUILDER_EKU_TESTING_MULTIPLE_OIDS[];
#define	X509_EXTENSION_BUILDER_EKU_TESTING_MULTIPLE_OIDS_COUNT		4

extern const uint8_t X509_EXTENSION_BUILDER_EKU_TESTING_DATA_MULTIPLE[];
extern const size_t X509_EXTENSION_BUILDER_EKU_TESTING_DATA_MULTIPLE_LEN;

extern const struct x509_extension X509_EXTENSION_BUILDER_EKU_TESTING_EXTENSION_MULTIPLE;


#endif	/* X509_EXTENSION_BUILDER_EKU_TESTING_H_ */
