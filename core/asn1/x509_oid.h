// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef X509_OID_H_
#define X509_OID_H_

#include <stddef.h>
#include <stdint.h>


/* Standard X.509 Extensions */

/**
 * Length of the encoded Extended Key Usage extension OID.
 */
#define	X509_OID_EKU_EXTENSION_LENGTH		3
extern const uint8_t X509_OID_EKU_EXTENSION[];


/* X.509 Extended Key Usage */

/**
 * Length of the encoded TLS WWW client authentication OID.
 */
#define	X509_OID_CLIENT_AUTH_LENGTH			8
extern const uint8_t X509_OID_CLIENT_AUTH[];


#endif	/* X509_OID_H_ */
