// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef SPDM_OID_H_
#define SPDM_OID_H_

#include <stddef.h>
#include <stdint.h>


/* SPDM Extended Key Usage */

/**
 * Length of the encoded SPDM responder authentication OID.
 */
#define	SPDM_OID_RESPONDER_AUTH_LENGTH		10
extern const uint8_t SPDM_OID_RESPONDER_AUTH[];

/**
 * Length of the encoded SPDM requester authentication OID.
 */
#define	SPDM_OID_REQUESTER_AUTH_LENGTH		10
extern const uint8_t SPDM_OID_REQUESTER_AUTH[];


#endif	/* SPDM_OID_H_ */
