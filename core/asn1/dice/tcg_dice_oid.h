// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef TCG_DICE_OID_H_
#define TCG_DICE_OID_H_

#include <stddef.h>
#include <stdint.h>


/* TCG DICE Extensions */

/**
 * Length of the encoded TCG DICE TcbInfo extension OID.
 */
#define	TCG_DICE_OID_TCBINFO_EXTENSION_LENGTH	6
extern const uint8_t TCG_DICE_OID_TCBINFO_EXTENSION[];

/**
 * Length of the encoded TCG DICE Ueid extension OID.
 */
#define	TCG_DICE_OID_UEID_EXTENSION_LENGTH		6
extern const uint8_t TCG_DICE_OID_UEID_EXTENSION[];


/* TCG DICE Extended Key Usage */

/**
 * Length of the encoded TCG DICE Initial Identity key OID.
 */
#define	TCG_DICE_OID_IDEVID_LENGTH				7
extern const uint8_t TCG_DICE_OID_IDEVID[];

/**
 * Length of the encoded TCG DICE Local Identity key OID.
 */
#define	TCG_DICE_OID_LDEVID_LENGTH				7
extern const uint8_t TCG_DICE_OID_LDEVID[];

/**
 * Length of the encoded TCG DICE Initial Attestation key OID.
 */
#define	TCG_DICE_OID_ATTEST_INIT_LENGTH			7
extern const uint8_t TCG_DICE_OID_ATTEST_INIT[];

/**
 * Length of the encoded TCG DICE Local Attestation key OID.
 */
#define	TCG_DICE_OID_ATTEST_LOCAL_LENGTH		7
extern const uint8_t TCG_DICE_OID_ATTEST_LOCAL[];

/**
 * Length of the encoded TCG DICE Initial Assertion key OID.
 */
#define	TCG_DICE_OID_ASSERT_INIT_LENGTH			7
extern const uint8_t TCG_DICE_OID_ASSERT_INIT[];

/**
 * Length of the encoded TCG DICE Local Assertion key OID.
 */
#define	TCG_DICE_OID_ASSERT_LOCAL_LENGTH		7
extern const uint8_t TCG_DICE_OID_ASSERT_LOCAL[];

/**
 * Length of the encoded TCG DICE Embedded Certificate Authority OID.
 */
#define	TCG_DICE_OID_ECA_LENGTH					7
extern const uint8_t TCG_DICE_OID_ECA[];


#endif	/* TCG_DICE_OID_H_ */
