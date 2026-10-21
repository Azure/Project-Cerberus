// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "tcg_dice_oid.h"


/**
 * The encoded OID for the TCG DICE TcbInfo extension:  2.23.133.5.4.1
 */
const uint8_t TCG_DICE_OID_TCBINFO_EXTENSION[] = {
	0x67, 0x81, 0x05, 0x05, 0x04, 0x01
};

/**
 * The encoded OID for the TCG DICE Ueid extension:  2.23.133.5.4.4
 */
const uint8_t TCG_DICE_OID_UEID_EXTENSION[] = {
	0x67, 0x81, 0x05, 0x05, 0x04, 0x04
};


/**
 * The encoded OID for a TCG DICE Initial Identity key (IDevID):  2.23.133.5.4.100.6
 */
const uint8_t TCG_DICE_OID_IDEVID[] = {
	0x67, 0x81, 0x05, 0x05, 0x04, 0x64, 0x06
};

/**
 * The encoded OID for a TCG DICE Local Identity key (LDevID):  2.23.133.5.4.100.7
 */
const uint8_t TCG_DICE_OID_LDEVID[] = {
	0x67, 0x81, 0x05, 0x05, 0x04, 0x64, 0x07
};

/**
 * The encoded OID for a TCG DICE Initial Attestation key:  2.23.133.5.4.100.8
 */
const uint8_t TCG_DICE_OID_ATTEST_INIT[] = {
	0x67, 0x81, 0x05, 0x05, 0x04, 0x64, 0x08
};

/**
 * The encoded OID for a TCG DICE Local Attestation key:  2.23.133.5.4.100.9
 */
const uint8_t TCG_DICE_OID_ATTEST_LOCAL[] = {
	0x67, 0x81, 0x05, 0x05, 0x04, 0x64, 0x09
};

/**
 * The encoded OID for a TCG DICE Initial Assertion key:  2.23.133.5.4.100.10
 */
const uint8_t TCG_DICE_OID_ASSERT_INIT[] = {
	0x67, 0x81, 0x05, 0x05, 0x04, 0x64, 0x0a
};

/**
 * The encoded OID for a TCG DICE Local Assertion key:  2.23.133.5.4.100.11
 */
const uint8_t TCG_DICE_OID_ASSERT_LOCAL[] = {
	0x67, 0x81, 0x05, 0x05, 0x04, 0x64, 0x0b
};

/**
 * The encoded OID for a TCG DICE Embedded Certificate Authority:  2.23.133.5.4.100.12
 */
const uint8_t TCG_DICE_OID_ECA[] = {
	0x67, 0x81, 0x05, 0x05, 0x04, 0x64, 0x0c
};
