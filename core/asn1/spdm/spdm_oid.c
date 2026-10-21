// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "spdm_oid.h"


/**
 * The encoded OID for an SPDM responder authentication key:  1.3.6.1.4.1.412.274.3
 */
const uint8_t SPDM_OID_RESPONDER_AUTH[] = {
	0x2b, 0x06, 0x01, 0x04, 0x01, 0x83, 0x1c, 0x82, 0x12, 0x03
};

/**
 * The encoded OID for an SPDM requester authentication key:  1.3.6.1.4.1.412.274.4
 */
const uint8_t SPDM_OID_REQUESTER_AUTH[] = {
	0x2b, 0x06, 0x01, 0x04, 0x01, 0x83, 0x1c, 0x82, 0x12, 0x04
};
