// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef MCTP_LOGGING_H_
#define MCTP_LOGGING_H_

#include "logging/debug_log.h"


/**
 * Logging messages for MCTP stack operations.
 */
enum {
	MCTP_LOGGING_PROTOCOL_ERROR,			/**< Error while processing input in MCTP protocol layer. */
	MCTP_LOGGING_ERR_MSG,					/**< Cerberus protocol error message recevied. */
	MCTP_LOGGING_CONTROL_FAIL,				/**< Failure while processing MCTP control message. */
	MCTP_LOGGING_PKT_DROPPED,				/**< MCTP packet dropped. */
	MCTP_LOGGING_CHANNEL,					/**< MCTP command channel identifier. */
	MCTP_LOGGING_SET_EID_FAIL,				/**< Received an invalid response to a Set EID request. */
	MCTP_LOGGING_INVALID_LEN,				/**< Received a MCTP control message with invalid length. */
};


#endif /* MCTP_LOGGING_H_ */
