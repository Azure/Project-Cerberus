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
};


#endif /* MCTP_LOGGING_H_ */
