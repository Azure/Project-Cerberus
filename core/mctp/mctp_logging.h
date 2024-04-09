// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef MCTP_LOGGING_H_
#define MCTP_LOGGING_H_

#include "logging/debug_log.h"


/**
 * Logging messages for MCTP stack operations.
 */
enum {
	MCTP_LOGGING_PROTOCOL_ERROR,				/**< Error while processing input in MCTP protocol layer. */
	MCTP_LOGGING_ERR_MSG,						/**< Cerberus protocol error message received. */
	MCTP_LOGGING_MCTP_CONTROL_REQ_FAIL,			/**< Failure while processing MCTP control request message. */
	MCTP_LOGGING_PKT_DROPPED,					/**< MCTP packet dropped. */
	MCTP_LOGGING_CHANNEL,						/**< MCTP command channel identifier. */
	MCTP_LOGGING_SET_EID_FAIL,					/**< Failed when processing a Set EID request. */
	MCTP_LOGGING_MCTP_CONTROL_INVALID_LEN,		/**< Received a MCTP control message with invalid length. */
	MCTP_LOGGING_MCTP_CONTROL_RSP_CC_FAIL,		/**< Received a MCTP control message with a failed completion code. */
	MCTP_LOGGING_MCTP_CONTROL_RSP_FAIL,			/**< Failure while processing MCTP control response message. */
	MCTP_LOGGING_GET_EID_FAIL,					/**< Failed when processing a Get EID request. */
	MCTP_LOGGING_RSP_TIMEOUT,					/**< Timed out while waiting for MCTP response. */
	MCTP_LOGGING_RSP_DROPPED,					/**< Dropped a received response message. */
	MCTP_LOGGING_RESTART_MESSAGE,				/**< A new message was started before finishing the previous one. */
};

/**
 * Reason details for why a response message was dropped.
 */
enum {
	MCTP_LOGGING_RSP_DROPPED_UNEXPECTED,	/**< No response message was expected. */
	MCTP_LOGGING_RSP_DROPPED_WRONG_TAG,		/**< The response message has the wrong message tag. */
	MCTP_LOGGING_RSP_DROPPED_WRONG_SOURCE,	/**< The response message came from the wrong EID. */
	MCTP_LOGGING_RSP_DROPPED_WRONG_TYPE,	/**< The response message is the wrong message type. */
};


#endif /* MCTP_LOGGING_H_ */
