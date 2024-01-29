// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef DOE_INTERFACE_H_
#define DOE_INTERFACE_H_

#include "doe_base_protocol.h"
#include "cmd_interface/cmd_interface.h"


/**
 * Information for a DOE message.
 */
struct doe_cmd_message {
	uint8_t message[DOE_MESSAGE_MAX_SIZE_IN_BYTES];	/**< Buffer for message data. */
};

/**
 * DOE interface context
 */
struct doe_interface {
	const struct cmd_interface *cmd_spdm_responder;		/**< Command interface instance to handle SPDM protocol requests */
};


int doe_interface_init (struct doe_interface *doe, struct cmd_interface *cmd_spdm_responder);

void doe_interface_release (const struct doe_interface *doe);

int doe_interface_process_message (const struct doe_interface *doe,
	struct doe_cmd_message *message);


#define	DOE_INTERFACE_ERROR(code)	ROT_ERROR (ROT_MODULE_DOE_INTERFACE, code)

/**
 * Error codes that can be generated by the DOE interface.
 */
enum {
	DOE_INTERFACE_INVALID_ARGUMENT = DOE_INTERFACE_ERROR (0x00),				/**< Input parameter is null or not valid. */
	DOE_INTERFACE_NO_MEMORY = DOE_INTERFACE_ERROR (0x01),						/**< Memory allocation failed. */
	DOE_INTERFACE_UNSUPPORTED_DATA_OBJECT_TYPE = DOE_INTERFACE_ERROR (0x02),	/**< Data object type is unsupported. */
	DOE_INTERFACE_INVALID_MSG_SIZE = DOE_INTERFACE_ERROR (0x03),				/**< The message size is incorrect. */
	DOE_INTERFACE_INVALID_VENDOR_ID = DOE_INTERFACE_ERROR (0x04),				/**< The vendor id is invalid. */
};


#endif /* DOE_INTERFACE_H_ */