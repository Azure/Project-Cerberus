// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef CMD_INTERFACE_MULTI_HANDLER_H_
#define CMD_INTERFACE_MULTI_HANDLER_H_

#include <stdint.h>
#include "cmd_interface.h"


/**
 * A command handler for a single message type in a protocol stack that supports multiple different
 * types of messages.
 */
struct cmd_interface_multi_handler_msg_type {
	uint32_t type_id;						/**< Identifier for the type of message being handled. */
	const struct cmd_interface *handler;	/**< Command handler for the message type. */
};

/**
 * An intermediate command processing layer for protocol stacks that support multiple different
 * message types that share some common encapsulation, while each message type has a different
 * payload structure requiring unique processing.  It's expected that the type of each message can
 * be identified by some value contained within the payload, which can than be used as a search key
 * against a set of registered command handlers for the supported message types.
 */
struct cmd_interface_multi_handler {
	struct cmd_interface base;				/**< The base command handler API. */

	/**
	 * Determine if a specified message type is supported by the message type handler.
	 *
	 * @param intf The command handler to query for message type support.
	 * @param message_type Identifier for the type of message to check for.
	 *
	 * @return 0 if the requested message type is supported by the handler or an error code.  This
	 * will be CMD_HANDLER_UNKNOWN_MESSAGE_TYPE if the message type does not map to any registered
	 * handlers.
	 */
	int (*is_message_type_supported) (const struct cmd_interface_multi_handler *intf,
		uint32_t message_type);

	const struct cmd_interface_protocol *protocol;					/**< The protocol to use with the handler. */
	const struct cmd_interface_multi_handler_msg_type *msg_types;	/**< The list of message types supported by the protocol. */
	size_t type_count;												/**< The number of supported message types. */
};


int cmd_interface_multi_handler_msg_type_init (
	struct cmd_interface_multi_handler_msg_type *msg_type, uint32_t type_id,
	const struct cmd_interface *handler);

int cmd_interface_multi_handler_init (struct cmd_interface_multi_handler *intf,
	const struct cmd_interface_protocol *protocol,
	const struct cmd_interface_multi_handler_msg_type *msg_types, size_t type_count);
void cmd_interface_multi_handler_release (const struct cmd_interface_multi_handler *intf);


#endif /* CMD_INTERFACE_MULTI_HANDLER_H_ */
