// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef CMD_INTERFACE_NULL_H_
#define CMD_INTERFACE_NULL_H_

#include "cmd_interface.h"


/**
 * A command handler that does not support processing any requests or responses.  However, it will
 * generate Cerberus error messages.
 */
struct cmd_interface_null {
	struct cmd_interface base;	/**< The base command handler API. */
};


int cmd_interface_null_init (struct cmd_interface_null *intf);
void cmd_interface_null_release (const struct cmd_interface_null *intf);


#endif	/* CMD_INTERFACE_NULL_H_ */
