// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef CMD_INTERFACE_DUAL_CMD_SET_H_
#define CMD_INTERFACE_DUAL_CMD_SET_H_

#include "cmd_interface.h"


/**
 * Command interface for processing requests from two command sets
 */
struct cmd_interface_dual_cmd_set {
	struct cmd_interface base;					/**< Base command interface */
	struct cmd_interface *intf_0;				/**< Interface to process commands from set 0 */
	struct cmd_interface *intf_1;				/**< Interface to process commands from set 1 */
};


int cmd_interface_dual_cmd_set_init (struct cmd_interface_dual_cmd_set *intf,
	struct cmd_interface *intf_0, struct cmd_interface *intf_1);
void cmd_interface_dual_cmd_set_deinit (struct cmd_interface_dual_cmd_set *intf);


#endif /* CMD_INTERFACE_DUAL_CMD_SET_H_ */
