// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef CMD_INTERFACE_PROTOCOL_MCTP_H_
#define CMD_INTERFACE_PROTOCOL_MCTP_H_

#include "cmd_interface/cmd_interface.h"


/**
 * Protocol handler for MCTP messages.
 */
struct cmd_interface_protocol_mctp {
	struct cmd_interface_protocol base;			/**< Base protocol handling API. */
};


int cmd_interface_protocol_mctp_init (struct cmd_interface_protocol_mctp *mctp);
void cmd_interface_protocol_mctp_release (const struct cmd_interface_protocol_mctp *mctp);


#endif /* CMD_INTERFACE_PROTOCOL_MCTP_H_ */
