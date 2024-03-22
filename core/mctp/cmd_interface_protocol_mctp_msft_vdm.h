// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef CMD_INTERFACE_PROTOCOL_MCTP_MSFT_VDM_H_
#define CMD_INTERFACE_PROTOCOL_MCTP_MSFT_VDM_H_

#include "cmd_interface/cmd_interface.h"


/**
 * Protocol handler for Microsoft MCTP vendor defined messages.
 */
struct cmd_interface_protocol_mctp_msft_vdm {
	struct cmd_interface_protocol base;			/**< Base protocol handling API. */
};


int cmd_interface_protocol_mctp_msft_vdm_init (struct cmd_interface_protocol_mctp_msft_vdm *mctp);
void cmd_interface_protocol_mctp_msft_vdm_release (
	const struct cmd_interface_protocol_mctp_msft_vdm *mctp);


#endif /* CMD_INTERFACE_PROTOCOL_MCTP_MSFT_VDM_H_ */
