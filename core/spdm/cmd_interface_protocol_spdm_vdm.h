// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef CMD_INTERFACE_PROTOCOL_SPDM_VDM_H_
#define CMD_INTERFACE_PROTOCOL_SPDM_VDM_H_

#include "cmd_interface/cmd_interface.h"
#include "spdm/spdm_protocol_vdm.h"


/**
 * Protocol handler for SPDM VDM (vendor defined messages) messages.
 */
struct cmd_interface_protocol_spdm_vdm {
	struct cmd_interface_protocol base;	/**< Base protocol handling API. */
};


int cmd_interface_protocol_spdm_vdm_init (struct cmd_interface_protocol_spdm_vdm *spdm_vdm);
void cmd_interface_protocol_spdm_vdm_release (
	const struct cmd_interface_protocol_spdm_vdm *spdm_vdm);


#endif	/* CMD_INTERFACE_PROTOCOL_SPDM_VDM_H_ */
