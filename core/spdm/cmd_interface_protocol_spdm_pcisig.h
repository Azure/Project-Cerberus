// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef CMD_INTERFACE_PROTOCOL_SPDM_PCISIG_H_
#define CMD_INTERFACE_PROTOCOL_SPDM_PCISIG_H_

#include "cmd_interface/cmd_interface.h"
#include "spdm/spdm_protocol_pcisig.h"


/**
 * Protocol handler for SPDM PCISIG messages.
 */
struct cmd_interface_protocol_spdm_pcisig {
	struct cmd_interface_protocol base;	/**< Base protocol handling API. */
};


int cmd_interface_protocol_spdm_pcisig_init (
	struct cmd_interface_protocol_spdm_pcisig *spdm_pcisig);
void cmd_interface_protocol_spdm_pcisig_release (
	const struct cmd_interface_protocol_spdm_pcisig *spdm_pcisig);


#endif	/* CMD_INTERFACE_PROTOCOL_SPDM_PCISIG_H_ */
