// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef CMD_INTERFACE_AC_ROT_H_
#define CMD_INTERFACE_AC_ROT_H_

#include <stdint.h>
#include <stdbool.h>
#include "attestation/attestation_responder.h"
#include "cmd_interface.h"
#include "device_manager.h"
#include "session_manager.h"
#include "cmd_background.h"
#include "cmd_authorization.h"
#include "riot/riot_key_manager.h"
#include "cmd_device.h"


/**
 * Command interface for processing received requests from system.
 */
struct cmd_interface_ac_rot {
	struct cmd_interface base;								/**< Base command interface */
	const struct cmd_background *background;				/**< Context for completing background commands */
	struct riot_key_manager *riot;							/**< RIoT key manager */
	struct attestation_responder *attestation;				/**< Attestation responder instance */
	const struct cmd_interface_fw_version *fw_version;		/**< FW version numbers */
	struct device_manager *device_manager;					/**< Device manager instance */
	const struct cmd_device *cmd_device;					/**< Device command handler instance */
	struct cmd_interface_device_id device_id;				/**< Device ID information */
};


int cmd_interface_ac_rot_init (struct cmd_interface_ac_rot *intf,
	struct attestation_responder *attestation, struct device_manager *device_manager,
	const struct cmd_background *background, const struct cmd_interface_fw_version *fw_version,
	struct riot_key_manager *riot, const struct cmd_device *cmd_device, uint16_t vendor_id,
	uint16_t device_id, uint16_t subsystem_vid, uint16_t subsystem_id,
	struct session_manager *session);
void cmd_interface_ac_rot_deinit (const struct cmd_interface_ac_rot *intf);


#endif /* CMD_INTERFACE_AC_ROT_H_ */
