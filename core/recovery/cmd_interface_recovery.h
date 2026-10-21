// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef CMD_INTERFACE_RECOVERY_H_
#define CMD_INTERFACE_RECOVERY_H_

#include <stdbool.h>
#include <stdint.h>
#include "attestation/pcr_store.h"
#include "cmd_interface/cmd_interface.h"
#include "cmd_interface/device_manager.h"
#include "crypto/hash.h"
#include "firmware/firmware_update_control.h"
#include "manifest/manifest_cmd_interface.h"
#include "recovery/recovery_image_cmd_interface.h"
#include "recovery/recovery_image_manager.h"


/**
 * A minimal command handler for supporting recovery processing.  Only commands explicitly needed in the
 * recovery context will be supported.
 */
struct cmd_interface_recovery {
	struct cmd_interface base;							/**< Base command interface */
	const struct firmware_update_control *control;		/**< FW update control instance */
	const struct cmd_interface_fw_version *fw_version;	/**< FW version numbers */
	struct device_manager *device_manager;				/**< Device manager instance */
	struct cmd_interface_device_id device_id;			/**< Device ID information */
	const struct riot_key_manager *riot;				/**< RIoT key manager */
	struct attestation_responder *attestation;			/**< Attestation responder instance */
	const struct cmd_device *cmd_device;				/**< Device command handler instance */
	const struct cmd_background *background;			/**< Context for completing background commands */
};


int cmd_interface_recovery_init (struct cmd_interface_recovery *intf,
	struct attestation_responder *attestation, const struct firmware_update_control *control,
	struct device_manager *device_manager, const struct cmd_background *background,
	const struct riot_key_manager *riot, const struct cmd_interface_fw_version *fw_version,
	uint16_t vendor_id, uint16_t device_id,	uint16_t subsystem_vid,	uint16_t subsystem_id,
	const struct cmd_device *cmd_device);

void cmd_interface_recovery_deinit (const struct cmd_interface_recovery *intf);


#endif	/* CMD_INTERFACE_RECOVERY_H_ */
