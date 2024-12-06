// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef CMD_INTERFACE_SYSTEM_H_
#define CMD_INTERFACE_SYSTEM_H_

#include <stdbool.h>
#include <stdint.h>
#include "cerberus_protocol_observer.h"
#include "cmd_authorization.h"
#include "cmd_background.h"
#include "cmd_device.h"
#include "cmd_interface.h"
#include "device_manager.h"
#include "session_manager.h"
#include "session_manager.h"
#include "attestation/attestation_responder.h"
#include "attestation/pcr_store.h"
#include "common/observable.h"
#include "crypto/hash.h"
#include "firmware/firmware_update_control.h"
#include "host_fw/host_processor.h"
#include "manifest/cfm/cfm_manager.h"
#include "manifest/manifest_cmd_interface.h"
#include "manifest/pfm/pfm_manager.h"
#include "recovery/recovery_image_cmd_interface.h"
#include "recovery/recovery_image_manager.h"
#include "riot/riot_key_manager.h"


/**
 * Command interface for processing received requests from system.
 */
struct cmd_interface_system {
	struct cmd_interface base;									/**< Base command interface */
	const struct firmware_update_control *control;				/**< FW update control instance */
	const struct manifest_cmd_interface *pfm_0;					/**< PFM update command interface instance for port 0 */
	const struct manifest_cmd_interface *pfm_1;					/**< PFM update command interface instance for port 1 */
	const struct manifest_cmd_interface *cfm;					/**< CFM update command interface instance */
	const struct cmd_background *background;					/**< Context for completing background commands */
	const struct manifest_cmd_interface *pcd;					/**< PCD update command interface instance */
	const struct pfm_manager *pfm_manager_0;					/**< PFM manager instance for port 0 */
	const struct pfm_manager *pfm_manager_1;					/**< PFM manager instance for port 1 */
	const struct cfm_manager *cfm_manager;						/**< CFM manager instance */
	const struct pcd_manager *pcd_manager;						/**< PCD manager instance */
	struct host_processor *host_0;								/**< Host interface for port 0 */
	struct host_processor *host_1;								/**< Host interface for port 1 */
	struct pcr_store *pcr_store;								/**< PCR storage */
	const struct riot_key_manager *riot;						/**< RIoT key manager */
	const struct cmd_authorization *auth;						/**< Authorization handler */
	struct attestation_responder *attestation;					/**< Attestation responder instance */
	const struct hash_engine *hash;								/**< The hashing engine for PCR operations. */
	const struct cmd_interface_fw_version *fw_version;			/**< FW version numbers */
	const struct host_control *host_0_ctrl;						/**< Host hardware control for port 0. */
	const struct host_control *host_1_ctrl;						/**< Host hardware control for port 1. */
	struct device_manager *device_manager;						/**< Device manager instance */
	struct recovery_image_manager *recovery_manager_0;			/**< Recovery image manager instance for port 0 */
	struct recovery_image_manager *recovery_manager_1;			/**< Recovery image manager instance for port 1 */
	const struct recovery_image_cmd_interface *recovery_cmd_0;	/**< Recovery image update command interface instance for port 0 */
	const struct recovery_image_cmd_interface *recovery_cmd_1;	/**< Recovery image update command interface instance for port 1 */
	const struct cmd_device *cmd_device;						/**< Device command handler instance */
	struct cmd_interface_device_id device_id;					/**< Device ID information */
	struct observable observable;								/**< Observer manager for the interface. */
};


/* TODO:  Observable needs to support const model in order to support static/const instances. */
int cmd_interface_system_init (struct cmd_interface_system *intf,
	const struct firmware_update_control *control, const struct manifest_cmd_interface *pfm_0,
	const struct manifest_cmd_interface *pfm_1, const struct manifest_cmd_interface *cfm,
	const struct manifest_cmd_interface *pcd, const struct pfm_manager *pfm_manager_0,
	const struct pfm_manager *pfm_manager_1, const struct cfm_manager *cfm_manager,
	const struct pcd_manager *pcd_manager, struct attestation_responder *attestation,
	struct device_manager *device_manager, struct pcr_store *store, const struct hash_engine *hash,
	const struct cmd_background *background, struct host_processor *host_0,
	struct host_processor *host_1, const struct cmd_interface_fw_version *fw_version,
	const struct riot_key_manager *riot, const struct cmd_authorization *auth,
	const struct host_control *host_ctrl_0, const struct host_control *host_ctrl_1,
	const struct recovery_image_cmd_interface *recovery_cmd_0,
	const struct recovery_image_cmd_interface *recovery_cmd_1,
	struct recovery_image_manager *recovery_manager_0,
	struct recovery_image_manager *recovery_manager_1, const struct cmd_device *cmd_device,
	uint16_t vendor_id, uint16_t device_id, uint16_t subsystem_vid, uint16_t subsystem_id,
	struct session_manager *session);
void cmd_interface_system_deinit (struct cmd_interface_system *intf);

int cmd_interface_system_add_cerberus_protocol_observer (struct cmd_interface_system *intf,
	const struct cerberus_protocol_observer *observer);
int cmd_interface_system_remove_cerberus_protocol_observer (struct cmd_interface_system *intf,
	const struct cerberus_protocol_observer *observer);

/* Internal functions for use by derived types. */
int cmd_interface_system_process_request (const struct cmd_interface *intf,
	struct cmd_interface_msg *request);
int cmd_interface_system_process_response (const struct cmd_interface *intf,
	struct cmd_interface_msg *response);


#endif	/* CMD_INTERFACE_SYSTEM_H_ */
