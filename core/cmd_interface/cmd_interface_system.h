// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef CMD_INTERFACE_SYSTEM_H_
#define CMD_INTERFACE_SYSTEM_H_

#include <stdint.h>
#include <stdbool.h>
#include "attestation/attestation_master.h"
#include "attestation/attestation_slave.h"
#include "cmd_interface.h"
#include "device_manager.h"
#include "session_manager.h"
#include "cmd_background.h"
#include "cmd_authorization.h"
#include "session_manager.h"
#include "crypto/hash.h"
#include "firmware/firmware_update_control.h"
#include "manifest/manifest_cmd_interface.h"
#include "manifest/pfm/pfm_manager.h"
#include "manifest/cfm/cfm_manager.h"
#include "attestation/pcr_store.h"
#include "host_fw/host_processor.h"
#include "riot/riot_key_manager.h"
#include "recovery/recovery_image_manager.h"
#include "recovery/recovery_image_cmd_interface.h"
#include "cmd_device.h"
#include "common/observable.h"
#include "cerberus_protocol_observer.h"


/**
 * Command interface for processing received requests from system.
 */
struct cmd_interface_system {
	struct cmd_interface base;								/**< Base command interface */
	struct firmware_update_control *control;				/**< FW update control instance */
	struct manifest_cmd_interface *pfm_0;					/**< PFM update command interface instance for port 0 */
	struct manifest_cmd_interface *pfm_1;					/**< PFM update command interface instance for port 1 */
	struct manifest_cmd_interface *cfm;						/**< CFM update command interface instance */
	struct cmd_background *background;						/**< Context for completing background commands */
	struct manifest_cmd_interface *pcd;						/**< PCD update command interface instance */
	struct pfm_manager *pfm_manager_0;						/**< PFM manager instance for port 0 */
	struct pfm_manager *pfm_manager_1;						/**< PFM manager instance for port 1 */
	struct cfm_manager *cfm_manager;						/**< CFM manager instance */
	struct pcd_manager *pcd_manager;						/**< PCD manager instance */
	struct host_processor *host_0;							/**< Host interface for port 0 */
	struct host_processor *host_1;							/**< Host interface for port 1 */
	struct pcr_store *pcr_store;							/**< PCR storage */
	struct riot_key_manager *riot;							/**< RIoT key manager */
	struct cmd_authorization *auth;							/**< Authorization handler */
	struct attestation_master *master_attestation;			/**< Master attestation manager instance */
	struct attestation_slave *slave_attestation;			/**< Slave attestation manager instance */
	struct hash_engine *hash;								/**< The hashing engine for PCR operations. */
	struct cmd_interface_fw_version *fw_version;			/**< FW version numbers */
	struct host_control *host_0_ctrl;						/**< Host hardware control for port 0. */
	struct host_control *host_1_ctrl;						/**< Host hardware control for port 1. */
	struct device_manager *device_manager;					/**< Device manager instance */
	struct recovery_image_manager *recovery_manager_0;		/**< Recovery image manager instance for port 0 */
	struct recovery_image_manager *recovery_manager_1;		/**< Recovery image manager instance for port 1 */
	struct recovery_image_cmd_interface *recovery_cmd_0;	/**< Recovery image update command interface instance for port 0 */
	struct recovery_image_cmd_interface *recovery_cmd_1;	/**< Recovery image update command interface instance for port 1 */
	struct cmd_device *cmd_device;							/**< Device command handler instance */
	struct cmd_interface_device_id device_id;				/**< Device ID information */
	struct observable observable;							/**< Observer manager for the interface. */
};


int cmd_interface_system_init (struct cmd_interface_system *intf,
	struct firmware_update_control *control, struct manifest_cmd_interface *pfm_0,
	struct manifest_cmd_interface *pfm_1, struct manifest_cmd_interface *cfm,
	struct manifest_cmd_interface *pcd, struct pfm_manager *pfm_manager_0,
	struct pfm_manager *pfm_manager_1, struct cfm_manager *cfm_manager,
	struct pcd_manager *pcd_manager,  struct attestation_master *master_attestation,
	struct attestation_slave *slave_attestation, struct device_manager *device_manager,
	struct pcr_store *store, struct hash_engine *hash, struct cmd_background *background,
	struct host_processor *host_0, struct host_processor *host_1,
	struct cmd_interface_fw_version *fw_version, struct riot_key_manager *riot,
	struct cmd_authorization *auth, struct host_control *host_0_ctrl,
	struct host_control *host_1_ctrl, struct recovery_image_cmd_interface *recovery_cmd_0,
	struct recovery_image_cmd_interface *recovery_cmd_1,
	struct recovery_image_manager *recovery_manager_0,
	struct recovery_image_manager *recovery_manager_1, struct cmd_device *cmd_device,
	uint16_t vendor_id, uint16_t device_id, uint16_t subsystem_vid, uint16_t subsystem_id,
	struct session_manager *session);
void cmd_interface_system_deinit (struct cmd_interface_system *intf);

int cmd_interface_system_add_cerberus_protocol_observer (struct cmd_interface_system *intf,
	struct cerberus_protocol_observer *observer);
int cmd_interface_system_remove_cerberus_protocol_observer (struct cmd_interface_system *intf,
	struct cerberus_protocol_observer *observer);

/* Internal functions for use by derived types. */
int cmd_interface_system_process_request (struct cmd_interface *intf,
	struct cmd_interface_msg *request);
int cmd_interface_system_process_response (struct cmd_interface *intf,
	struct cmd_interface_msg *response);


#endif /* CMD_INTERFACE_SYSTEM_H_ */
