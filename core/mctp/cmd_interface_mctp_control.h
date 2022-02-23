// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef CMD_INTERFACE_MCTP_CONTROL_H_
#define CMD_INTERFACE_MCTP_CONTROL_H_

#include <stdint.h>
#include "platform_config.h"
#include "common/observable.h"
#include "cmd_interface/cmd_interface.h"
#include "mctp_interface.h"
#include "mctp_control_protocol_observer.h"


/**
 * Command interface for processing received MCTP control protocol requests.
 */
struct cmd_interface_mctp_control {
	struct cmd_interface base;						/**< Base command interface */
	struct observable observable;					/**< Observer manager for the interface. */
	struct device_manager *device_manager;			/**< Device manager instance */
	uint16_t pci_vendor_id;							/**< Cerberus protocol PCI vendor ID */
	uint16_t protocol_version;						/**< Cerberus protocol version */
};


int cmd_interface_mctp_control_init (struct cmd_interface_mctp_control *intf,
	struct device_manager *device_manager, uint16_t pci_vendor_id, uint16_t protocol_version);
void cmd_interface_mctp_control_deinit (struct cmd_interface_mctp_control *intf);

int cmd_interface_mctp_control_add_mctp_control_protocol_observer (
	struct cmd_interface_mctp_control *intf, struct mctp_control_protocol_observer *observer);
int cmd_interface_mctp_control_remove_mctp_control_protocol_observer (
	struct cmd_interface_mctp_control *intf, struct mctp_control_protocol_observer *observer);


#endif /* CMD_INTERFACE_MCTP_CONTROL_H_ */
