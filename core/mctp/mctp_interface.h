// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef MCTP_INTERFACE_H_
#define MCTP_INTERFACE_H_

#include <stdint.h>
#include "cmd_interface/cmd_channel.h"
#include "cmd_interface/device_manager.h"
#include "cmd_interface/cmd_interface.h"
#include "mctp_protocol.h"


/**
 * MCTP interface context
 */
struct mctp_interface {
	struct cmd_interface *cmd_interface;			/**< Command interface instance */
	struct device_manager *device_manager;			/**< Device manager linked to command interface */
	struct cmd_interface_request msg_buffer;		/**< Message buffer */
	int start_packet_len;							/**< Length of MCTP start packet */
	uint16_t pci_vendor_id;							/**< Protocol PCI vendor ID */
	uint16_t protocol_version;						/**< Protocol version */
	uint8_t packet_seq;								/**< Current MCTP exchange packet sequence */
	uint8_t msg_tag;								/**< Current MCTP exchange message tag */
	uint8_t msg_type;								/**< Current MCTP exchange message type */
	uint8_t eid;									/**< MCTP EID to listen to */
	int channel_id;									/**< Channel ID associated with the interface. */
};


int mctp_interface_init (struct mctp_interface *interface, struct cmd_interface *cmd_interface,
	struct device_manager *device_mgr, uint8_t eid, uint16_t pci_vid, uint16_t protocol_version);
void mctp_interface_deinit (struct mctp_interface *interface);

int mctp_interface_set_channel_id (struct mctp_interface *interface, int channel_id);
int mctp_interface_process_packet (struct mctp_interface *interface, struct cmd_packet *rx_packet,
	struct cmd_packet **tx_packets, size_t *num_packets);
void mctp_interface_reset_message_processing (struct mctp_interface *interface);
int mctp_interface_issue_request (struct mctp_interface *interface, uint8_t dest_addr,
	uint8_t dest_eid, uint8_t src_addr, uint8_t src_eid, uint8_t command_id, void *request_params,
	uint8_t *buf, int buf_len, uint8_t msg_type);


#endif /* MCTP_INTERFACE_H_ */
