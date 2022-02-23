// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef MCTP_INTERFACE_H_
#define MCTP_INTERFACE_H_

#include <stdint.h>
#include <stdbool.h>
#include "platform.h"
#include "cmd_interface/cmd_channel.h"
#include "cmd_interface/device_manager.h"
#include "cmd_interface/cmd_interface.h"
#include "mctp_base_protocol.h"


/**
 * MCTP interface context
 */
struct mctp_interface {
	struct cmd_interface *cmd_cerberus;						/**< Command interface instance to handle Cerberus protocol messages */
	struct cmd_interface *cmd_mctp;							/**< Command interface instance to handle MCTP control protocol messages */
	struct device_manager *device_manager;					/**< Device manager linked to command interface */
	uint8_t msg_buffer[MCTP_BASE_PROTOCOL_MAX_MESSAGE_LEN];	/**< Buffer for MCTP messages */
	struct cmd_message resp_buffer;							/**< Buffer for transmitting responses */
	struct cmd_interface_msg req_buffer;					/**< Buffer for request processing */
	int start_packet_len;									/**< Length of MCTP start packet */
	uint8_t packet_seq;										/**< Current MCTP exchange packet sequence */
	uint8_t msg_tag;										/**< Current MCTP exchange message tag */
	uint8_t msg_type;										/**< Current MCTP exchange message type */
	int channel_id;											/**< Channel ID associated with the interface. */
	uint8_t response_eid;									/**< MCTP EID for device we expect a response from */
	uint8_t response_msg_tag;								/**< MCTP message tag for transaction we expect response for */
	bool response_expected;									/**< A boolean indicating whether a response is expected or not */
#ifdef CMD_ENABLE_ISSUE_REQUEST
	platform_semaphore wait_for_response;					/**< Semaphore used by requester to wait for response. */
	platform_mutex lock;									/**< Synchronization for shared interfaces */
#endif
};


int mctp_interface_init (struct mctp_interface *mctp, struct cmd_interface *cmd_cerberus,
	struct cmd_interface *cmd_mctp, struct device_manager *device_mgr);
void mctp_interface_deinit (struct mctp_interface *mctp);

int mctp_interface_set_channel_id (struct mctp_interface *mctp, int channel_id);

int mctp_interface_process_packet (struct mctp_interface *mctp, struct cmd_packet *rx_packet,
	struct cmd_message **tx_message);
void mctp_interface_reset_message_processing (struct mctp_interface *mctp);

#ifdef CMD_ENABLE_ISSUE_REQUEST
int mctp_interface_issue_request (struct mctp_interface *mctp, struct cmd_channel *channel,
	uint8_t dest_addr, uint8_t dest_eid, uint8_t *request, size_t length, uint8_t *msg_buffer,
	size_t max_buffer, uint32_t timeout_ms);
#endif

#endif /* MCTP_INTERFACE_H_ */
