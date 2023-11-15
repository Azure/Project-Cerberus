// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef MCTP_INTERFACE_H_
#define MCTP_INTERFACE_H_

#include <stdint.h>
#include <stdbool.h>
#include "platform_api.h"
#include "cmd_interface/cmd_channel.h"
#include "cmd_interface/device_manager.h"
#include "cmd_interface/cmd_interface.h"
#include "mctp_base_protocol.h"


/**
 * MCTP interface state for transactions started by device
 */
enum mctp_interface_response_state {
	MCTP_INTERFACE_RESPONSE_IDLE,							/**< No active transaction started by device. */
	MCTP_INTERFACE_RESPONSE_WAITING,						/**< Request send, waiting for response. */
	MCTP_INTERFACE_RESPONSE_FAIL,							/**< Response processing failed. */
	MCTP_INTERFACE_RESPONSE_ERROR,							/**< Received error response from target. */
	MCTP_INTERFACE_RESPONSE_SUCCESS,						/**< Successfully received response from target. */
};

/**
 * MCTP interface context
 */
struct mctp_interface {
	const struct cmd_interface *cmd_cerberus;				/**< Command interface instance to handle Cerberus protocol messages */
	const struct cmd_interface *cmd_mctp;					/**< Command interface instance to handle MCTP control protocol messages */
	const struct cmd_interface *cmd_spdm;					/**< Command interface instance to handle SPDM protocol messages */
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
	enum mctp_interface_response_state rsp_state;			/**< State of transactions started by device */
#ifdef CMD_ENABLE_ISSUE_REQUEST
	platform_semaphore wait_for_response;					/**< Semaphore used by requester to wait for response. */
	platform_mutex lock;									/**< Synchronization for shared interfaces */
#endif
};


int mctp_interface_init (struct mctp_interface *mctp, const struct cmd_interface *cmd_cerberus,
	const struct cmd_interface *cmd_mctp, const struct cmd_interface *cmd_spdm,
	struct device_manager *device_mgr);
void mctp_interface_deinit (struct mctp_interface *mctp);

int mctp_interface_set_channel_id (struct mctp_interface *mctp, int channel_id);

int mctp_interface_process_packet (struct mctp_interface *mctp, struct cmd_packet *rx_packet,
	struct cmd_message **tx_message);
void mctp_interface_reset_message_processing (struct mctp_interface *mctp);

#ifdef CMD_ENABLE_ISSUE_REQUEST
int mctp_interface_issue_request (struct mctp_interface *mctp, const struct cmd_channel *channel,
	uint8_t dest_addr, uint8_t dest_eid, uint8_t *request, size_t length, uint8_t *msg_buffer,
	size_t max_buffer, uint32_t timeout_ms);

int mctp_interface_send_discovery_notify (struct mctp_interface *mctp,
	const struct cmd_channel *channel);
#endif

#endif /* MCTP_INTERFACE_H_ */
