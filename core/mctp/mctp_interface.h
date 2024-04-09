// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef MCTP_INTERFACE_H_
#define MCTP_INTERFACE_H_

#include <stdint.h>
#include <stdbool.h>
#include "mctp_base_protocol.h"
#include "platform_api.h"
#include "cmd_interface/cmd_channel.h"
#include "cmd_interface/cmd_interface_multi_handler.h"
#include "cmd_interface/device_manager.h"
#include "cmd_interface/msg_transport.h"


/**
 * MCTP interface state for transactions started by device
 */
enum mctp_interface_response_state {
	MCTP_INTERFACE_RESPONSE_IDLE,			/**< No active transaction started by device. */
	MCTP_INTERFACE_RESPONSE_WAITING,		/**< Request sent, waiting for a response. */
	MCTP_INTERFACE_RESPONSE_PENDING,		/**< Request sent, not waiting for a response. */
	MCTP_INTERFACE_RESPONSE_TOO_BIG,		/**< Received response was too large for the buffer. */
	MCTP_INTERFACE_RESPONSE_SUCCESS,		/**< Successfully received response from the target. */
	MCTP_INTERFACE_RESPONSE_WAITING_DEPRECATED,	/**< Using the deprecated workflow to wait for a response. */
	MCTP_INTERFACE_RESPONSE_ERROR_DEPRECATED,	/**< Deprecated indication of an error response. */
	MCTP_INTERFACE_RESPONSE_FAIL_DEPRECATED,	/**< Deprecated indication of a response processing failure. */
};

/**
 * Variable context for an SMBus MCTP handler.
 */
struct mctp_interface_state {
	uint8_t msg_buffer[MCTP_BASE_PROTOCOL_MAX_MESSAGE_LEN];	/**< Buffer for MCTP messages */
	struct cmd_message resp_buffer;							/**< Buffer for transmitting responses */
	struct cmd_interface_msg req_buffer;					/**< Buffer for request processing */
	size_t start_packet_len;								/**< Length of MCTP start packet */
	uint8_t packet_seq;										/**< Current MCTP exchange packet sequence */
	uint8_t msg_tag;										/**< Current MCTP exchange message tag */
	uint8_t tag_owner;										/**< Tag owner for the current message. */
	uint8_t msg_type;										/**< Current MCTP exchange message type */
	int channel_id;											/**< Channel ID associated with the interface. */
#ifdef CMD_ENABLE_ISSUE_REQUEST
	uint8_t response_eid;									/**< MCTP EID for device we expect a response from. */
	uint8_t response_msg_tag;								/**< MCTP message tag for transaction we expect response for. */
	uint8_t response_msg_type;								/**< Expected message type of the response message. */
	struct cmd_interface_msg *response_msg;					/**< Descriptor for handling response messages. */
	uint8_t next_msg_tag;									/**< MCTP message tag for the next request. */
	enum mctp_interface_response_state rsp_state;			/**< State of transactions started by device */
	platform_semaphore wait_for_response;					/**< Semaphore used by requester to wait for response. */
	platform_mutex request_lock;							/**< Synchronization te serialize outgoing requests. */
	platform_mutex response_lock;							/**< Synchronization for internal response handling. */
#endif
};

/**
 * Handler for MCTP messages using the SMBus binding to transport packets.
 *
 * TODO:  Since the focus of this module really should be MCTP transport layer handling, the type
 * name should be changed to be more descriptive.  At minimum, it should be mctp_transport, but even
 * better would be msg_transport_mctp_smbus.
 */
struct mctp_interface {
#ifdef CMD_ENABLE_ISSUE_REQUEST
	struct msg_transport base;								/**< Base transport API for sending requests. */
	const struct cmd_channel *channel;						/**< Command channel to use for sending requests. */
	const struct cmd_interface *cmd_mctp;					/**< Deprecated handler for MCTP responses. */
	const struct cmd_interface *cmd_spdm;					/**< Deprecated handler for SPDM responses. */
#endif
	struct mctp_interface_state *state;						/**< Variable context for the handler. */
	const struct cmd_interface_multi_handler *req_handler;	/**< Handler for processing MCTP requests. */
	struct device_manager *device_manager;					/**< Device manager linked to command interface */
	const struct cmd_interface *cmd_cerberus;				/**< Deprecated handler for Cerberus responses and error messages. */
};


int mctp_interface_init (struct mctp_interface *mctp, struct mctp_interface_state *state,
	const struct cmd_interface_multi_handler *req_handler, struct device_manager *device_mgr,
	const struct cmd_channel *channel, const struct cmd_interface *cmd_cerberus,
	const struct cmd_interface *cmd_mctp, const struct cmd_interface *cmd_spdm);
int mctp_interface_init_state (const struct mctp_interface *mctp);
void mctp_interface_release (const struct mctp_interface *mctp);

int mctp_interface_set_channel_id (const struct mctp_interface *mctp, int channel_id);

int mctp_interface_process_packet (const struct mctp_interface *mctp, struct cmd_packet *rx_packet,
	struct cmd_message **tx_message);

#ifdef CMD_ENABLE_ISSUE_REQUEST
int mctp_interface_issue_request (const struct mctp_interface *mctp,
	const struct cmd_channel *channel, uint8_t dest_addr, uint8_t dest_eid, uint8_t *request,
	size_t length, uint8_t *msg_buffer, size_t max_buffer, uint32_t timeout_ms);

int mctp_interface_send_discovery_notify (const struct mctp_interface *mctp, uint32_t timeout_ms,
	struct cmd_interface_msg *response);
#endif


#endif /* MCTP_INTERFACE_H_ */
