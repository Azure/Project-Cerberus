// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include "platform.h"
#include "cmd_channel.h"
#include "cmd_logging.h"
#include "common/common_math.h"
#include "mctp/mctp_interface.h"


/**
 * Initialize the base channel components.
 *
 * @param channel The channel to initialize.
 * @param id An ID to associate with this command channel.
 *
 * @return 0 if the channel was successfully initialized or an error code.
 */
int cmd_channel_init (struct cmd_channel *channel, int id)
{
	int status;

	if (channel == NULL) {
		return CMD_CHANNEL_INVALID_ARGUMENT;
	}

	memset (channel, 0, sizeof (struct cmd_channel));

	status = platform_mutex_init (&channel->lock);
	if (status != 0) {
		return status;
	}

	channel->id = id;

	return 0;
}

/**
 * Release the resources used by the base channel.
 *
 * @param channel The channel to release.
 */
void cmd_channel_release (struct cmd_channel *channel)
{
	if (channel) {
		platform_mutex_free (&channel->lock);
	}
}

/**
 * Get the ID assigned to a command channel.
 *
 * @param channel The command channel to query.
 *
 * @return The ID assigned to the channel or an error code.  Use ROT_IS_ERROR to check for errors.
 */
int cmd_channel_get_id (struct cmd_channel *channel)
{
	if (channel) {
		return channel->id;
	}
	else {
		return CMD_CHANNEL_INVALID_ARGUMENT;
	}
}

/**
 * Send a sequence of packets over a command channel.  Packets will be sequentially sent until all
 * packets have been successfully trasmitted or there is an error sending a packet.  Sending cannot
 * be interrupted by a different sequence of packets.  This ensures no interleaving of different
 * messages over the channel.
 *
 * @param channel The channel to send the packets on.
 * @param message The message container with the packets that should be sent.
 * @param packet A packet buffer to use for sending the packets.  Once access to the channel is
 * granted, the timeout on this packet will be checked to see if it should still be sent.
 *
 * @return 0 if all packets were successfully sent or an error code.  If no packets were sent due to
 * the packet timeout value, CMD_CHANNEL_PKT_EXPIRED will be returned.
 */
static int cmd_channel_send_packets (struct cmd_channel *channel, struct cmd_message *message,
	struct cmd_packet *packet)
{
	uint8_t *pkt_pos;
	size_t msg_len;
	size_t pkt_len;
	int status = 0;

	platform_mutex_lock (&channel->lock);

	if (!packet->timeout_valid || !platform_has_timeout_expired (&packet->pkt_timeout)) {
		pkt_pos = message->data;
		msg_len = message->msg_size;

		memset (packet, 0, sizeof (*packet));
		packet->state = CMD_VALID_PACKET;
		packet->dest_addr = message->dest_addr;

		while ((msg_len > 0) && (status == 0)) {
			pkt_len = min (message->pkt_size, msg_len);
			memcpy (packet->data, pkt_pos, pkt_len);

			packet->pkt_size = pkt_len;
			status = channel->send_packet (channel, packet);

			pkt_pos += pkt_len;
			msg_len -= pkt_len;
		}
	}
	else {
		status = CMD_CHANNEL_PKT_EXPIRED;
	}

	platform_mutex_unlock (&channel->lock);
	return status;
}
/**
 * Receive a single packet from the command channel and process it.  Errors will be logged.
 *
 * @param channel The channel to receive a packet from.
 * @param mctp The MCTP interface to use for processing the received packet.
 * @param ms_timeout The amount of time to wait to receive a packet, in milliseconds.  A negative
 * value will wait forever, and a value of 0 will return immediately.
 *
 * @return 0 if a packet was processed successfully or an error code.
 */
int cmd_channel_receive_and_process (struct cmd_channel *channel, struct mctp_interface *mctp,
	int ms_timeout)
{
	struct cmd_packet packet;
	struct cmd_message *message;
	int status;

	if ((channel == NULL) || (mctp == NULL)) {
		return CMD_CHANNEL_INVALID_ARGUMENT;
	}

	status = channel->receive_packet (channel, &packet, ms_timeout);
	if (status != 0) {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_CMD_INTERFACE,
			CMD_LOGGING_RECEIVE_PACKET_FAIL, channel->id, status);
		return status;
	}

	/* We don't support packets larger than the maximum defined size, so there is no need to
	 * attempt to aggregate transactions that send too much data.  Just throw the data away. */
	if (packet.state == CMD_OVERFLOW_PACKET) {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_INFO, DEBUG_LOG_COMPONENT_CMD_INTERFACE,
			CMD_LOGGING_PACKET_OVERFLOW, channel->id, 0);

		channel->overflow = true;
		mctp_interface_reset_message_processing (mctp);
		return CMD_CHANNEL_PKT_OVERFLOW;
	}
	else if (channel->overflow) {
		/* We need to throw away the next "good" packet after detecting overflow.  It will be the
		 * remaining bytes from the transaction that triggered the overflow condition, so it doesn't
		 * actually represent valid data. */
		channel->overflow = false;
		return 0;
	}

	if (packet.state == CMD_RX_ERROR) {
		/* If we detect a channel error, just log it and pass the packet on for processing.  Let
		 * the upper layers detect any packet issues resulting from the lower layer error. */
		debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_CMD_INTERFACE,
			CMD_LOGGING_CHANNEL_PACKET_ERROR, channel->id, 0);
	}

	status = mctp_interface_process_packet (mctp, &packet, &message);
	if (status == 0) {
		if (message != NULL) {
			status = cmd_channel_send_packets (channel, message, &packet);
			if (status != 0) {
				if (status == CMD_CHANNEL_PKT_EXPIRED) {
					platform_clock now;
					platform_init_current_tick (&now);
					debug_log_create_entry (DEBUG_LOG_SEVERITY_WARNING,
						DEBUG_LOG_COMPONENT_CMD_INTERFACE, CMD_LOGGING_COMMAND_TIMEOUT, channel->id,
						platform_get_duration (&packet.pkt_timeout, &now));

					status = 0;
				}
				else {
					debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR,
						DEBUG_LOG_COMPONENT_CMD_INTERFACE, CMD_LOGGING_SEND_PACKET_FAIL,
						channel->id, status);
				}
			}
		}
	}
	else {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_CMD_INTERFACE,
			CMD_LOGGING_PROCESS_FAIL, status, channel->id);
	}

	return status;
}

/**
 * Send a packetized message over a communication channel.  This call will block until the last
 * packet has been sent, which follows the same postconditions as the send_packet call.
 *
 * @param channel The channel to send the message on.
 * @param message A packetized message to send.
 *
 * @return 0 if the message was successfully sent or an error code.
 */
int cmd_channel_send_message (struct cmd_channel *channel, struct cmd_message *message)
{
	struct cmd_packet packet;

	if ((channel == NULL) || (message == NULL)) {
		return CMD_CHANNEL_INVALID_ARGUMENT;
	}

	packet.timeout_valid = false;
	return cmd_channel_send_packets (channel, message, &packet);
}
