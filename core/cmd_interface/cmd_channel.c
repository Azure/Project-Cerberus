// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include "platform.h"
#include "mctp/mctp_interface.h"
#include "cmd_channel.h"
#include "cmd_logging.h"


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
	if (channel == NULL) {
		return CMD_CHANNEL_INVALID_ARGUMENT;
	}

	memset (channel, 0, sizeof (struct cmd_channel));

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
	struct cmd_packet rx_packet;
	struct cmd_packet *tx_packets;
	size_t num_packets;
	int i;
	int status;

	if ((channel == NULL) || (mctp == NULL)) {
		return CMD_CHANNEL_INVALID_ARGUMENT;
	}

	status = channel->receive_packet (channel, &rx_packet, ms_timeout);
	if (status != 0) {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_CMD_INTERFACE,
			CMD_LOGGING_RECEIVE_PACKET_FAIL, channel->id, status);
		return status;
	}

	/* We don't support packets larger than the maximum defined size, so there is no need to
	 * attempt to aggregate transactions that send too much data.  Just throw the data away. */
	if (rx_packet.state == CMD_OVERFLOW_PACKET) {
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

	status = mctp_interface_process_packet (mctp, &rx_packet, &tx_packets, &num_packets);
	if (status == 0) {
		if (!rx_packet.timeout_valid || !platform_has_timeout_expired (&rx_packet.pkt_timeout)) {
			i = 0;
			while ((i < num_packets) && (status == 0)) {
				status = channel->send_packet (channel, &tx_packets[i]);
				if (status != 0) {
					debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR,
						DEBUG_LOG_COMPONENT_CMD_INTERFACE, CMD_LOGGING_SEND_PACKET_FAIL,
						channel->id, status);
				}

				i++;
			}
		}
		else {
			debug_log_create_entry (DEBUG_LOG_SEVERITY_WARNING, DEBUG_LOG_COMPONENT_CMD_INTERFACE,
				CMD_LOGGING_COMMAND_TIMEOUT, channel->id, 0);
		}

		platform_free (tx_packets);
	}
	else {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_CMD_INTERFACE,
			CMD_LOGGING_PROCESS_FAIL, status, channel->id);
	}

	return status;
}
