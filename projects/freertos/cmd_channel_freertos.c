// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include "cmd_channel_freertos.h"
#include "task.h"


/**
 * Receive a packet from a command channel.
 *
 * @param rx_queue The queue to receive packets from.
 * @param packet Output for the packet data being received.
 * @param ms_timeout The amount of time to wait for a received packet, in milliseconds.  A
 * negative value will wait forever, and a value of 0 will return immediately.
 *
 * @return 0 if a packet was successfully received or an error code.
 */
int cmd_channel_freertos_receive_packet (QueueHandle_t rx_queue, struct cmd_packet *packet,
	int ms_timeout)
{
	TickType_t timeout = (ms_timeout < 0) ? portMAX_DELAY : pdMS_TO_TICKS (ms_timeout);
	BaseType_t status;

	if (packet == NULL) {
		return CMD_CHANNEL_INVALID_ARGUMENT;
	}

	status = xQueueReceive (rx_queue, packet, timeout);
	if (status == pdFALSE) {
		return CMD_CHANNEL_RX_TIMEOUT;
	}

	return 0;
}

/**
 * Send a packet to a command channel using a FreeRTOS queue.
 *
 * @param tx_queue The queue of packets waiting to be sent.
 * @param packet The packet to add to the queue.
 * @param ms_timeout The amount of time to wait for a received packet, in milliseconds.  A
 * negative value will wait forever, and a value of 0 will return immediately.
 *
 * @return 0 if the packet was successfully queued or an error code.
 */
int cmd_channel_freertos_send_packet (QueueHandle_t tx_queue, struct cmd_packet *packet,
	int ms_timeout)
{
	TickType_t timeout = (ms_timeout < 0) ? portMAX_DELAY : pdMS_TO_TICKS (ms_timeout);
	BaseType_t status;

	if (packet == NULL) {
		return CMD_CHANNEL_INVALID_ARGUMENT;
	}

	status = xQueueSendToBack (tx_queue, packet, timeout);
	if (status == pdFALSE) {
		return CMD_CHANNEL_TX_TIMEOUT;
	}

	return 0;
}

/**
 * Receive a command packet from a communication channel.
 * This is an implementation of the receive_packet() function for
 * the struct cmd_channel and uses the global I2CRequestQueue.
 *
 * @param channel The channel to receive a packet from.
 * @param packet Output for the packet data being received.
 * @param ms_timeout The amount of time to wait for a received packet, in milliseconds.  A
 * negative value will wait forever, and a value of 0 will return immediately.
 *
 * @return 0 if a packet was successfully received or an error code.
 */
static int cmd_channel_receive_packet (struct cmd_channel *channel,
	struct cmd_packet *packet, int ms_timeout)
{
	return cmd_channel_freertos_receive_packet(I2CRequestQueue, packet,
		ms_timeout);
}

/**
 * Send a command packet over a communication channel.
 * This is an implementation of the send_packet() function for
 * the struct cmd_channel and uses the global I2CResponseQueue.
 *
 * @param channel The channel to send a packet on.
 * @param packet The packet to send.
 *
 * @return 0 if the the packet was successfully sent or an error code.
 */
static int cmd_channel_send_packet (struct cmd_channel *channel,
	struct cmd_packet *packet)
{
	return cmd_channel_freertos_send_packet(I2CResponseQueue, packet, 0);
}

/**
 * Set the default receive_packet and send_packet function hooks.
 * These use the global I2CRequestQueue and I2CResponseQueue.
 *
 * @param channel The channel to initialise.
 */
void cmd_channel_packet_default_init (struct cmd_channel *channel)
{
	channel->receive_packet = cmd_channel_receive_packet;
	channel->send_packet = cmd_channel_send_packet;
}
