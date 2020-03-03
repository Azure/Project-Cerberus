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
