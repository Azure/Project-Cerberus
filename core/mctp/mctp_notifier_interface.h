// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef MCTP_NOTIFIER_INTERFACE_H_
#define MCTP_NOTIFIER_INTERFACE_H_

#include <stddef.h>
#include <stdint.h>
#include "status/module_id.h"
#include "status/rot_status.h"


/**
 * MCTP notifier interface object parameters for endpoint listener registration/deregistration
 * and sending notification to all registered listeners.
 */
struct mctp_notifier_interface {
	/**
	 * Send MCTP notification to all registered endpoints.
	 *
	 * @param notifier MCTP notifier interface instance.
	 * @param payload Notification request message payload filled by application layer.
	 * @param payload_len Payload buffer length.
	 *
	 * @return 0 if the request was transmitted successfully or an error code.
	 */
	int (*send_notification_request) (const struct mctp_notifier_interface *notifier,
		uint8_t *payload, size_t payload_len);

	/**
	 * Register given external entity for the upcoming event notification.
	 *
	 * @param notifier MCTP notifier interface instance.
	 * @param dest_eid External entity EID info for enabling notification.
	 *
	 * @return 0 if entity successfully registered or an error code.
	 */
	int (*register_listener) (const struct mctp_notifier_interface *notifier, uint8_t dest_eid);

	/**
	 * Force register given external entity for the upcoming event notification. An existing
	 * listener EID will be deregistered if the notifier can not support any additional listeners.
	 *
	 * @param notifier MCTP notifier interface instance.
	 * @param dest_eid External entity EID info for enabling notification.
	 *
	 * @return 0 if entity successfully registered or an error code.
	 */
	int (*force_register_listener) (const struct mctp_notifier_interface *notifier,
		uint8_t dest_eid);

	/**
	 * Deregister given external entity from the upcoming event notification.
	 *
	 * @param notifier MCTP notifier interface instance.
	 * @param dest_eid External entity EID info for disabling notification.
	 *
	 * @return 0 if entity successfully registered or an error code.
	 */
	int (*deregister_listener) (const struct mctp_notifier_interface *notifier, uint8_t dest_eid);
};


#define MCTP_NOTIFIER_ERROR(code)		ROT_ERROR (ROT_MODULE_MCTP_NOTIFIER, code)

/**
 * Error codes that can be generated by the mctp notifier interface.
 */
enum {
	MCTP_NOTIFIER_INVALID_ARGUMENT = MCTP_NOTIFIER_ERROR (0x00),			/**< Input parameter is null or not valid. */
	MCTP_NOTIFIER_NO_MEMORY = MCTP_NOTIFIER_ERROR (0x01),					/**< Memory allocation failed. */
	MCTP_NOTIFIER_REGISTER_FAILED = MCTP_NOTIFIER_ERROR (0x02),				/**< Registration failed. */
	MCTP_NOTIFIER_FORCE_REGISTER_FAILED = MCTP_NOTIFIER_ERROR (0x03),		/**< Force registration failed. */
	MCTP_NOTIFIER_DEREGISTER_FAILED = MCTP_NOTIFIER_ERROR (0x04),			/**< Deregistration failed. */
	MCTP_NOTIFIER_SEND_NOTIFICATION_FAILED = MCTP_NOTIFIER_ERROR (0x05),	/**< Sending notification failed. */
	MCTP_NOTIFIER_NOTIFICATION_RESP_MISMATCH = MCTP_NOTIFIER_ERROR (0x06),	/**< Notification response mismatch. */
	MCTP_NOTIFIER_MAX_REGISTERED = MCTP_NOTIFIER_ERROR (0x07),				/**< Max number of EID already registered. */
	MCTP_NOTIFIER_NOT_REGISTERED = MCTP_NOTIFIER_ERROR (0x08),				/**< EID is not registered. */
	MCTP_NOTIFIER_PAYLOAD_TOO_LARGE = MCTP_NOTIFIER_ERROR (0x09),			/**< Notification payload length too long. */
	MCTP_NOTIFIER_PAYLOAD_TOO_SHORT = MCTP_NOTIFIER_ERROR (0x0A),			/**< Notification payload length too short. */
	MCTP_NOTIFIER_RESP_PAYLOAD_TOO_SHORT = MCTP_NOTIFIER_ERROR (0x0B),		/**< Notification response payload length too short. */
};


#endif	/* MCTP_NOTIFIER_INTERFACE_H_ */
