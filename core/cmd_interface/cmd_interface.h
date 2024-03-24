// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef CMD_INTERFACE_H_
#define CMD_INTERFACE_H_

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include "status/rot_status.h"
#include "session_manager.h"


/**
 * Container for message data.
 */
struct cmd_interface_msg {
	/**
	 * The raw message data buffer.
	 *
	 * This contains the full message to process, including all protocol headers. If the message is
	 * a request, this buffer can be updated with the response data, while providing sufficient
	 * space before the data for any protocol headers that will need to be added.
	 *
	 * This pointer must not be changed during message processing.
	 */
	uint8_t *data;

	/**
	 * Length of the data buffer contents.
	 *
	 * This doesn't necessarily equate to the maximum size of the data buffer, since a message may
	 * only be using part of the overall buffer.
	 */
	size_t length;

	/**
	 * Maximum length allowed for a response.
	 *
	 * This indicates the maximum amount of data that should be written into the data buffer when
	 * constructing a response payload.  When using the payload pointer for response building, this
	 * field should not be accessed directly, but instead should be queried using
	 * {@link cmd_interface_msg_get_max_response}.
	 */
	size_t max_response;

	/**
	 * Payload data for the message.
	 *
	 * This is a pointer to a location in the message buffer indicating where the payload starts,
	 * after accounting for protocol headers.  The protocol stack will move this pointer as messages
	 * pass through the various processing layers.  This can be filled with response data without
	 * needing to account for protocol header space.
	 */
	uint8_t *payload;

	/**
	 * Length of the message payload.
	 *
	 * This does not indicate the maximum length of the payload buffer for building responses.  This
	 * value can be determined with {@link cmd_interface_msg_get_max_payload}.
	 */
	size_t payload_length;

	/**
	 * Endpoint ID that generated the message.
	 */
	uint8_t source_eid;

	/**
	 * Address of the device that generated the message.
	 */
	uint8_t source_addr;

	/**
	 * Endpoint ID that should process the message.
	 */
	uint8_t target_eid;

	/**
	 * Flag indicating if the message is encrypted or should be encrypted.
	 */
	bool is_encrypted;

	/**
	 * Flag indicating if the message is a request and required cryptographic operations.  If so, it
	 * should be granted a longer timeout for request processing.
	 *
	 * This is set for every message, even when there is an error.
	 */
	bool crypto_timeout;

	/**
	 * Channel on which the message was received.
	 */
	int channel_id;
};

/**
 * A list of firmware versions.
 */
struct cmd_interface_fw_version {
	size_t count;					/**< The number of firmware identifiers. */
	const char **id;				/**< The list of firmware identifiers. */
};

/**
 * A list of device IDs.
 */
struct cmd_interface_device_id {
	uint16_t vendor_id;				/**< Vendor ID */
	uint16_t device_id;				/**< Device ID */
	uint16_t subsystem_vid;			/**< Subsystem vendor ID */
	uint16_t subsystem_id;			/**< Subsystem ID */
};


/**
 * Command interface for processing received requests.
 */
struct cmd_interface {
	/**
	 * Process a received request.
	 *
	 * @param intf The command interface that will process the request.
	 * @param request The request data to process.  This will be updated to contain a response, if
	 * necessary.
	 *
	 * @return 0 if the request was successfully processed or an error code.
	 */
	int (*process_request) (const struct cmd_interface *intf, struct cmd_interface_msg *request);

#ifdef CMD_ENABLE_ISSUE_REQUEST
	/**
	 * Process a received response.
	 *
	 * TODO:  Likely remove this function from this interface.  The request issuing flow using
	 * msg_transport does not rely on this type of response handling.  Removing this would make this
	 * interface cleaner (i.e. remove the need for the #ifdef).
	 *
	 * @param intf The command interface that will process the response.
	 * @param response The response data to process.
	 *
	 * @return 0 if the response was successfully processed or an error code.
	 */
	int (*process_response) (const struct cmd_interface *intf, struct cmd_interface_msg *response);
#endif

	/**
	 * Generate a message to indicate an error condition.
	 *
	 * TODO:  Revisit the need for this function and how it gets used.  Generally, individual
	 * protocols will generate their own error responses (e.g. SPDM).  This is really only used for
	 * transport layer errors (e.g. MCTP) when there is no other associated protocol known (or no
	 * protocol handling of the error), so perhaps it doesn't belong here.  Maybe it belongs in
	 * cmd_interface_protocol?  Maybe this function should be removed entirely and it should be up
	 * to the transport to internally figure out what to do?  Does it really make sense to always
	 * return Cerberus error messages for MCTP layer errors?
	 *
	 * @param intf The command interface to utilize.
 	 * @param request The request container to utilize.
	 * @param error_code Identifier for the error.
	 * @param error_data Data for the error condition.
 	 * @param cmd_set Command set to respond on.
	 *
	 * @return 0 if the packet was generated successfully or an error code.
	 */
	int (*generate_error_packet) (const struct cmd_interface *intf,
		struct cmd_interface_msg *request, uint8_t error_code, uint32_t error_data,
		uint8_t cmd_set);

	/* TODO:  Now that the cmd_interface is used for more than Cerberus messages, this should get
	 * refactored out of the base interface and into some Cerberus specific handling, like the
	 * protocol handlers. */
	struct session_manager *session;				/**< Session manager for channel encryption */
};

/**
 * Interface to a protocol specific handler that can be used to extract message details necessary
 * for routing the message to an appropriate handler and to apply any necessary protocol handling as
 * part of message processing.
 */
struct cmd_interface_protocol {
	/**
	 * Parse a message based on protocol rules and prepare it for further message handling.  Parsing
	 * a message can involve operations such as:
	 * - Checking that a message meets the minimum protocol requirements.
	 * - Removing protocol specific headers from the payload.
	 * - Adjusting the maximum allowed response message.
	 * - Decrypting messages.
	 *
	 * Since this call will alter the state of the message container, and possibly the payload data
	 * itself, it must only be called once per message for each protocol handler.
	 *
	 * @param protocol The protocol handler to use for parsing the message.
	 * @param message The received message to parse.  Upon successful return, the message will have
	 * been updated based on the protocol requirements.
	 * @param message_type Output for the message type identifier to use for message routing.
	 *
	 * @return 0 if the message was parsed successfully or an error code.  If an error response
	 * message was generated during processing, CMD_HANDLER_PROTO_ERROR_RESPONSE will be returned.
	 */
	int (*parse_message) (const struct cmd_interface_protocol *protocol,
		struct cmd_interface_msg *message, uint32_t *message_type);

	/**
	 * Execute any additional processing on a request message after it has been processed by the
	 * appropriate command handler(s).
	 *
	 * The specific actions that are necessary here will be determined by the protocol handler, but
	 * at minimum, this call will need to manage the protocol header for the response payload.
	 * - If the request processing was successful, meaning the message descriptor contains a
	 *   response message, the necessary protocol header will need to be added to the response
	 *   payload.
	 * - If the request processing failed, there are two ways the protocol header could be dealt
	 *   with.
	 * 		1. A protocol error response is generated with necessary protocol headers.
	 * 		2. The message descriptor payload is updated to add the protocol header space without
	 * 		   adding any data.  This makes the space available for the next layer in the stack to
	 * 		   use when handling the error.
	 *
	 * This can be set to null if a specific protocol does not need to do any additional processing.
	 *
	 * @param protocol The protocol handler to use for message processing.
	 * @param result Result from request message processing.  This will be 0 if processing was
	 * successful or a response message has already been  generated.  Otherwise, this will be an
	 * error code.  If no handler could be found to process the request, this result will be
	 * CMD_HANDLER_UNKNOWN_MESSAGE_TYPE.
	 * @param message_type The message type identifier of the request message.
	 * @param message The message descriptor for message processing.  Depending on the processing
	 * result, this will either contain a response message or the failed request.
	 *
	 * @return 0 if the message descriptor contains a response message or an error code to return to
	 * the to the previous layer of the protocol stack.
	 */
	int (*handle_request_result) (const struct cmd_interface_protocol *protocol, int result,
		uint32_t message_type, struct cmd_interface_msg *message);
};


/* Utility functions for managing messages. */
void cmd_interface_msg_new_message (struct cmd_interface_msg *message, uint8_t source_eid,
	uint8_t source_addr, uint8_t target_eid, int channel_id);

void cmd_interface_msg_add_payload_data (struct cmd_interface_msg *message, const uint8_t *data,
	size_t length);
void cmd_interface_msg_set_message_payload_length (struct cmd_interface_msg *message,
	size_t length);

void cmd_interface_msg_remove_protocol_header (struct cmd_interface_msg *message,
	size_t header_length);
void cmd_interface_msg_add_protocol_header (struct cmd_interface_msg *message,
	size_t header_length);

size_t cmd_interface_msg_get_protocol_length (const struct cmd_interface_msg *message);
size_t cmd_interface_msg_get_max_response (const struct cmd_interface_msg *message);

/* Internal functions for use by derived types. */
int cmd_interface_process_cerberus_protocol_message (const struct cmd_interface *intf,
	struct cmd_interface_msg *message, uint8_t *command_id, uint8_t *command_set, bool decrypt,
	bool rsvd_zero);
int cmd_interface_prepare_response (const struct cmd_interface *intf,
	struct cmd_interface_msg *response);
int cmd_interface_generate_error_packet (const struct cmd_interface *intf,
	struct cmd_interface_msg *request, uint8_t error_code, uint32_t error_data, uint8_t cmd_set);


#define	CMD_HANDLER_ERROR(code)		ROT_ERROR (ROT_MODULE_CMD_HANDLER, code)

/**
 * Error codes that can be generated by the command handler.
 *
 * Note: Commented error codes have been deprecated.
 */
enum {
	CMD_HANDLER_INVALID_ARGUMENT = CMD_HANDLER_ERROR (0x00),		/**< Input parameter is null or not valid. */
	CMD_HANDLER_NO_MEMORY = CMD_HANDLER_ERROR (0x01),				/**< Memory allocation failed. */
	CMD_HANDLER_PROCESS_FAILED = CMD_HANDLER_ERROR (0x02),			/**< A general error while processing the request. */
	CMD_HANDLER_PAYLOAD_TOO_SHORT = CMD_HANDLER_ERROR (0x03),		/**< The request does not contain the minimum amount of data. */
	CMD_HANDLER_BAD_LENGTH = CMD_HANDLER_ERROR (0x04),				/**< The payload length is wrong for the request. */
	CMD_HANDLER_OUT_OF_RANGE = CMD_HANDLER_ERROR (0x05),			/**< A request argument is not within the valid range. */
	CMD_HANDLER_UNKNOWN_REQUEST = CMD_HANDLER_ERROR (0x06),			/**< A command does not represent a known request. */
	//CMD_HANDLER_UNSUPPORTED_EID = CMD_HANDLER_ERROR (0x07),		/**< The request was sent to an unsupported endpoint. */
	CMD_HANDLER_UNSUPPORTED_INDEX = CMD_HANDLER_ERROR (0x08),		/**< Request for information with an unsupported index was received. */
	CMD_HANDLER_UNSUPPORTED_LEN = CMD_HANDLER_ERROR (0x09),			/**< Request for information with an unsupported length was received. */
	CMD_HANDLER_INVALID_DEVICE_MODE = CMD_HANDLER_ERROR (0x0A),		/**< Invalid device mode. */
	CMD_HANDLER_BUF_TOO_SMALL = CMD_HANDLER_ERROR (0x0B),			/**< Provided buffer too small for output. */
	CMD_HANDLER_UNSUPPORTED_COMMAND = CMD_HANDLER_ERROR (0x0C),		/**< The command is valid but is not supported by the device. */
	CMD_HANDLER_UNSUPPORTED_MSG = CMD_HANDLER_ERROR (0x0D),			/**< Message type not supported. */
	CMD_HANDLER_UNSUPPORTED_CHANNEL = CMD_HANDLER_ERROR (0x0E),		/**< The command is received on a channel not supported by the device. */
	CMD_HANDLER_UNSUPPORTED_OPERATION = CMD_HANDLER_ERROR (0x0F),	/**< The requested operation is not supported. */
	CMD_HANDLER_RESPONSE_TOO_SMALL = CMD_HANDLER_ERROR (0x10),		/**< The maximum allowed response is too small for the output. */
	CMD_HANDLER_ENCRYPTION_UNSUPPORTED = CMD_HANDLER_ERROR (0x11),	/**< Channel encryption not supported on this interface. */
	CMD_HANDLER_CMD_SHOULD_BE_ENCRYPTED = CMD_HANDLER_ERROR (0x12),	/**< Secure command received unencrypted after establishing an encrypted channel. */
	CMD_HANDLER_RSVD_NOT_ZERO = CMD_HANDLER_ERROR (0x13),			/**< Reserved field is non-zero. */
	CMD_HANDLER_ERROR_MESSAGE = CMD_HANDLER_ERROR (0x14),			/**< The handler received an error message for processing. */
	CMD_HANDLER_ISSUE_FAILED = CMD_HANDLER_ERROR (0x15),			/**< Failed to generate the request message. */
	CMD_HANDLER_ERROR_MSG_FAILED = CMD_HANDLER_ERROR (0x16),		/**< Failed to generate an error message. */
	CMD_HANDLER_UNKNOWN_RESPONSE = CMD_HANDLER_ERROR (0x17),		/**< A command does not represent a known response. */
	CMD_HANDLER_INVALID_ERROR_MSG = CMD_HANDLER_ERROR (0x18),		/**< The handler received an invalid error message. */
	CMD_HANDLER_UNKNOWN_MESSAGE_TYPE = CMD_HANDLER_ERROR (0x19),	/**< The received message type is unknown to the handler. */
	CMD_HANDLER_PROTO_PARSE_FAILED = CMD_HANDLER_ERROR (0x1a),		/**< Failed to parse a message. */
	CMD_HANDLER_PROTO_HANDLE_FAILED = CMD_HANDLER_ERROR (0x1b),		/**< Failed to handle the result of request processing. */
	CMD_HANDLER_PROTO_ERROR_RESPONSE = CMD_HANDLER_ERROR (0x1c),	/**< The protocol generated an error response. */
};


#endif /* CMD_INTERFACE_H_ */
