// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef MCTP_CONTROL_PROTOCOL_COMMANDS_H_
#define MCTP_CONTROL_PROTOCOL_COMMANDS_H_

#include <stdint.h>
#include "cmd_interface/cmd_interface.h"
#include "cmd_interface/device_manager.h"
#include "mctp_control_protocol.h"
#include "platform_config.h"


/* Configurable command response field.  Default can be overridden in platform_config.h. */
#ifndef CERBERUS_VID_SET_RESPONSE
#define CERBERUS_VID_SET_RESPONSE 								0xFF
#endif

#define CERBERUS_VID_SET										0

#define MCTP_CONTROL_SET_EID_OPERATION_SET_ID					0
#define MCTP_CONTROL_SET_EID_OPERATION_FORCE_ID					1

#define MCTP_CONTROL_SET_EID_ASSIGNMENT_STATUS_ACCEPTED			0
#define MCTP_CONTROL_SET_EID_ASSIGNMENT_STATUS_REJECTED 		1

#define MCTP_CONTROL_SET_EID_ALLOCATION_STATUS_NO_EID_POOL		0

#define MCTP_CONTROL_GET_EID_EID_TYPE_DYNAMIC_EID				0
#define MCTP_CONTROL_GET_EID_EID_TYPE_STATIC_EID_SUPPORTED  	1

#define MCTP_CONTROL_GET_EID_ENDPOINT_TYPE_SIMPLE_ENDPOINT  	0
#define MCTP_CONTROL_GET_EID_ENDPOINT_TYPE_BUS_OWNER_BRIDGE 	1

#define MCTP_CONTROL_GET_MCTP_VERSION_MSG_TYPE_UNSUPPORTED	 	0x80
#define MCTP_CONTROL_GET_MCTP_VERSION_VERSION_ENCODING		 	0xF0
#define MCTP_CONTROL_GET_MCTP_VERSION_VERSION_IGNORE_UPDATE		0xFF

#define MCTP_CONTROL_PCI_VID_FORMAT								0x00
#define MCTP_CONTROL_IANA_VID_FORMAT							0x01


#pragma pack(push, 1)
/**
 * MCTP control set EID request format
 */
struct mctp_control_set_eid {
	struct mctp_control_protocol_header header;					/**< Message header */
	uint8_t operation:2;										/**< EID operation to perform */
	uint8_t reserved:6;											/**< Reserved */
	uint8_t eid;												/**< EID assignment */
};

/**
 * MCTP control set EID response format
 */
struct mctp_control_set_eid_response {
	struct mctp_control_protocol_header header;					/**< Message header */
	uint8_t completion_code;									/**< Operation completion code */
	uint8_t eid_allocation_status:2;							/**< Status of EID allocation */
	uint8_t reserved1:2;										/**< Reserved */
	uint8_t eid_assignment_status:2;							/**< Status of EID assignment */
	uint8_t reserved2:2;										/**< Reserved */
	uint8_t eid_setting;										/**< EID setting */
	uint8_t eid_pool_size;										/**< EID pool size */
};

/**
 * MCTP control get EID request
 */
struct mctp_control_get_eid {
	struct mctp_control_protocol_header header;					/**< Message header */
};

/**
 * MCTP control get EID response format
 */
struct mctp_control_get_eid_response {
	struct mctp_control_protocol_header header;					/**< Message header */
	uint8_t completion_code;									/**< Operation completion code */
	uint8_t eid;												/**< Endpoint ID */
	uint8_t eid_type:2;											/**< Endpoint ID type */
	uint8_t reserved:2;											/**< Reserved */
	uint8_t endpoint_type:2;									/**< Endpoint type */
	uint8_t reserved2:2;										/**< Reserved */
	uint8_t medium_specific_info;								/**< Medium-specific info */
};

/**
 * MCTP control get MCTP version request
 */
struct mctp_control_get_mctp_version {
	struct mctp_control_protocol_header header;					/**< Message header */
	uint8_t message_type_num;									/**< Message type number */
};

/**
 * Single version number entry of a MCTP control get version response
 */
struct mctp_control_mctp_version_number_entry {
	uint8_t alpha;												/**< Byte indicating pre-release version */
	uint8_t update;												/**< Update version number */
	uint8_t minor;												/**< Minor version number */
	uint8_t major;												/**< Major version number */
};

/**
 * MCTP control get MCTP version response format
 */
struct mctp_control_get_mctp_version_response {
	struct mctp_control_protocol_header header;					/**< Message header */
	uint8_t completion_code;									/**< Operation completion code */
	uint8_t version_num_entry_count;							/**< Version number entry count */
};

/**
 * Get the total message length for a get MCTP version response message.
 *
 * @param num_entries Number of entries in version number table.
 */
#define	mctp_control_get_mctp_version_response_length(num_entries)	\
	(sizeof (struct mctp_control_get_mctp_version_response) + \
		((num_entries) * sizeof (struct mctp_control_mctp_version_number_entry)))

/**
 * Get the buffer containing the entries from a get MCTP version response message.
 *
 * @param resp Pointer to a get version response message.
 */
#define	mctp_control_get_mctp_version_response_get_entries(resp) \
	((struct mctp_control_mctp_version_number_entry*) (resp + 1))

/**
 * MCTP control get message type support request
 */
struct mctp_control_get_message_type {
	struct mctp_control_protocol_header header;					/**< Message header */
};

/**
 * MCTP control get message type support response format
 */
struct mctp_control_get_message_type_response {
	struct mctp_control_protocol_header header;					/**< Message header */
	uint8_t completion_code;									/**< Operation completion code */
	uint8_t message_type_count;									/**< Number of supported message type in list */
};

/**
 * Get the total message length for a message type support response message.
 *
 * @param num_msg_type Number of supported message types.
 */
#define	mctp_control_get_message_type_response_length(num_msg_type)	\
	(sizeof (struct mctp_control_get_message_type_response) + num_msg_type)

/**
 * Get the buffer containing the supported message type list from a get message type response
 * message.
 *
 * @param resp Pointer to a get message type response message.
 */
#define	mctp_control_get_message_type_response_get_entries(resp) 	((uint8_t*) (resp + 1))

/**
 * MCTP control get vendor defined message support request format
 */
struct mctp_control_get_vendor_def_msg_support {
	struct mctp_control_protocol_header header;					/**< Message header */
	uint8_t vid_set_selector;									/**< Vendor ID set selector */
};

/**
 * MCTP control get vendor defined message support response packet format for PCI VID
 */
struct mctp_control_get_vendor_def_msg_support_pci_response {
	struct mctp_control_protocol_header header;					/**< Message header */
	uint8_t completion_code;									/**< Completion code */
	uint8_t vid_set_selector;									/**< Vendor ID set selector */
	uint8_t vid_format;											/**< Vendor ID format */
	uint16_t vid;												/**< Vendor ID */
	uint16_t protocol_version;									/**< Protocol version */
};

/**
 * MCTP control get vendor defined message support response packet format for IANA enterpise number
 */
struct mctp_control_get_vendor_def_msg_support_iana_response {
	struct mctp_control_protocol_header header;					/**< Message header */
	uint8_t completion_code;									/**< Completion code */
	uint8_t vid_set_selector;									/**< Vendor ID set selector */
	uint8_t vid_format;											/**< Vendor ID format */
	uint32_t vid;												/**< IANA enterprise number */
	uint16_t protocol_version;									/**< Protocol version */
};

/**
 * MCTP control get routing table entries message request format
 */
struct mctp_control_get_routing_table_entries {
	struct mctp_control_protocol_header header;					/**< Message header */
	uint8_t entry_handle;										/**< Entry handle */
};

/**
 * MCTP control routing table entry format
 */
struct mctp_control_routing_table_entry {
	uint8_t eid_range_size;										/**< Size of EID range */
	uint8_t starting_eid;										/**< Starting EID */
	uint8_t port_number:5;										/**< Port number */
	uint8_t eid_assignment_type:1;								/**< Dynamic/Static entry */
	uint8_t entry_type:2;										/**< Entry type*/
	uint8_t binding_type_id;									/**< Physical transport binding type ID */
	uint8_t media_type_id;										/**< Physical media type ID */
	uint8_t address_size;										/**< Physical address size */
	uint8_t address;											/**< Physical address */
};

/**
 * MCTP control get routing table entries message response format
 */
struct mctp_control_get_routing_table_entries_response {
	struct mctp_control_protocol_header header;					/**< Message header */
	uint8_t completion_code;									/**< Completion code */
	uint8_t next_entry_handle;									/**< Next entry handle */
	uint8_t num_entries;										/**< Number of entries in response */
};

/**
 * Get the total message length for a routing table entries response message.
 *
 * @param num_entries Number of entries in routing table.
 */
#define	mctp_control_get_routing_table_entries_response_length(num_entries)	\
	(sizeof (struct mctp_control_get_routing_table_entries_response) + \
		((num_entries) * sizeof (struct mctp_control_routing_table_entry)))

/**
 * Get the buffer containing the entries from a get routing table entries response message.
 *
 * @param resp Pointer to a routing table entries response message.
 */
#define	mctp_control_get_routing_table_entries_response_get_entries(resp) \
	((struct mctp_control_routing_table_entry*) (resp + 1))
#pragma pack(pop)


int mctp_control_protocol_set_eid (struct device_manager *device_mgr,
	struct cmd_interface_msg *request);

int mctp_control_protocol_get_eid (struct device_manager *device_mgr,
	struct cmd_interface_msg *request);

int mctp_control_protocol_get_mctp_version_support (struct cmd_interface_msg *request);

int mctp_control_protocol_get_message_type_support (struct cmd_interface_msg *request);
int mctp_control_protocol_generate_get_message_type_support_request (uint8_t *buf, size_t buf_len);
int mctp_control_protocol_process_get_message_type_support_response (
	struct cmd_interface_msg *response);

int mctp_control_protocol_get_vendor_def_msg_support (uint16_t pci_vendor_id,
	uint16_t protocol_version, struct cmd_interface_msg *request);
int mctp_control_protocol_generate_get_vendor_def_msg_support_request (uint8_t vendor_id_set,
	uint8_t *buf, size_t buf_len);
int mctp_control_protocol_process_get_vendor_def_msg_support_response (
	struct cmd_interface_msg *response);

int mctp_control_protocol_generate_get_routing_table_entries_request (uint8_t entry_handle,
	uint8_t *buf, size_t buf_len);
int mctp_control_protocol_process_get_routing_table_entries_response (
	struct cmd_interface_msg *response);


#define	CMD_HANDLER_MCTP_CTRL_ERROR(code)												ROT_ERROR (ROT_MODULE_CMD_HANDLER_MCTP_CTRL, code)

/**
 * Error codes that can be generated by the command handler.
 *
 * Note: Commented error codes have been deprecated.
 */
enum {
	CMD_HANDLER_MCTP_CTRL_INVALID_ARGUMENT = CMD_HANDLER_MCTP_CTRL_ERROR (0x00),		/**< Input parameter is null or not valid. */
	CMD_HANDLER_MCTP_CTRL_NO_MEMORY = CMD_HANDLER_MCTP_CTRL_ERROR (0x01),				/**< Memory allocation failed. */
	CMD_HANDLER_MCTP_CTRL_PAYLOAD_TOO_SHORT = CMD_HANDLER_MCTP_CTRL_ERROR (0x02),		/**< The request does not contain the minimum amount of data. */
	CMD_HANDLER_MCTP_CTRL_BAD_LENGTH = CMD_HANDLER_MCTP_CTRL_ERROR (0x03),				/**< The payload length is wrong for the request. */
	CMD_HANDLER_MCTP_CTRL_OUT_OF_RANGE = CMD_HANDLER_MCTP_CTRL_ERROR (0x04),			/**< A request argument is not within the valid range. */
	CMD_HANDLER_MCTP_CTRL_UNKNOWN_REQUEST = CMD_HANDLER_MCTP_CTRL_ERROR (0x05),			/**< A command does not represent a known request. */
	CMD_HANDLER_MCTP_CTRL_BUF_TOO_SMALL = CMD_HANDLER_MCTP_CTRL_ERROR (0x06),			/**< Provided buffer too small for output. */
	CMD_HANDLER_MCTP_CTRL_UNSUPPORTED_MSG = CMD_HANDLER_MCTP_CTRL_ERROR (0x07),			/**< Message type not supported. */
	CMD_HANDLER_MCTP_CTRL_UNSUPPORTED_OPERATION = CMD_HANDLER_MCTP_CTRL_ERROR (0x08),	/**< The requested operation is not supported. */
	CMD_HANDLER_MCTP_CTRL_RSVD_NOT_ZERO = CMD_HANDLER_MCTP_CTRL_ERROR (0x09),			/**< Reserved field is non-zero. */
	CMD_HANDLER_MCTP_CTRL_UNKNOWN_RESPONSE = CMD_HANDLER_MCTP_CTRL_ERROR (0x0A),		/**< A command does not represent a known response. */
};


#endif /* MCTP_CONTROL_PROTOCOL_COMMANDS_H_ */
