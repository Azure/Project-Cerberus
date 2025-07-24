// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef TDISP_PROTOCOL_H_
#define TDISP_PROTOCOL_H_

#include "platform_api.h"

#define PCI_PROTOCOL_ID_TDISP	0x01

#pragma pack(1)

/**
 * TDISP request/response codes.
 */
enum {
	TDISP_RESPONSE_GET_VERSION = 0x01,					/**< TDISP version response . */
	TDISP_RESPONSE_GET_CAPABILITIES = 0x02,				/**< TDISP capabilities response. */
	TDISP_RESPONSE_LOCK_INTERFACE = 0x03,				/**< Lock interface response. */
	TDISP_RESPONSE_GET_DEVICE_INTERFACE_REPORT = 0x04,	/**< Device interface report response. */
	TDISP_RESPONSE_GET_DEVICE_INTERFACE_STATE = 0x05,	/**< Device interface state response. */
	TDISP_RESPONSE_START_INTERFACE = 0x06,				/**< Start interface response. */
	TDISP_RESPONSE_STOP_INTERFACE = 0x07,				/**< Stop interface response. */
	TDISP_RESPONSE_BIND_P2P_STREAM = 0x08,				/**< Bind P2P stream response. */
	TDISP_RESPONSE_UNBIND_P2P_STREAM = 0x09,			/**< Unbind P2P stream response. */
	TDISP_RESPONSE_SET_MMIO_ATTRIBUTE = 0x0A,			/**< Set MMIO attribute response. */
	TDISP_RESPONSE_VDM = 0x0B,							/**< Vendor Defined Message response. */
	TDISP_ERROR = 0x7F,									/**< Error response. */
	TDISP_REQUEST_GET_VERSION = 0x81,					/**< Get version request. */
	TDISP_REQUEST_GET_CAPABILITIES = 0x82,				/**< Get capabilities request. */
	TDISP_REQUEST_LOCK_INTERFACE = 0x83,				/**< Lock interface request. */
	TDISP_REQUEST_GET_DEVICE_INTERFACE_REPORT = 0x84,	/**< Get device interface report request. */
	TDISP_REQUEST_GET_DEVICE_INTERFACE_STATE = 0x85,	/**< Get device interface state request. */
	TDISP_REQUEST_START_INTERFACE = 0x86,				/**< Start interface request. */
	TDISP_REQUEST_STOP_INTERFACE = 0x87,				/**< Stop interface request. */
	TDISP_REQUEST_BIND_P2P_STREAM = 0x88,				/**< Bind P2P stream request. */
	TDISP_REQUEST_UNBIND_P2P_STREAM = 0x89,				/**< Unbind P2P stream request. */
	TDISP_REQUEST_SET_MMIO_ATTRIBUTE = 0x8A,			/**< Set MMIO attribute request. */
	TDISP_REQUEST_VDM = 0x8B,							/**< Vendor Defined Message request. */
};

/**
 * TDISP TDI states
 */
enum {
	TDISP_TDI_STATE_CONFIG_UNLOCKED = 0,	/**< TDI state CONFIG_UNLOCKED */
	TDISP_TDI_STATE_CONFIG_LOCKED = 1,		/**< TDI state CONFIG_LOCKED */
	TDISP_TDI_STATE_RUN = 2,				/**< TDI state RUN state */
	TDISP_TDI_STATE_ERROR = 3,				/**< TDI state ERROR state */
};

/**
 * TDISP function ID format.
 */
union PLATFORM_LITTLE_ENDIAN_STORAGE tdisp_function_id {
	uint32_t value;	/**< The raw register value. */

	struct {
		union {
			uint16_t bdf;				/**< Bus/Device/Function number in BDF format. */
			struct {
				uint16_t function : 3;	/**< PCI function number. */
				uint16_t device : 5;	/**< PCI device number. */
				uint16_t bus : 8;		/**< PCI bus number. */
			};
		};

		uint32_t reguester_segment : 8;			/**< Requester segment, reserved if not valid */
		uint32_t requester_segment_valid : 1;	/**< Requester segment valid flag, 0 - not valid, 1 - valid */
		uint32_t reserved : 7;					/**< Reserved. */
	};
};

/**
 * TDISP interface Id format.
 */
struct tdisp_interface_id {
	union tdisp_function_id function_id;	/**< Identifies the function of the device hosting the TDI. */
	uint64_t reserved;						/**< Reserved. */
};

/**
 * TDISP message header format.
 */
struct tdisp_header {
	uint8_t version;						/**< Version of the TDISP protocol. */
	uint8_t message_type;					/**< Message type. See Table 3 TDISP Request Codes and Table 4 TDISP Response Codes).*/
	uint8_t reserved[2];					/**< Reserved. */
	struct tdisp_interface_id interface_id;	/**< Identifies the TDI interface. */
};

/**
 * TDISP GET_VERSION request format.
 */
struct tdisp_get_version_request {
	struct tdisp_header header;	/**< TDISP message header. */
};

/**
 * TDISP GET_VERSION response format.
 */
struct tdisp_version_response {
	struct tdisp_header header;	/**< TDISP message header. */
	uint8_t version_num_count;	/**< Number of version numbers. */
};

/**
 * Get the offset in the version response where the version number array is located.
 *
 * @param rsp The TDISP version response.
 */
#define	tdisp_version_response_get_version_num_offset(rsp)	(rsp + 1)

/**
 * TDISP requester capabilities.
 */
struct tdisp_requester_capabilities {
	uint32_t tsm_caps;	/**< TSM Capability Flags. */
};

/**
 * TDISP GET_CAPABILITIES request format.
 */
struct tdisp_get_capabilities_request {
	struct tdisp_header header;						/**< TDISP message header. */
	struct tdisp_requester_capabilities req_caps;	/**< Requester capabilities. */
};


/**
 * TDISP lock interface flags
 */
enum {
	TDISP_LOCK_INTERFACE_FLAGS_NO_FW_UPDATE = 0x01,			/**< While intreface is locked no FW update is allowed */
	TDISP_LOCK_INTERFACE_FLAGS_CACHE_LINE_SIZE = 0x02,		/**< System cache line size. 0 - 64 bytes, 1 - 128 bytes */
	TDISP_LOCK_INTERFACE_FLAGS_LOCK_MSIX = 0x04,			/**< Lock MSIX table and PBA */
	TDISP_LOCK_INTERFACE_FLAGS_BIND_P2P = 0x08,				/**< P2P support, 0 - is not allowed/enabled, 1 - can be enabled */
	TDISP_LOCK_INTERFACE_FLAGS_ALL_REQUEST_REDIRECT = 0x10,	/**< TDI must redirect all ATS translated requests to Root complex */
};

/**
 * TDISP responder capabilities.
 */
struct tdisp_responder_capabilities {
	uint32_t dsm_caps;							/**< DSM Capability Flags. */
	uint8_t req_msg_supported[16];				/**< Bitmask indicating each type of request message supported by the device. */
	uint16_t lock_interface_flags_supported;	/**< Bitmask indicating lock interface flags supported by the device. */
	uint8_t reserved[3];						/**< Reserved. */
	uint8_t dev_addr_width;						/**< Number of address bits device supports. */
	uint8_t num_req_this;						/**< Number of outstanding Requests permitted by the DSM for this TDI. */
	uint8_t num_req_all;						/**< Number of outstanding Requests permitted by the DSM for all TDIs managed by this DSM. */
};

/**
 * TDISP GET_CAPABILITIES response format.
 */
struct tdisp_capabilities_response {
	struct tdisp_header header;						/**< TDISP message header. */
	struct tdisp_responder_capabilities rsp_caps;	/**< Responder capabilities. */
};

/**
 * TDISP LOCK_INTERFACE_REQUEST request flags.
 */
struct PLATFORM_LITTLE_ENDIAN_STORAGE tdisp_lock_interface_flags {
	union {
		uint16_t value;	/**< The raw register value. */

		struct {
			/**
			 * When 1, indicates that device firmware updates are not permitted while in
			 * CONFIG_LOCKED or RUN. When 0, indicates that firmware updates are allowed
			 * while in these states.
			 */
			uint16_t no_fw_update : 1;

			/**
			 * When 0, indicates the system CLS is 64 bytes;
			 * when set, indicates system CLS is 128 bytes.
			 */
			uint16_t system_cache_line_size : 1;

			/**
			 * Lock MSI-X table and PBA.
			 */
			uint16_t lock_msix : 1;

			/**
			 * When 1, indicates that Direct-P2P support may be enabled later via
			 * BIND_P2P_STREAM_REQUEST messages and a valid P2P address mask is specified in this
			 * request. When 0, indicates that Direct-P2P is not allowed or enabled for this TDI.
			 */
			uint16_t bind_p2p : 1;

			/**
			 * The TDI must redirect all ATS Translated Requests upstream to
			 * the Root Complex to perform access checks.
			 */
			uint16_t all_request_redirect : 1;

			uint16_t reserved : 11;	/**< Reserved. */
		};
	};
};

/**
 * TDISP LOCK_INTERFACE_REQUEST request parameters.
 */
struct tdisp_lock_interface_param {
	struct tdisp_lock_interface_flags flags;	/**< Lock interface request flags. */

	/**
	 * Indicates the Stream ID for the Stream configured as the IDE default stream.
	 */
	uint8_t default_stream_id;
	uint8_t reserved;	/**< Reserved. */

	/**
	 * MMIO ranges reported in all DEVICE_INTERFACE_REPORT is reported with
	 * this offset added to the physical address
	 */
	uint64_t mmio_reporting_offset;

	/**
	 * Mask to be applied to target addresses for peer-to-peer transaction issued by the TDI
	 * using the BIND_P2P_STREAM_REQUEST stream (to clear-out any metadata information embedded
	 * in the address). This mask must be applied prior to using the
	 * Selective IDE Address Association mechanism. This mask is not applicable or applied for
	 * Requests bound to the Root Complex.
	 */
	uint64_t bind_p2p_address_mask;
};

/**
 * TDISP LOCK_INTERFACE_REQUEST request format.
 */
struct tdisp_lock_interface_request {
	struct tdisp_header header;								/**< TDISP message header. */
	struct tdisp_lock_interface_param lock_interface_param;	/**< Lock interface request parameters. */
};

/**
 * TDISP START_INTERFACE nonce size.
 */
#define TDISP_START_INTERFACE_NONCE_SIZE	32

/**
 * TDISP LOCK_INTERFACE_RESPONSE response format.
 */
struct tdisp_lock_interface_response {
	struct tdisp_header header;											/**< TDISP message header. */
	uint8_t start_interface_nonce[TDISP_START_INTERFACE_NONCE_SIZE];	/**< Start interface nonce. */
};

/**
 * TDISP GET_DEVICE_INTERFACE_REPORT request format.
 */
struct tdisp_get_device_interface_report_request {
	struct tdisp_header header;	/**< TDISP message header. */

	/**
	 * Offset in bytes from the start of the report to where the read request message begins.
	 * The responder must send its report starting from this offset.
	 * For first GET_DEVICE_INTERFACE_REPORT request, the Requester must set this field to 0.
	 * For non-first requests, Offset is the sum of PORTION_LENGTH values in all
	 * previous DEVICE_INTERFACE_REPORT responses.
	 */
	uint16_t offset;

	/**
	 * Length of report, in bytes, to be returned in the corresponding response.
	 * Length is an unsigned 16-bit integer.
	 *
	 * This value is the smaller of the following values:
	 * Capacity of requester's internal buffer for receiving Responder's report.
	 * The REMAINDER_LENGTH of the preceding DEVICE_INTERFACE_REPORT response.
	 *
	 * For the first GET_DEVICE_INTERFACE_REPORT request, the requester must use the capacity
	 * of the requester's receiving buffer. If offset=0 and length=FFFFh,
	 * the requester is requesting the entire report.
	 *
	 * The Responder is permitted to provide less than the requested length if
	 * the Responder’s buffer length is limited.
	 */
	uint16_t length;
};

/**
 * TDISP DEVICE_INTERFACE_REPORT response format.
 */
struct tdisp_device_interface_report_response {
	struct tdisp_header header;	/**< TDISP message header. */

	/**
	 * Number of bytes of this portion of TDI report. This must be less than or equal to LENGTH
	 * received as part of the request. For example, the Responder is permitted to set this field
	 * to a value less than LENGTH received as part of the request due limitations on the
	 * Responder's internal buffer.
	 */
	uint16_t portion_length;

	/**
	 * Number of bytes of the TDI report that have not been sent yet after the current response.
	 * For the last response, this field must be 0 as an indication to the Requester that the
	 * entire TDI report has been sent.
	 */
	uint16_t remainder_length;
};


/**
 * Get the buffer at which the device report starts.
 *
 * @param resp The TDISP DEVICE_INTERFACE_REPORT response.
 */
#define	tdisp_device_interface_report_resp_report_ptr(resp) \
	(((uint8_t*) resp) + sizeof (struct tdisp_device_interface_report_response))

/**
 * TDISP LOCK_INTERFACE_REQUEST request flags.
 */
struct PLATFORM_LITTLE_ENDIAN_STORAGE tdisp_mmio_range_attributes {
	union {
		uint32_t value;	/**< The raw register value. */

		struct {
			/**
			 * If the range maps MSI-X table.
			 * This must be reported only if locked by the LOCK_INTERFACE_REQUEST.
			 */
			uint32_t msi_x_table : 1;

			/**
			 * If the range maps MSI-X PBA.
			 * This must be reported only if locked by the LOCK_INTERFACE_REQUEST.
			 */
			uint32_t msi_x_pba : 1;

			/**
			 * Must be 1b if the range is non-TEE memory.
			 * For attribute updatable ranges, this field must indicate attribute of the
			 * range when the TDI was locked.
			 */
			uint32_t is_non_tee_mem : 1;

			/**
			 * Must be 1b if the attributes of this range is updatable using
			 * SET_MMIO_ATTRIBUTE_REQUEST.
			 */
			uint32_t is_mem_attr_updatable : 1;

			uint32_t reserved : 12;	/**< Reserved. */

			/**
			 * A device specific identifier for the specified range.
			 * The range ID may be used to logically group one or more MMIO ranges
			 * into a larger range.
			 */
			uint32_t range_id : 16;
		};
	};
};

/**
 * TDISP MMIO_RANGE structure.
 */
struct tdisp_mmio_range {
	uint64_t first_page;									/**< First 4K page with offset added. */
	uint32_t number_of_pages;								/**< Number of 4K pages in this range. */
	struct tdisp_mmio_range_attributes range_attributes;	/**< MMIO range attributes. */
};

/**
 * TDISP interface info.
 */
struct PLATFORM_LITTLE_ENDIAN_STORAGE tdisp_interface_info {
	union {
		uint16_t value;	/**< The raw register value. */

		struct {
			/**
			 * When 1, indicates that device firmware updates are not permitted while in
			 * CONFIG_LOCKED or RUN. When 0, indicates that firmware updates are permitted
			 * while in these states.
			 */
			uint16_t no_fw_update : 1;

			uint16_t dma_requests_without_pasid : 1;	/**< TDI generates DMA requests without PASID. */

			uint16_t dma_requests_with_pasid : 1;		/**< TDI generates DMA requests with PASID. */

			uint16_t ats_supported : 1;					/**< ATS supported and enabled for the TDI. */

			uint16_t prs_supported : 1;					/**< PRS supported and enabled for the TDI. */

			uint16_t reserved : 11;
		};
	};
};

/**
 * TDISP DEVICE_INTERFACE_REPORT structure.
 */
struct tdisp_device_interface_report {
	struct tdisp_interface_info interface_info;	/**< TDISP interface info. */
	uint16_t reserved;							/**< Reserved. */

	/**
	 * MSI-X capability message control register state. Must be Clear if
	 * a) capability is not supported or
	 * b) MSI-X table is not locked.
	 */
	uint16_t msi_x_message_control;

	/**
	 * LNR control register from LN Requester Extended Capability.
	 * Must be Clear if LNR capability is not supported.
	 * LN is deprecated in PCIe Revision 6.0.
	 */
	uint16_t lnr_control;

	/**
	 * TPH Requester Control Register from the TPH Requester Extended Capability. Must be Clear if
	 * a) TPH capability is not support or
	 * b) MSI-X table is not locked.
	 */
	uint32_t tph_control;

	uint32_t mmio_range_count;	/**< Number of MMIO Ranges in report */
};

/**
 * TDISP GET_DEVICE_INTERFACE_STATE request format.
 */
struct tdisp_get_device_interface_state_request {
	struct tdisp_header header;	/**< TDISP message header. */
};

/**
 * TDISP DEVICE_INTERFACE_STATE response format.
 */
struct tdisp_device_interface_state_response {
	struct tdisp_header header;	/**< TDISP message header. */
	uint8_t tdi_state;			/**< TDI state. */
};

/**
 * TDISP START_INTERFACE_REQUEST request format.
 */
struct tdisp_start_interface_request {
	struct tdisp_header header;											/**< TDISP message header. */
	uint8_t start_interface_nonce[TDISP_START_INTERFACE_NONCE_SIZE];	/**< Start interface nonce. */
};

/**
 * TDISP START_INTERFACE_RESPONSE response format.
 */
struct tdisp_start_interface_response {
	struct tdisp_header header;	/**< TDISP message header. */
};

/**
 * TDISP STOP_INTERFACE_REQUEST request format.
 */
struct tdisp_stop_interface_request {
	struct tdisp_header header;	/**< TDISP message header. */
};

/**
 * TDISP STOP_INTERFACE_RESPONSE response format.
 */
struct tdisp_stop_interface_response {
	struct tdisp_header header;	/**< TDISP message header. */
};

/**
 * TDISP ERROR response format.
 */
struct tdisp_error_response {
	struct tdisp_header header;	/**< TDISP message header. */
	uint32_t error_code;		/**< TDISP error code. */
	uint32_t error_data;		/**< TDISP error data. */
};

/**
 * TDISP extended error data format.
 */
struct tdisp_extended_error_data {
	uint8_t registry_id;	/**< Registry ID. */
	uint8_t vendor_id_len;	/**< Vendor ID length. */
};

/**
 * TDISP Registry Ids.
 */
#define PCI_TDISP_REGISTRY_ID_PCISIG	0x00
#define PCI_TDISP_REGISTRY_ID_CXL		0x01

/**
 * TDISP error codes.
 */
enum {
	TDISP_ERROR_CODE_INVALID_REQUEST = 0x01,				/**< The request is invalid. */
	TDISP_ERROR_CODE_BUSY = 0x03,							/**< The device is busy. */
	TDISP_ERROR_CODE_INVALID_INTERFACE_STATE = 0x04,		/**< The interface state is invalid. */
	TDISP_ERROR_CODE_UNSPECIFIED = 0x05,					/**< An unspecified error occurred. */
	TDISP_ERROR_CODE_UNSUPPORTED_REQUEST = 0x07,			/**< The request is unsupported. */
	TDISP_ERROR_CODE_VERSION_MISMATCH = 0x41,				/**< The version is not supported. */
	TDISP_ERROR_CODE_INVALID_INTERFACE = 0x101,				/**< The interface is invalid. */
	TDISP_ERROR_CODE_INVALID_NONCE = 0x102,					/**< The nonce is invalid. */
	TDISP_ERROR_CODE_INSUFFICIENT_ENTROPY = 0x103,			/**< Entropy is insufficient. */
	TDISP_ERROR_CODE_INVALID_DEVICE_CONFIGURATION = 0x104,	/**< The device configuration is invalid. */
};

#pragma pack()


#endif	/* TDISP_PROTOCOL_H_ */
