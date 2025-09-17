// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef IDE_PROTOCOL_H_
#define IDE_PROTOCOL_H_


#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>


/**
 * AES 256 KEY length in bytes
 */
#define IDE_AES_256_KEY_LENGTH				(32)

/**
 * AES 256 KEY length in bytes
 */
#define IDE_AES_256_IV_LENGTH				(8)

/**
 * AES 256 KEY length in DWORDS
 */
#define IDE_AES_256_KEY_LENGTH_IN_DWORDS	(IDE_AES_256_KEY_LENGTH / 4)

/**
 * AES 256 IV length in DWORDS
 */
#define IDE_AES_256_IV_LENGTH_IN_DWORDS		(IDE_AES_256_IV_LENGTH / 4)


#pragma pack(1)

/**
 * IDE_KM header format.
 */
struct ide_km_header {
	uint8_t object_id;	/**< IDE command Id. */
};


/**
 * IDE_KM Commands.
 */
enum {
	IDE_KM_OBJECT_ID_QUERY = 0x00,				/**< IDE_KM QUERY command. */
	IDE_KM_OBJECT_ID_QUERY_RESP = 0x01,			/**< IDE_KM QUERY_RESP command. */
	IDE_KM_OBJECT_ID_KEY_PROG = 0x02,			/**< IDE_KM KEY_PROG command. */
	IDE_KM_OBJECT_ID_KP_ACK = 0x03,				/**< IDE_KM KP_ACK command. */
	IDE_KM_OBJECT_ID_K_SET_GO = 0x04,			/**< IDE_KM K_SET_GO command. */
	IDE_KM_OBJECT_ID_K_SET_STOP = 0x05,			/**< IDE_KM K_SET_STOP command. */
	IDE_KM_OBJECT_ID_K_SET_GOSTOP_ACK = 0x06,	/**< IDE_KM K_GOSTOP_ACK command. */
};

/**
 * IDE_KM QUERY format.
 */
struct ide_km_query {
	struct ide_km_header header;	/**< IDE command header. */
	uint8_t reserved;				/**< Reserved. */
	uint8_t port_index;				/**< Index of the port for the query. */
};

/**
 * IDE_KM QUERY_RESP format.
 */
struct ide_km_query_resp {
	struct ide_km_header header;	/**< IDE command header. */
	uint8_t reserved;				/**< Reserved. */
	uint8_t port_index;				/**< Index of the port for the query. */
	uint8_t dev_func_num;			/**< Device function number. */
	uint8_t bus_num;				/**< Bus number. */
	uint8_t segment;				/**< Segment number. */
	uint8_t max_port_index;			/**< Max port index. */
	uint32_t capability_register;	/**< Capability register. */
	uint32_t control_register;		/**< Control register. */
};

/**
 * IDE_KM Link IDE Stream Register block max count.
 */
#define IDE_KM_LINK_IDE_REG_BLOCK_MAX_COUNT		8

/**
 * Key stream info.
 */
struct ide_km_sub_stream_info {
	/**
	 * The Key Set field indicates the Key Set,
	 * corresponding to the K bit value in the IDE TLP Prefix.
	 */
	uint8_t key_set:1;

	/**
	 * The Key Direction field indicates the Key Direction,
	 * corresponding to the D bit value in the IDE TLP Prefix.
	 * 0b – Receive
	 * 1b - Transmit
	 */
	uint8_t rx_tx:1;

	uint8_t reserved:2;	/**< Reserved. */

	/**
	 * The Key Sub-Stream field indicates the Key Sub-Stream, using the same encodings as defined
	 * for the Sub-Stream identifier (see Section 6.99.3 of IDE specification).
	 */
	uint8_t key_sub_stream:4;
};

/**
 * IDE_KM KEY_PROG format.
 */
struct ide_km_key_prog {
	struct ide_km_header header;					/**< IDE command header. */
	uint8_t reserved[2];							/**< Reserved. */
	uint8_t stream_id;								/**< Stream ID. */
	uint8_t reserved2;								/**< Reserved. */
	struct ide_km_sub_stream_info sub_stream_info;	/**< Sub stream info. */
	uint8_t port_index;								/**< Index of the port for programming the key. */
};

/**
 * AES GCM 256 key buffer format.
 */
struct ide_km_aes_256_gcm_key_buffer {
	uint32_t key[IDE_AES_256_KEY_LENGTH_IN_DWORDS];	/**< 256-bit key. */
	uint32_t iv[IDE_AES_256_IV_LENGTH_IN_DWORDS];	/**< 64-bit IV. */
};


/**
 * NOTE: It is important to keep these structs as is to make sure binary compatibility
 * with previous versions
 */
_Static_assert (offsetof (struct ide_km_aes_256_gcm_key_buffer, key) == 0,
	"Unexpected struct member offset");
_Static_assert (offsetof (struct ide_km_aes_256_gcm_key_buffer, iv) == 32,
	"Unexpected struct member offset");
_Static_assert (sizeof (struct ide_km_aes_256_gcm_key_buffer) == 40,
	"Unexpected struct member offset");

/**
 * IDE_KM KP_ACK format.
 */
struct ide_km_kp_ack {
	struct ide_km_header header;					/**< IDE command header. */
	uint8_t reserved[2];							/**< Reserved. */
	uint8_t stream_id;								/**< Stream ID. */
	uint8_t status;									/**< Status of the KEY_PROG operation. */
	struct ide_km_sub_stream_info sub_stream_info;	/**< Sub stream info. */
	uint8_t port_index;								/**< Index of the port for the programmed key. */
};


/**
 * IDE_KM KP_ACK status values.
 */
enum {
	IDE_KM_KP_ACK_STATUS_SUCCESS = 0x00,
	IDE_KM_KP_ACK_STATUS_INCORRECT_LENGTH = 0x01,
	IDE_KM_KP_ACK_STATUS_UNSUPPORTED_PORT_INDEX = 0x02,
	IDE_KM_KP_ACK_STATUS_UNSUPPORTED_VALUE = 0x03,
	IDE_KM_KP_ACK_STATUS_UNSPECIFIED_FAILURE = 0x04,
};

/**
 * IDE_KM K_SET_GO format.
 */
struct ide_km_k_set_go {
	struct ide_km_header header;					/**< IDE command header. */
	uint8_t reserved[2];							/**< Reserved. */
	uint8_t stream_id;								/**< Stream ID. */
	uint8_t reserved2;								/**< Reserved. */
	struct ide_km_sub_stream_info sub_stream_info;	/**< Sub stream info. */
	uint8_t port_index;								/**< Index of the port for the key to be activated. */
};

/**
 * IDE_KM K_SET_STOP format.
 */
struct ide_km_k_set_stop {
	struct ide_km_header header;					/**< IDE command header. */
	uint8_t reserved[2];							/**< Reserved. */
	uint8_t stream_id;								/**< Stream ID. */
	uint8_t reserved2;								/**< Reserved. */
	struct ide_km_sub_stream_info sub_stream_info;	/**< Sub stream info. */
	uint8_t port_index;								/**< Index of the port for the key to be deactivated. */
};

/**
 * IDE_KM K_GOSTOP_ACK format.
 */
struct ide_km_k_gostop_ack {
	struct ide_km_header header;					/**< IDE command header. */
	uint8_t reserved[2];							/**< Reserved. */
	uint8_t stream_id;								/**< Stream ID. */
	uint8_t reserved2;								/**< Reserved. */
	struct ide_km_sub_stream_info sub_stream_info;	/**< Sub stream info. */
	uint8_t port_index;								/**< Index of the port for the key that was activated/deactivated. */
};

/**
 * IDE Capability Register
 */
struct ide_capability_register {
	union {
		uint32_t value;	/**< The raw register value. */

		struct {
			/**
			 * When Set, indicates that the Port support Link IDE Streams, and that one or more
			 * Link IDE Stream Registers block(s) immediately follow the IDE Control Register, per
			 * the value in the Number of TCs Supported for Link IDE field.
			 */
			uint32_t link_ide_stream_supported : 1;

			/**
			 * When Set, indicates that the Port support Selective IDE Streams, and that one or
			 * more Selective IDE Stream Register block(s) are implemented, per the value in the
			 * Number of Selective IDE Streams Supported field.
			 */
			uint32_t selective_ide_streams_supported : 1;

			/**
			 * For a Switch or Root Port, when Set indicates support for passing Selective IDE
			 * Streams to all other Switch or Root Ports. If this bit is Set and both Link IDE
			 * Stream Supported and Selective IDE Streams Supported are Clear, then no Link IDE
			 * register blocks or Selective IDE register blocks are required.
			 * Reserved for Endpoints.
			 */
			uint32_t flow_through_ide_stream_supported : 1;

			uint32_t reserved : 1;	/**< Reserved. */

			/**
			 * If Link IDE Stream Supported or Selective IDE Streams Supported are Set, then this
			 * bit, when Set, indicates the Port supports aggregation. Undefined if Link IDE Stream
			 * Supported and Selective IDE Streams Supported are both Clear.
			 */
			uint32_t aggregation_supported : 1;

			/**
			 * When Set, indicates that the Port supports the generation and checking of PCRC.
			 */
			uint32_t pcrc_supported : 1;

			/**
			 * When Set, indicates that the Port supports the IDE_KM protocol in the resopnder role.
			 */
			uint32_t ide_km_protocol_supported : 1;

			/**
			 * For a Root Port, Switch Upstream Port, or Endpoint Upstream Port, if Selective IDE
			 * Streams Supported is Set, then this bit, if Set, indicates that the Port supports
			 * the assocation of Configuration Requests with Selective IDE Streams. For a Switch
			 * Upstream Port, when Set, this bit indicates the Switch supports Selective IDE for
			 * Configuration Requests targeting all Functions of the Switch. This bit is Reserved
			 * for Switch Downstream Ports. If Selective IDE Streams Supported is Clear,
			 * this bit is Reserved.
			 */
			uint32_t selective_ide_for_configuration_requests_supported : 1;

			/**
			 * Indicates the supported algorithms for securing IDE TLPs, encoded as:
			 * 0 0000b – AES-GCM 256 key size, 96b MAC
			 * Others – Reserved
			 */
			uint32_t supported_algorithms : 5;

			/**
			 * If Link IDE Stream Supported is Set, indicates the number of TCs supported for
			 * Link IDE Streams encoded as:
			 * 000b – One TC supported
			 * 001b – 2 TCs supported
			 * 010b – 3 TCs supported
			 * 011b – 4 TCs supported
			 * 100b – 5 TCs supported
			 * 101b – 6 TCs supported
			 * 110b – 7 TCs supported
			 * 111b – 8 TCs supported
			 * If Link IDE Stream Supported is Clear, this field is undefined.
			 */
			uint32_t number_of_tcs_supported_for_link_ide : 3;

			/**
			 * If Selective IDE Streams Supported is Set then this field indicates number of
			 * Selective IDE Streams Supported such that 0=1 Stream. A corresponding number of
			 * Selective IDE Stream Register blocks must be implemented. If Link IDE Stream
			 * Supported is Clear, then these blocks must immediately follow the IDE Control
			 * Register. If Link IDE Stream Supported is Set, then these blocks must immediately
			 * follow the Link IDE Stream Control and Status Registers. If Selective IDE Streams
			 * Supported is Clear, this field is undefined.
			 */
			uint32_t number_of_selective_ide_streams_supported : 8;

			uint32_t reserved2 : 8;	/**< Reserved. */
		};
	};
};

/**
 * IDE Control Register
 */
struct ide_control_register {
	union {
		uint32_t value;				/**< The raw register value. */

		struct {
			uint32_t reserved : 2;	/**< Reserved. */

			/**
			 * For Switch Ports and Root Ports, Enables the Port for flow-through operation of TLPs
			 * associated with Selective IDE Streams. Reserved for Upstream Ports associated
			 * with Endpoints.
			 */
			uint32_t flow_through_ide_stream_enabled : 1;

			uint32_t reserved2 : 29;	/**< Reserved. */
		};
	};
};

/**
 * Link IDE Stream Control Register
 */
struct ide_link_ide_stream_control_register {
	union {
		uint32_t value;	/**< The raw register value. */

		struct {
			/**
			 * When Set, enables Link IDE Stream such that IDE operation will start when triggered
			 * by means of the IDE_KM protocol (see Section 6.99.3). When Cleared, must immediately
			 * transition the Stream to Insecure. It is permitted for the default value to be 1b if
			 * and only if implementation-specific means can ensure that the Link IDE Stream will
			 * default into a state where operation in the Secure state is possible, otherwise the
			 * default value must be 0b.
			 */
			uint32_t link_ide_stream_enable : 1;

			uint32_t reserved : 1;	/**< Reserved. */

			/**
			 * If Aggregation Supported is Set then this field selects the level of aggregation for
			 * Transmitted Non-Posted Requests for this Stream, encoded as:
			 * 00b – No aggregation
			 * 01b – Up to 2 Non-Posted Requests
			 * 10b – Up to 4 Non-Posted Requests
			 * 11b – Up to 8 Non-Posted Requests
			 * Reserved If Aggregation Supported is Clear.
			 * Default value is 00b
			 */
			uint32_t tx_aggregation_mode_npr : 2;

			/**
			 * If Aggregation Supported is Set then this field selects the level of aggregation for
			 * Transmitted Posted Requests for this Stream, encoded as:
			 * 00b – No aggregation
			 * 01b – Up to 2 Posted Requests
			 * 10b – Up to 4 Posted Requests
			 * 11b – Up to 8 Posted Requests
			 * Reserved If Aggregation Supported is Clear.
			 * Default value is 00b
			 */
			uint32_t tx_aggregation_mode_pr : 2;

			/**
			 * If Aggregation Supported is Set then this field selects the level of aggregation for
			 * Trasmitted Completions for this Stream, encoded as:
			 * 00b – No aggregation
			 * 01b – Up to 2 Completions
			 * 10b – Up to 4 Completions
			 * 11b – Up to 8 Completions
			 * Reserved If Aggregation Supported is Clear.
			 * Default value is 00b
			 */
			uint32_t tx_aggregation_mode_cpl : 2;

			/**
			 * When Set, Transmitted IDE TLPs associated with this Stream must include PCRC, and
			 * Received TLPs must be checked for PRCR failure. Reserved if PCRC Supported is Clear.
			 * Default value is 0b.
			 */
			uint32_t pcrc_enable : 1;

			uint32_t reserved2 : 5;	/**< Reserved. */

			/**
			 * Selects the algorithm to be used for securing IDE TLPs for this IDE Stream. Must be
			 * programmed to the same value in both the Upstream and Downstream Ports. Must be
			 * configured while Link IDE Stream Enable is Clear. When Link IDE Stream Enable is Set,
			 * the setting is sampled, and this field becomes RO with reads returning the sampled
			 * value.
			 * 0 0000b – AES-GCM 256 key size, 96b MAC
			 * Others – Reserved
			 */
			uint32_t selected_algorithm : 5;

			/**
			 * System firmware/software must program this field to indicate the TC associated with
			 * this Link IDE Register block. Default value is 000b
			 */
			uint32_t tc : 3;

			uint32_t reserved3 : 2;	/**< Reserved. */

			/**
			 * Indicates the Stream ID associated with this Link IDE Stream. Software must program
			 * the same Stream ID into both Ports associated with a given Link IDE Stream.
			 * Default value is 00h.
			 */
			uint32_t stream_id : 8;
		};
	};
};

/**
 * Link IDE Stream Status Register
 */
struct ide_link_ide_stream_status_register {
	union {
		uint32_t value;	/**< The raw register value. */

		struct {
			/**
			 * When Link IDE Stream Enable is Set, this field indicates the state of the Port.
			 * Encodings:
			 * 0000b – Insecure
			 * 0010b – Secure
			 * Others – Reserved – Software must handle reserved values as indicating unknown state
			 * When Link IDE Stream Enable is Clear, the value of this field must be 0000b.
			 */
			uint32_t link_ide_stream_state : 4;

			uint32_t reserved : 27;	/**< Reserved. */

			/**
			 * When Set, indicates that one or more Integrity Check Fail Message(s) have been
			 * received for this Stream.
			 */
			uint32_t received_integrity_check_fail_message : 1;
		};
	};
};

/**
 * Link IDE Register Block
 */
struct ide_link_ide_stream_register_block {
	struct ide_link_ide_stream_control_register stream_control_register;	/**< Stream control register. */
	struct ide_link_ide_stream_status_register stream_status_register;		/**< Stream status register. */
};

/**
 * Selective IDE Stream Capability Register
 */
struct ide_selective_ide_stream_capability_register {
	union {
		uint32_t value;	/**< The raw register value. */

		struct {
			/**
			 * Indicates the number of Selective IDE Address Association register blocks for this
			 * Selective IDE Stream. The number of Selective IDE Address Association register blocks
			 * for a given IDE Stream is hardware implementation-specific, and is permitted to be
			 * any number between 0 and 15.
			 */
			uint32_t number_of_address_association_register_blocks : 4;

			uint32_t reserved : 28;	/**< Reserved. */
		};
	};
};

/**
 * Selective IDE Stream Control Register
 */
struct ide_selective_ide_stream_control_register {
	union {
		uint32_t value;	/**< The raw register value. */

		struct {
			/**
			 * When Set, enables this IDE Stream such that IDE operation will start when triggered
			 * by means of the IDE_KM protocol (see Section 6.99.3). When Cleared, must immediately
			 * transition the Stream to Insecure. The following must be programmed before this bit
			 * is Set:
			 * Selected Algorithm (below)
			 * Requester ID Limit in IDE RID Association Register 1
			 * Requester ID Base in IDE RID Association Register 2
			 * V bit in IDE RID Association Register 2
			 * If this bit is Set when the V bit is Clear, the IDE Stream must transition to
			 * Insecure.
			 * When Cleared, must immediately transition the Stream to Insecure.
			 * It is strongly recommended that the IDE Address Association Registers, and the
			 * Default Stream bit (if applicable), also be programmed prior to Setting this bit.
			 * Default value is 0b.
			 */
			uint32_t selective_ide_stream_enable : 1;

			uint32_t reserved : 1;	/**< Reserved. */

			/**
			 * Tx Aggregation Mode NPR – If Aggregation Supported is Set then this field selects the
			 * level of aggregation for Transmitted Non-Posted Requests for this Stream, encoded as:
			 * 00b – No aggregation
			 * 01b – Up to 2 Non-Posted Requests
			 * 10b – Up to 4 Non-Posted Requests
			 * 11b – Up to 8 Non-Posted Requests
			 * Reserved If Aggregation Supported is Clear.
			 * Default value is 00b
			 */
			uint32_t tx_aggregation_mode_npr : 2;

			/**
			 * If Aggregation Supported is Set then this field selects the level of aggregation for
			 * Transmitted Posted Requests for this Stream, encoded as:
			 * 00b – No aggregation
			 * 01b – Up to 2 Posted Requests
			 * 10b – Up to 4 Posted Requests
			 * 11b – Up to 8 Posted Requests
			 * Reserved If Aggregation Supported is Clear.
			 * Default value is 00b
			 */
			uint32_t tx_aggregation_mode_pr : 2;

			/**
			 * If Aggregation Supported is Set then this field selects the level of aggregation for
			 * Transmitted Completions for this Stream, encoded as:
			 * 00b – No aggregation
			 * 01b – Up to 2 Completions
			 * 10b – Up to 4 Completions
			 * 11b – Up to 8 Completions
			 * Reserved If Aggregation Supported is Clear.
			 * Default value is 00b
			 */
			uint32_t tx_aggregation_mode_cpl : 2;

			/**
			 * When Set, Transmitted IDE TLPs associated with this Stream must include PCRC, and
			 * Received TLPs must be checked for PRCR failure.
			 * Reserved if PCRC Supported is Clear.
			 * Default value is 0b.
			 */
			uint32_t pcrc_enable : 1;

			/**
			 * For Root Ports, if Selective IDE for Configuration Requests Supported is Set, then
			 * this bit, when Set, must cause the Port to transmit as IDE TLPs associated with this
			 * Selective IDE Stream all Configuration Requests for which the destination RID is
			 * greater than or equal to the RID Base and less than or equal to the RID Limit in the
			 * Selective IDE RID Association Register block. For Ports other than Root Ports,
			 * this bit is Reserved.
			 * If Selective IDE for Configuration Requests Supported is Clear, this bit is Reserved.
			 */
			uint32_t selective_ide_for_configuration_requests_enable : 1;

			uint32_t reserved2 : 4;	/**< Reserved. */

			/**
			 * Selects the algorithm to be used for securing IDE TLPs for this IDE Stream.
			 * Must be programmed to the same value in both the Upstream and Downstream Ports.
			 * Must be configured while Selective IDE Stream Enable is Clear.
			 * When Selective IDE Stream Enable is Set, the setting is sampled, and this field
			 * becomes RO with reads returning the sampled value.
			 *
			 * 0 0000b – AES-GCM 256 key size, 96b MAC
			 * Others – Reserved
			 */
			uint32_t selected_algorithm : 5;

			/**
			 * System firmware/software must program this field to indicate the TC associated with
			 * this Selective IDE Register block.
			 *
			 * Default value is 000b
			 */
			uint32_t tc : 3;

			/**
			 * When Set, ATS and Memory Request TLPs using the Traffic Class indicated in the TC
			 * field are associated with this Stream, unless the TLP matches some other Stream for
			 * the indicated TC.
			 *
			 * It is not permitted to configure more than one Default Stream to be associated with
			 * the same TC. If this is done, hardware must select one of the Streams to be
			 * associated with the TC – the selection is implementation-specific.
			 *
			 * Applicable for Endpoint Upstream Ports only. Reserved for other Port types.
			 *
			 * Default value is 0b.
			*/
			uint32_t default_stream : 1;

			uint32_t reserved3 : 1;	/**< Reserved. */

			/**
			 * Indicates the Stream ID associated with the Selective IDE Stream.
			 * Software must program the same Stream ID into both Ports associated with a given
			 * Selective IDE Stream.
			 *
			 * Default value is 00h.
			 */
			uint32_t stream_id : 8;
		};
	};
};

/**
 * Selective IDE Stream Status Register
 */
struct ide_selective_ide_stream_status_register {
	union {
		uint32_t value;	/**< The raw register value. */

		struct {
			/**
			 * When Selective IDE Stream Enable is Set, this field indicates the state of the
			 * Selective IDE Stream at this Port. Encodings:
			 * 0000b – Insecure
			 * 0010b – Secure
			 * Others – Reserved – Software must handle reserved values as indicating unknown state
			 *
			 * When IDE Stream Enable is Clear, the value of this field must be 0000b.
			 */
			uint32_t selective_ide_stream_state : 4;

			uint32_t reserved : 27;	/**< Reserved. */

			/**
			 * When Set, indicates that one or more Integrity Check Fail Message(s) have been
			 * Received for this Stream.
			 */
			uint32_t received_integrity_check_fail_message : 1;
		};
	};
};

/**
 * Selective IDE RID Association Register 1
 */
struct ide_selective_ide_rid_association_register_1 {
	union {
		uint32_t value;				/**< The raw register value. */

		struct {
			uint32_t reserved : 8;	/**< Reserved. */

			/**
			 * Indicates the highest value RID in the range associated with this Stream ID at the
			 * IDE Partner Port.
			 */
			uint32_t rid_limit : 16;

			uint32_t reserved2 : 8;	/**< Reserved. */
		};
	};
};

/**
 * Selective IDE RID Association Register 2
 */
struct ide_selective_ide_rid_association_register_2 {
	union {
		uint32_t value;	/**< The raw register value. */

		struct {
			/**
			 * When Set, indicates the RID Base and RID Limit fields have been programmed.
			 * Default is 0b
			 */
			uint32_t valid : 1;

			uint32_t reserved : 7;	/**< Reserved. */

			/**
			 * Indicates the lowest value RID in the range associated with this Stream ID at the
			 * IDE Partner Port.
			 */
			uint32_t rid_base : 16;

			uint32_t reserved2 : 8;	/**< Reserved. */
		};
	};
};

/**
 * Selective IDE Address Association Register 1
 */
struct ide_selective_ide_address_association_register_1 {
	union {
		uint32_t value;	/**< The raw register value. */

		struct {
			/**
			 * When Set, indicates this IDE Stream Association Block is valid, that the address
			 * range defined by Memory Base and Memory Limit corresponding to a range of memory
			 * addresses assigned to the IDE Partner Port, and that all Transmitted Address Routed
			 * TLPs within this address range must be associated with this IDE Stream.
			 *
			 * Hardware behavior is undefined if overlapping address ranges are assigned for
			 * different IDE Streams.
			 *
			 * Default is 0b
			 */
			uint32_t valid : 1;

			uint32_t reserved : 7;	/**< Reserved. */

			/**
			 * Corresponds to Address bits [31:20]. Address[19:0] bits are implicitly 0_0000h.
			 */
			uint32_t memory_base_lower : 12;

			/**
			 * Memory Limit Lower – Corresponds to Address bits [31:20]. Address bits [19:0] are
			 * implicitly F_FFFFh.
			 */
			uint32_t memory_limit_lower : 12;
		};
	};
};

/**
 * Selective IDE Address Association Register Block
 */
struct ide_selective_ide_address_association_register_block {
	struct ide_selective_ide_address_association_register_1 register_1;	/**< Address Association Register 1. */

	/**
	 * Memory Limit Upper - Corresponds to Address bits [63:32]
	 */
	uint32_t register_2;

	/**
	 * Memory Base Upper - Corresponds to Address bits [63:32]
	 */
	uint32_t register_3;
};

/**
 * Selective IDE Stream Register block max. count.
 */
#define SELECTIVE_IDE_ADDRESS_ASSOCIATION_REGISTER_BLOCK_MAX_COUNT		15

/**
 * Selective IDE Stream Register Block
 */
struct ide_selective_ide_stream_register_block {
	struct ide_selective_ide_stream_capability_register sel_ide_stream_cap_reg;				/**< Selective Stream Capability Register. */
	struct ide_selective_ide_stream_control_register sel_ide_stream_control_reg;			/**< Selective Stream Control Register. */
	struct ide_selective_ide_stream_status_register sel_ide_stream_status_reg;				/**< Selective Stream Status Register. */
	struct ide_selective_ide_rid_association_register_1 ide_rid_assoc_reg_1;				/**< RID Association Register 1. */
	struct ide_selective_ide_rid_association_register_2 ide_rid_assoc_reg_2;				/**< RID Association Register 2. */
	struct ide_selective_ide_address_association_register_block
		addr_assoc_reg_block[SELECTIVE_IDE_ADDRESS_ASSOCIATION_REGISTER_BLOCK_MAX_COUNT];	/**< Address Association Register Block. */
};

#pragma pack()


#endif	/* IDE_PROTOCOL_H_ */
