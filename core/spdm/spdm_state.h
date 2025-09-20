// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef SPDM_STATE_H_
#define SPDM_STATE_H_

#include <stddef.h>
#include <stdint.h>
#include "platform_api.h"

/**
 * SPDM connection states.
 */
enum spdm_connection_state {
	SPDM_CONNECTION_STATE_NOT_STARTED,			/**< Before GET_VERSION/VERSION. */
	SPDM_CONNECTION_STATE_AFTER_VERSION,		/**< After GET_VERSION/VERSION. */
	SPDM_CONNECTION_STATE_AFTER_CAPABILITIES,	/**< After GET_CAPABILITIES/CAPABILITIES. */
	SPDM_CONNECTION_STATE_NEGOTIATED,			/**< After NEGOTIATE_ALGORITHMS/ALGORITHMS. */
	SPDM_CONNECTION_STATE_AFTER_DIGESTS,		/**< After GET_DIGESTS/DIGESTS. */
	SPDM_CONNECTION_STATE_AFTER_CERTIFICATE,	/**< After GET_CERTIFICATE/CERTIFICATE. */
	SPDM_CONNECTION_STATE_AUTHENTICATED,		/**< After CHALLENGE/CHALLENGE_AUTH, and ENCAP CHALLENGE/CHALLENGE_AUTH if MUT_AUTH is enabled. */
	SPDM_CONNECTION_STATE_MAX,					/**< MAX */
};

/**
 * SPDM version info.
 */
struct PLATFORM_LITTLE_ENDIAN_STORAGE spdm_version_number {
	uint16_t alpha:4;					/**< Pre-release version nubmer. */
	uint16_t update_version_number:4;	/**< Update version number. */
	uint16_t minor_version:4;			/**< Major version number. */
	uint16_t major_version:4;			/**< Minor version number. */
};


/**
 * NOTE: It is important to keep these structs as is to make sure binary compatibility
 * with previous versions
 */
_Static_assert ((sizeof (struct spdm_version_number)) == 2,
	"Unexpected size of struct spdm_version_number");

/**
 * SPDM get capabilities flags format
 */
struct PLATFORM_LITTLE_ENDIAN_STORAGE spdm_get_capabilities_flags_format {
	uint8_t cache_cap:1;					/**< Supports ability to cache negotiated state across reset. Only set in response messages */
	uint8_t cert_cap:1;						/**< Supports Get Digests and Get Certificate commands */
	uint8_t chal_cap:1;						/**< Supports Challenge command */
	uint8_t meas_cap:2;						/**< Measurement response capabilities. Only set in response messages */
	uint8_t meas_fresh_cap:1;				/**< Measurement response capabilities. Only set in response messages */
	uint8_t encrypt_cap:1;					/**< Supports message encryption */
	uint8_t mac_cap:1;						/**< Supports message authentication */
	uint8_t mut_auth_cap:1;					/**< Supports mutual authentication */
	uint8_t key_ex_cap:1;					/**< Supports Key Exchange command */
	uint8_t psk_cap:2;						/**< Pre-shared key capabilities */
	uint8_t encap_cap:1;					/**< Supports encapsulated requests */
	uint8_t hbeat_cap:1;					/**< Supports heartbeat command */
	uint8_t key_upd_cap:1;					/**< Supports Key Update command */
	uint8_t handshake_in_the_clear_cap:1;	/**< Supports communication with messages exchanged during the Session Handshake Phase in the clear */
	uint8_t pub_key_id_cap:1;				/**< Public key of device was provisioned to target */
	uint8_t chunk_cap:1;					/**< Supports large SPDM message transfer mechanism */
	uint8_t alias_cert_cap:1;				/**< Uses the AliasCert model */
	uint8_t reserved:5;						/**< Reserved */
	uint8_t reserved2;						/**< Reserved */
};


_Static_assert ((sizeof (struct spdm_get_capabilities_flags_format)) == 4,
	"Unexpected size of struct spdm_get_capabilities_flags_format");

/**
 * SPDM device capabilities.
 */
struct PLATFORM_LITTLE_ENDIAN_STORAGE spdm_device_capability {
	/**
	 * Maximum amount of time the endpoint has to provide any response requiring
	 * cryptographic processing such as the GET_MEASUREMENTS or CHALLENGE request messages.
	 */
	union {
		uint8_t ct_exponent;
		uint32_t align_value;
	};

	struct spdm_get_capabilities_flags_format flags;	/**< Capabilities flags */
	uint32_t data_transfer_size;						/**< Maximum buffer size of the device. */
	uint32_t max_spdm_msg_size;							/**< Maximum size for a single SPDM message */
};


_Static_assert ((sizeof (struct spdm_device_capability)) == 16,
	"Unexpected size of struct spdm_device_capability");

/**
 * SPDM Negotiate Algorithm 'OtherParamsSupport' format.
 */
struct PLATFORM_LITTLE_ENDIAN_STORAGE spdm_other_params_support {
	uint8_t opaque_data_format:4;	/**< Opaque Data Format Support and Selection */
	uint8_t reserved:4;				/**< Reserved */
};

/**
 * SPDM algorithms.
 */
struct PLATFORM_LITTLE_ENDIAN_STORAGE spdm_device_algorithms {
	union {
		uint32_t unused;									/**< Unused variable to align the size of types which could have different size */
		uint8_t measurement_spec;							/**< Measurement specification */
	};

	struct spdm_other_params_support other_params_support;	/**< Additional params supported */
	uint32_t measurement_hash_algo;							/**< Measurement hash algorithm. */
	uint32_t base_asym_algo;								/**< Base asymmetric algorithm. */
	uint32_t base_hash_algo;								/**< Base hash algorithm. */
	uint16_t dhe_named_group;								/**< DHE named group. */
	uint16_t aead_cipher_suite;								/**< AEAD cipher suite. */
	uint16_t req_base_asym_alg;								/**< Requested base asymmetric algorithm. */
	uint16_t key_schedule;									/**< Key schedule. */
};


/**
 * NOTE: It is important to keep these structs as is to make sure binary compatibility
 * with previous versions
 */
_Static_assert (offsetof (struct spdm_device_algorithms, measurement_spec) == 0,
	"Unexpected struct member offset");
_Static_assert (offsetof (struct spdm_device_algorithms, other_params_support) == 4,
	"Unexpected struct member offset");
_Static_assert (offsetof (struct spdm_device_algorithms, measurement_hash_algo) == 8,
	"Unexpected struct member offset");
_Static_assert (offsetof (struct spdm_device_algorithms, base_hash_algo) == 16,
	"Unexpected struct member offset");
_Static_assert (offsetof (struct spdm_device_algorithms, dhe_named_group) == 20,
	"Unexpected struct member offset");
_Static_assert (offsetof (struct spdm_device_algorithms, aead_cipher_suite) == 22,
	"Unexpected struct member offset");
_Static_assert (offsetof (struct spdm_device_algorithms, req_base_asym_alg) == 24,
	"Unexpected struct member offset");
_Static_assert (offsetof (struct spdm_device_algorithms, key_schedule) == 26,
	"Unexpected struct member offset");
_Static_assert (sizeof (struct spdm_device_algorithms) == 28,
	"Unexpected size of struct spdm_device_algorithms");

/**
 * SPDM END SESSION 'Negotiated State Preservation Indicator' format per DSP0274 Table 77.
 */
struct PLATFORM_LITTLE_ENDIAN_STORAGE spdm_end_session_request_attributes {
	uint8_t negotiated_state_preservation_indicator:1;	/**< State preservation config */
	uint8_t reserved:7;									/**< Reserved */
};


_Static_assert ((sizeof (struct spdm_end_session_request_attributes)) == 1,
	"Unexpected size of struct spdm_end_session_request_attributes");

/**
 * SPDM connection info.
 */
struct spdm_connection_info {
	union {
		uint32_t unused;
		enum spdm_connection_state connection_state;	/**< State of the SPDM connection. */
	};

	struct spdm_version_number version;					/**< Negotiated version */
	struct spdm_device_capability peer_capabilities;	/**< Peer capabilities. */
	struct spdm_device_algorithms peer_algorithms;		/**< Negotiated algorithms. */
	struct spdm_version_number secure_message_version;	/**< Negotiated secure message version. */
	/** Specifies whether the cached negotiated state should be invalidated. (responder only)
	 * This is a sticky bit wherein if it is set to 1 then it cannot be set to 0.
	 */
	union {
		struct spdm_end_session_request_attributes end_session_attributes;
		uint32_t unused2;
	};
};


_Static_assert ((sizeof (struct spdm_connection_info)) == 60,
	"Unexpected size of struct spdm_connection_info");

/**
 * Response states of the responder.
 */
enum spdm_response_state {
	SPDM_RESPONSE_STATE_NORMAL,				/**< Normal response. */
	SPDM_RESPONSE_STATE_BUSY,				/**< Other component is busy. */
	SPDM_RESPONSE_STATE_NOT_READY,			/**< Hardware is not ready. */
	SPDM_RESPONSE_STATE_NEED_RESYNC,		/**< Firmware Update is done. Need resync. */
	SPDM_RESPONSE_STATE_PROCESSING_ENCAP,	/**< Processing Encapsulated message. */
	SPDM_RESPONSE_STATE_MAX,				/**< MAX */
};


/**
 * SPDM context for a requester/responder.
 */
struct spdm_responder_state {
	struct spdm_connection_info connection_info;	/**< Connection info. */
	uint64_t max_spdm_session_sequence_number;		/**< Max SPDM session sequence number. */

	union {
		uint32_t unused;
		enum spdm_response_state response_state;	/**< Responder response state */
	};

	union {
		uint32_t unused2;
		uint16_t current_local_session_id;	/**< Current local session Id. */
	};

	union {
		uint32_t unused3;
		uint8_t handle_error_return_policy;	/**< Handle error return policy. */
	};
};


/* 88 bytes, because default alignment for this struct is 8 bytes (due uint64_t)*/
_Static_assert ((sizeof (struct spdm_responder_state)) == 88,
	"Unexpected size of struct spdm_responder_state");

int spdm_responder_init_state (struct spdm_responder_state *state);


#endif	/* SPDM_STATE_H_ */
