// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef SPDM_COMMANDS_H_
#define SPDM_COMMANDS_H_

#include "common/common_math.h"
#include "attestation/attestation_responder.h"
#include "cmd_interface/device_manager.h"
#include "cmd_interface/cmd_interface.h"
#include "cmd_interface_spdm.h"
#include "cmd_interface_spdm_responder.h"
#include "crypto/hash.h"
#include "spdm_protocol.h"
#include "spdm_transcript_manager.h"
#include "platform_config.h"


/* Configurable parameters. Defaults can be overridden in platform_config.h. */

/**
 * Maximum exponent for cryptographic processing time as described in section 10.3 of the DSP0274 SPDM spec.
 */
#ifndef SPDM_MAX_CT_EXPONENT
#define SPDM_MAX_CT_EXPONENT						31
#endif

/**
 * Capabilities of SPDM requester. Capabilities described in section 10.3 in DSP0274 SPDM spec.
 */
#define SPDM_REQUESTER_CACHE_CAP					0
#define SPDM_REQUESTER_CERT_CAP						0
#define SPDM_REQUESTER_CHAL_CAP						0
#define SPDM_REQUESTER_MEAS_CAP						0
#define SPDM_REQUESTER_MEAS_FRESH_CAP				0
#define SPDM_REQUESTER_ENCRYPT_CAP					0
#define SPDM_REQUESTER_MAC_CAP						0
#define SPDM_REQUESTER_MUT_AUTH_CAP					0
#define SPDM_REQUESTER_KEY_EX_CAP					0
#define SPDM_REQUESTER_PSK_CAP						0
#define SPDM_REQUESTER_ENCAP_CAP					0
#define SPDM_REQUESTER_HBEAT_CAP					0
#define SPDM_REQUESTER_KEY_UPD_CAP					0
#define SPDM_REQUESTER_HANDSHAKE_IN_THE_CLEAR_CAP	0
#define SPDM_REQUESTER_PUB_KEY_ID_CAP				0
#define SPDM_REQUESTER_CHUNK_CAP					0
#define SPDM_REQUESTER_ALIAS_CERT_CAP				0

/**
 * SPDM measurement response capabilities values for the Get Capabilities command, from section 10.3
 * in DSP0274 SPDM spec.
 */
#define SPDM_MEASUREMENT_RSP_CAP_MEASUREMENTS_WITHOUT_SIG		(0x01)
#define SPDM_MEASUREMENT_RSP_CAP_MEASUREMENTS_WITH_SIG			(0x02)

/**
 * SPDM combined prefix length as described in section 15 of DSP0274 SPDM spec.
 */
#define SPDM_COMBINED_PREFIX_LEN					100

#pragma pack(push, 1)

/**
 * SPDM get version request format
 */
struct spdm_get_version_request {
	struct spdm_protocol_header header;		/**< Message header */
	uint8_t reserved;						/**< Reserved */
	uint8_t reserved2;						/**< Reserved */
};

/**
 * SPDM get version response format
 */
struct spdm_get_version_response {
	struct spdm_protocol_header header;		/**< Message header */
	uint8_t reserved;						/**< Reserved */
	uint8_t reserved2;						/**< Reserved */
	uint8_t reserved3;						/**< Reserved */
	uint8_t version_num_entry_count;		/**< Number of version entries present in response */
};

/**
 * SPDM version entry format
 */
struct spdm_version_num_entry {
	uint8_t alpha:4;						/**< Pre-release WIP version of the specification */
	uint8_t update_version:4;				/**< Specification update version */
	uint8_t minor_version:4;				/**< Specification minor version */
	uint8_t major_version:4;				/**< Specification major version */
};

/**
 * Get the total length of a SPDM get version response message
 *
 * @param resp Buffer with struct spdm_get_version_response
 */
#define	spdm_get_version_resp_length(resp)	\
	((resp->version_num_entry_count * sizeof (struct spdm_version_num_entry)) + \
		sizeof (struct spdm_get_version_response))

/**
 * Get the buffer containing the version table from a SPDM get version response
 *
 * @param resp Buffer with struct spdm_get_version_response
 */
#define	spdm_get_version_resp_version_table(resp)	\
	((struct spdm_version_num_entry*) (((uint8_t*) resp) + sizeof (*resp)))

/**
 * Convert SPDM CT base 2 exponent to timeout in milliseconds
 *
 * @param ct Exponent of base 2 used to calculate CT defined in section 9.2 in DSP0274 SPDM spec
 */
#define spdm_capabilities_rsp_ct_to_ms(ct)						((1 << (ct)) / 1000)

/**
 * Minimum data transfer size for 1.2 per SPDM spec section 10.3
 */
#define SPDM_MIN_DATA_TRANSFER_SIZE_VERSION_1_2		42

/**
 * SPDM get capabilities flags format
 */
struct spdm_get_capabilities_flags_format {
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

/**
 * SPDM pre-shared key capabilities flag values.
 */
enum spdm_pre_shared_key_capability_options {
	SPDM_PSK_NOT_SUPPORTED, 			/**< Pre-shared key capabilities not supported.*/
	SPDM_PSK_SUPPORTED_NO_CONTEXT, 		/** <Pre-shared key supported without session key derviation context.*/
	SPDM_PSK_SUPPORTED_WITH_CONTEXT, 	/** <Pre-shared key supported with session key derviation context.*/
	SPDM_PSK_RESERVED,					/**< Reserved.*/
};

/**
 * SPDM get capabilities request/response format for SPDM 1.1
 */
struct spdm_get_capabilities_1_1 {
	struct spdm_protocol_header header;					/**< Message header */
	uint8_t reserved;									/**< Reserved */
	uint8_t reserved2;									/**< Reserved */
	uint8_t reserved3;									/**< Reserved */
	uint8_t ct_exponent;								/**< Exponent of base 2 used to calculate CT from timing specification table */
	uint16_t reserved4;									/**< Reserved */
	struct spdm_get_capabilities_flags_format flags;	/**< Capabilities flags */
};

/**
 * SPDM get capabilities request/response format
 */
struct spdm_get_capabilities {
	struct spdm_get_capabilities_1_1 base_capabilities;		/**< Common capabilities segment with v1.1 get capabilities format*/
	uint32_t data_transfer_size;							/**< Maximum buffer size in bytes of the device for receiving a single SPDM message */
	uint32_t max_spdm_msg_size;								/**< Maximum size in bytes of the internal buffer for processing a single large SPDM message */
};

/**
 * SPDM measurement specification values for Negotiate Algorithm command, from section 10.4 in
 * DSP0274 SPDM spec.
 */
#define SPDM_MEASUREMENT_SPEC_DMTF								(1 << 0)

/**
 * SPDM asymmetric key signature algorithm bitmask selection for Negotiate Algorithm command, from
 * section 10.4 in DSP0274 SPDM spec.
 */
#define SPDM_TPM_ALG_RSASSA_2048 								(1 << 0)
#define SPDM_TPM_ALG_RSAPSS_2048 								(1 << 1)
#define SPDM_TPM_ALG_RSASSA_3072 								(1 << 2)
#define SPDM_TPM_ALG_RSAPSS_3072 								(1 << 3)
#define SPDM_TPM_ALG_ECDSA_ECC_NIST_P256 						(1 << 4)
#define SPDM_TPM_ALG_RSASSA_4096 								(1 << 5)
#define SPDM_TPM_ALG_RSAPSS_4096 								(1 << 6)
#define SPDM_TPM_ALG_ECDSA_ECC_NIST_P384 						(1 << 7)
#define SPDM_TPM_ALG_ECDSA_ECC_NIST_P521 						(1 << 8)

/**
 * SPDM cryptographic hashing algorithm bitmask selection for Negotiate Algorithm command, from
 * section 10.4 in DSP0274 SPDM spec.
 */
#define SPDM_TPM_ALG_SHA_256	 								(1 << 0)
#define SPDM_TPM_ALG_SHA_384	 								(1 << 1)
#define SPDM_TPM_ALG_SHA_512	 								(1 << 2)
#define SPDM_TPM_ALG_SHA3_256	 								(1 << 3)
#define SPDM_TPM_ALG_SHA3_384	 								(1 << 4)
#define SPDM_TPM_ALG_SHA3_512	 								(1 << 5)

/**
 * SPDM cryptographic hashing algorithm bitmask selection for measurements in Negotiate Algorithm
 * response, from section 10.4 in DSP0274 SPDM spec.
 */
#define SPDM_MEAS_RSP_ALG_RAW_BIT_STREAM_ONLY					(1 << 0)
#define SPDM_MEAS_RSP_TPM_ALG_SHA_256	 						(1 << 1)
#define SPDM_MEAS_RSP_TPM_ALG_SHA_384	 						(1 << 2)
#define SPDM_MEAS_RSP_TPM_ALG_SHA_512	 						(1 << 3)
#define SPDM_MEAS_RSP_TPM_ALG_SHA3_256	 						(1 << 4)
#define SPDM_MEAS_RSP_TPM_ALG_SHA3_384	 						(1 << 5)
#define SPDM_MEAS_RSP_TPM_ALG_SHA3_512	 						(1 << 6)

/**
 * SPDM algorithm type for an algorithm request structure, from section 10.4 in DSP0274 SPDM spec.
 */
#define SPDM_ALG_REQ_STRUCT_MAX_NUM_STRUCT_TABLE_ALG		4
#define SPDM_ALG_REQ_STRUCT_ALG_TYPE_DHE 					2
#define SPDM_ALG_REQ_STRUCT_ALG_TYPE_AEAD 					3
#define SPDM_ALG_REQ_STRUCT_ALG_TYPE_REQ_BASE_ASYM_ALG 		4
#define SPDM_ALG_REQ_STRUCT_ALG_TYPE_KEY_SCHEDULE 			5

/**
 * SPDM negotiate alorithms maximum request size, from section 10.4 in DSP0274 SPDM spec.
 */
#define SPDM_NEGOTIATE_ALGORITHMS_REQUEST_MAX_LENGTH	0x80

/**
 * SPDM negotiate alorithms maximum extension algorithm count, from section 10.4 in DSP0274 SPDM spec.
 */
#define SPDM_NEGOTIATE_ALGORITHMS_REQUEST_MAX_EXT_ALG_COUNT_VERSION		0x14

/**
 * SPDM Opaque Data Format (v1.2).
 */
#define SPDM_ALGORITHMS_OPAQUE_DATA_FORMAT_NONE		0x0
#define SPDM_ALGORITHMS_OPAQUE_DATA_FORMAT_0		0x1
#define SPDM_ALGORITHMS_OPAQUE_DATA_FORMAT_1		0x2

/**
 *  SPDM Negotiate Algorithm request KEY_SCHEDULE algorithm.
 */
#define SPDM_ALG_KEY_SCHEDULE_HMAC_HASH		0x00000001

/**
 * SPDM Negotiate Algorithm request AEAD algorithms.
 */
#define SPDM_ALG_AEAD_CIPHER_SUITE_AES_128_GCM 			0x00000001
#define SPDM_ALG_AEAD_CIPHER_SUITE_AES_256_GCM 			0x00000002
#define SPDM_ALG_AEAD_CIPHER_SUITE_CHACHA20_POLY1305 	0x00000004
#define SPDM_ALG_AEAD_CIPHER_SUITE_AEAD_SM4_GCM			0x00000008

/**
 *  SPDM Negotiate Algorithm request DHE algorithms.
 */
#define SPDM_ALG_DHE_NAMED_GROUP_FFDHE_2048		0x00000001
#define SPDM_ALG_DHE_NAMED_GROUP_FFDHE_3072		0x00000002
#define SPDM_ALG_DHE_NAMED_GROUP_FFDHE_4096		0x00000004
#define SPDM_ALG_DHE_NAMED_GROUP_SECP_256_R1	0x00000008
#define SPDM_ALG_DHE_NAMED_GROUP_SECP_384_R1	0x00000010
#define SPDM_ALG_DHE_NAMED_GROUP_SECP_521_R1	0x00000020

/**
 * SPDM Negotiate Algorithm request algorithm structure types.
 */
#define SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_DHE					2
#define SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_AEAD				3
#define SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_REQ_BASE_ASYM_ALG	4
#define SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_KEY_SCHEDULE		5

/**
 * SPDM Negotiate Algorithm 'OtherParamsSupport' format.
 */
struct spdm_other_params_support {
	uint8_t opaque_data_format:4;		/**< Opaque Data Format Support and Selection */
	uint8_t reserved:4;					/**< Reserved */
};

/**
 * SPDM negotiate algorithms request format
 */
struct spdm_negotiate_algorithms_request {
	struct spdm_protocol_header header;		/**< Message header */
	uint8_t num_alg_structure_tables;		/**< Number of algorithm structure tables in request */
	uint8_t reserved;						/**< Reserved */
	uint16_t length;						/**< Length of the entire message in bytes */
	uint8_t measurement_specification;		/**< Measurement specification bitmask */
	struct spdm_other_params_support other_params_support; /**< Additional params supported */
	uint32_t base_asym_algo;				/**< Supported asymmetric key signature algorithms */
	uint32_t base_hash_algo;				/**< Supported cryptographic hashing algorithms */
	uint8_t reserved3[12];					/**< Reserved */
	uint8_t ext_asym_count;					/**< Number of supported extended asymmetric key signature algorithms */
	uint8_t ext_hash_count;					/**< Number of supported extended cryptographic hashing algorithms */
	uint16_t reserved4;						/**< Reserved */
};

/**
 * SPDM extended algorithm format
 */
struct spdm_extended_algorithm {
	uint8_t registry_id;			/**< Registry or standards body */
	uint8_t reserved;				/**< Reserved */
	uint16_t algorithm_id;			/**< Algorithm ID */
};

/**
 * SPDM algorithm request structure format
 */
struct spdm_algorithm_request {
	uint8_t alg_type;					/**< Type of algorithm */
	uint8_t ext_alg_count:4;			/**< Number of supported extended algorithms */
	uint8_t fixed_alg_count:4;			/**< Number of supported SPDM-enumerated fixed algorithms */
	uint16_t alg_supported;				/**< Bitmask for supported SPDM-enumerated algorithms */
};

/**
 * Get the minimum length of a SPDM negotiate algorithms request message
 *
 * @param req Buffer containing struct spdm_negotiate_algorithms_request
 */
#define	spdm_negotiate_algorithms_min_req_length(req)	( \
	sizeof (struct spdm_negotiate_algorithms_request) + \
	(sizeof (struct spdm_extended_algorithm) * (req->ext_asym_count + req->ext_hash_count)) + \
	(sizeof (struct spdm_algorithm_request) * req->num_alg_structure_tables))

/**
 * Get the next algorithm struct table entry.
 * 
 * @param curr_alg_struct_table_entry Current algorithm struct table entry.
*/
#define spdm_negotiate_algorithms_get_next_alg_struct_table_entry(curr_alg_struct_table_entry) ( \
	(struct spdm_algorithm_request*)((size_t) curr_alg_struct_table_entry + \
	sizeof (struct spdm_algorithm_request) + \
	sizeof (struct spdm_extended_algorithm) * curr_alg_struct_table_entry->ext_alg_count))

/**
 * Get the extended asymmetric key signature algorithms table from a negotiate algorithms request
 *
 * @param req Buffer with struct spdm_negotiate_algorithms_request
 */
#define	spdm_negotiate_algorithms_req_ext_asym_table(req)	\
	((struct spdm_extended_algorithm*) (((uint8_t*) req) + sizeof (*req)))

/**
 * Get the extended cryptographic hashing algorithms table from a negotiate algorithms request
 *
 * @param req Buffer with struct spdm_negotiate_algorithms_request
 */
#define	spdm_negotiate_algorithms_req_ext_hash_table(req)	((struct spdm_extended_algorithm*) \
	(((uint8_t*) spdm_negotiate_algorithms_req_ext_asym_table (req)) + \
	req->ext_asym_count * (sizeof (struct spdm_extended_algorithm))))

/**
 * Get the first algorithm request structure table from a negotiate algorithms request
 *
 * @param req Buffer with struct spdm_negotiate_algorithms_request
 */
#define	spdm_negotiate_algorithms_req_algstruct_table(req)	((struct spdm_algorithm_request*) \
	((uint8_t*) spdm_negotiate_algorithms_req_ext_hash_table (req) + \
	req->ext_hash_count * (sizeof (struct spdm_extended_algorithm))))

/**
 * Get the expected extended algorithm structure total size.
 * 
 * @param algstruct_table Algorithm structure table.
 */
#define spdm_negotiate_algorithms_expected_extended_algo_size(algstruct_table) ( \
	sizeof (struct spdm_extended_algorithm) * algstruct_table->ext_alg_count)

/**
 * Get the actual extended algorithm structure total size.
 * 
 * @param rq Buffer containing extended algorithm structure
 * @param algstruct_table Algorithm structure table.
 */
#define spdm_negotiate_algorithms_actual_extended_algo_size(req, algstruct_table) ( \
	(size_t) (req) + request->payload_length - (size_t) (algstruct_table) - \
	sizeof (struct spdm_algorithm_request))

/**
 * SPDM negotiate algorithms response format
 */
struct spdm_negotiate_algorithms_response {
	struct spdm_protocol_header header;		/**< Message header */
	uint8_t num_alg_structure_tables;		/**< Number of algorithm structure tables in request */
	uint8_t reserved;						/**< Reserved */
	uint16_t length;						/**< Length of the entire message in bytes */
	uint8_t measurement_specification;		/**< Measurement specification bitmask */
	struct spdm_other_params_support other_params_selection;	/**< Additional params selected */
	uint32_t measurement_hash_algo;			/**< SPDM-enumerated hashing algorithm selected for measurements */
	uint32_t base_asym_sel;					/**< Asymmetric key signature algorithm selected */
	uint32_t base_hash_sel;					/**< Cryptographic hashing algorithm selected */
	uint8_t reserved3[12];					/**< Reserved */
	uint8_t ext_asym_sel_count;				/**< Number of extended asymmetric key signature algorithms selected */
	uint8_t ext_hash_sel_count;				/**< Number of extended cryptographic hashing algorithms selected */
	uint16_t reserved4;						/**< Reserved */
};

/**
 * Maximum algorithm structs in negotiate algorithms response.
 */
#define SPDM_NEGOTIATE_ALGORITHMS_MAX_NUM_STRUCT_TABLE_ALG		4

/**
 * SPDM negotiate algorithms response with no external algorithms.
 */
struct spdm_negotiate_algorithms_response_no_ext_alg {
	struct spdm_negotiate_algorithms_response base;
	struct spdm_algorithm_request
		algstruct_table[SPDM_NEGOTIATE_ALGORITHMS_MAX_NUM_STRUCT_TABLE_ALG];
};

/**
 * Get the minimum length of a SPDM negotiate algorithms response message
 *
 * @param rsp Buffer containing struct spdm_negotiate_algorithms_response
 */
#define	spdm_negotiate_algorithms_min_rsp_length(rsp)	( \
	sizeof (struct spdm_negotiate_algorithms_response) + \
	(sizeof (struct spdm_extended_algorithm) * \
		(rsp->ext_asym_sel_count + rsp->ext_hash_sel_count)) + \
	(sizeof (struct spdm_algorithm_request) * rsp->num_alg_structure_tables))

/**
 * Get the extended asymmetric key signature algorithms table from a negotiate algorithms response
 *
 * @param resp Buffer with struct spdm_negotiate_algorithms_response
 */
#define	spdm_negotiate_algorithms_rsp_ext_asym_table(resp)	\
	((struct spdm_extended_algorithm*) (((uint8_t*) resp) + sizeof (*resp)))

/**
 * Get the extended cryptographic hashing algorithms table from a negotiate algorithms response
 *
 * @param resp Buffer with struct spdm_negotiate_algorithms_response
 */
#define	spdm_negotiate_algorithms_rsp_ext_hash_table(resp)	((struct spdm_extended_algorithm*) \
	(((uint8_t*) spdm_negotiate_algorithms_rsp_ext_asym_table (resp)) + \
	resp->ext_asym_sel_count * (sizeof (struct spdm_extended_algorithm))))

/**
 * Get the first algorithm request structure table from a negotiate algorithms response
 *
 * @param resp Buffer with struct spdm_negotiate_algorithms_response
 */
#define	spdm_negotiate_algorithms_rsp_algstruct_table(resp)	((struct spdm_algorithm_request*) \
	((uint8_t*) spdm_negotiate_algorithms_rsp_ext_hash_table (resp) + \
		(resp->ext_hash_sel_count * (sizeof (struct spdm_extended_algorithm)))))


/**
 * Get the negotiate algorithm response size. This is based on the negotiate algorithms request.
 * 
 * @param req Buffer containing the negotiate algorithms request.
 */
#define spdm_negotiate_algorithms_rsp_size(req) ( \
	sizeof (struct spdm_negotiate_algorithms_response_no_ext_alg) - \
	((SPDM_ALG_REQ_STRUCT_MAX_NUM_STRUCT_TABLE_ALG - req->num_alg_structure_tables) * \
	sizeof (struct spdm_algorithm_request)));

/**
 * SPDM get certificate request/response slot id mask
 */
#define SPDM_GET_CERTIFICATE_SLOT_ID_MASK	0xF

/**
 * SPDM certificate slot maximum count.
 * [TODO] This will be removed when the Certificate Manager component is available.
 */
#ifndef SPDM_MAX_SLOT_COUNT
#define SPDM_MAX_SLOT_COUNT		1
#endif

/**
 * SPDM max. certificates in a chain.
 * [TODO] This will be removed when the Certificate Manager component is available.
 */
#ifndef SPDM_MAX_CERT_COUNT_IN_CHAIN
#define SPDM_MAX_CERT_COUNT_IN_CHAIN		4
#endif

/**
 * SPDM get digests request format
 */
struct spdm_get_digests_request {
	struct spdm_protocol_header header;		/**< Message header */
	uint8_t reserved;						/**< Reserved */
	uint8_t reserved2;						/**< Reserved */
};

/**
 * SPDM get digests response format
 */
struct spdm_get_digests_response {
	struct spdm_protocol_header header;		/**< Message header */
	uint8_t reserved;						/**< Reserved */
	uint8_t slot_mask;						/**< Slot mask */
};

/**
 * SPDM cert chain format
 */
struct spdm_cert_chain {
	uint16_t length;							/**< Length of the cert chain including this struct. */
	uint16_t reserved;							/**< Reserved */
	uint8_t root_hash[HASH_MAX_HASH_LEN];		/**< Max. hash size of the root cert. */
};

/**
 * Get the total length of a SPDM certificate chain.
 *
 * @param hash_size Size of the cert chain hash.
 * @param cert_chain_length Length of the cert chain.
 */
#define	spdm_get_digests_cert_chain_length(hash_size, cert_chain_length)	\
	(offsetof (struct spdm_cert_chain, root_hash) + hash_size + cert_chain_length)

/**
 * Get the total length of a SPDM get digests response message
 *
 * @param resp Buffer containing struct spdm_get_digests_response
 * @param digest_len Size of each certificate chain digest
 */
#define	spdm_get_digests_resp_length(resp, digest_len)	\
	(common_math_get_num_bits_set (resp->slot_mask) * digest_len + sizeof (*resp))

/**
 * Get the buffer containing the digests table stored in SPDM get digests response
 *
 * @param resp Buffer with struct spdm_get_digests_response
 */
#define	spdm_get_digests_resp_digests(resp)	(((uint8_t*) resp) + sizeof (*resp))

/**
 * Get the buffer containing a single entry from digest table stored in SPDM get digests response
 *
 * @param resp Buffer with struct spdm_get_digests_response
 * @param slot_num Slot number of requested certificate chain digest
 * @param digest_len Size of each certificate chain digest
 */
#define	spdm_get_digests_resp_digest(resp, slot_num, digest_len) \
	(spdm_get_digests_resp_digests (resp) + \
		(common_math_get_num_bits_set_before_index (resp->slot_mask, slot_num) * digest_len))

/**
 * SPDM get certificate request format
 */
struct spdm_get_certificate_request {
	struct spdm_protocol_header header;		/**< Message header */
	uint8_t slot_num;						/**< Slot number to read certificate chain from */
	uint8_t reserved;						/**< Reserved */
	uint16_t offset;						/**< Offset in bytes from start of certificate chain requested */
	uint16_t length;						/**< Length in bytes requested */
};

/**
 * SPDM get certificate response format
 */
struct spdm_get_certificate_response {
	struct spdm_protocol_header header;		/**< Message header */
	uint8_t slot_num;						/**< Slot number of the certificate chain returned */
	uint8_t reserved;						/**< Reserved */
	uint16_t portion_len;					/**< Number of certificate chain bytes included in response */
	uint16_t remainder_len;					/**< Number of certificate chain bytes not sent yet */
};

/**
 * Get the total length of a SPDM get certificate response message
 *
 * @param resp Buffer containing struct spdm_get_certificate_response
 */
#define	spdm_get_certificate_resp_length(resp) 	(resp->portion_len + sizeof (*resp))

/**
 * Maximum amount of certificate data that can be returned in the response
 */
#define	SPDM_GET_CERTIFICATE_MAX_CERT_BUFFER 	(MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY - \
	sizeof (struct spdm_get_certificate_response))

/**
 * Maximum amount of certificate data that can be returned in the response
 *
 * @param max_response Maximum response length
 */
#define	spdm_get_certificate_max_cert_buffer(max_response) 	\
	(max_response - sizeof (struct spdm_get_certificate_response))

/**
 * Get the buffer containing the certificate chain portion returned in SPDM get certificate response
 *
 * @param resp Buffer with struct spdm_get_certificate_response
 */
#define	spdm_get_certificate_resp_cert_chain(resp)	(((uint8_t*) resp) + sizeof (*resp))

/**
 * SPDM certificate chain format
 */
struct spdm_certificate_chain {
	uint16_t length;			/**< Total length of certificate chain including all fields */
	uint16_t reserved;			/**< Reserved */
};

/**
 * SPDM measurement summary hash types for Challenge command, from section 10.9 in DSP0274 SPDM
 * spec.
 */
#define SPDM_MEASUREMENT_SUMMARY_HASH_NONE 						0x0
#define SPDM_MEASUREMENT_SUMMARY_HASH_TCB						0x1
#define SPDM_MEASUREMENT_SUMMARY_HASH_ALL 						0xFF

/**
 * SPDM challenge request format
 */
struct spdm_challenge_request {
	struct spdm_protocol_header header;				/**< Message header */
	uint8_t slot_num;								/**< Slot number selected */
	uint8_t req_measurement_summary_hash_type;		/**< Requested measurement summary hash type */
	uint8_t nonce[SPDM_NONCE_LEN];					/**< Random nonce */
};

/**
 * SPDM challenge response format
 */
struct spdm_challenge_response {
	struct spdm_protocol_header header;		/**< Message header */
	uint8_t slot_num:4;						/**< Slot number selected in request */
	uint8_t reserved:3;						/**< Reserved */
	uint8_t basic_mutual_auth_req:1;		/**< Request identity authentication of requester */
	uint8_t slot_mask;						/**< Slot mask indicating certificate chains supporting SPDM protocol version */
};

/**
 * Get the minimum length of a SPDM challenge response message, not including variable length fields
 *
 * @param cert_chain_hash_len Length of certificate chain
 */
#define spdm_get_challenge_resp_min_length(cert_chain_hash_len)					\
	(sizeof (struct spdm_challenge_response) + cert_chain_hash_len + SPDM_NONCE_LEN + \
		sizeof (uint16_t))

/**
 * Get the total length of a SPDM challenge response message, not including signature
 *
 * @param resp Buffer containing struct spdm_get_certificate_response
 * @param cert_chain_hash_len Length of certificate chain
 * @param measurement_summary_hash Length of measurement summary hash
 */
#define	spdm_get_challenge_resp_length(resp, cert_chain_hash_len, measurement_summary_hash) \
	(spdm_get_challenge_resp_min_length (cert_chain_hash_len) + measurement_summary_hash + \
		spdm_get_challenge_resp_opaque_len (resp, cert_chain_hash_len, measurement_summary_hash))

/**
 * Get the buffer containing the certificate chain hash in SPDM challenge response
 *
 * @param resp Buffer with struct spdm_challenge_response
 */
#define	spdm_get_challenge_resp_cert_chain_hash(resp)	(((uint8_t*) resp) + sizeof (*resp))

/**
 * Get the buffer containing the nonce in SPDM challenge response
 *
 * @param resp Buffer with struct spdm_challenge_response
 * @param cert_chain_hash_len Length of certificate chain
 */
#define	spdm_get_challenge_resp_nonce(resp, cert_chain_hash_len)	\
	(spdm_get_challenge_resp_cert_chain_hash (resp) + cert_chain_hash_len)

/**
 * Get the buffer containing the measurement summary hash in SPDM challenge response
 *
 * @param resp Buffer with struct spdm_challenge_response
 * @param cert_chain_hash_len Length of certificate chain
 */
#define	spdm_get_challenge_resp_measurement_summary_hash(resp, cert_chain_hash_len)	\
	(spdm_get_challenge_resp_nonce (resp, cert_chain_hash_len) + SPDM_NONCE_LEN)

/**
 * Get the max measurement summary hash length in SPDM challenge response
 *
 * @param max_response Maximum response length
 * @param cert_chain_hash_len Length of certificate chain
 * @param opaque_data_len Opaque data length
 * @param sig_len Signature length
 */
#define	spdm_get_challenge_resp_measurement_summary_hash_max_len(max_response, \
	cert_chain_hash_len, sig_len, opaque_data_len)	\
	(max_response - \
		spdm_get_challenge_resp_min_length (cert_chain_hash_len) - opaque_data_len - sig_len)

/**
 * Get the pointer holding the opaque data size from a SPDM challenge response
 *
 * @param resp Buffer with struct spdm_challenge_response
 * @param cert_chain_hash_len Length of certificate chain
 * @param measurement_summary_hash Length of measurement summary hash
 */
#define	spdm_get_challenge_resp_opaque_len_ptr(resp, cert_chain_hash_len, \
	measurement_summary_hash)	\
	((uint16_t*) (spdm_get_challenge_resp_measurement_summary_hash (resp, cert_chain_hash_len) + \
		measurement_summary_hash))

/**
 * Get the opaque data size from a SPDM challenge response
 *
 * @param resp Buffer with struct spdm_challenge_response
 * @param cert_chain_hash_len Length of certificate chain
 * @param measurement_summary_hash Length of measurement summary hash
 */
#define	spdm_get_challenge_resp_opaque_len(resp, cert_chain_hash_len, measurement_summary_hash)	\
	(*spdm_get_challenge_resp_opaque_len_ptr (resp, cert_chain_hash_len, measurement_summary_hash))

/**
 * Get the buffer containing opaque data from a SPDM challenge response
 *
 * @param resp Buffer with struct spdm_challenge_response
 * @param cert_chain_hash_len Length of certificate chain
 * @param measurement_summary_hash Length of measurement summary hash
 */
#define	spdm_get_challenge_resp_opaque_data(resp, cert_chain_hash_len, measurement_summary_hash) \
	(spdm_get_challenge_resp_measurement_summary_hash (resp, cert_chain_hash_len) + \
		measurement_summary_hash + sizeof (uint16_t))

/**
 * Get the buffer containing the signature from a SPDM challenge response
 *
 * @param resp Buffer with struct spdm_challenge_response
 * @param cert_chain_hash_len Length of certificate chain
 * @param measurement_summary_hash Length of measurement summary hash
 */
#define	spdm_get_challenge_resp_signature(resp, cert_chain_hash_len, measurement_summary_hash)	\
	(spdm_get_challenge_resp_opaque_data (resp, cert_chain_hash_len, measurement_summary_hash) + \
		spdm_get_challenge_resp_opaque_len (resp,cert_chain_hash_len, measurement_summary_hash))

/**
 * Get the signature length of a SPDM challenge response message
 *
 * @param resp Buffer containing struct spdm_challenge_response
 * @param cert_chain_hash_len Length of certificate chain
 * @param len Total response length
 * @param measurement_summary_hash Length of measurement summary hash
 */
#define	spdm_get_challenge_resp_signature_length(resp, cert_chain_hash_len, len, \
	measurement_summary_hash) \
	(len - spdm_get_challenge_resp_length (resp, cert_chain_hash_len, measurement_summary_hash))


/**
 * SPDM measurement operation types for Get Measurements command, from section 10.11 in DSP0274 SPDM
 * spec.
 */
#define SPDM_MEASUREMENT_OPERATION_GET_NUM_BLOCKS				0x0
#define SPDM_MEASUREMENT_OPERATION_GET_ALL_BLOCKS				0xFF

/**
 * SPDM custom device ID measurement block needed for discovery of SPDM devices by Cerberus
 */
#define SPDM_MEASUREMENT_OPERATION_GET_DEVICE_ID				0xEF

/**
 * SPDM get measurements request format
 */
struct spdm_get_measurements_request {
	struct spdm_protocol_header header;		/**< Message header */
	uint8_t sig_required:1;					/**< Signature required in response */
	uint8_t raw_bit_stream_requested:1;		/**< Raw measurement block requested */
	uint8_t reserved:6;						/**< Reserved */
	uint8_t measurement_operation;			/**< Measurement operation */
};

/**
 * Get the total length of a SPDM get measurements request message
 *
 * @param rq Buffer containing struct spdm_get_measurements_request
 */
#define	spdm_get_measurements_rq_length(rq)		(sizeof (struct spdm_get_measurements_request) + \
	((rq)->sig_required * (sizeof (uint8_t) + SPDM_NONCE_LEN)))

/**
 * Get the buffer containing the nonce in SPDM get measurements request.  This is only valid when
 * the signature required flag is set.
 *
 * @param rq Buffer containing struct spdm_get_measurements_request
 */
#define	spdm_get_measurements_rq_nonce(rq)		(((uint8_t*) rq) + sizeof (*rq))

/**
 * Get pointer containing slot ID buffer in SPDM get measurements request.  This is only valid when
 * the signature required flag is set.
 *
 * @param rq Buffer with struct spdm_get_measurements_request
 */
#define	spdm_get_measurements_rq_slot_id_ptr(rq)	\
	((uint8_t*) (spdm_get_measurements_rq_nonce (rq) + (rq)->sig_required * SPDM_NONCE_LEN))

/**
 * Get slot ID in SPDM get measurements request
 *
 * @param rq Buffer with struct spdm_get_measurements_request
 */
#define	spdm_get_measurements_rq_slot_id(rq)		\
	(*(spdm_get_measurements_rq_slot_id_ptr (rq)) & 0x0F)

/**
 * SPDM get measurements response format
 */
struct spdm_get_measurements_response {
	struct spdm_protocol_header header;		/**< Message header */
	uint8_t num_measurement_indices;		/**< Number of measurement indices in device */
	uint8_t slot_id:4;						/**< Slot ID */
	uint8_t reserved:4;						/**< Reserved */
	uint8_t number_of_blocks;				/**< Number of measurement blocks in measurement record */
	uint8_t measurement_record_len[3];		/**< Length of measurement record */
};

/**
 * Get the minimum length of a SPDM get measurements response message, not including variable length
 * 	fields
 */
#define SPDM_GET_MEASUREMENTS_RESP_MIN_LENGTH		\
	(sizeof (struct spdm_get_measurements_response) + SPDM_NONCE_LEN + sizeof (uint16_t))

/**
 * Get the total length of a SPDM get measurements response message, not including signature
 *
 * @param resp Buffer containing struct spdm_get_measurements_response
 * @param hash_len Hashing algorithm length
 */
#define	spdm_get_measurements_resp_length(resp) (SPDM_GET_MEASUREMENTS_RESP_MIN_LENGTH + \
	spdm_get_measurements_resp_measurement_record_len (resp) + \
	spdm_get_measurements_resp_opaque_len (resp))

/**
 * Get the buffer containing the measurement record in SPDM get measurements response
 *
 * @param resp Buffer with struct spdm_get_measurements_response
 */
#define	spdm_get_measurements_resp_measurement_record(resp)	(((uint8_t*) resp) + sizeof (*resp))

/**
 * Get measurement record length from measurement record length entry in
 * spdm_get_measurements_response
 *
 * @param resp Buffer with struct spdm_get_measurements_response
 */
#define spdm_get_measurements_resp_measurement_record_len(resp) \
	((*((uint32_t*) resp->measurement_record_len)) & 0x00FFFFFF)

/**
 * Get the max measurement record length in SPDM get measurements response
 *
 * @param max_response Maximum response length
 * @param opaque_data_len Opaque data length
 */
#define	spdm_get_measurements_resp_measurement_record_max_len(max_response, opaque_data_len)	\
	(max_response - SPDM_GET_MEASUREMENTS_RESP_MIN_LENGTH - opaque_data_len)

/**
 * Get the buffer containing the nonce in SPDM get measurements response
 *
 * @param resp Buffer with struct spdm_get_measurements_response
 */
#define	spdm_get_measurements_resp_nonce(resp)	\
	(spdm_get_measurements_resp_measurement_record (resp) + \
	spdm_get_measurements_resp_measurement_record_len (resp))

/**
 * Get pointer containing opaque data length buffer in SPDM get measurements response
 *
 * @param resp Buffer with struct spdm_get_measurements_response
 */
#define	spdm_get_measurements_resp_opaque_len_ptr(resp)	\
	((uint16_t*) (spdm_get_measurements_resp_nonce (resp) + SPDM_NONCE_LEN))

/**
 * Get opaque data length in bytes in SPDM get measurements response
 *
 * @param resp Buffer with struct spdm_get_measurements_response
 */
#define	spdm_get_measurements_resp_opaque_len(resp)	\
	(*(spdm_get_measurements_resp_opaque_len_ptr (resp)))

/**
 * Get the buffer containing the opaque data in SPDM get measurements response
 *
 * @param resp Buffer with struct spdm_get_measurements_response
 */
#define	spdm_get_measurements_resp_opaque_data(resp) \
	(spdm_get_measurements_resp_nonce (resp) + SPDM_NONCE_LEN + sizeof (uint16_t))

/**
 * Get the buffer containing the signature in SPDM get measurements response
 *
 * @param resp Buffer with struct spdm_get_measurements_response
 */
#define	spdm_get_measurements_resp_signature(resp) \
	(spdm_get_measurements_resp_opaque_data (resp) + spdm_get_measurements_resp_opaque_len (resp))

/**
 * Get the signature length of a SPDM get measurements response message
 *
 * @param resp Buffer containing struct spdm_get_measurements_response
 * @param len Total response length
 */
#define	spdm_get_measurements_resp_signature_length(resp, len) \
	(len - spdm_get_measurements_resp_length (resp))


/**
 * SPDM error codes, from section 10.12 in DSP0274 SPDM spec.
 */
enum {
	SPDM_ERROR_RESERVED = 0x00,									/**< Reserved */
	SPDM_ERROR_INVALID_REQUEST = 0x01,							/**< One or more request fields are invalid */
	SPDM_ERROR_INVALID_SESSION = 0x02,							/**< The record layer used an invalid session ID */
	SPDM_ERROR_BUSY = 0x03,										/**< Responder busy, try again */
	SPDM_ERROR_UNEXPECTED_REQUEST = 0x04,						/**< Responder received unexpected request message */
	SPDM_ERROR_UNSPECIFIED = 0x05,								/**< Unspecified error occurred */
	SPDM_ERROR_DECRYPT_ERROR = 0x06,							/**< Receiver of record cannot decrypt record or verify data */
	SPDM_ERROR_UNSUPPORTED_REQUEST = 0x07,						/**< RequestResponseCode in request not supported */
	SPDM_ERROR_REQUEST_IN_FLIGHT = 0x08,						/**< Responder has delivered request to which it is still waiting for response */
	SPDM_ERROR_INVALID_RESPONSE_CODE = 0x09,					/**< Requester delivered an invalid response for an encapsulated response */
	SPDM_ERROR_SESSION_LIMIT_EXCEEDED = 0x0A,					/**< Maximum number of concurrent sessions reached */
	SPDM_ERROR_SESSION_REQUIRED = 0x0B,							/**< Request received only allowed within a session */
	SPDM_ERROR_RESET_REQUIRED = 0x0C,							/**< Device requires a reset to complete requested operation */
	SPDM_ERROR_RESP_TOO_LARGE = 0x0D,							/**< Response is greater than requester maximum message size */
	SPDM_ERROR_REQ_TOO_LARGE = 0x0E,							/**< Request is greater than responder maximum message size */
	SPDM_ERROR_LARGE_RESPONSE = 0x0F,							/**< Response is greater than DataTransferSize of requesting SPDM endpoint */
	SPDM_ERROR_MSG_LOST = 0x10,									/**< SPDM message lost */
	SPDM_ERROR_VERSION_MISMATCH = 0x41,							/**< Requested SPDM version is not supported or is a different version from the selected version. */
	SPDM_ERROR_RESPONSE_NOT_READY = 0x42,						/**< Response not ready */
	SPDM_ERROR_REQUEST_RESYNCH = 0x43,							/**< Responder is requesting Requester to reissue Get Version */
	SPDM_ERROR_VENDOR_OR_OTHER_STANDARDS_DEFINED = 0xFF,		/**< Vendor or other standards defined */
};

/**
 * SPDM error response format
 */
struct spdm_error_response {
	struct spdm_protocol_header header;		/**< Message header */
	uint8_t error_code;						/**< Error code */
	uint8_t error_data;						/**< Error data */
};

/**
 * SPDM error response not ready optional data format
 */
struct spdm_error_response_not_ready {
	uint8_t rdt_exponent;	/**< Exponent for duration in microseconds after which the responder can provide response */
	uint8_t request_code;	/**< Request code that triggered this response */
	uint8_t token;			/**< Opaque handle to pass in with RESPOND_IF_READY request */
	uint8_t rdtm;			/**< Multiplier used to compute duration in microseconds after which the responder will stop processing initial request */
};

/**
 * Get the buffer containing the SPDM error response optional data
 *
 * @param resp Buffer with struct spdm_error_response
 */
#define	spdm_get_spdm_error_rsp_optional_data(resp)				(((uint8_t*) resp) + sizeof (*resp))

/**
 * SPDM respond if ready request format
 */
struct spdm_respond_if_ready_request {
	struct spdm_protocol_header header;		/**< Message header */
	uint8_t original_request_code;			/**< Original request code that triggered ResponseNotReady response */
	uint8_t token;							/**< Token received in ResponseNotReady response */
};

#pragma pack(pop)

/**
 * Identifier for an invalid session Id.
 */
#define SPDM_INVALID_SESSION_ID		0

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
	SPDM_CONNECTION_STATE_MAX					/**< MAX */
};

/**
 * SPDM version info.
 */
struct spdm_version_number {
	uint16_t alpha : 4;						/**< Pre-release version nubmer. */
	uint16_t update_version_number : 4;		/**< Update version number. */
	uint16_t minor_version: 4;				/**< Major version number. */
	uint16_t major_version : 4;				/**< Minor version number. */
};

/**
 * SPDM device capabilities.
 */
struct spdm_device_capability {
	/**
	 * Maximum amount of time the endpoint has to provide any response requiring
	 * cryptographic processing such as the GET_MEASUREMENTS or CHALLENGE request messages.
	 */
	uint8_t ct_exponent;
	struct spdm_get_capabilities_flags_format flags;	/**< Capabilities flags */
	uint32_t data_transfer_size;		/**< Maximum buffer size of the device. */
	uint32_t max_spdm_msg_size;			/**< Maximum size for a single SPDM message */
};

/**
 * SPDM algorithms.
 */
struct spdm_device_algorithms {
	uint8_t measurement_spec;			/**< Measurement specification */
	struct spdm_other_params_support other_params_support;	/**< Additional params supported */
	uint32_t measurement_hash_algo;		/**< Measurement hash algorithm. */
	uint32_t base_asym_algo;			/**< Base asymmetric algorithm. */
	uint32_t base_hash_algo;			/**< Base hash algorithm. */
	uint16_t dhe_named_group;			/**< DHE named group. */
	uint16_t aead_cipher_suite;			/**< AEAD cipher suite. */
	uint16_t req_base_asym_alg;			/**< Requested base asymmetric algorithm. */
	uint16_t key_schedule;				/**< Key schedule. */
};

/**
 * SPDM local device algorithms priority tables.
 */
struct spdm_local_device_algorithms_priority_table {
	uint32_t *hash_priority_table;						/**< Hash algorithms priority table. */
	uint32_t *asym_priority_table;						/**< Asymmetric key signature algorithms priority table. */
	uint32_t *req_asym_priority_table;					/**< Requested asymmetric key signature algorithms priority table. */
	uint32_t *dhe_priority_table;						/**< DHE named groups priority table. */
	uint32_t *aead_priority_table;						/**< AEAD cipher suites priority table. */
	uint32_t *key_schedule_priority_table;				/**< Key schedule priority table. */
	uint32_t *measurement_spec_priority_table;			/**< Measurement specification priority table. */
	uint32_t *other_params_support_priority_table;		/**< Other params support priority table. */
	uint8_t hash_priority_table_count;					/**< Number of hash algorithms in priority table. */
	uint8_t asym_priority_table_count;					/**< Number of asymmetric key signature algorithms in priority table. */
	uint8_t req_asym_priority_table_count;				/**< Number of requested asymmetric key signature algorithms in priority table. */
	uint8_t dhe_priority_table_count;					/**< Number of DHE named groups in priority table. */
	uint8_t aead_priority_table_count;					/**< Number of AEAD cipher suites in priority table. */
	uint8_t key_schedule_priority_table_count;			/**< Number of key schedules in priority table. */
	uint8_t measurement_spec_priority_table_count;		/**< Number of measurement specifications in priority table. */
	uint8_t other_params_support_priority_table_count;	/**< Number of other params support in priority table. */
};

/**
 * SPDM local device algorithms and their selection priorities.
 */
struct spdm_local_device_algorithms {
	struct spdm_device_algorithms device_algorithms;								/**< Local device algorithms. */
	struct spdm_local_device_algorithms_priority_table algorithms_priority_table;	/**< Algorithm priority tables. */
};

/**
 * SPDM connection info.
 */
struct spdm_connection_info {
	enum spdm_connection_state connection_state;		/**< State of the SPDM connection. */
	struct spdm_version_number version; 				/**< Negotiated version */
	struct spdm_device_capability peer_capabilities;	/**< Peer capabilities. */
	struct spdm_device_algorithms peer_algorithms;		/**< Negotiated algorithms. */
};

/**
 * Response states of the responder.
 */
enum spdm_response_state {
	SPDM_RESPONSE_STATE_NORMAL,				/**< Normal response. */
	SPDM_RESPONSE_STATE_BUSY,				/**< Other component is busy. */
	SPDM_RESPONSE_STATE_NOT_READY,			/**< Hardware is not ready. */
	SPDM_RESPONSE_STATE_NEED_RESYNC,		/**< Firmware Update is done. Need resync. */
	SPDM_RESPONSE_STATE_PROCESSING_ENCAP,	/**< Processing Encapsulated message. */
	SPDM_RESPONSE_STATE_MAX					/**< MAX */
};

/**
 * SPDM context for a requester/responder.
 */
struct spdm_state {
	uint32_t last_spdm_request_session_id;				/**< Session Id of last secured message. [TODO] This will be moved to the session manager */
	bool last_spdm_request_session_id_valid; 			/**< Session Id validity. [TODO] This will be moved to the session manager */
	struct spdm_connection_info connection_info;		/**< Connection info. */
	enum spdm_response_state response_state; 			/**< Responder response state */
};


int spdm_init_state (struct spdm_state *state);

bool spdm_check_request_flag_compatibility (struct spdm_get_capabilities_flags_format flags,
	uint8_t version);

int spdm_get_command_id (struct cmd_interface_msg *message, uint8_t *command_id);

void spdm_populate_mctp_header (struct spdm_protocol_mctp_header *header);

void spdm_generate_error_response (struct cmd_interface_msg *response, uint8_t spdm_minor_version,
	uint8_t error_code, uint8_t error_data, uint8_t *optional_data, size_t optional_data_len,
	uint8_t req_code, int status);

int spdm_get_version (const struct cmd_interface_spdm_responder *spdm_responder,
	struct cmd_interface_msg *request);
int spdm_generate_get_version_request (uint8_t *buf, size_t buf_len);
int spdm_process_get_version_response (struct cmd_interface_msg *response);

int spdm_get_capabilities (const struct cmd_interface_spdm_responder *spdm_responder,
	struct cmd_interface_msg *request);
int spdm_generate_get_capabilities_request (uint8_t *buf, size_t buf_len,
	uint8_t spdm_minor_version);
int spdm_process_get_capabilities_response (struct cmd_interface_msg *response);

int spdm_negotiate_algorithms (const struct cmd_interface_spdm_responder *spdm_responder,
	struct cmd_interface_msg *request);
int spdm_generate_negotiate_algorithms_request (uint8_t *buf, size_t buf_len,
	uint32_t base_asym_algo, uint32_t base_hash_algo, uint8_t spdm_minor_version);
int spdm_process_negotiate_algorithms_response (struct cmd_interface_msg *response);

int spdm_get_digests (const struct cmd_interface_spdm_responder *spdm_responder,
	struct cmd_interface_msg *request);
int spdm_generate_get_digests_request (uint8_t *buf, size_t buf_len, uint8_t spdm_minor_version);
int spdm_process_get_digests_response (struct cmd_interface_msg *response);

int spdm_generate_get_certificate_request (uint8_t *buf, size_t buf_len, uint8_t slot_num,
	uint16_t offset, uint16_t length, uint8_t spdm_minor_version);
int spdm_process_get_certificate_response (struct cmd_interface_msg *response);

int spdm_generate_challenge_request (uint8_t *buf, size_t buf_len, uint8_t slot_num,
	uint8_t req_measurement_summary_hash_type, uint8_t* nonce, uint8_t spdm_minor_version);
int spdm_process_challenge_response (struct cmd_interface_msg *response);

int spdm_generate_get_measurements_request (uint8_t *buf, size_t buf_len, uint8_t slot_num,
	uint8_t measurement_operation, bool sig_required, bool raw_bitstream_requested, uint8_t* nonce,
	uint8_t spdm_minor_version);
int spdm_process_get_measurements_response (struct cmd_interface_msg *response);

int spdm_generate_respond_if_ready_request (uint8_t *buf, size_t buf_len,
	uint8_t original_request_code, uint8_t token, uint8_t spdm_minor_version);

int spdm_format_signature_digest (struct hash_engine *hash, enum hash_type hash_type,
	uint8_t spdm_minor_version, char *spdm_state, uint8_t *digest);


#endif /* SPDM_COMMANDS_H_ */
