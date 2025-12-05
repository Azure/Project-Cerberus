// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef ATTESTATION_LOGGING_H_
#define ATTESTATION_LOGGING_H_

#include "logging/debug_log.h"


/**
 * Logging messages for attestation operations.
 */
enum {
	ATTESTATION_LOGGING_DEVICE_NOT_INTEROPERABLE,					/**< Target device does not support interoperable protocol specification version. */
	ATTESTATION_LOGGING_GET_CERT_NOT_SUPPORTED,						/**< Target device does not support get certificate command. */
	ATTESTATION_LOGGING_MEASUREMENT_CAP_NOT_SUPPORTED,				/**< Target device does not support measurement response capabilities. */
	ATTESTATION_LOGGING_SLOT_NUMBER_EMPTY,							/**< Requested slot number not occupied by certificate chain on target device. */
	ATTESTATION_LOGGING_UNEXPECTED_SLOT_NUM_IN_RSP,					/**< Requested slot number not utilized by target device in response. */
	ATTESTATION_LOGGING_CERT_CHAIN_DIGEST_MISMATCH,					/**< Certificate chain digest provided by target device in response different than cached. */
	ATTESTATION_LOGGING_TARGET_REQ_UNSUPPORTED_MUTUAL_AUTH,			/**< Target device requested unsupported mutual authentication. */
	ATTESTATION_LOGGING_UNEXPECTED_HASH_LEN_IN_RSP,					/**< Expected hash length not utilized by target device in attestation response. */
	ATTESTATION_LOGGING_UNEXPECTED_HASH_ALGO_IN_RSP,				/**< Expected hash algorithm not utilized by target device in attestation response. */
	ATTESTATION_LOGGING_UNEXPECTED_MEAS_HASH_ALGO_IN_RSP,			/**< Expected measurement hash algorithm not utilized by target device in attestation response. */
	ATTESTATION_LOGGING_CERBERUS_PROTOCOL_VER_UNSUPPORTED,			/**< Attestation target device protocol version not interoperable with device. */
	ATTESTATION_LOGGING_ALIAS_KEY_TYPE_UNSUPPORTED,					/**< Attestation target device sent an alias certificate with an unsupported key type. */
	ATTESTATION_LOGGING_CERT_CHAIN_COMPUTED_DIGEST_MISMATCH,		/**< Target sent a certificate chain which has a different digest than that sent by target. */
	ATTESTATION_LOGGING_UNEXPECTED_RESPONSE_RECEIVED,				/**< Received response unexpected. */
	ATTESTATION_LOGGING_MEASUREMENT_SPEC_UNSUPPORTED,				/**< Target device uses unsupported measurement spec. */
	ATTESTATION_LOGGING_BASE_ASYM_KEY_SIG_ALG_UNSUPPORTED,			/**< Target device uses unsupported asymmetric key signature algorithm. */
	ATTESTATION_LOGGING_HASHING_ALGORITHM_UNSUPPORTED,				/**< Target device uses unsupported hashing algorithm. */
	ATTESTATION_LOGGING_HASHING_MEAS_ALGORITHM_UNSUPPORTED,			/**< Target device uses unsupported measurement hashing algorithm. */
	ATTESTATION_LOGGING_UNEXPECTED_RSP_LEN,							/**< Received response has unexpected length. */
	ATTESTATION_LOGGING_UNEXPECTED_NUM_MEASUREMENT_BLOCKS,			/**< Received measurements response has unexpected number of measurement blocks. */
	ATTESTATION_LOGGING_DEVICE_FAILED_ATTESTATION,					/**< Device failed during attestation flow. */
	ATTESTATION_LOGGING_UNEXPECTED_MEASUREMENT_BLOCK_DIGEST,		/**< Received measurements response has digest of measurement block when raw requested. */
	ATTESTATION_LOGGING_MEASUREMENT_DATA_TOO_LARGE,					/**< Received measurements response too large. */
	ATTESTATION_LOGGING_UNEXPECTED_MEASUREMENT_BLOCK_RAW,			/**< Received measurements response has raw measurement block when digest requested. */
	ATTESTATION_LOGGING_GET_DEVICE_ID_FAILED,						/**< Device failed to send SPDM device ID block. */
	ATTESTATION_LOGGING_ILLEGAL_RSP_NOT_READY,						/**< Received response not ready response for a command that does not permit it. */
	ATTESTATION_LOGGING_UNEXPECTED_RQ_CODE_IN_RSP,					/**< Response not ready for unexpected command received. */
	ATTESTATION_LOGGING_BRIDGE_RESET_TRIGGERED_ROUTING_TABLE_SYNC,	/**< MCTP bridge has triggered a MCTP routing table sync. */
	ATTESTATION_LOGGING_BRIDGE_FAILED_TO_DETECT_MCTP_BRIDGE_RESET,	/**< MCTP bridge reset detection failed. */
	ATTESTATION_LOGGING_ROUTING_TABLE_REFRESH_REQUEST_FAILED,		/**< Failed to request an MCTP routing table refresh. */
	ATTESTATION_LOGGING_CFM_VERSION_SET_SELECTOR_INVALID,			/**< CFM version set selector entry invalid. */
	ATTESTATION_LOGGING_VERSION_SET_SELECTION_FAILED,				/**< Failed to determine device version set using CFM version set selector entry. */
	ATTESTATION_LOGGING_DEVICE_FAILED_DISCOVERY,					/**< Device discovery failed during attestation flow. */
	ATTESTATION_LOGGING_NEXT_DEVICE_DISCOVERY_ERROR,				/**< Failed to find next device for discovery. */
	ATTESTATION_LOGGING_NEXT_DEVICE_ATTESTATION_ERROR,				/**< Failed to find next device for attestation. */
	ATTESTATION_LOGGING_PCR_UPDATE_ERROR,							/**< Error while updating a PCR entry. */
	ATTESTATION_LOGGING_GET_ATTESTATION_STATUS_ERROR,				/**< Failed to get attestation status. */
	ATTESTATION_LOGGING_GET_MCTP_ROUTING_TABLE_ERROR,				/**< Failed to get MCTP routing table. */
	ATTESTATION_LOGGING_GET_MEASUREMENT_CAP_MISMATCH_ERROR,			/**< Target device support mismatched measurement response capabilities. */
	ATTESTATION_LOGGING_CHALLENGE_CAP_MISMATCH_ERROR,				/**< Target device support mismatched challenge response capabilities. */
	ATTESTATION_LOGGING_DEVICE_FIRST_ATTESTATION,					/**< Target device EID is attested for the first time. */
	ATTESTATION_LOGGING_MEASUREMENT_VERIFICATION_FAILED,			/**< Target device measurement verification failed. */
	ATTESTATION_LOGGING_MEASUREMENT_HASH_TYPE_NOT_ALLOWED,			/**< Target device measurement hash type is not allowed for attestation. */
	ATTESTATION_LOGGING_MEASUREMENT_RULE_FAILED,					/**< Target device measurement failed attestation rule check. */
	ATTESTATION_LOGGING_MEASUREMENT_BITMASK_TOO_SMALL,				/**< CFM defined bitmask is too small for the runtime measurement. */
	ATTESTATION_LOGGING_CFM_MULTIPLE_DATA_PER_VERSION_SET,			/**< CFM has multiple allowable data entries for a single version set where only one is permitted. */
	ATTESTATION_LOGGING_DEVICE_DISCOVERY_COMPLETE,					/**< Device discovery completed successfully. */
	ATTESTATION_LOGGING_EID_DISCOVERED,								/**< Target device EID is discovered. */
	ATTESTATION_LOGGING_PROCESS_PENDING_ACTION_ERROR,				/**< Failed to process pending action in device manager. */
};


#endif	/* ATTESTATION_LOGGING_H_ */
