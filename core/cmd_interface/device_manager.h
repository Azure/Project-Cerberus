// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef DEVICE_MANAGER_
#define DEVICE_MANAGER_

#include <stdint.h>
#include "attestation/attestation.h"
#include "common/certificate.h"
#include "crypto/ecc.h"
#include "crypto/hash.h"
#include "crypto/rsa.h"
#include "status/rot_status.h"


// Reserved device manager table entry numbers
#define DEVICE_MANAGER_SELF_DEVICE_NUM							0
#define DEVICE_MANAGER_MCTP_BRIDGE_DEVICE_NUM					1

// Index indicating component not in PCD
#define DEVICE_MANAGER_NOT_PCD_COMPONENT						0xFF

// Maximum key length
#define DEVICE_MANAGER_MAX_KEY_LEN								RSA_MAX_KEY_LENGTH

// Attestation cadences
#define DEVICE_MANAGER_UNAUTHENTICATED_CADENCE_MS				30000
#define DEVICE_MANAGER_AUTHENTICATED_CADENCE_MS					3600000
#define DEVICE_MANAGER_UNIDENTIFIED_TIMEOUT_CADENCE_MS			30000

/**
 * Convert response timeout in milliseconds to timeout in 10ms multiples
 *
 * @param timeout Timeout value in milliseconds
 */
#define device_manager_set_timeout_ms(timeout)					((timeout) / 10)

/**
 * Convert crypto response timeout in milliseconds to timeout in 100ms multiples
 *
 * @param timeout Timeout value in milliseconds
 */
#define device_manager_set_crypto_timeout_ms(timeout)			((timeout) / 100)

/**
 * Determine if device is ready to be attested
 *
 * @param state Device state
 */
#define device_manager_can_device_be_attested(state)			\
	((state != DEVICE_MANAGER_NOT_ATTESTABLE) || (state == DEVICE_MANAGER_UNIDENTIFIED))


/**
 * Device states
 */
enum device_manager_device_state {
	DEVICE_MANAGER_AUTHENTICATED = 0,							/**< Authenticated state */
	DEVICE_MANAGER_UNIDENTIFIED,								/**< Communication with device not established */
	DEVICE_MANAGER_NEVER_ATTESTED,								/**< Device ready for attestation start, but never attested before */
	DEVICE_MANAGER_READY_FOR_ATTESTATION,						/**< Device ready for attestation start */
	DEVICE_MANAGER_NOT_ATTESTABLE,								/**< Not an attestable device */
	NUM_DEVICE_MANAGER_STATES									/**< Number of device states */
};

/**
 * Device hierarchy roles as defined in the Cerberus protocol.
 */
enum {
	DEVICE_MANAGER_AC_ROT_MODE = 0,								/**< Device acting as AC-RoT */
	DEVICE_MANAGER_PA_ROT_MODE,									/**< Device acting as PA-RoT */
	NUM_BUS_HIERACHY_ROLES										/**< Number of hierarchy roles */
};

/**
 * Roles a device supports on the I2C bus as defined in the Cerberus protocol.
 */
enum {
	DEVICE_MANAGER_UNKNOWN_BUS_ROLE = 0,						/**< Unknown bus role */
	DEVICE_MANAGER_MASTER_BUS_ROLE,								/**< Device acting as bus master */
	DEVICE_MANAGER_SLAVE_BUS_ROLE,								/**< Device acting as bus slave */
	DEVICE_MANAGER_MASTER_AND_SLAVE_BUS_ROLE,					/**< Device acting as both master and slave on bus */
	NUM_BUS_ROLES												/**< Number of bus roles */
};

/**
 * Channel security capabilities of the device as defined in the Cerberus protocol.
 */
enum {
	DEVICE_MANAGER_SECURITY_NONE = 0,							/**< No channel security. */
	DEVICE_MANAGER_SECURITY_HASH_KDF = 1,						/**< Channel supports using hash/KDF. */
	DEVICE_MANAGER_SECURITY_AUTHENTICATION = 2,					/**< Channel support certificate authentication. */
	DEVICE_MANAGER_SECURITY_CONFIDENTIALITY = 4					/**< Channel support AES encryption. */
};

/**
 * Supported ECC key strength as defined in the Cerberus protocol.
 */
enum {
	DEVICE_MANAGER_ECC_KEY_NONE = 0,							/**< No ECC key support. */
	DEVICE_MANAGER_ECC_KEY_160 = 1,								/**< Supports ECC-160. */
	DEVICE_MANAGER_ECC_KEY_256 = 2,								/**< Supports ECC-256. */
	DEVICE_MANAGER_ECC_KEY_RESERVED = 4							/**< Unused. */
};

/**
 * Supported RSA key strength as defined in the Cerberus protocol.
 */
enum {
	DEVICE_MAANGER_RSA_KEY_NONE = 0,							/**< No RSA key support. */
	DEVICE_MANAGER_RSA_KEY_2048 = 1,							/**< Supports RSA-2048. */
	DEVICE_MANAGER_RSA_KEY_3072 = 2,							/**< Supports RSA-3072. */
	DEVICE_MANAGER_RSA_KEY_4096 = 4								/**< Supports RSA-4096. */
};

/**
 * Supported AES key strength as defined in the Cerberus protocol.
 */
enum {
	DEVICE_MANAGER_AES_KEY_NONE = 0,							/**< No AES key support. */
	DEVICE_MANAGER_AES_KEY_128 = 1,								/**< Supports AES-128. */
	DEVICE_MANAGER_AES_KEY_256 = 2,								/**< Supports AES-256. */
	DEVICE_MANAGER_AES_KEY_384 = 4								/**< Supports AES-384. */
};

#pragma pack(push, 1)
/**
 * Container for a device's capabilities.  This matches the Cerberus protocol request format.
 */
struct device_manager_capabilities {
	uint16_t max_message_size;									/**< Maximum message payload the device can accept */
	uint16_t max_packet_size;									/**< Maximum packet payload the device can accept */
	uint8_t security_mode:3;									/**< Security mode */
	uint8_t reserved1:1;										/**< Reserved */
	uint8_t bus_role:2;											/**< Master/Slave role enabled */
	uint8_t hierarchy_role:2;									/**< AC-RoT or PA-RoT */
	uint8_t reserved2:5;										/**< Reserved */
	uint8_t fw_protection:1;									/**< FW protection enabled */
	uint8_t policy_support:1;									/**< Policy support enabled */
	uint8_t pfm_support:1;										/**< PFM support enabled */
	uint8_t rsa_key_strength:3;									/**< RSA key strength */
	uint8_t ecc_key_strength:3;									/**< ECC key strength */
	uint8_t ecdsa:1;											/**< ECDSA capable */
	uint8_t rsa:1;												/**< RSA capable */
	uint8_t aes_enc_key_strength:3;								/**< AES encryption key strength */
	uint8_t reserved3:4;										/**< Reserved */
	uint8_t ecc:1;												/**< ECC encryption capable */
};

/**
 * Container for all of a device's capabilities.  This matches the Cerberus protocol response
 * format.
 */
struct device_manager_full_capabilities {
	struct device_manager_capabilities request;					/**< Capabilities request information. */
	uint8_t max_timeout;										/**< Maximum timeout in 10ms multiples. */
	uint8_t max_sig;											/**< Maximum cryptographic response delay in 100ms multiples. */
};
#pragma pack(pop)

/**
 * Container holding public key
 */
struct device_manager_key {
	uint8_t key[DEVICE_MANAGER_MAX_KEY_LEN];					/**< Buffer with public key */
	size_t key_len;												/**< Length of key in buffer */
	int key_type;												/**< Key type */
};

/**
 * Entry type in a device manager table
 */
struct device_manager_entry {
	struct device_manager_full_capabilities capabilities;		/**< Device capabilities */
	struct device_manager_key alias_key;						/**< Container with device alias key */
	platform_clock attestation_timeout;							/**< Clock tracking when device should be attested */
	uint8_t component_type[SHA256_HASH_LENGTH];					/**< Digest of component type key in PCD and CFM */
	uint8_t cert_chain_digest[HASH_MAX_HASH_LEN];				/**< Device certificate chain digest */
	enum device_manager_device_state state;						/**< Device state */
	size_t hash_len;											/**< Length of certificate chain hash */
	uint16_t pci_vid;											/**< PCI Vendor ID */
	uint16_t pci_device_id;										/**< PCI Device ID */
	uint16_t pci_subsystem_vid;									/**< PCI Subsystem Vendor ID */
	uint16_t pci_subsystem_id;									/**< PCI Subsystem ID */
	uint8_t slot_num;											/**< Device certificate chain slot number */
	uint8_t smbus_addr;											/**< SMBUS address */
	uint8_t eid;												/**< Endpoint ID */
	uint8_t pcd_component_index;								/**< Index of component in PCD */
};

/**
 * Entry type in an unidentified device manager linked list
 */
struct device_manager_unidentified_entry {
	platform_clock discovery_timeout;							/**< Clocking tracking when device should be discovered */
	bool timeout;												/**< Flag indicating if last discovery timed out */
	uint8_t eid;												/**< Endpoint ID */
	struct device_manager_unidentified_entry *next;				/**< Next entry in circular linked list */
};

/**
 * Module which holds a table of all devices Cerberus expects to communicate with and itself, to be
 * populated from PCD
 */
struct device_manager {
	struct device_manager_entry *entries;						/**< Device table entries. */
	uint8_t *attestation_status;								/**< Dynamically allocated buffer to hold attestation status of all attestable devices. */
	uint8_t num_devices;										/**< Number of device table entries. */
	uint8_t num_requester_devices; 								/**< Number of requester device table entries. */
	uint8_t num_responder_devices; 								/**< Number of responder device table entries. */
	uint8_t last_device_authenticated;							/**< Device number of last device authenticated. */
	uint32_t unauthenticated_cadence_ms; 						/**< Period to wait before reauthenticating unauthenticated device. */
 	uint32_t authenticated_cadence_ms; 							/**< Period to wait before reauthenticating authenticated device. */
 	uint32_t unidentified_timeout_ms;							/**< Timeout period to wait before reidentifying unidentified device. */
	bool attestable_components_list_invalid;					/**< Flag indicating we failed to correctly load components from PCD. */
#ifdef ATTESTATION_SUPPORT_DEVICE_DISCOVERY
	struct device_manager_unidentified_entry *unidentified;		/**< Unidentified device circular linked list. */
#endif
};


int device_manager_init (struct device_manager *mgr, int num_requester_devices,
	int num_responder_devices, uint8_t hierarchy, uint8_t bus_role,
	uint32_t unauthenticated_cadence_ms, uint32_t authenticated_cadence_ms,
	uint32_t unidentified_timeout_ms);
void device_manager_release (struct device_manager *mgr);

int device_manager_get_device_num (struct device_manager *mgr, uint8_t eid);
int device_manager_get_device_addr (struct device_manager *mgr, int device_num);
int device_manager_get_device_addr_by_eid (struct device_manager *mgr, uint8_t eid);
int device_manager_get_device_eid (struct device_manager *mgr, int device_num);
int device_manager_update_device_eid (struct device_manager *mgr, int device_num, uint8_t eid);
int device_manager_update_not_attestable_device_entry (struct device_manager *mgr, int device_num,
	uint8_t eid, uint8_t smbus_addr, uint8_t pcd_component_index);
int device_manager_update_mctp_bridge_device_entry (struct device_manager *mgr, int device_num,
	uint16_t pci_vid, uint16_t pci_device_id, uint16_t pci_subsystem_vid, uint16_t pci_subsystem_id,
	uint8_t components_count, uint8_t *component_type, uint8_t pcd_component_index);

int device_manager_get_device_capabilities (struct device_manager *mgr, int device_num,
	struct device_manager_full_capabilities *capabilities);
int device_manager_update_device_capabilities (struct device_manager *mgr, int device_num,
	struct device_manager_full_capabilities *capabilities);

int device_manager_get_device_capabilities_request (struct device_manager *mgr,
	struct device_manager_capabilities *capabilites);
int device_manager_update_device_capabilities_request (struct device_manager *mgr, int device_num,
	struct device_manager_capabilities *capabilities);

size_t device_manager_get_max_message_len (struct device_manager *mgr, int device_num);
size_t device_manager_get_max_message_len_by_eid (struct device_manager *mgr, uint8_t eid);

size_t device_manager_get_max_transmission_unit (struct device_manager *mgr, int device_num);
size_t device_manager_get_max_transmission_unit_by_eid (struct device_manager *mgr, uint8_t eid);

uint32_t device_manager_get_reponse_timeout (struct device_manager *mgr, int device_num);
uint32_t device_manager_get_reponse_timeout_by_eid (struct device_manager *mgr, uint8_t eid);

uint32_t device_manager_get_crypto_timeout (struct device_manager *mgr, int device_num);
uint32_t device_manager_get_crypto_timeout_by_eid (struct device_manager *mgr, uint8_t eid);

int device_manager_update_cert_chain_digest (struct device_manager *mgr, uint8_t eid,
	uint8_t slot_num, const uint8_t *buf, size_t buf_len);
int device_manager_compare_cert_chain_digest (struct device_manager *mgr, uint8_t eid,
	uint8_t *digest, size_t digest_len);

int device_manager_update_alias_key (struct device_manager *mgr, uint8_t eid, const uint8_t *key,
	size_t key_len, int key_type);
const struct device_manager_key* device_manager_get_alias_key (struct device_manager *mgr,
	uint8_t eid);

int device_manager_get_device_state (struct device_manager *mgr, int device_num);
int device_manager_get_device_state_by_eid (struct device_manager *mgr, uint8_t eid);

int device_manager_update_device_state (struct device_manager *mgr, int device_num,
	enum device_manager_device_state state);
int device_manager_update_device_state_by_eid (struct device_manager *mgr, uint8_t eid,
	enum device_manager_device_state state);

int device_manager_get_eid_of_next_device_to_attest (struct device_manager *mgr);
int device_manager_reset_authenticated_devices (struct device_manager *mgr);
int device_manager_reset_discovered_devices (struct device_manager *mgr);

const uint8_t* device_manager_get_component_type_digest (struct device_manager *mgr, uint8_t eid);

int device_manager_get_device_num_by_device_ids (struct device_manager *mgr, uint16_t pci_vid,
	uint16_t pci_device_id, uint16_t pci_subsystem_vid, uint16_t pci_subsystem_id);
int device_manager_update_device_ids (struct device_manager *mgr, int device_num, uint16_t pci_vid,
	uint16_t pci_device_id, uint16_t pci_subsystem_vid, uint16_t pci_subsystem_id);

#ifdef ATTESTATION_SUPPORT_DEVICE_DISCOVERY
void device_manager_clear_unidentified_devices (struct device_manager *mgr);
int device_manager_add_unidentified_device (struct device_manager *mgr, uint8_t eid);
int device_manager_remove_unidentified_device (struct device_manager *mgr, uint8_t eid);
int device_manager_unidentified_device_timed_out (struct device_manager *mgr, uint8_t eid);
int device_manager_get_eid_of_next_device_to_discover (struct device_manager *mgr);
#endif

uint32_t device_manager_get_time_till_next_action (struct device_manager *mgr);
int device_manager_get_attestation_status (struct device_manager *mgr,
	const uint8_t **attestation_status);

int device_manager_mark_component_attestation_invalid (struct device_manager *mgr);

bool device_manager_is_device_unattestable (struct device_manager *mgr, uint8_t eid);


#define	DEVICE_MGR_ERROR(code)		ROT_ERROR (ROT_MODULE_DEVICE_MANAGER, code)

/**
 * Error codes that can be generated by the device manager.
 */
enum {
	DEVICE_MGR_INVALID_ARGUMENT = DEVICE_MGR_ERROR (0x00),		/**< Input parameter is null or not valid. */
	DEVICE_MGR_NO_MEMORY = DEVICE_MGR_ERROR (0x01),				/**< Memory allocation failed. */
	DEVICE_MGR_UNKNOWN_DEVICE = DEVICE_MGR_ERROR (0x02),		/**< Invalid device number. */
	DEVICE_MGR_INVALID_CERT_NUM = DEVICE_MGR_ERROR (0x03),		/**< Invalid certificate number. */
	DEVICE_MGR_BUF_TOO_SMALL = DEVICE_MGR_ERROR (0x04),			/**< Provided buffer too small for output. */
	DEVICE_MGR_INPUT_TOO_LARGE = DEVICE_MGR_ERROR (0x05),		/**< Provided data larger than storage buffer. */
	DEVICE_MGR_DIGEST_LEN_MISMATCH = DEVICE_MGR_ERROR (0x06),	/**< Provided digest not same length as cached digest. */
	DEVICE_MGR_DIGEST_MISMATCH = DEVICE_MGR_ERROR (0x07),		/**< Provided digest not same as cached digest. */
	DEVICE_MGR_NO_DEVICES_AVAILABLE = DEVICE_MGR_ERROR (0x08),	/**< No devices ready for attestation. */
	DEVICE_MGR_DIGEST_NOT_UNIQUE = DEVICE_MGR_ERROR (0x09),		/**< Certificate chain digest not unique. */
};


#endif // DEVICE_MANAGER_
