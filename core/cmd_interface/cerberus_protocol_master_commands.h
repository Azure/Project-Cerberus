// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef CERBERUS_PROTOCOL_MASTER_COMMANDS_H_
#define CERBERUS_PROTOCOL_MASTER_COMMANDS_H_

#include <stdint.h>
#include <stdbool.h>
#include "attestation/pcr_store.h"
#include "crypto/hash.h"
#include "manifest/cfm/cfm_manager.h"
#include "manifest/pcd/pcd_manager.h"
#include "manifest/manifest_cmd_interface.h"
#include "attestation/attestation_master.h"
#include "cmd_authorization.h"
#include "cmd_background.h"
#include "cmd_interface.h"
#include "cmd_device.h"


/**
 * Escape sequence to intitiate transaction with slave device instead of responding to system.
 */
#define ATTESTATION_START_TEST_ESCAPE_SEQ 	0xBBCC


/**
 * Parameters needed to construct a get certificate request.
 */
struct cerberus_protocol_cert_req_params {
	uint8_t slot_num;								/**< Certificate chain slot num */
	uint8_t cert_num;								/**< Certificate index in chain */
};

/**
 * Parameters needed to construct a challenge request.
 */
struct cerberus_protocol_challenge_req_params {
	uint8_t slot_num;								/**< Certificate chain slot num */
	uint8_t eid;									/**< Certificate index in chain */
};


int cerberus_protocol_issue_get_certificate_digest (struct attestation_master *attestation,
	uint8_t *buf, size_t buf_len);
int cerberus_protocol_issue_get_certificate (struct cerberus_protocol_cert_req_params *params,
	uint8_t *buf, size_t buf_len);
int cerberus_protocol_issue_challenge (struct attestation_master *attestation,
	struct cerberus_protocol_challenge_req_params *params, uint8_t *buf, size_t buf_len);

int cerberus_protocol_manifest_update_init (
	struct manifest_cmd_interface *manifest_interface, struct cmd_interface_request *request,
	int offset, int default_status);
int cerberus_protocol_manifest_update (struct manifest_cmd_interface *manifest_interface,
	struct cmd_interface_request *request, int offset, int default_status);
int cerberus_protocol_manifest_update_complete (
	struct manifest_cmd_interface *manifest_interface, struct cmd_interface_request *request,
	int offset, int default_status, bool delayed_activation_allowed);
int cerberus_protocol_get_manifest_update_status (
	struct manifest_cmd_interface *manifest_interface, struct cmd_interface_request *request,
	int default_status);

int cerberus_protocol_get_cfm_id (struct cfm_manager *cfm_mgr,
	struct cmd_interface_request *request);
int cerberus_protocol_get_cfm_component_ids (struct cfm_manager *cfm_mgr,
	struct cmd_interface_request *request);

int cerberus_protocol_get_device_certificate (struct device_manager *device_mgr,
	struct cmd_interface_request *request);
int cerberus_protocol_get_device_cert_digest (struct device_manager *device_mgr,
	struct hash_engine *hash, struct cmd_interface_request *request);
int cerberus_protocol_get_device_challenge (struct device_manager *device_mgr,
	struct attestation_master *attestation, struct hash_engine *hash,
	struct cmd_interface_request *request);
int cerberus_protocol_start_attestation (struct cmd_interface_request *request);
int cerberus_protocol_get_attestation_state (struct device_manager *device_mgr,
	struct cmd_interface_request *request);

int cerberus_protocol_process_certificate_digest (struct attestation_master *attestation,
	struct cmd_interface_request *request);
int cerberus_protocol_process_certificate (struct attestation_master *attestation,
	struct cmd_interface_request *request);
int cerberus_protocol_process_challenge_response (struct attestation_master *attestation,
	struct cmd_interface_request *request);

int cerberus_protocol_get_pcd_id (struct pcd_manager *pcd_mgr,
	struct cmd_interface_request *request);


#endif // CERBERUS_PROTOCOL_MASTER_COMMANDS_H_
