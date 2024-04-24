// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <string.h>
#include "testing.h"
#include "cmd_interface/cmd_interface.h"
#include "pcisig/tdisp/cmd_interface_tdisp_responder_static.h"
#include "pcisig/tdisp/tdisp_driver.h"
#include "pcisig/tdisp/tdisp_commands.h"
#include "testing/mock/pcisig/tdisp/tdisp_driver_mock.h"
#include "common/array_size.h"
#include "pcisig/doe/doe_base_protocol.h"
#include "testing/mock/crypto/rng_mock.h"


TEST_SUITE_LABEL ("tdisp_commands");


#define TDISP_SUPPORTED_VERSION_MAX_COUNT		3

/**
 * Dependencies for testing.
 */
struct tdisp_commands_testing {
	struct tdisp_driver_interface_mock tdisp_driver_mock;	/**< TDISP driver mock. */
	uint8_t version_num[TDISP_SUPPORTED_VERSION_MAX_COUNT];	/**< Version number entries. */
	struct tdisp_state tdisp_state;							/**< TDISP state. */
	struct rng_engine_mock rng_mock;						/**< Mock RNG engine. */
};

/**
 * Helper to initialize all dependencies for testing.
 *
 * @param test The test framework.
 * @param testing Testing dependencies to initialize.
 */
static void tdisp_commands_testing_init_dependencies (CuTest *test,
	struct tdisp_commands_testing *testing)
{
	int status;
	uint8_t version_num[TDISP_SUPPORTED_VERSION_MAX_COUNT] = { TDISP_VERSION_1_0, 0xAA, 0xBB };

	memcpy (testing->version_num, version_num, sizeof (version_num));

	status = tdisp_driver_interface_mock_init (&testing->tdisp_driver_mock);
	CuAssertIntEquals (test, 0, status);

	status = rng_mock_init (&testing->rng_mock);
	CuAssertIntEquals (test, 0, status);

	status = tdisp_init_state (&testing->tdisp_state);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Helper to release all dependencies for testing.
 *
 * @param test The test framework.
 * @param testing Testing dependencies to release.
 */
static void tdisp_commands_testing_release_dependencies (CuTest *test,
	struct tdisp_commands_testing *testing)
{
	int status;

	status = tdisp_driver_interface_mock_validate_and_release (&testing->tdisp_driver_mock);
	CuAssertIntEquals (test, 0, status);

	status = rng_mock_validate_and_release (&testing->rng_mock);
	CuAssertIntEquals (test, 0, status);
}

/*******************
 * Test cases
 *******************/


static void tdisp_commands_test_header_format (CuTest *test)
{
	uint8_t raw_buffer[] = {
		0xAA, /* version */
		0xBB, /* message_type */
		0xCC, /* reserved[0] */
		0xDD, /* reserved[1] */
		0xEF, 0xBE, 0xAD, 0xDE,
		0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0
	};
	struct tdisp_header *tdisp_header = (struct tdisp_header*) raw_buffer;

	TEST_START;

	CuAssertIntEquals (test, sizeof (raw_buffer), sizeof (struct tdisp_header));

	CuAssertIntEquals (test, 0xAA, tdisp_header->version);
	CuAssertIntEquals (test, 0xBB, tdisp_header->message_type);
	CuAssertIntEquals (test, 0xCC, tdisp_header->reserved[0]);
	CuAssertIntEquals (test, 0xDD, tdisp_header->reserved[1]);
	CuAssertIntEquals (test, 0xDEADBEEF, tdisp_header->interface_id.function_id);
	CuAssertInt64Equals (test, 0xF0DEBC9A78563412, tdisp_header->interface_id.reserved);
}

static void tdisp_commands_test_get_version_request_format (CuTest *test)
{
	uint8_t raw_buffer[] = {
		0xAA, /* version */
		0xBB, /* message_type */
		0xCC, /* reserved[0] */
		0xDD, /* reserved[1] */
		0xEF, 0xBE, 0xAD, 0xDE,
		0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0
	};
	struct tdisp_get_version_request *get_version_rq =
		(struct tdisp_get_version_request*) raw_buffer;

	TEST_START;

	CuAssertIntEquals (test, sizeof (raw_buffer), sizeof (struct tdisp_get_version_request));

	CuAssertIntEquals (test, 0xAA, get_version_rq->header.version);
	CuAssertIntEquals (test, 0xBB, get_version_rq->header.message_type);
	CuAssertIntEquals (test, 0xCC, get_version_rq->header.reserved[0]);
	CuAssertIntEquals (test, 0xDD, get_version_rq->header.reserved[1]);
	CuAssertIntEquals (test, 0xDEADBEEF, get_version_rq->header.interface_id.function_id);
	CuAssertInt64Equals (test, 0xF0DEBC9A78563412, get_version_rq->header.interface_id.reserved);
}

static void tdisp_commands_test_get_version_response_format (CuTest *test)
{
	uint8_t raw_buffer[] = {
		0xAA, /* version */
		0xBB, /* message_type */
		0xCC, /* reserved[0] */
		0xDD, /* reserved[1] */
		0xEF, 0xBE, 0xAD, 0xDE,
		0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0,
		0xAA
	};
	struct tdisp_version_response *get_version_resp = (struct tdisp_version_response*) raw_buffer;

	TEST_START;

	CuAssertIntEquals (test, sizeof (raw_buffer), sizeof (struct tdisp_version_response));

	CuAssertIntEquals (test, 0xAA, get_version_resp->header.version);
	CuAssertIntEquals (test, 0xBB, get_version_resp->header.message_type);
	CuAssertIntEquals (test, 0xCC, get_version_resp->header.reserved[0]);
	CuAssertIntEquals (test, 0xDD, get_version_resp->header.reserved[1]);
	CuAssertIntEquals (test, 0xDEADBEEF, get_version_resp->header.interface_id.function_id);
	CuAssertInt64Equals (test, 0xF0DEBC9A78563412, get_version_resp->header.interface_id.reserved);
	CuAssertIntEquals (test, 0xAA, get_version_resp->version_num_count);
}

static void tdisp_commands_test_get_capabilities_request_format (CuTest *test)
{
	uint8_t raw_buffer[] = {
		0xAA, /* version */
		0xBB, /* message_type */
		0xCC, /* reserved[0] */
		0xDD, /* reserved[1] */
		0xEF, 0xBE, 0xAD, 0xDE, /* function_id */
		0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, /* reserved */
		0xCA, 0xFE, 0xB0, 0xBA /* tsm_caps */
	};
	struct tdisp_get_capabilities_request *capabilities_request =
		(struct tdisp_get_capabilities_request*) raw_buffer;

	TEST_START;

	CuAssertIntEquals (test, sizeof (raw_buffer), sizeof (struct tdisp_get_capabilities_request));

	CuAssertIntEquals (test, 0xAA, capabilities_request->header.version);
	CuAssertIntEquals (test, 0xBB, capabilities_request->header.message_type);
	CuAssertIntEquals (test, 0xCC, capabilities_request->header.reserved[0]);
	CuAssertIntEquals (test, 0xDD, capabilities_request->header.reserved[1]);
	CuAssertIntEquals (test, 0xDEADBEEF,
		capabilities_request->header.interface_id.function_id);
	CuAssertInt64Equals (test, 0xF0DEBC9A78563412,
		capabilities_request->header.interface_id.reserved);

	CuAssertIntEquals (test, 0xBAB0FECA, capabilities_request->req_caps.tsm_caps);
}

static void tdisp_commands_test_get_capabilities_response_format (CuTest *test)
{
	uint8_t raw_buffer[] = {
		0x56, /* version */
		0x49, /* message_type */
		0x53, /* reserved[0] */
		0x48, /* reserved[1] */
		0x41, 0x4C, 0x20, 0x41, /* function_id */
		0x53, 0x48, 0x4F, 0x4B, 0x20, 0x41, 0x41, 0x52, /* reserved */
		0x54, 0x49, 0x20, 0x4D, /* dsm_caps */
		0x48, 0x41, 0x54, 0x52, 0x45, 0x76, 0x69, 0x73, /* req_msg_supported[16] */
		0x68, 0x61, 0x6C, 0x20, 0x61, 0x73, 0x68, 0x6F,
		0x6B, 0x20, /* lock_interface_flags_supported */
		0x61, 0x63, 0x72, /* reserved[3] */
		0x74, /* dev_addr_width */
		0x69, /* num_req_this */
		0x20, /* num_req_all */
	};
	struct tdisp_capabilities_response *capabilities_response =
		(struct tdisp_capabilities_response*) raw_buffer;

	TEST_START;

	CuAssertIntEquals (test, sizeof (raw_buffer), sizeof (struct tdisp_capabilities_response));

	CuAssertIntEquals (test, 0x56, capabilities_response->header.version);
	CuAssertIntEquals (test, 0x49, capabilities_response->header.message_type);
	CuAssertIntEquals (test, 0x53, capabilities_response->header.reserved[0]);
	CuAssertIntEquals (test, 0x48, capabilities_response->header.reserved[1]);
	CuAssertIntEquals (test, 0x41204C41, capabilities_response->header.interface_id.function_id);
	CuAssertInt64Equals (test, 0x524141204B4F4853,
		capabilities_response->header.interface_id.reserved);
	CuAssertIntEquals (test, 0x4D204954, capabilities_response->rsp_caps.dsm_caps);
	CuAssertInt64Equals (test, 0x7369764552544148,
		*((uint64_t*) capabilities_response->rsp_caps.req_msg_supported));
	CuAssertInt64Equals (test, 0x6F687361206C6168,
		*((uint64_t*)(&capabilities_response->rsp_caps.req_msg_supported[8])));
	CuAssertIntEquals (test, 0x206B,
		capabilities_response->rsp_caps.lock_interface_flags_supported);
	CuAssertIntEquals (test, 0x61, capabilities_response->rsp_caps.reserved[0]);
	CuAssertIntEquals (test, 0x63, capabilities_response->rsp_caps.reserved[1]);
	CuAssertIntEquals (test, 0x72, capabilities_response->rsp_caps.reserved[2]);
	CuAssertIntEquals (test, 0x74, capabilities_response->rsp_caps.dev_addr_width);
	CuAssertIntEquals (test, 0x69, capabilities_response->rsp_caps.num_req_this);
	CuAssertIntEquals (test, 0x20, capabilities_response->rsp_caps.num_req_all);
}

static void tdisp_commands_test_tdisp_lock_interface_request_format (CuTest *test)
{
	uint8_t raw_buffer[] = {
		0xCE, /* version */
		0xDF, /* message_type */
		0xA1, /* reserved[0] */
		0x8B, /* reserved[1] */
		0x42, 0xED, 0x21, 0x31, /* function_id */
		0x23, 0x48, 0x3F, 0x4C, 0x21, 0x51, 0x41, 0x53, /* reserved */
		0xAB, 0xCD, /* flags */
		0xFE, /* default_stream_id */
		0x12, /* reserved */
		0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x57, 0x6F, 0x72, /* mmio_reporting_offset */
		0x53, 0x75, 0x70, 0x65, 0x72, 0x6D, 0x61, 0x6E /* bind_p2p_address_mask */
	};

	struct tdisp_lock_interface_request *lock_interface_request =
		(struct tdisp_lock_interface_request*) raw_buffer;

	TEST_START;

	CuAssertIntEquals (test, sizeof (raw_buffer), sizeof (struct tdisp_lock_interface_request));

	CuAssertIntEquals (test, 0xCE, lock_interface_request->header.version);
	CuAssertIntEquals (test, 0xDF, lock_interface_request->header.message_type);
	CuAssertIntEquals (test, 0xA1, lock_interface_request->header.reserved[0]);
	CuAssertIntEquals (test, 0x8B, lock_interface_request->header.reserved[1]);
	CuAssertIntEquals (test, 0x3121ED42, lock_interface_request->header.interface_id.function_id);
	CuAssertInt64Equals (test, 0x534151214C3F4823,
		lock_interface_request->header.interface_id.reserved);

	CuAssertIntEquals (test, 0xCDAB, lock_interface_request->lock_interface_param.flags.value);
	CuAssertIntEquals (test, 1, lock_interface_request->lock_interface_param.flags.no_fw_update);
	CuAssertIntEquals (test, 1,
		lock_interface_request->lock_interface_param.flags.system_cache_line_size);
	CuAssertIntEquals (test, 0, lock_interface_request->lock_interface_param.flags.lock_msix);
	CuAssertIntEquals (test, 1, lock_interface_request->lock_interface_param.flags.bind_p2p);
	CuAssertIntEquals (test, 0,
		lock_interface_request->lock_interface_param.flags.all_request_redirect);
	CuAssertIntEquals (test, 0x66D, lock_interface_request->lock_interface_param.flags.reserved);

	raw_buffer[16] = 0x54;
	raw_buffer[17] = 0x32;
	CuAssertIntEquals (test, 0x3254, lock_interface_request->lock_interface_param.flags.value);
	CuAssertIntEquals (test, 0, lock_interface_request->lock_interface_param.flags.no_fw_update);
	CuAssertIntEquals (test, 0,
		lock_interface_request->lock_interface_param.flags.system_cache_line_size);
	CuAssertIntEquals (test, 1, lock_interface_request->lock_interface_param.flags.lock_msix);
	CuAssertIntEquals (test, 0, lock_interface_request->lock_interface_param.flags.bind_p2p);
	CuAssertIntEquals (test, 1,
		lock_interface_request->lock_interface_param.flags.all_request_redirect);
	CuAssertIntEquals (test, 0x192, lock_interface_request->lock_interface_param.flags.reserved);

	CuAssertIntEquals (test, 0xFE, lock_interface_request->lock_interface_param.default_stream_id);
	CuAssertIntEquals (test, 0x12, lock_interface_request->lock_interface_param.reserved);
	CuAssertInt64Equals (test, 0x726F576F6C6C6548,
		lock_interface_request->lock_interface_param.mmio_reporting_offset);
	CuAssertInt64Equals (test, 0x6E616D7265707553,
		lock_interface_request->lock_interface_param.bind_p2p_address_mask);
}

static void tdisp_commands_test_tdisp_lock_interface_response_format (CuTest *test)
{
	uint8_t raw_buffer[] = {
		0x1D, /* version */
		0x1F, /* message_type */
		0x1E, /* reserved[0] */
		0x1B, /* reserved[1] */
		0x4F, 0xEE, 0x22, 0x32, /* function_id */
		0x24, 0x39, 0x40, 0x4C, 0x22, 0x52, 0x41, 0x53, /* reserved */
		0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, /* start_interface_nonce */
		0x39, 0x31, 0x30, 0x31, 0x31, 0x31, 0x32, 0x31,
		0x33, 0x31, 0x34, 0x31, 0x35, 0x31, 0x36, 0x31,
		0x37, 0x31, 0x38, 0x31, 0x39, 0x32, 0x30, 0x32
	};

	struct tdisp_lock_interface_response *lock_interface_response =
		(struct tdisp_lock_interface_response*) raw_buffer;

	TEST_START;

	CuAssertIntEquals (test, sizeof (raw_buffer), sizeof (struct tdisp_lock_interface_response));

	CuAssertIntEquals (test, 0x1D, lock_interface_response->header.version);
	CuAssertIntEquals (test, 0x1F, lock_interface_response->header.message_type);
	CuAssertIntEquals (test, 0x1E, lock_interface_response->header.reserved[0]);
	CuAssertIntEquals (test, 0x1B, lock_interface_response->header.reserved[1]);
	CuAssertIntEquals (test, 0x3222EE4F, lock_interface_response->header.interface_id.function_id);
	CuAssertInt64Equals (test, 0x534152224C403924,
		lock_interface_response->header.interface_id.reserved);

	CuAssertInt64Equals (test, 0x3837363534333231,
		*((uint64_t*) lock_interface_response->start_interface_nonce));

	CuAssertInt64Equals (test, 0x3132313131303139,
		*((uint64_t*)(&lock_interface_response->start_interface_nonce[8])));

	CuAssertInt64Equals (test, 0x3136313531343133,
		*((uint64_t*)(&lock_interface_response->start_interface_nonce[16])));

	CuAssertInt64Equals (test, 0x3230323931383137,
		*((uint64_t*)(&lock_interface_response->start_interface_nonce[24])));
}

static void tdisp_commands_test_get_device_interface_report_request_format (CuTest *test)
{
	uint8_t raw_buffer[] = {
		0x2D, /* version */
		0x2F, /* message_type */
		0x2E, /* reserved[0] */
		0x2B, /* reserved[1] */
		0x50, 0xEF, 0x23, 0x33, /* function_id */
		0x25, 0x40, 0x41, 0x4D, 0x23, 0x53, 0x42, 0x54, /* reserved */
		0x21, 0x34, /* offset */
		0x45, 0xFE /* length */
	};

	struct tdisp_get_device_interface_report_request *get_device_interface_report_request =
		(struct tdisp_get_device_interface_report_request*) raw_buffer;

	TEST_START;

	CuAssertIntEquals (test, sizeof (raw_buffer),
		sizeof (struct tdisp_get_device_interface_report_request));

	CuAssertIntEquals (test, 0x2D, get_device_interface_report_request->header.version);
	CuAssertIntEquals (test, 0x2F, get_device_interface_report_request->header.message_type);
	CuAssertIntEquals (test, 0x2E, get_device_interface_report_request->header.reserved[0]);
	CuAssertIntEquals (test, 0x2B, get_device_interface_report_request->header.reserved[1]);
	CuAssertIntEquals (test, 0x3323EF50,
		get_device_interface_report_request->header.interface_id.function_id);
	CuAssertInt64Equals (test, 0x544253234D414025,
		get_device_interface_report_request->header.interface_id.reserved);
	CuAssertIntEquals (test, 0x3421, get_device_interface_report_request->offset);
	CuAssertIntEquals (test, 0xFE45, get_device_interface_report_request->length);
}

static void tdisp_commands_test_get_device_interface_report_response_format (CuTest *test)
{
	uint8_t raw_buffer[] = {
		0x3D, /* version */
		0x3F, /* message_type */
		0x3E, /* reserved[0] */
		0x3B, /* reserved[1] */
		0x51, 0xD0, 0x24, 0x34, /* function_id */
		0x26, 0x41, 0x42, 0x4E, 0x24, 0x54, 0x43, 0x55, /* reserved */
		0x22, 0x35, /* portion_length */
		0x46, 0xFF /* remainder_length */
	};

	struct tdisp_device_interface_report_response *device_interface_report_response =
		(struct tdisp_device_interface_report_response*) raw_buffer;

	TEST_START;

	CuAssertIntEquals (test, sizeof (raw_buffer),
		sizeof (struct tdisp_device_interface_report_response));

	CuAssertIntEquals (test, 0x3D, device_interface_report_response->header.version);
	CuAssertIntEquals (test, 0x3F, device_interface_report_response->header.message_type);
	CuAssertIntEquals (test, 0x3E, device_interface_report_response->header.reserved[0]);
	CuAssertIntEquals (test, 0x3B, device_interface_report_response->header.reserved[1]);
	CuAssertIntEquals (test, 0x3424D051,
		device_interface_report_response->header.interface_id.function_id);
	CuAssertInt64Equals (test, 0x554354244E424126,
		device_interface_report_response->header.interface_id.reserved);
	CuAssertIntEquals (test, 0x3522, device_interface_report_response->portion_length);
	CuAssertIntEquals (test, 0xFF46, device_interface_report_response->remainder_length);
}

static void tdisp_commands_test_mmio_range_format (CuTest *test)
{
	uint8_t raw_buffer[] = {
		0x47, 0x6F, 0x6F, 0x64, 0x62, 0x79, 0x65, 0x73, /* first_page */
		0x4B, 0x49, 0x54, 0x45, /* number_of_pages */
		0x0A, 0x34, 0x2E, 0x98 /* mmio_range_attributes */
	};

	struct tdisp_mmio_range *mmio_range = (struct tdisp_mmio_range*) raw_buffer;

	TEST_START;

	CuAssertIntEquals (test, sizeof (raw_buffer), sizeof (struct tdisp_mmio_range));

	CuAssertInt64Equals (test, 0x73657962646F6F47, mmio_range->first_page);
	CuAssertIntEquals (test, 0x4554494B, mmio_range->number_of_pages);

	CuAssertIntEquals (test, 0, mmio_range->range_attributes.msi_x_table);
	CuAssertIntEquals (test, 1, mmio_range->range_attributes.msi_x_pba);
	CuAssertIntEquals (test, 0, mmio_range->range_attributes.is_non_tee_mem);
	CuAssertIntEquals (test, 1, mmio_range->range_attributes.is_mem_attr_updatable);
	CuAssertIntEquals (test, 0x340, mmio_range->range_attributes.reserved);
	CuAssertIntEquals (test, 0x982E, mmio_range->range_attributes.range_id);

	raw_buffer[12] = 0xF5;
	raw_buffer[13] = 0xCB;
	raw_buffer[14] = 0xD1;
	raw_buffer[15] = 0x67;
	CuAssertIntEquals (test, 1, mmio_range->range_attributes.msi_x_table);
	CuAssertIntEquals (test, 0, mmio_range->range_attributes.msi_x_pba);
	CuAssertIntEquals (test, 1, mmio_range->range_attributes.is_non_tee_mem);
	CuAssertIntEquals (test, 0, mmio_range->range_attributes.is_mem_attr_updatable);
	CuAssertIntEquals (test, 0xCBF, mmio_range->range_attributes.reserved);
	CuAssertIntEquals (test, 0x67D1, mmio_range->range_attributes.range_id);
}

static void tdisp_commands_test_device_interface_report_format (CuTest *test)
{
	uint8_t raw_buffer[] = {
		0x15, 0xFF, /* interface_info */
		0xAB, 0xCD, /* reserved */
		0x12, 0x34, /* msi_x_message_control */
		0x56, 0x78, /* lnr_control */
		0xDE, 0xAD, 0xBE, 0xEF, /* tph_control */
		0xBA, 0xAD, 0xF0, 0x0D, /* mmio_range_count */
	};

	struct tdisp_device_interface_report *device_interface_report =
		(struct tdisp_device_interface_report*) raw_buffer;

	TEST_START;

	CuAssertIntEquals (test, sizeof (raw_buffer), sizeof (struct tdisp_device_interface_report));

	CuAssertIntEquals (test, 1, device_interface_report->interface_info.no_fw_update);
	CuAssertIntEquals (test, 0, device_interface_report->interface_info.dma_requests_without_pasid);
	CuAssertIntEquals (test, 1, device_interface_report->interface_info.dma_requests_with_pasid);
	CuAssertIntEquals (test, 0, device_interface_report->interface_info.ats_supported);
	CuAssertIntEquals (test, 1, device_interface_report->interface_info.prs_supported);
	CuAssertIntEquals (test, 0x7F8, device_interface_report->interface_info.reserved);

	raw_buffer[0] = 0xEA;
	raw_buffer[1] = 0x00;
	CuAssertIntEquals (test, 0, device_interface_report->interface_info.no_fw_update);
	CuAssertIntEquals (test, 1, device_interface_report->interface_info.dma_requests_without_pasid);
	CuAssertIntEquals (test, 0, device_interface_report->interface_info.dma_requests_with_pasid);
	CuAssertIntEquals (test, 1, device_interface_report->interface_info.ats_supported);
	CuAssertIntEquals (test, 0, device_interface_report->interface_info.prs_supported);
	CuAssertIntEquals (test, 0x7, device_interface_report->interface_info.reserved);

	CuAssertIntEquals (test, 0xCDAB, device_interface_report->reserved);
	CuAssertIntEquals (test, 0x3412, device_interface_report->msi_x_message_control);
	CuAssertIntEquals (test, 0x7856, device_interface_report->lnr_control);
	CuAssertIntEquals (test, 0xEFBEADDE, device_interface_report->tph_control);
	CuAssertIntEquals (test, 0x0DF0ADBA, device_interface_report->mmio_range_count);
}

static void tdisp_commands_test_get_device_interface_state_request_format (CuTest *test)
{
	uint8_t raw_buffer[] = {
		0x3D, /* version */
		0x3F, /* message_type */
		0x3E, /* reserved[0] */
		0x3B, /* reserved[1] */
		0x51, 0xEF, 0x23, 0x34, /* function_id */
		0x25, 0x41, 0x41, 0x4D, 0x23, 0x53, 0x43, 0x54, /* reserved */
	};

	struct tdisp_get_device_interface_state_request *get_device_interface_state_request =
		(struct tdisp_get_device_interface_state_request*) raw_buffer;

	TEST_START;

	CuAssertIntEquals (test, sizeof (raw_buffer),
		sizeof (struct tdisp_get_device_interface_state_request));

	CuAssertIntEquals (test, 0x3D, get_device_interface_state_request->header.version);
	CuAssertIntEquals (test, 0x3F, get_device_interface_state_request->header.message_type);
	CuAssertIntEquals (test, 0x3E, get_device_interface_state_request->header.reserved[0]);
	CuAssertIntEquals (test, 0x3B, get_device_interface_state_request->header.reserved[1]);
	CuAssertIntEquals (test, 0x3423EF51,
		get_device_interface_state_request->header.interface_id.function_id);
	CuAssertInt64Equals (test, 0x544353234D414125,
		get_device_interface_state_request->header.interface_id.reserved);
}

static void tdisp_commands_test_get_device_interface_state_response_format (CuTest *test)
{
	uint8_t raw_buffer[] = {
		0x4D, /* version */
		0x4F, /* message_type */
		0x4E, /* reserved[0] */
		0x4B, /* reserved[1] */
		0x51, 0xEF, 0x25, 0x35, /* function_id */
		0x25, 0x42, 0x43, 0x4D, 0x23, 0x53, 0x43, 0x54, /* reserved */
		0xAD, /* tdi_state */
	};

	struct tdisp_device_interface_state_response *get_device_interface_state_response =
		(struct tdisp_device_interface_state_response*) raw_buffer;

	TEST_START;

	CuAssertIntEquals (test, sizeof (raw_buffer),
		sizeof (struct tdisp_device_interface_state_response));

	CuAssertIntEquals (test, 0x4D, get_device_interface_state_response->header.version);
	CuAssertIntEquals (test, 0x4F, get_device_interface_state_response->header.message_type);
	CuAssertIntEquals (test, 0x4E, get_device_interface_state_response->header.reserved[0]);
	CuAssertIntEquals (test, 0x4B, get_device_interface_state_response->header.reserved[1]);
	CuAssertIntEquals (test, 0x3525EF51,
		get_device_interface_state_response->header.interface_id.function_id);
	CuAssertInt64Equals (test, 0x544353234D434225,
		get_device_interface_state_response->header.interface_id.reserved);
	CuAssertIntEquals (test, 0xAD, get_device_interface_state_response->tdi_state);
}

static void tdisp_commands_test_tdisp_start_interface_request_format (CuTest *test)
{
	uint8_t raw_buffer[] = {
		0x1D, /* version */
		0x1F, /* message_type */
		0x1E, /* reserved[0] */
		0x1B, /* reserved[1] */
		0x4F, 0xEE, 0x22, 0x32, /* function_id */
		0x24, 0x39, 0x40, 0x4C, 0x22, 0x52, 0x41, 0x53, /* reserved */
		0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, /* start_interface_nonce */
		0x39, 0x31, 0x30, 0x31, 0x31, 0x31, 0x32, 0x31,
		0x33, 0x31, 0x34, 0x31, 0x35, 0x31, 0x36, 0x31,
		0x37, 0x31, 0x38, 0x31, 0x39, 0x32, 0x30, 0x32
	};

	struct tdisp_start_interface_request *start_interface_request =
		(struct tdisp_start_interface_request*) raw_buffer;

	TEST_START;

	CuAssertIntEquals (test, sizeof (raw_buffer), sizeof (struct tdisp_start_interface_request));

	CuAssertIntEquals (test, 0x1D, start_interface_request->header.version);
	CuAssertIntEquals (test, 0x1F, start_interface_request->header.message_type);
	CuAssertIntEquals (test, 0x1E, start_interface_request->header.reserved[0]);
	CuAssertIntEquals (test, 0x1B, start_interface_request->header.reserved[1]);
	CuAssertIntEquals (test, 0x3222EE4F, start_interface_request->header.interface_id.function_id);
	CuAssertInt64Equals (test, 0x534152224C403924,
		start_interface_request->header.interface_id.reserved);

	CuAssertInt64Equals (test, 0x3837363534333231,
		*((uint64_t*) start_interface_request->start_interface_nonce));

	CuAssertInt64Equals (test, 0x3132313131303139,
		*((uint64_t*)(&start_interface_request->start_interface_nonce[8])));

	CuAssertInt64Equals (test, 0x3136313531343133,
		*((uint64_t*)(&start_interface_request->start_interface_nonce[16])));

	CuAssertInt64Equals (test, 0x3230323931383137,
		*((uint64_t*)(&start_interface_request->start_interface_nonce[24])));
}

static void tdisp_commands_test_tdisp_start_interface_response_format (CuTest *test)
{
	uint8_t raw_buffer[] = {
		0x1D, /* version */
		0x1F, /* message_type */
		0x1E, /* reserved[0] */
		0x1B, /* reserved[1] */
		0x4E, 0xCE, 0x42, 0x92, /* function_id */
		0x24, 0x49, 0x82, 0x4F, 0x22, 0x52, 0x41, 0x84, /* reserved */
	};

	struct tdisp_start_interface_response *start_interface_response =
		(struct tdisp_start_interface_response*) raw_buffer;

	TEST_START;

	CuAssertIntEquals (test, sizeof (raw_buffer), sizeof (struct tdisp_start_interface_response));

	CuAssertIntEquals (test, 0x1D, start_interface_response->header.version);
	CuAssertIntEquals (test, 0x1F, start_interface_response->header.message_type);
	CuAssertIntEquals (test, 0x1E, start_interface_response->header.reserved[0]);
	CuAssertIntEquals (test, 0x1B, start_interface_response->header.reserved[1]);
	CuAssertIntEquals (test, 0x9242CE4E, start_interface_response->header.interface_id.function_id);
	CuAssertInt64Equals (test, 0x844152224F824924,
		start_interface_response->header.interface_id.reserved);
}


static void tdisp_commands_test_tdisp_stop_interface_request_format (CuTest *test)
{
	uint8_t raw_buffer[] = {
		0x6D, /* version */
		0x6F, /* message_type */
		0x6E, /* reserved[0] */
		0x6B, /* reserved[1] */
		0x4E, 0xFE, 0x42, 0x82, /* function_id */
		0x24, 0x39, 0x42, 0x4F, 0x22, 0x52, 0x41, 0x84, /* reserved */
	};

	struct tdisp_stop_interface_request *stop_interface_request =
		(struct tdisp_stop_interface_request*) raw_buffer;

	TEST_START;

	CuAssertIntEquals (test, sizeof (raw_buffer), sizeof (struct tdisp_stop_interface_request));

	CuAssertIntEquals (test, 0x6D, stop_interface_request->header.version);
	CuAssertIntEquals (test, 0x6F, stop_interface_request->header.message_type);
	CuAssertIntEquals (test, 0x6E, stop_interface_request->header.reserved[0]);
	CuAssertIntEquals (test, 0x6B, stop_interface_request->header.reserved[1]);
	CuAssertIntEquals (test, 0x8242FE4E, stop_interface_request->header.interface_id.function_id);
	CuAssertInt64Equals (test, 0x844152224F423924,
		stop_interface_request->header.interface_id.reserved);
}

static void tdisp_commands_test_tdisp_stop_interface_response_format (CuTest *test)
{
	uint8_t raw_buffer[] = {
		0x2D, /* version */
		0x2F, /* message_type */
		0x2E, /* reserved[0] */
		0x2B, /* reserved[1] */
		0x4E, 0xEE, 0x42, 0x32, /* function_id */
		0x24, 0x39, 0x42, 0x4C, 0x22, 0x52, 0x41, 0x54, /* reserved */
	};

	struct tdisp_stop_interface_response *stop_interface_response =
		(struct tdisp_stop_interface_response*) raw_buffer;

	TEST_START;

	CuAssertIntEquals (test, sizeof (raw_buffer), sizeof (struct tdisp_stop_interface_response));

	CuAssertIntEquals (test, 0x2D, stop_interface_response->header.version);
	CuAssertIntEquals (test, 0x2F, stop_interface_response->header.message_type);
	CuAssertIntEquals (test, 0x2E, stop_interface_response->header.reserved[0]);
	CuAssertIntEquals (test, 0x2B, stop_interface_response->header.reserved[1]);
	CuAssertIntEquals (test, 0x3242EE4E, stop_interface_response->header.interface_id.function_id);
	CuAssertInt64Equals (test, 0x544152224C423924,
		stop_interface_response->header.interface_id.reserved);
}

static void tdisp_commands_test_tdisp_error_response_format (CuTest *test)
{
	uint8_t raw_buffer[] = {
		0x3D, /* version */
		0x3F, /* message_type */
		0x3E, /* reserved[0] */
		0x3B, /* reserved[1] */
		0x4D, 0xEE, 0x72, 0x32, /* function_id */
		0x24, 0x39, 0x42, 0x4C, 0x28, 0x52, 0x40, 0x54, /* reserved */
		0x31, 0x32, 0x33, 0x34, /* error_code */
		0x35, 0x36, 0x37, 0x38, /* error_data */
	};

	struct tdisp_error_response *erro_response =
		(struct tdisp_error_response*) raw_buffer;

	TEST_START;

	CuAssertIntEquals (test, sizeof (raw_buffer), sizeof (struct tdisp_error_response));

	CuAssertIntEquals (test, 0x3D, erro_response->header.version);
	CuAssertIntEquals (test, 0x3F, erro_response->header.message_type);
	CuAssertIntEquals (test, 0x3E, erro_response->header.reserved[0]);
	CuAssertIntEquals (test, 0x3B, erro_response->header.reserved[1]);
	CuAssertIntEquals (test, 0x3272EE4D, erro_response->header.interface_id.function_id);
	CuAssertInt64Equals (test, 0x544052284C423924,
		erro_response->header.interface_id.reserved);
	CuAssertIntEquals (test, 0x34333231, erro_response->error_code);
	CuAssertIntEquals (test, 0x38373635, erro_response->error_data);
}

static void tdisp_commands_test_tdisp_extended_error_data_format (CuTest *test)
{
	uint8_t raw_buffer[] = {
		0xDE, /* registry_id */
		0xAD, /* vendor_id_len */
	};

	struct tdisp_extended_error_data *extended_error_data =
		(struct tdisp_extended_error_data*) raw_buffer;

	TEST_START;

	CuAssertIntEquals (test, sizeof (raw_buffer), sizeof (struct tdisp_extended_error_data));

	CuAssertIntEquals (test, 0xDE, extended_error_data->registry_id);
	CuAssertIntEquals (test, 0xAD, extended_error_data->vendor_id_len);
}

static void tdisp_commands_test_get_version (CuTest *test)
{
	uint8_t buf[DOE_MESSAGE_MAX_SIZE_IN_BYTES];
	struct tdisp_get_version_request *rq = (struct tdisp_get_version_request*) buf;
	struct tdisp_version_response *resp = (struct tdisp_version_response*) buf;
	struct cmd_interface_msg msg;
	int status;
	struct tdisp_commands_testing testing;

	TEST_START;

	tdisp_commands_testing_init_dependencies (test, &testing);

	memset (&msg, 0, sizeof (msg));
	msg.data = buf;
	msg.payload = buf;
	msg.max_response = sizeof (buf);
	msg.payload_length = sizeof (struct tdisp_get_version_request);
	msg.length = msg.payload_length;

	rq->header.version = TDISP_CURRENT_VERSION;
	rq->header.message_type = TDISP_REQUEST_GET_VERSION;
	rq->header.interface_id.function_id = 0;

	status = tdisp_get_version (&testing.tdisp_state, testing.version_num,
		ARRAY_SIZE (testing.version_num), &msg);

	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, sizeof (struct tdisp_version_response) +
		ARRAY_SIZE (testing.version_num), msg.length);
	CuAssertIntEquals (test, msg.length, msg.payload_length);
	CuAssertPtrEquals (test, buf, msg.data);
	CuAssertPtrEquals (test, resp, msg.payload);
	CuAssertIntEquals (test, TDISP_CURRENT_VERSION, resp->header.version);
	CuAssertIntEquals (test, TDISP_RESPONSE_GET_VERSION, resp->header.message_type);
	CuAssertIntEquals (test, 0, resp->header.interface_id.function_id);
	CuAssertIntEquals (test, ARRAY_SIZE (testing.version_num), resp->version_num_count);
	CuAssertIntEquals (test, 1, testing.tdisp_state.interface_context_count);
	CuAssertIntEquals (test, 0, memcmp (resp + 1, testing.version_num,
		sizeof (testing.version_num)));

	tdisp_commands_testing_release_dependencies (test, &testing);
}

static void tdisp_commands_test_get_version_multiple_query (CuTest *test)
{
	uint8_t buf[DOE_MESSAGE_MAX_SIZE_IN_BYTES];
	struct tdisp_get_version_request *rq = (struct tdisp_get_version_request*) buf;
	struct tdisp_version_response *resp = (struct tdisp_version_response*) buf;
	struct cmd_interface_msg msg;
	int status;
	struct tdisp_commands_testing testing;

	TEST_START;

	tdisp_commands_testing_init_dependencies (test, &testing);

	memset (&msg, 0, sizeof (msg));
	msg.data = buf;
	msg.payload = buf;
	msg.max_response = sizeof (buf);
	msg.payload_length = sizeof (struct tdisp_get_version_request);
	msg.length = msg.payload_length;

	rq->header.version = TDISP_CURRENT_VERSION;
	rq->header.message_type = TDISP_REQUEST_GET_VERSION;
	rq->header.interface_id.function_id = 0;

	status = tdisp_get_version (&testing.tdisp_state, testing.version_num,
		ARRAY_SIZE (testing.version_num), &msg);

	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, sizeof (struct tdisp_version_response) +
		ARRAY_SIZE (testing.version_num), msg.length);
	CuAssertIntEquals (test, msg.length, msg.payload_length);
	CuAssertPtrEquals (test, buf, msg.data);
	CuAssertPtrEquals (test, resp, msg.payload);
	CuAssertIntEquals (test, TDISP_CURRENT_VERSION, resp->header.version);
	CuAssertIntEquals (test, TDISP_RESPONSE_GET_VERSION, resp->header.message_type);
	CuAssertIntEquals (test, 0, resp->header.interface_id.function_id);
	CuAssertIntEquals (test, ARRAY_SIZE (testing.version_num), resp->version_num_count);
	CuAssertIntEquals (test, 0, memcmp (resp + 1, testing.version_num,
		sizeof (testing.version_num)));

	memset (&msg, 0, sizeof (msg));
	msg.data = buf;
	msg.payload = buf;
	msg.max_response = sizeof (buf);
	msg.payload_length = sizeof (struct tdisp_get_version_request);
	msg.length = msg.payload_length;

	rq->header.version = TDISP_CURRENT_VERSION;
	rq->header.message_type = TDISP_REQUEST_GET_VERSION;
	rq->header.interface_id.function_id = 0;

	status = tdisp_get_version (&testing.tdisp_state, testing.version_num,
		ARRAY_SIZE (testing.version_num), &msg);

	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, sizeof (struct tdisp_version_response) + sizeof (testing.version_num),
		msg.length);
	CuAssertIntEquals (test, msg.length, msg.payload_length);
	CuAssertPtrEquals (test, buf, msg.data);
	CuAssertPtrEquals (test, resp, msg.payload);
	CuAssertIntEquals (test, TDISP_CURRENT_VERSION, resp->header.version);
	CuAssertIntEquals (test, TDISP_RESPONSE_GET_VERSION, resp->header.message_type);
	CuAssertIntEquals (test, 0, resp->header.interface_id.function_id);
	CuAssertIntEquals (test, ARRAY_SIZE (testing.version_num), resp->version_num_count);
	CuAssertIntEquals (test, 0, memcmp (resp + 1, testing.version_num,
		sizeof (testing.version_num)));

	tdisp_commands_testing_release_dependencies (test, &testing);
}

static void tdisp_commands_test_get_version_max_interface_count (CuTest *test)
{
	uint8_t buf[DOE_MESSAGE_MAX_SIZE_IN_BYTES];
	struct tdisp_get_version_request *rq = (struct tdisp_get_version_request*) buf;
	struct tdisp_version_response *resp = (struct tdisp_version_response*) buf;
	struct cmd_interface_msg msg;
	int status;
	struct tdisp_commands_testing testing;
	uint8_t i;

	TEST_START;

	tdisp_commands_testing_init_dependencies (test, &testing);

	for (i = 0; i < TDISP_INTERFACE_MAX_COUNT; i++) {
		memset (&msg, 0, sizeof (msg));
		msg.data = buf;
		msg.payload = buf;
		msg.max_response = sizeof (buf);
		msg.payload_length = sizeof (struct tdisp_get_version_request);
		msg.length = msg.payload_length;

		rq->header.version = TDISP_CURRENT_VERSION;
		rq->header.message_type = TDISP_REQUEST_GET_VERSION;
		rq->header.interface_id.function_id = i;

		status = tdisp_get_version (&testing.tdisp_state, testing.version_num,
			ARRAY_SIZE (testing.version_num), &msg);

		CuAssertIntEquals (test, 0, status);
		CuAssertIntEquals (test, sizeof (struct tdisp_version_response) +
			ARRAY_SIZE (testing.version_num), msg.length);
		CuAssertIntEquals (test, msg.length, msg.payload_length);
		CuAssertPtrEquals (test, buf, msg.data);
		CuAssertPtrEquals (test, resp, msg.payload);
		CuAssertIntEquals (test, TDISP_CURRENT_VERSION, resp->header.version);
		CuAssertIntEquals (test, TDISP_RESPONSE_GET_VERSION, resp->header.message_type);
		CuAssertIntEquals (test, i, resp->header.interface_id.function_id);
		CuAssertIntEquals (test, ARRAY_SIZE (testing.version_num), resp->version_num_count);
		CuAssertIntEquals (test, i + 1, testing.tdisp_state.interface_context_count);
		CuAssertIntEquals (test, 0, memcmp (resp + 1, testing.version_num,
			sizeof (testing.version_num)));
	}

	tdisp_commands_testing_release_dependencies (test, &testing);
}

static void tdisp_commands_test_get_version_invalid_params (CuTest *test)
{
	int status;
	struct tdisp_commands_testing testing;
	struct cmd_interface_msg request;

	TEST_START;

	tdisp_commands_testing_init_dependencies (test, &testing);

	status = tdisp_get_version (NULL, testing.version_num, ARRAY_SIZE (testing.version_num),
		&request);
	CuAssertIntEquals (test, CMD_INTERFACE_TDISP_RESPONDER_INVALID_ARGUMENT, status);

	status = tdisp_get_version (&testing.tdisp_state, NULL, ARRAY_SIZE (testing.version_num),
		&request);
	CuAssertIntEquals (test, CMD_INTERFACE_TDISP_RESPONDER_INVALID_ARGUMENT, status);

	status = tdisp_get_version (&testing.tdisp_state, testing.version_num, 0, &request);
	CuAssertIntEquals (test, CMD_INTERFACE_TDISP_RESPONDER_INVALID_ARGUMENT, status);

	status = tdisp_get_version (&testing.tdisp_state, testing.version_num,
		ARRAY_SIZE (testing.version_num), NULL);
	CuAssertIntEquals (test, CMD_INTERFACE_TDISP_RESPONDER_INVALID_ARGUMENT, status);

	tdisp_commands_testing_release_dependencies (test, &testing);
}

static void tdisp_commands_test_get_version_request_lt_min_length (CuTest *test)
{
	uint8_t buf[DOE_MESSAGE_MAX_SIZE_IN_BYTES];
	struct tdisp_get_version_request *rq = (struct tdisp_get_version_request*) buf;
	struct tdisp_error_response *error_response = (struct tdisp_error_response*) buf;
	struct cmd_interface_msg msg;
	int status;
	struct tdisp_commands_testing testing;

	TEST_START;

	tdisp_commands_testing_init_dependencies (test, &testing);

	memset (&msg, 0, sizeof (msg));
	msg.data = buf;
	msg.payload = buf;
	msg.max_response = sizeof (buf);
	msg.payload_length = sizeof (struct tdisp_get_version_request) - 1;
	msg.length = msg.payload_length;

	rq->header.version = TDISP_CURRENT_VERSION;
	rq->header.message_type = TDISP_REQUEST_GET_VERSION;
	rq->header.interface_id.function_id = 0;

	status = tdisp_get_version (&testing.tdisp_state, testing.version_num,
		ARRAY_SIZE (testing.version_num), &msg);

	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, sizeof (struct tdisp_error_response), msg.length);
	CuAssertIntEquals (test, msg.length, msg.payload_length);
	CuAssertPtrEquals (test, buf, msg.data);
	CuAssertPtrEquals (test, error_response, msg.payload);
	CuAssertIntEquals (test, TDISP_VERSION_1_0, error_response->header.version);
	CuAssertIntEquals (test, TDISP_ERROR_CODE_INVALID_REQUEST, error_response->error_code);
	CuAssertIntEquals (test, 0, error_response->error_data);
	CuAssertIntEquals (test, TDISP_ERROR, error_response->header.message_type);

	tdisp_commands_testing_release_dependencies (test, &testing);
}

static void tdisp_commands_test_get_version_invalid_version (CuTest *test)
{
	uint8_t buf[DOE_MESSAGE_MAX_SIZE_IN_BYTES];
	struct tdisp_get_version_request *rq = (struct tdisp_get_version_request*) buf;
	struct tdisp_error_response *error_response = (struct tdisp_error_response*) buf;
	struct cmd_interface_msg msg;
	int status;
	struct tdisp_commands_testing testing;

	TEST_START;

	tdisp_commands_testing_init_dependencies (test, &testing);

	memset (&msg, 0, sizeof (msg));
	msg.data = buf;
	msg.payload = buf;
	msg.max_response = sizeof (buf);
	msg.payload_length = sizeof (struct tdisp_get_version_request);
	msg.length = msg.payload_length;

	rq->header.version = UINT8_MAX;
	rq->header.message_type = TDISP_REQUEST_GET_VERSION;
	rq->header.interface_id.function_id = 0;

	status = tdisp_get_version (&testing.tdisp_state, testing.version_num,
		ARRAY_SIZE (testing.version_num), &msg);

	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, sizeof (struct tdisp_error_response), msg.length);
	CuAssertIntEquals (test, msg.length, msg.payload_length);
	CuAssertPtrEquals (test, buf, msg.data);
	CuAssertPtrEquals (test, error_response, msg.payload);
	CuAssertIntEquals (test, TDISP_VERSION_1_0, error_response->header.version);
	CuAssertIntEquals (test, TDISP_ERROR_CODE_VERSION_MISMATCH, error_response->error_code);
	CuAssertIntEquals (test, 0, error_response->error_data);
	CuAssertIntEquals (test, TDISP_ERROR, error_response->header.message_type);

	tdisp_commands_testing_release_dependencies (test, &testing);
}

static void tdisp_commands_test_get_version_insufficient_output_buffer (CuTest *test)
{
	uint8_t buf[DOE_MESSAGE_MAX_SIZE_IN_BYTES];
	struct tdisp_get_version_request *rq = (struct tdisp_get_version_request*) buf;
	struct tdisp_error_response *error_response = (struct tdisp_error_response*) buf;
	struct cmd_interface_msg msg;
	int status;
	struct tdisp_commands_testing testing;

	TEST_START;

	tdisp_commands_testing_init_dependencies (test, &testing);

	memset (&msg, 0, sizeof (msg));
	msg.data = buf;
	msg.payload = buf;
	msg.max_response = sizeof (buf);
	msg.payload_length = sizeof (struct tdisp_get_version_request);
	msg.length = msg.payload_length;
	msg.max_response = ARRAY_SIZE (testing.version_num) * sizeof (uint8_t) +
		sizeof (struct tdisp_version_response) - 1;

	rq->header.version = TDISP_CURRENT_VERSION;
	rq->header.message_type = TDISP_REQUEST_GET_VERSION;

	status = tdisp_get_version (&testing.tdisp_state, testing.version_num,
		ARRAY_SIZE (testing.version_num), &msg);

	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, sizeof (struct tdisp_error_response), msg.length);
	CuAssertIntEquals (test, msg.length, msg.payload_length);
	CuAssertPtrEquals (test, buf, msg.data);
	CuAssertPtrEquals (test, error_response, msg.payload);
	CuAssertIntEquals (test, TDISP_VERSION_1_0, error_response->header.version);
	CuAssertIntEquals (test, TDISP_ERROR_CODE_UNSPECIFIED, error_response->error_code);
	CuAssertIntEquals (test, 0, error_response->error_data);
	CuAssertIntEquals (test, TDISP_ERROR, error_response->header.message_type);

	tdisp_commands_testing_release_dependencies (test, &testing);
}

static void tdisp_commands_test_get_version_no_interface_context (CuTest *test)
{
	uint8_t buf[DOE_MESSAGE_MAX_SIZE_IN_BYTES];
	struct tdisp_get_version_request *rq = (struct tdisp_get_version_request*) buf;
	struct tdisp_error_response *error_response = (struct tdisp_error_response*) buf;
	struct cmd_interface_msg msg;
	int status;
	struct tdisp_commands_testing testing;
	uint8_t i;

	TEST_START;

	tdisp_commands_testing_init_dependencies (test, &testing);

	for (i = 0; i < TDISP_INTERFACE_MAX_COUNT; i++) {
		memset (&msg, 0, sizeof (msg));
		msg.data = buf;
		msg.payload = buf;
		msg.max_response = sizeof (buf);
		msg.payload_length = sizeof (struct tdisp_get_version_request);
		msg.length = msg.payload_length;

		rq->header.version = TDISP_CURRENT_VERSION;
		rq->header.message_type = TDISP_REQUEST_GET_VERSION;
		rq->header.interface_id.function_id = i;

		status = tdisp_get_version (&testing.tdisp_state, testing.version_num,
			ARRAY_SIZE (testing.version_num), &msg);

		CuAssertIntEquals (test, 0, status);
	}

	memset (&msg, 0, sizeof (msg));
	msg.data = buf;
	msg.payload = buf;
	msg.max_response = sizeof (buf);
	msg.payload_length = sizeof (struct tdisp_get_version_request);
	msg.length = msg.payload_length;

	rq->header.version = TDISP_CURRENT_VERSION;
	rq->header.message_type = TDISP_REQUEST_GET_VERSION;
	rq->header.interface_id.function_id = i;

	status = tdisp_get_version (&testing.tdisp_state, testing.version_num,
		ARRAY_SIZE (testing.version_num), &msg);

	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, sizeof (struct tdisp_error_response), msg.length);
	CuAssertIntEquals (test, msg.length, msg.payload_length);
	CuAssertPtrEquals (test, buf, msg.data);
	CuAssertPtrEquals (test, error_response, msg.payload);
	CuAssertIntEquals (test, TDISP_VERSION_1_0, error_response->header.version);
	CuAssertIntEquals (test, TDISP_ERROR_CODE_INVALID_INTERFACE, error_response->error_code);
	CuAssertIntEquals (test, 0, error_response->error_data);
	CuAssertIntEquals (test, TDISP_ERROR, error_response->header.message_type);

	tdisp_commands_testing_release_dependencies (test, &testing);
}

static void tdisp_commands_test_get_version_out_of_interface_context (CuTest *test)
{
	uint8_t buf[DOE_MESSAGE_MAX_SIZE_IN_BYTES];
	struct tdisp_get_version_request *rq = (struct tdisp_get_version_request*) buf;
	struct tdisp_error_response *error_response = (struct tdisp_error_response*) buf;
	struct cmd_interface_msg msg;
	int status;
	struct tdisp_commands_testing testing;

	TEST_START;

	tdisp_commands_testing_init_dependencies (test, &testing);

	memset (&msg, 0, sizeof (msg));
	msg.data = buf;
	msg.payload = buf;
	msg.max_response = sizeof (buf);
	msg.payload_length = sizeof (struct tdisp_get_version_request);
	msg.length = msg.payload_length;

	rq->header.version = TDISP_CURRENT_VERSION;
	rq->header.message_type = TDISP_REQUEST_GET_VERSION;
	rq->header.interface_id.function_id = 0;

	status = tdisp_get_version (&testing.tdisp_state, testing.version_num,
		ARRAY_SIZE (testing.version_num), &msg);

	CuAssertIntEquals (test, 0, status);

	memset (&msg, 0, sizeof (msg));
	msg.data = buf;
	msg.payload = buf;
	msg.max_response = sizeof (buf);
	msg.payload_length = sizeof (struct tdisp_get_version_request);
	msg.length = msg.payload_length;

	rq->header.version = TDISP_CURRENT_VERSION;
	rq->header.message_type = TDISP_REQUEST_GET_VERSION;
	rq->header.interface_id.function_id = 1;

	testing.tdisp_state.interface_context_count = TDISP_INTERFACE_MAX_COUNT;

	status = tdisp_get_version (&testing.tdisp_state, testing.version_num,
		ARRAY_SIZE (testing.version_num), &msg);

	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, sizeof (struct tdisp_error_response), msg.length);
	CuAssertIntEquals (test, msg.length, msg.payload_length);
	CuAssertPtrEquals (test, buf, msg.data);
	CuAssertPtrEquals (test, error_response, msg.payload);
	CuAssertIntEquals (test, TDISP_VERSION_1_0, error_response->header.version);
	CuAssertIntEquals (test, TDISP_ERROR_CODE_INVALID_INTERFACE, error_response->error_code);
	CuAssertIntEquals (test, 0, error_response->error_data);
	CuAssertIntEquals (test, TDISP_ERROR, error_response->header.message_type);

	tdisp_commands_testing_release_dependencies (test, &testing);
}

static void tdisp_commands_test_get_capabilities (CuTest *test)
{
	uint8_t buf[DOE_MESSAGE_MAX_SIZE_IN_BYTES];
	struct tdisp_get_capabilities_request *rq = (struct tdisp_get_capabilities_request*) buf;
	struct tdisp_get_capabilities_request rq_copy;
	struct tdisp_capabilities_response *resp = (struct tdisp_capabilities_response*) buf;
	struct cmd_interface_msg msg;
	int status;
	struct tdisp_commands_testing testing;
	struct tdisp_responder_capabilities expected_rsp_caps = {0};
	uint8_t i;

	TEST_START;

	tdisp_commands_testing_init_dependencies (test, &testing);

	memset (&msg, 0, sizeof (msg));
	msg.data = buf;
	msg.payload = buf;
	msg.max_response = sizeof (buf);
	msg.payload_length = sizeof (struct tdisp_get_capabilities_request);
	msg.length = msg.payload_length;

	rq->header.version = TDISP_CURRENT_VERSION;
	rq->header.message_type = TDISP_REQUEST_GET_CAPABILITIES;
	rq->header.interface_id.function_id = 0;
	rq->req_caps.tsm_caps = rand ();

	expected_rsp_caps.dsm_caps = rand ();
	for (i = 0; i < sizeof (expected_rsp_caps.req_msg_supported); i++) {
		expected_rsp_caps.req_msg_supported[i] = rand ();
	}
	expected_rsp_caps.lock_interface_flags_supported = rand ();
	expected_rsp_caps.dev_addr_width = rand ();
	expected_rsp_caps.num_req_this = rand ();
	expected_rsp_caps.num_req_all = rand ();

	memcpy (&rq_copy, rq, sizeof (rq_copy));
	status = mock_expect (&testing.tdisp_driver_mock.mock,
		testing.tdisp_driver_mock.base.get_tdisp_capabilities, &testing.tdisp_driver_mock, 0,
		MOCK_ARG_PTR_CONTAINS (&rq_copy.req_caps, sizeof (struct tdisp_requester_capabilities)),
		MOCK_ARG_NOT_NULL);

	status |= mock_expect_output (&testing.tdisp_driver_mock.mock, 1, &expected_rsp_caps,
		sizeof (struct tdisp_responder_capabilities), -1);

	CuAssertIntEquals (test, 0, status);

	status = tdisp_get_capabilities (&testing.tdisp_driver_mock.base, &msg);

	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, sizeof (struct tdisp_capabilities_response), msg.length);
	CuAssertIntEquals (test, msg.length, msg.payload_length);
	CuAssertPtrEquals (test, buf, msg.data);
	CuAssertPtrEquals (test, resp, msg.payload);
	CuAssertIntEquals (test, TDISP_CURRENT_VERSION, resp->header.version);
	CuAssertIntEquals (test, TDISP_RESPONSE_GET_CAPABILITIES, resp->header.message_type);
	CuAssertIntEquals (test, 0, resp->header.interface_id.function_id);
	CuAssertIntEquals (test, 0, memcmp (&expected_rsp_caps, &resp->rsp_caps,
		sizeof (struct tdisp_responder_capabilities)));

	tdisp_commands_testing_release_dependencies (test, &testing);
}

static void tdisp_commands_test_get_capabilities_invalid_params (CuTest *test)
{
	int status;
	struct cmd_interface_msg request;
	struct tdisp_commands_testing testing;

	TEST_START;

	tdisp_commands_testing_init_dependencies (test, &testing);

	status = tdisp_get_capabilities (NULL, &request);
	CuAssertIntEquals (test, CMD_INTERFACE_TDISP_RESPONDER_INVALID_ARGUMENT, status);

	status = tdisp_get_capabilities ( &testing.tdisp_driver_mock.base, NULL);
	CuAssertIntEquals (test, CMD_INTERFACE_TDISP_RESPONDER_INVALID_ARGUMENT, status);

	tdisp_commands_testing_release_dependencies (test, &testing);
}

static void tdisp_commands_test_get_capabilities_request_lt_min_length (CuTest *test)
{
	uint8_t buf[DOE_MESSAGE_MAX_SIZE_IN_BYTES];
	struct tdisp_get_capabilities_request *rq = (struct tdisp_get_capabilities_request*) buf;
	struct tdisp_error_response *error_response = (struct tdisp_error_response*) buf;
	struct cmd_interface_msg msg;
	int status;
	struct tdisp_commands_testing testing;

	TEST_START;

	tdisp_commands_testing_init_dependencies (test, &testing);

	memset (&msg, 0, sizeof (msg));
	msg.data = buf;
	msg.payload = buf;
	msg.max_response = sizeof (buf);
	msg.payload_length = sizeof (struct tdisp_get_capabilities_request) - 1;
	msg.length = msg.payload_length;

	rq->header.version = TDISP_CURRENT_VERSION;
	rq->header.message_type = TDISP_REQUEST_GET_CAPABILITIES;
	rq->header.interface_id.function_id = 0;

	status = tdisp_get_capabilities (&testing.tdisp_driver_mock.base, &msg);

	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, sizeof (struct tdisp_error_response), msg.length);
	CuAssertIntEquals (test, msg.length, msg.payload_length);
	CuAssertPtrEquals (test, buf, msg.data);
	CuAssertPtrEquals (test, error_response, msg.payload);
	CuAssertIntEquals (test, TDISP_VERSION_1_0, error_response->header.version);
	CuAssertIntEquals (test, TDISP_ERROR_CODE_INVALID_REQUEST, error_response->error_code);
	CuAssertIntEquals (test, 0, error_response->error_data);
	CuAssertIntEquals (test, TDISP_ERROR, error_response->header.message_type);

	tdisp_commands_testing_release_dependencies (test, &testing);
}

static void tdisp_commands_test_get_capabilities_invalid_version (CuTest *test)
{
	uint8_t buf[DOE_MESSAGE_MAX_SIZE_IN_BYTES];
	struct tdisp_get_capabilities_request *rq = (struct tdisp_get_capabilities_request*) buf;
	struct tdisp_error_response *error_response = (struct tdisp_error_response*) buf;
	struct cmd_interface_msg msg;
	int status;
	struct tdisp_commands_testing testing;

	TEST_START;

	tdisp_commands_testing_init_dependencies (test, &testing);

	memset (&msg, 0, sizeof (msg));
	msg.data = buf;
	msg.payload = buf;
	msg.max_response = sizeof (buf);
	msg.payload_length = sizeof (struct tdisp_get_capabilities_request);
	msg.length = msg.payload_length;

	rq->header.version = UINT8_MAX;
	rq->header.message_type = TDISP_REQUEST_GET_CAPABILITIES;
	rq->header.interface_id.function_id = 0;

	status = tdisp_get_capabilities (&testing.tdisp_driver_mock.base, &msg);

	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, sizeof (struct tdisp_error_response), msg.length);
	CuAssertIntEquals (test, msg.length, msg.payload_length);
	CuAssertPtrEquals (test, buf, msg.data);
	CuAssertPtrEquals (test, error_response, msg.payload);
	CuAssertIntEquals (test, TDISP_VERSION_1_0, error_response->header.version);
	CuAssertIntEquals (test, TDISP_ERROR_CODE_VERSION_MISMATCH, error_response->error_code);
	CuAssertIntEquals (test, 0, error_response->error_data);
	CuAssertIntEquals (test, TDISP_ERROR, error_response->header.message_type);

	tdisp_commands_testing_release_dependencies (test, &testing);
}

static void tdisp_commands_test_get_capabilities_insufficient_output_buffer (CuTest *test)
{
	uint8_t buf[DOE_MESSAGE_MAX_SIZE_IN_BYTES];
	struct tdisp_get_capabilities_request *rq = (struct tdisp_get_capabilities_request*) buf;
	struct tdisp_error_response *error_response = (struct tdisp_error_response*) buf;
	struct cmd_interface_msg msg;
	int status;
	struct tdisp_commands_testing testing;

	TEST_START;

	tdisp_commands_testing_init_dependencies (test, &testing);

	memset (&msg, 0, sizeof (msg));
	msg.data = buf;
	msg.payload = buf;
	msg.max_response = sizeof (buf);
	msg.payload_length = sizeof (struct tdisp_get_capabilities_request);
	msg.length = msg.payload_length;
	msg.max_response = sizeof (struct tdisp_capabilities_response) - 1;

	rq->header.version = TDISP_CURRENT_VERSION;
	rq->header.message_type = TDISP_REQUEST_GET_CAPABILITIES;

	status = tdisp_get_capabilities (&testing.tdisp_driver_mock.base, &msg);

	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, sizeof (struct tdisp_error_response), msg.length);
	CuAssertIntEquals (test, msg.length, msg.payload_length);
	CuAssertPtrEquals (test, buf, msg.data);
	CuAssertPtrEquals (test, error_response, msg.payload);
	CuAssertIntEquals (test, TDISP_VERSION_1_0, error_response->header.version);
	CuAssertIntEquals (test, TDISP_ERROR_CODE_UNSPECIFIED, error_response->error_code);
	CuAssertIntEquals (test, 0, error_response->error_data);
	CuAssertIntEquals (test, TDISP_ERROR, error_response->header.message_type);

	tdisp_commands_testing_release_dependencies (test, &testing);
}

static void tdisp_commands_test_get_capabilities_fail (CuTest *test)
{
	uint8_t buf[DOE_MESSAGE_MAX_SIZE_IN_BYTES];
	struct tdisp_get_capabilities_request *rq = (struct tdisp_get_capabilities_request*) buf;
	struct tdisp_error_response *error_response = (struct tdisp_error_response*) buf;
	struct cmd_interface_msg msg;
	int status;
	struct tdisp_commands_testing testing;

	TEST_START;

	tdisp_commands_testing_init_dependencies (test, &testing);

	memset (&msg, 0, sizeof (msg));
	msg.data = buf;
	msg.payload = buf;
	msg.max_response = sizeof (buf);
	msg.payload_length = sizeof (struct tdisp_get_capabilities_request);
	msg.length = msg.payload_length;

	rq->header.version = TDISP_CURRENT_VERSION;
	rq->header.message_type = TDISP_REQUEST_GET_CAPABILITIES;
	rq->header.interface_id.function_id = 0;
	rq->req_caps.tsm_caps = rand ();

	status = mock_expect (&testing.tdisp_driver_mock.mock,
		testing.tdisp_driver_mock.base.get_tdisp_capabilities, &testing.tdisp_driver_mock,
		TDISP_DRIVER_GET_TDISP_CAPABILITIES_FAILED, MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	status = tdisp_get_capabilities (&testing.tdisp_driver_mock.base, &msg);

	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, sizeof (struct tdisp_error_response), msg.length);
	CuAssertIntEquals (test, msg.length, msg.payload_length);
	CuAssertPtrEquals (test, buf, msg.data);
	CuAssertPtrEquals (test, error_response, msg.payload);
	CuAssertIntEquals (test, TDISP_VERSION_1_0, error_response->header.version);
	CuAssertIntEquals (test, TDISP_ERROR_CODE_UNSPECIFIED, error_response->error_code);
	CuAssertIntEquals (test, 0, error_response->error_data);
	CuAssertIntEquals (test, TDISP_ERROR, error_response->header.message_type);

	tdisp_commands_testing_release_dependencies (test, &testing);
}

static void tdisp_commands_test_lock_interface (CuTest *test)
{
	uint8_t buf[DOE_MESSAGE_MAX_SIZE_IN_BYTES] = {0};
	struct tdisp_lock_interface_request *rq = (struct tdisp_lock_interface_request*) buf;
	struct tdisp_lock_interface_request rq_copy;
	struct tdisp_lock_interface_response *resp = (struct tdisp_lock_interface_response*) buf;
	struct cmd_interface_msg msg;
	int status;
	struct tdisp_commands_testing testing;
	uint8_t i;
	uint32_t function_id;
	uint8_t expected_nonce[TDISP_START_INTERFACE_NONCE_SIZE];

	TEST_START;

	tdisp_commands_testing_init_dependencies (test, &testing);

	memset (&msg, 0, sizeof (msg));
	msg.data = buf;
	msg.payload = buf;
	msg.max_response = sizeof (buf);
	msg.payload_length = sizeof (struct tdisp_lock_interface_request);
	msg.length = msg.payload_length;

	function_id = rand ();
	rq->header.version = TDISP_CURRENT_VERSION;
	rq->header.message_type = TDISP_REQUEST_LOCK_INTERFACE;
	rq->header.interface_id.function_id = function_id;
	rq->lock_interface_param.default_stream_id = rand ();
	rq->lock_interface_param.mmio_reporting_offset = rand ();
	rq->lock_interface_param.bind_p2p_address_mask = rand ();

	testing.tdisp_state.interface_context[0].interface_id.function_id = function_id;

	for (i = 0; i < TDISP_START_INTERFACE_NONCE_SIZE; i++) {
		expected_nonce[i] = rand ();
	}
	status = mock_expect (&testing.rng_mock.mock,
		testing.rng_mock.base.generate_random_buffer, &testing.rng_mock, 0,
		MOCK_ARG (TDISP_START_INTERFACE_NONCE_SIZE), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&testing.rng_mock.mock, 1, expected_nonce,
		TDISP_START_INTERFACE_NONCE_SIZE, 0);

	memcpy (&rq_copy, rq, sizeof (rq_copy));
	status |= mock_expect (&testing.tdisp_driver_mock.mock,
		testing.tdisp_driver_mock.base.lock_interface_request, &testing.tdisp_driver_mock, 0,
		MOCK_ARG(function_id), MOCK_ARG_PTR_CONTAINS (&rq_copy.lock_interface_param,
		sizeof (struct tdisp_lock_interface_param)));

	CuAssertIntEquals (test, 0, status);

	status = tdisp_lock_interface (&testing.tdisp_state, &testing.tdisp_driver_mock.base,
		&testing.rng_mock.base, &msg);

	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, sizeof (struct tdisp_lock_interface_response), msg.length);
	CuAssertIntEquals (test, msg.length, msg.payload_length);
	CuAssertPtrEquals (test, buf, msg.data);
	CuAssertPtrEquals (test, resp, msg.payload);
	CuAssertIntEquals (test, TDISP_CURRENT_VERSION, resp->header.version);
	CuAssertIntEquals (test, TDISP_RESPONSE_LOCK_INTERFACE, resp->header.message_type);
	CuAssertIntEquals (test, function_id, resp->header.interface_id.function_id);
	CuAssertIntEquals (test, 0, memcmp (&expected_nonce, &resp->start_interface_nonce,
		TDISP_START_INTERFACE_NONCE_SIZE));

	tdisp_commands_testing_release_dependencies (test, &testing);
}

static void tdisp_commands_test_lock_interface_invalid_params (CuTest *test)
{
	int status;
	struct cmd_interface_msg request;
	struct tdisp_commands_testing testing;

	TEST_START;

	tdisp_commands_testing_init_dependencies (test, &testing);

	status = tdisp_lock_interface (NULL, &testing.tdisp_driver_mock.base,
		&testing.rng_mock.base, &request);
	CuAssertIntEquals (test, CMD_INTERFACE_TDISP_RESPONDER_INVALID_ARGUMENT, status);

	status = tdisp_lock_interface (&testing.tdisp_state, NULL, &testing.rng_mock.base, &request);
	CuAssertIntEquals (test, CMD_INTERFACE_TDISP_RESPONDER_INVALID_ARGUMENT, status);

	status = tdisp_lock_interface (&testing.tdisp_state, &testing.tdisp_driver_mock.base, NULL,
		&request);
	CuAssertIntEquals (test, CMD_INTERFACE_TDISP_RESPONDER_INVALID_ARGUMENT, status);

	status = tdisp_lock_interface (&testing.tdisp_state, &testing.tdisp_driver_mock.base,
		&testing.rng_mock.base, NULL);
	CuAssertIntEquals (test, CMD_INTERFACE_TDISP_RESPONDER_INVALID_ARGUMENT, status);

	tdisp_commands_testing_release_dependencies (test, &testing);
}

static void tdisp_commands_test_lock_interface_request_lt_min_length (CuTest *test)
{
	uint8_t buf[DOE_MESSAGE_MAX_SIZE_IN_BYTES];
	struct tdisp_lock_interface_request *rq = (struct tdisp_lock_interface_request*) buf;
	struct tdisp_error_response *error_response = (struct tdisp_error_response*) buf;
	struct cmd_interface_msg msg;
	int status;
	struct tdisp_commands_testing testing;

	TEST_START;

	tdisp_commands_testing_init_dependencies (test, &testing);

	memset (&msg, 0, sizeof (msg));
	msg.data = buf;
	msg.payload = buf;
	msg.max_response = sizeof (buf);
	msg.payload_length = sizeof (struct tdisp_lock_interface_request) - 1;
	msg.length = msg.payload_length;

	rq->header.version = TDISP_CURRENT_VERSION;
	rq->header.message_type = TDISP_REQUEST_LOCK_INTERFACE;
	rq->header.interface_id.function_id = 0;

	status = tdisp_lock_interface (&testing.tdisp_state, &testing.tdisp_driver_mock.base,
		&testing.rng_mock.base, &msg);

	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, sizeof (struct tdisp_error_response), msg.length);
	CuAssertIntEquals (test, msg.length, msg.payload_length);
	CuAssertPtrEquals (test, buf, msg.data);
	CuAssertPtrEquals (test, error_response, msg.payload);
	CuAssertIntEquals (test, TDISP_VERSION_1_0, error_response->header.version);
	CuAssertIntEquals (test, TDISP_ERROR_CODE_INVALID_REQUEST, error_response->error_code);
	CuAssertIntEquals (test, 0, error_response->error_data);
	CuAssertIntEquals (test, TDISP_ERROR, error_response->header.message_type);

	tdisp_commands_testing_release_dependencies (test, &testing);
}

static void tdisp_commands_test_lock_interface_invalid_version (CuTest *test)
{
	uint8_t buf[DOE_MESSAGE_MAX_SIZE_IN_BYTES];
	struct tdisp_lock_interface_request *rq = (struct tdisp_lock_interface_request*) buf;
	struct tdisp_error_response *error_response = (struct tdisp_error_response*) buf;
	struct cmd_interface_msg msg;
	int status;
	struct tdisp_commands_testing testing;

	TEST_START;

	tdisp_commands_testing_init_dependencies (test, &testing);

	memset (&msg, 0, sizeof (msg));
	msg.data = buf;
	msg.payload = buf;
	msg.max_response = sizeof (buf);
	msg.payload_length = sizeof (struct tdisp_lock_interface_request);
	msg.length = msg.payload_length;

	rq->header.version = UINT8_MAX;
	rq->header.message_type = TDISP_REQUEST_LOCK_INTERFACE;
	rq->header.interface_id.function_id = 0;

	status = tdisp_lock_interface (&testing.tdisp_state, &testing.tdisp_driver_mock.base,
		&testing.rng_mock.base, &msg);

	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, sizeof (struct tdisp_error_response), msg.length);
	CuAssertIntEquals (test, msg.length, msg.payload_length);
	CuAssertPtrEquals (test, buf, msg.data);
	CuAssertPtrEquals (test, error_response, msg.payload);
	CuAssertIntEquals (test, TDISP_VERSION_1_0, error_response->header.version);
	CuAssertIntEquals (test, TDISP_ERROR_CODE_VERSION_MISMATCH, error_response->error_code);
	CuAssertIntEquals (test, 0, error_response->error_data);
	CuAssertIntEquals (test, TDISP_ERROR, error_response->header.message_type);

	tdisp_commands_testing_release_dependencies (test, &testing);
}

static void tdisp_commands_test_lock_interface_insufficient_output_buffer (CuTest *test)
{
	uint8_t buf[DOE_MESSAGE_MAX_SIZE_IN_BYTES];
	struct tdisp_lock_interface_request *rq = (struct tdisp_lock_interface_request*) buf;
	struct tdisp_error_response *error_response = (struct tdisp_error_response*) buf;
	struct cmd_interface_msg msg;
	int status;
	struct tdisp_commands_testing testing;

	TEST_START;

	tdisp_commands_testing_init_dependencies (test, &testing);

	memset (&msg, 0, sizeof (msg));
	msg.data = buf;
	msg.payload = buf;
	msg.max_response = sizeof (buf);
	msg.payload_length = sizeof (struct tdisp_lock_interface_request);
	msg.length = msg.payload_length;
	msg.max_response = sizeof (struct tdisp_lock_interface_response) - 1;

	rq->header.version = TDISP_CURRENT_VERSION;
	rq->header.message_type = TDISP_REQUEST_LOCK_INTERFACE;

	status = tdisp_lock_interface (&testing.tdisp_state, &testing.tdisp_driver_mock.base,
		&testing.rng_mock.base, &msg);

	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, sizeof (struct tdisp_error_response), msg.length);
	CuAssertIntEquals (test, msg.length, msg.payload_length);
	CuAssertPtrEquals (test, buf, msg.data);
	CuAssertPtrEquals (test, error_response, msg.payload);
	CuAssertIntEquals (test, TDISP_VERSION_1_0, error_response->header.version);
	CuAssertIntEquals (test, TDISP_ERROR_CODE_UNSPECIFIED, error_response->error_code);
	CuAssertIntEquals (test, 0, error_response->error_data);
	CuAssertIntEquals (test, TDISP_ERROR, error_response->header.message_type);

	tdisp_commands_testing_release_dependencies (test, &testing);
}

static void tdisp_commands_test_lock_interface_get_interface_context_fail (CuTest *test)
{
	uint8_t buf[DOE_MESSAGE_MAX_SIZE_IN_BYTES];
	struct tdisp_lock_interface_request *rq = (struct tdisp_lock_interface_request*) buf;
	struct tdisp_error_response *error_response = (struct tdisp_error_response*) buf;
	struct cmd_interface_msg msg;
	int status;
	struct tdisp_commands_testing testing;

	TEST_START;

	tdisp_commands_testing_init_dependencies (test, &testing);

	memset (&msg, 0, sizeof (msg));
	msg.data = buf;
	msg.payload = buf;
	msg.max_response = sizeof (buf);
	msg.payload_length = sizeof (struct tdisp_lock_interface_request);
	msg.length = msg.payload_length;

	rq->header.version = TDISP_CURRENT_VERSION;
	rq->header.message_type = TDISP_REQUEST_LOCK_INTERFACE;
	rq->header.interface_id.function_id = 0;

	status = tdisp_lock_interface (&testing.tdisp_state, &testing.tdisp_driver_mock.base,
		&testing.rng_mock.base, &msg);

	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, sizeof (struct tdisp_error_response), msg.length);
	CuAssertIntEquals (test, msg.length, msg.payload_length);
	CuAssertPtrEquals (test, buf, msg.data);
	CuAssertPtrEquals (test, error_response, msg.payload);
	CuAssertIntEquals (test, TDISP_VERSION_1_0, error_response->header.version);
	CuAssertIntEquals (test, TDISP_ERROR_CODE_INVALID_INTERFACE, error_response->error_code);
	CuAssertIntEquals (test, 0, error_response->error_data);
	CuAssertIntEquals (test, TDISP_ERROR, error_response->header.message_type);

	tdisp_commands_testing_release_dependencies (test, &testing);
}

static void tdisp_commands_test_lock_interface_generate_random_buffer_fail (CuTest *test)
{
	uint8_t buf[DOE_MESSAGE_MAX_SIZE_IN_BYTES];
	struct tdisp_lock_interface_request *rq = (struct tdisp_lock_interface_request*) buf;
	struct tdisp_error_response *error_response = (struct tdisp_error_response*) buf;
	struct cmd_interface_msg msg;
	int status;
	struct tdisp_commands_testing testing;

	TEST_START;

	tdisp_commands_testing_init_dependencies (test, &testing);


	memset (&msg, 0, sizeof (msg));
	msg.data = buf;
	msg.payload = buf;
	msg.max_response = sizeof (buf);
	msg.payload_length = sizeof (struct tdisp_lock_interface_request);
	msg.length = msg.payload_length;

	rq->header.version = TDISP_CURRENT_VERSION;
	rq->header.message_type = TDISP_REQUEST_LOCK_INTERFACE;
	rq->header.interface_id.function_id = 0;

	testing.tdisp_state.interface_context[0].interface_id.function_id = 0;

	status = mock_expect (&testing.rng_mock.mock,
		testing.rng_mock.base.generate_random_buffer, &testing.rng_mock, RNG_ENGINE_RANDOM_FAILED,
		MOCK_ARG (TDISP_START_INTERFACE_NONCE_SIZE), MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	status = tdisp_lock_interface (&testing.tdisp_state, &testing.tdisp_driver_mock.base,
		&testing.rng_mock.base, &msg);

	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, sizeof (struct tdisp_error_response), msg.length);
	CuAssertIntEquals (test, msg.length, msg.payload_length);
	CuAssertPtrEquals (test, buf, msg.data);
	CuAssertPtrEquals (test, error_response, msg.payload);
	CuAssertIntEquals (test, TDISP_VERSION_1_0, error_response->header.version);
	CuAssertIntEquals (test, TDISP_ERROR_CODE_UNSPECIFIED, error_response->error_code);
	CuAssertIntEquals (test, 0, error_response->error_data);
	CuAssertIntEquals (test, TDISP_ERROR, error_response->header.message_type);

	tdisp_commands_testing_release_dependencies (test, &testing);
}

static void tdisp_commands_test_lock_interface_lock_interface_request_fail (CuTest *test)
{
	uint8_t buf[DOE_MESSAGE_MAX_SIZE_IN_BYTES];
	struct tdisp_lock_interface_request *rq = (struct tdisp_lock_interface_request*) buf;
	struct tdisp_error_response *error_response = (struct tdisp_error_response*) buf;
	struct cmd_interface_msg msg;
	int status;
	struct tdisp_commands_testing testing;

	TEST_START;

	tdisp_commands_testing_init_dependencies (test, &testing);

	memset (&msg, 0, sizeof (msg));
	msg.data = buf;
	msg.payload = buf;
	msg.max_response = sizeof (buf);
	msg.payload_length = sizeof (struct tdisp_lock_interface_request);
	msg.length = msg.payload_length;

	rq->header.version = TDISP_CURRENT_VERSION;
	rq->header.message_type = TDISP_REQUEST_LOCK_INTERFACE;
	rq->header.interface_id.function_id = 0;

	testing.tdisp_state.interface_context[0].interface_id.function_id = 0;

	status = mock_expect (&testing.rng_mock.mock,
		testing.rng_mock.base.generate_random_buffer, &testing.rng_mock, 0,
		MOCK_ARG (TDISP_START_INTERFACE_NONCE_SIZE), MOCK_ARG_NOT_NULL);

	status |= mock_expect (&testing.tdisp_driver_mock.mock,
		testing.tdisp_driver_mock.base.lock_interface_request, &testing.tdisp_driver_mock,
		TDISP_DRIVER_LOCK_INTERFACE_REQUEST_FAILED, MOCK_ARG(0), MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	status = tdisp_lock_interface (&testing.tdisp_state, &testing.tdisp_driver_mock.base,
		&testing.rng_mock.base, &msg);

	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, sizeof (struct tdisp_error_response), msg.length);
	CuAssertIntEquals (test, msg.length, msg.payload_length);
	CuAssertPtrEquals (test, buf, msg.data);
	CuAssertPtrEquals (test, error_response, msg.payload);
	CuAssertIntEquals (test, TDISP_VERSION_1_0, error_response->header.version);
	CuAssertIntEquals (test, TDISP_ERROR_CODE_UNSPECIFIED, error_response->error_code);
	CuAssertIntEquals (test, 0, error_response->error_data);
	CuAssertIntEquals (test, TDISP_ERROR, error_response->header.message_type);

	tdisp_commands_testing_release_dependencies (test, &testing);
}

static void tdisp_commands_test_get_device_interface_state (CuTest *test)
{
	uint8_t buf[DOE_MESSAGE_MAX_SIZE_IN_BYTES];
	struct tdisp_get_device_interface_state_request *rq =
		(struct tdisp_get_device_interface_state_request*) buf;
	struct tdisp_device_interface_state_response *resp =
		(struct tdisp_device_interface_state_response*) buf;
	struct cmd_interface_msg msg;
	int status;
	struct tdisp_commands_testing testing;
	uint32_t function_id;
	uint8_t expected_tdi_state;

	TEST_START;

	tdisp_commands_testing_init_dependencies (test, &testing);

	memset (&msg, 0, sizeof (msg));
	msg.data = buf;
	msg.payload = buf;
	msg.max_response = sizeof (buf);
	msg.payload_length = sizeof (struct tdisp_get_device_interface_state_request);
	msg.length = msg.payload_length;

	function_id = rand ();
	rq->header.version = TDISP_CURRENT_VERSION;
	rq->header.message_type = TDISP_REQUEST_GET_DEVICE_INTERFACE_STATE;
	rq->header.interface_id.function_id = function_id;

	status = mock_expect (&testing.tdisp_driver_mock.mock,
		testing.tdisp_driver_mock.base.get_device_interface_state, &testing.tdisp_driver_mock,
		0, MOCK_ARG(function_id), MOCK_ARG_NOT_NULL);

	expected_tdi_state = rand ();
	status |= mock_expect_output (&testing.tdisp_driver_mock.mock, 1, &expected_tdi_state,
		sizeof (expected_tdi_state), 0);

	CuAssertIntEquals (test, 0, status);

	status = tdisp_get_device_interface_state (&testing.tdisp_state,
		&testing.tdisp_driver_mock.base, &msg);

	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, sizeof (struct tdisp_device_interface_state_response), msg.length);
	CuAssertIntEquals (test, msg.length, msg.payload_length);
	CuAssertPtrEquals (test, buf, msg.data);
	CuAssertPtrEquals (test, resp, msg.payload);
	CuAssertIntEquals (test, TDISP_CURRENT_VERSION, resp->header.version);
	CuAssertIntEquals (test, TDISP_RESPONSE_GET_DEVICE_INTERFACE_STATE, resp->header.message_type);
	CuAssertIntEquals (test, function_id, resp->header.interface_id.function_id);
	CuAssertIntEquals (test, expected_tdi_state, resp->tdi_state);

	tdisp_commands_testing_release_dependencies (test, &testing);
}

static void tdisp_commands_test_get_device_interface_state_invalid_params (CuTest *test)
{
	int status;
	struct tdisp_commands_testing testing;
	struct cmd_interface_msg request;

	TEST_START;

	tdisp_commands_testing_init_dependencies (test, &testing);

	status = tdisp_get_device_interface_state (NULL, &testing.tdisp_driver_mock.base, &request);
	CuAssertIntEquals (test, CMD_INTERFACE_TDISP_RESPONDER_INVALID_ARGUMENT, status);

	status = tdisp_get_device_interface_state (&testing.tdisp_state, NULL,  &request);
	CuAssertIntEquals (test, CMD_INTERFACE_TDISP_RESPONDER_INVALID_ARGUMENT, status);

	status = tdisp_get_device_interface_state (&testing.tdisp_state,
		&testing.tdisp_driver_mock.base, NULL);
	CuAssertIntEquals (test, CMD_INTERFACE_TDISP_RESPONDER_INVALID_ARGUMENT, status);

	tdisp_commands_testing_release_dependencies (test, &testing);
}

static void tdisp_commands_test_get_device_interface_state_lt_min_length (CuTest *test)
{
	uint8_t buf[DOE_MESSAGE_MAX_SIZE_IN_BYTES];
	struct tdisp_get_device_interface_state_request *rq =
		(struct tdisp_get_device_interface_state_request*) buf;
	struct tdisp_error_response *error_response = (struct tdisp_error_response*) buf;
	struct cmd_interface_msg msg;
	int status;
	struct tdisp_commands_testing testing;

	TEST_START;

	tdisp_commands_testing_init_dependencies (test, &testing);

	memset (&msg, 0, sizeof (msg));
	msg.data = buf;
	msg.payload = buf;
	msg.max_response = sizeof (buf);
	msg.payload_length = sizeof (struct tdisp_get_device_interface_state_request) - 1;
	msg.length = msg.payload_length;

	rq->header.version = TDISP_CURRENT_VERSION;
	rq->header.message_type = TDISP_REQUEST_GET_DEVICE_INTERFACE_STATE;
	rq->header.interface_id.function_id = 0;

	status = tdisp_get_device_interface_state (&testing.tdisp_state,
		&testing.tdisp_driver_mock.base, &msg);

	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, sizeof (struct tdisp_error_response), msg.length);
	CuAssertIntEquals (test, msg.length, msg.payload_length);
	CuAssertPtrEquals (test, buf, msg.data);
	CuAssertPtrEquals (test, error_response, msg.payload);
	CuAssertIntEquals (test, TDISP_VERSION_1_0, error_response->header.version);
	CuAssertIntEquals (test, TDISP_ERROR_CODE_INVALID_REQUEST, error_response->error_code);
	CuAssertIntEquals (test, 0, error_response->error_data);
	CuAssertIntEquals (test, TDISP_ERROR, error_response->header.message_type);

	tdisp_commands_testing_release_dependencies (test, &testing);
}

static void tdisp_commands_test_get_device_interface_state_invalid_version (CuTest *test)
{
	uint8_t buf[DOE_MESSAGE_MAX_SIZE_IN_BYTES];
	struct tdisp_get_device_interface_state_request *rq =
		(struct tdisp_get_device_interface_state_request*) buf;
	struct tdisp_error_response *error_response = (struct tdisp_error_response*) buf;
	struct cmd_interface_msg msg;
	int status;
	struct tdisp_commands_testing testing;

	TEST_START;

	tdisp_commands_testing_init_dependencies (test, &testing);

	memset (&msg, 0, sizeof (msg));
	msg.data = buf;
	msg.payload = buf;
	msg.max_response = sizeof (buf);
	msg.payload_length = sizeof (struct tdisp_get_device_interface_state_request);
	msg.length = msg.payload_length;

	rq->header.version = UINT8_MAX;
	rq->header.message_type = TDISP_REQUEST_GET_DEVICE_INTERFACE_STATE;
	rq->header.interface_id.function_id = 0;

	status = tdisp_get_device_interface_state (&testing.tdisp_state,
		&testing.tdisp_driver_mock.base, &msg);

	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, sizeof (struct tdisp_error_response), msg.length);
	CuAssertIntEquals (test, msg.length, msg.payload_length);
	CuAssertPtrEquals (test, buf, msg.data);
	CuAssertPtrEquals (test, error_response, msg.payload);
	CuAssertIntEquals (test, TDISP_VERSION_1_0, error_response->header.version);
	CuAssertIntEquals (test, TDISP_ERROR_CODE_VERSION_MISMATCH, error_response->error_code);
	CuAssertIntEquals (test, 0, error_response->error_data);
	CuAssertIntEquals (test, TDISP_ERROR, error_response->header.message_type);

	tdisp_commands_testing_release_dependencies (test, &testing);
}

static void tdisp_commands_test_get_device_interface_state_insufficient_response_buffer (CuTest *test)
{
	uint8_t buf[DOE_MESSAGE_MAX_SIZE_IN_BYTES];
	struct tdisp_get_device_interface_state_request *rq =
		(struct tdisp_get_device_interface_state_request*) buf;
	struct tdisp_error_response *error_response = (struct tdisp_error_response*) buf;
	struct cmd_interface_msg msg;
	int status;
	struct tdisp_commands_testing testing;
	uint32_t function_id;

	TEST_START;

	tdisp_commands_testing_init_dependencies (test, &testing);

	memset (&msg, 0, sizeof (msg));
	msg.data = buf;
	msg.payload = buf;
	msg.max_response = sizeof (struct tdisp_device_interface_state_response) - 1;
	msg.payload_length = sizeof (struct tdisp_get_device_interface_state_request);
	msg.length = msg.payload_length;

	function_id = rand ();
	rq->header.version = TDISP_CURRENT_VERSION;
	rq->header.message_type = TDISP_REQUEST_GET_DEVICE_INTERFACE_STATE;
	rq->header.interface_id.function_id = function_id;

	status = tdisp_get_device_interface_state (&testing.tdisp_state,
		&testing.tdisp_driver_mock.base, &msg);

	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, sizeof (struct tdisp_error_response), msg.length);
	CuAssertIntEquals (test, msg.length, msg.payload_length);
	CuAssertPtrEquals (test, buf, msg.data);
	CuAssertPtrEquals (test, error_response, msg.payload);
	CuAssertIntEquals (test, TDISP_VERSION_1_0, error_response->header.version);
	CuAssertIntEquals (test, TDISP_ERROR_CODE_UNSPECIFIED, error_response->error_code);
	CuAssertIntEquals (test, 0, error_response->error_data);
	CuAssertIntEquals (test, TDISP_ERROR, error_response->header.message_type);

	tdisp_commands_testing_release_dependencies (test, &testing);
}

static void tdisp_commands_test_get_device_interface_state_fail (CuTest *test)
{
	uint8_t buf[DOE_MESSAGE_MAX_SIZE_IN_BYTES];
	struct tdisp_get_device_interface_state_request *rq =
		(struct tdisp_get_device_interface_state_request*) buf;
	struct tdisp_error_response *error_response = (struct tdisp_error_response*) buf;
	struct cmd_interface_msg msg;
	int status;
	struct tdisp_commands_testing testing;
	uint32_t function_id;

	TEST_START;

	tdisp_commands_testing_init_dependencies (test, &testing);

	memset (&msg, 0, sizeof (msg));
	msg.data = buf;
	msg.payload = buf;
	msg.max_response = sizeof (buf);
	msg.payload_length = sizeof (struct tdisp_get_device_interface_state_request);
	msg.length = msg.payload_length;

	function_id = rand ();
	rq->header.version = TDISP_CURRENT_VERSION;
	rq->header.message_type = TDISP_REQUEST_GET_DEVICE_INTERFACE_STATE;
	rq->header.interface_id.function_id = function_id;

	status = mock_expect (&testing.tdisp_driver_mock.mock,
		testing.tdisp_driver_mock.base.get_device_interface_state, &testing.tdisp_driver_mock,
		TDISP_DRIVER_GET_DEVICE_INTERFACE_STATE_FAILED, MOCK_ARG(function_id), MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	status = tdisp_get_device_interface_state (&testing.tdisp_state,
		&testing.tdisp_driver_mock.base, &msg);

	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, sizeof (struct tdisp_error_response), msg.length);
	CuAssertIntEquals (test, msg.length, msg.payload_length);
	CuAssertPtrEquals (test, buf, msg.data);
	CuAssertPtrEquals (test, error_response, msg.payload);
	CuAssertIntEquals (test, TDISP_VERSION_1_0, error_response->header.version);
	CuAssertIntEquals (test, TDISP_ERROR_CODE_INVALID_INTERFACE, error_response->error_code);
	CuAssertIntEquals (test, 0, error_response->error_data);
	CuAssertIntEquals (test, TDISP_ERROR, error_response->header.message_type);

	tdisp_commands_testing_release_dependencies (test, &testing);
}

static void tdisp_commands_test_start_interface (CuTest *test)
{
	uint8_t buf[DOE_MESSAGE_MAX_SIZE_IN_BYTES];
	struct tdisp_start_interface_request *rq =  (struct tdisp_start_interface_request*) buf;
	struct tdisp_start_interface_response *resp = (struct tdisp_start_interface_response*) buf;
	struct cmd_interface_msg msg;
	int status;
	struct tdisp_commands_testing testing;
	uint32_t function_id;
	uint8_t nonce[TDISP_START_INTERFACE_NONCE_SIZE];
	uint8_t i;
	struct tdisp_state *tdisp_state;

	TEST_START;

	tdisp_commands_testing_init_dependencies (test, &testing);

	tdisp_state = &testing.tdisp_state;

	memset (&msg, 0, sizeof (msg));
	msg.data = buf;
	msg.payload = buf;
	msg.max_response = sizeof (buf);
	msg.payload_length = sizeof (struct tdisp_start_interface_request);
	msg.length = msg.payload_length;

	function_id = rand ();
	for (i = 0; i < TDISP_START_INTERFACE_NONCE_SIZE; i++) {
		nonce[i] = rand ();
	}

	rq->header.version = TDISP_CURRENT_VERSION;
	rq->header.message_type = TDISP_REQUEST_START_INTERFACE;
	rq->header.interface_id.function_id = function_id;
	memcpy (rq->start_interface_nonce, nonce, TDISP_START_INTERFACE_NONCE_SIZE);

	tdisp_state->interface_context[0].interface_id.function_id = function_id;
	memcpy (tdisp_state->interface_context[0].start_interface_nonce, nonce,
		TDISP_START_INTERFACE_NONCE_SIZE);

	status = mock_expect (&testing.tdisp_driver_mock.mock,
		testing.tdisp_driver_mock.base.start_interface_request, &testing.tdisp_driver_mock,
		0, MOCK_ARG(function_id));

	CuAssertIntEquals (test, 0, status);

	status = tdisp_start_interface (tdisp_state, &testing.tdisp_driver_mock.base, &msg);

	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, sizeof (struct tdisp_start_interface_response), msg.length);
	CuAssertIntEquals (test, msg.length, msg.payload_length);
	CuAssertPtrEquals (test, buf, msg.data);
	CuAssertPtrEquals (test, resp, msg.payload);
	CuAssertIntEquals (test, TDISP_CURRENT_VERSION, resp->header.version);
	CuAssertIntEquals (test, TDISP_RESPONSE_START_INTERFACE, resp->header.message_type);
	CuAssertIntEquals (test, function_id, resp->header.interface_id.function_id);

	tdisp_commands_testing_release_dependencies (test, &testing);
}

static void tdisp_commands_test_start_interface_invalid_params (CuTest *test)
{
	int status;
	struct tdisp_commands_testing testing;
	struct cmd_interface_msg request;

	TEST_START;

	tdisp_commands_testing_init_dependencies (test, &testing);

	status = tdisp_start_interface (NULL, &testing.tdisp_driver_mock.base, &request);
	CuAssertIntEquals (test, CMD_INTERFACE_TDISP_RESPONDER_INVALID_ARGUMENT, status);

	status = tdisp_start_interface (&testing.tdisp_state, NULL,
		&request);
	CuAssertIntEquals (test, CMD_INTERFACE_TDISP_RESPONDER_INVALID_ARGUMENT, status);

	status = tdisp_start_interface (&testing.tdisp_state, &testing.tdisp_driver_mock.base, NULL);
	CuAssertIntEquals (test, CMD_INTERFACE_TDISP_RESPONDER_INVALID_ARGUMENT, status);

	tdisp_commands_testing_release_dependencies (test, &testing);
}

static void tdisp_commands_test_start_interface_lt_min_length (CuTest *test)
{
	uint8_t buf[DOE_MESSAGE_MAX_SIZE_IN_BYTES];
	struct tdisp_start_interface_request *rq = (struct tdisp_start_interface_request*) buf;
	struct tdisp_error_response *error_response = (struct tdisp_error_response*) buf;
	struct cmd_interface_msg msg;
	int status;
	struct tdisp_commands_testing testing;

	TEST_START;

	tdisp_commands_testing_init_dependencies (test, &testing);

	memset (&msg, 0, sizeof (msg));
	msg.data = buf;
	msg.payload = buf;
	msg.max_response = sizeof (buf);
	msg.payload_length = sizeof (struct tdisp_start_interface_request) - 1;
	msg.length = msg.payload_length;

	rq->header.version = TDISP_CURRENT_VERSION;
	rq->header.message_type = TDISP_REQUEST_START_INTERFACE;
	rq->header.interface_id.function_id = rand ();

	status = tdisp_start_interface (&testing.tdisp_state, &testing.tdisp_driver_mock.base, &msg);

	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, sizeof (struct tdisp_error_response), msg.length);
	CuAssertIntEquals (test, msg.length, msg.payload_length);
	CuAssertPtrEquals (test, buf, msg.data);
	CuAssertPtrEquals (test, error_response, msg.payload);
	CuAssertIntEquals (test, TDISP_VERSION_1_0, error_response->header.version);
	CuAssertIntEquals (test, TDISP_ERROR_CODE_INVALID_REQUEST, error_response->error_code);
	CuAssertIntEquals (test, 0, error_response->error_data);
	CuAssertIntEquals (test, TDISP_ERROR, error_response->header.message_type);
	CuAssertIntEquals (test, 0, error_response->header.interface_id.function_id);

	tdisp_commands_testing_release_dependencies (test, &testing);
}

static void tdisp_commands_test_start_interface_invalid_version (CuTest *test)
{
	uint8_t buf[DOE_MESSAGE_MAX_SIZE_IN_BYTES];
	struct tdisp_start_interface_request *rq = (struct tdisp_start_interface_request*) buf;
	struct tdisp_error_response *error_response = (struct tdisp_error_response*) buf;
	struct cmd_interface_msg msg;
	int status;
	struct tdisp_commands_testing testing;
	uint32_t function_id;

	TEST_START;

	tdisp_commands_testing_init_dependencies (test, &testing);

	memset (&msg, 0, sizeof (msg));
	msg.data = buf;
	msg.payload = buf;
	msg.max_response = sizeof (buf);
	msg.payload_length = sizeof (struct tdisp_start_interface_request);
	msg.length = msg.payload_length;

	function_id = rand ();

	rq->header.version = UINT8_MAX;
	rq->header.message_type = TDISP_REQUEST_START_INTERFACE;
	rq->header.interface_id.function_id = function_id;

	status = tdisp_start_interface (&testing.tdisp_state, &testing.tdisp_driver_mock.base, &msg);

	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, sizeof (struct tdisp_error_response), msg.length);
	CuAssertIntEquals (test, msg.length, msg.payload_length);
	CuAssertPtrEquals (test, buf, msg.data);
	CuAssertPtrEquals (test, error_response, msg.payload);
	CuAssertIntEquals (test, TDISP_VERSION_1_0, error_response->header.version);
	CuAssertIntEquals (test, TDISP_ERROR_CODE_VERSION_MISMATCH, error_response->error_code);
	CuAssertIntEquals (test, 0, error_response->error_data);
	CuAssertIntEquals (test, TDISP_ERROR, error_response->header.message_type);
	CuAssertIntEquals (test, function_id, error_response->header.interface_id.function_id);

	tdisp_commands_testing_release_dependencies (test, &testing);
}

static void  tdisp_commands_test_start_interface_no_interface_context (CuTest *test)
{
	uint8_t buf[DOE_MESSAGE_MAX_SIZE_IN_BYTES];
	struct tdisp_start_interface_request *rq =  (struct tdisp_start_interface_request*) buf;
	struct tdisp_error_response *error_response = (struct tdisp_error_response*) buf;
	struct cmd_interface_msg msg;
	int status;
	struct tdisp_commands_testing testing;
	uint32_t function_id;

	TEST_START;

	tdisp_commands_testing_init_dependencies (test, &testing);

	memset (&msg, 0, sizeof (msg));
	msg.data = buf;
	msg.payload = buf;
	msg.max_response = sizeof (buf);
	msg.payload_length = sizeof (struct tdisp_start_interface_request);
	msg.length = msg.payload_length;

	function_id = rand ();

	rq->header.version = TDISP_CURRENT_VERSION;
	rq->header.message_type = TDISP_REQUEST_START_INTERFACE;
	rq->header.interface_id.function_id = function_id;

	status = tdisp_start_interface (&testing.tdisp_state, &testing.tdisp_driver_mock.base, &msg);

	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, sizeof (struct tdisp_error_response), msg.length);
	CuAssertIntEquals (test, msg.length, msg.payload_length);
	CuAssertPtrEquals (test, buf, msg.data);
	CuAssertPtrEquals (test, error_response, msg.payload);
	CuAssertIntEquals (test, TDISP_VERSION_1_0, error_response->header.version);
	CuAssertIntEquals (test, TDISP_ERROR_CODE_INVALID_INTERFACE, error_response->error_code);
	CuAssertIntEquals (test, 0, error_response->error_data);
	CuAssertIntEquals (test, TDISP_ERROR, error_response->header.message_type);
	CuAssertIntEquals (test, function_id, error_response->header.interface_id.function_id);

	tdisp_commands_testing_release_dependencies (test, &testing);
}

static void  tdisp_commands_test_start_interface_nonce_mismatch (CuTest *test)
{
	uint8_t buf[DOE_MESSAGE_MAX_SIZE_IN_BYTES];
	struct tdisp_start_interface_request *rq =  (struct tdisp_start_interface_request*) buf;
	struct tdisp_error_response *error_response = (struct tdisp_error_response*) buf;
	struct cmd_interface_msg msg;
	int status;
	struct tdisp_commands_testing testing;
	uint32_t function_id;
	uint8_t nonce[TDISP_START_INTERFACE_NONCE_SIZE];
	uint8_t i;
	struct tdisp_state *tdisp_state;

	TEST_START;

	tdisp_commands_testing_init_dependencies (test, &testing);

	tdisp_state = &testing.tdisp_state;

	memset (&msg, 0, sizeof (msg));
	msg.data = buf;
	msg.payload = buf;
	msg.max_response = sizeof (buf);
	msg.payload_length = sizeof (struct tdisp_start_interface_request);
	msg.length = msg.payload_length;

	function_id = rand ();
	for (i = 0; i < TDISP_START_INTERFACE_NONCE_SIZE; i++) {
		nonce[i] = rand ();
	}

	rq->header.version = TDISP_CURRENT_VERSION;
	rq->header.message_type = TDISP_REQUEST_START_INTERFACE;
	rq->header.interface_id.function_id = function_id;
	memcpy (rq->start_interface_nonce, nonce, TDISP_START_INTERFACE_NONCE_SIZE);

	tdisp_state->interface_context[0].interface_id.function_id = function_id;
	memcpy (tdisp_state->interface_context[0].start_interface_nonce, nonce,
		TDISP_START_INTERFACE_NONCE_SIZE);
	tdisp_state->interface_context[0].start_interface_nonce[0] =
		~tdisp_state->interface_context[0].start_interface_nonce[0];

	status = tdisp_start_interface (tdisp_state, &testing.tdisp_driver_mock.base, &msg);

	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, sizeof (struct tdisp_error_response), msg.length);
	CuAssertIntEquals (test, msg.length, msg.payload_length);
	CuAssertPtrEquals (test, buf, msg.data);
	CuAssertPtrEquals (test, error_response, msg.payload);
	CuAssertIntEquals (test, TDISP_VERSION_1_0, error_response->header.version);
	CuAssertIntEquals (test, TDISP_ERROR_CODE_INVALID_NONCE, error_response->error_code);
	CuAssertIntEquals (test, 0, error_response->error_data);
	CuAssertIntEquals (test, TDISP_ERROR, error_response->header.message_type);
	CuAssertIntEquals (test, function_id, error_response->header.interface_id.function_id);

	tdisp_commands_testing_release_dependencies (test, &testing);
}

static void  tdisp_commands_test_start_interface_fail (CuTest *test)
{
	uint8_t buf[DOE_MESSAGE_MAX_SIZE_IN_BYTES];
	struct tdisp_start_interface_request *rq =  (struct tdisp_start_interface_request*) buf;
	struct tdisp_error_response *error_response = (struct tdisp_error_response*) buf;
	struct cmd_interface_msg msg;
	int status;
	struct tdisp_commands_testing testing;
	uint32_t function_id;
	uint8_t nonce[TDISP_START_INTERFACE_NONCE_SIZE];
	uint8_t i;
	struct tdisp_state *tdisp_state;

	TEST_START;

	tdisp_commands_testing_init_dependencies (test, &testing);

	tdisp_state = &testing.tdisp_state;

	memset (&msg, 0, sizeof (msg));
	msg.data = buf;
	msg.payload = buf;
	msg.max_response = sizeof (buf);
	msg.payload_length = sizeof (struct tdisp_start_interface_request);
	msg.length = msg.payload_length;

	function_id = rand ();
	for (i = 0; i < TDISP_START_INTERFACE_NONCE_SIZE; i++) {
		nonce[i] = rand ();
	}

	rq->header.version = TDISP_CURRENT_VERSION;
	rq->header.message_type = TDISP_REQUEST_START_INTERFACE;
	rq->header.interface_id.function_id = function_id;
	memcpy (rq->start_interface_nonce, nonce, TDISP_START_INTERFACE_NONCE_SIZE);

	tdisp_state->interface_context[0].interface_id.function_id = function_id;
	memcpy (tdisp_state->interface_context[0].start_interface_nonce, nonce,
		TDISP_START_INTERFACE_NONCE_SIZE);

	status = mock_expect (&testing.tdisp_driver_mock.mock,
		testing.tdisp_driver_mock.base.start_interface_request, &testing.tdisp_driver_mock,
		TDISP_DRIVER_START_INTERFACE_REQUEST_FAILED, MOCK_ARG(function_id));

	CuAssertIntEquals (test, 0, status);

	status = tdisp_start_interface (tdisp_state, &testing.tdisp_driver_mock.base, &msg);

	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, sizeof (struct tdisp_error_response), msg.length);
	CuAssertIntEquals (test, msg.length, msg.payload_length);
	CuAssertPtrEquals (test, buf, msg.data);
	CuAssertPtrEquals (test, error_response, msg.payload);
	CuAssertIntEquals (test, TDISP_VERSION_1_0, error_response->header.version);
	CuAssertIntEquals (test, TDISP_ERROR_CODE_UNSPECIFIED, error_response->error_code);
	CuAssertIntEquals (test, 0, error_response->error_data);
	CuAssertIntEquals (test, TDISP_ERROR, error_response->header.message_type);
	CuAssertIntEquals (test, function_id, error_response->header.interface_id.function_id);

	tdisp_commands_testing_release_dependencies (test, &testing);
}


TEST_SUITE_START (tdisp_commands);

TEST (tdisp_commands_test_header_format);
TEST (tdisp_commands_test_get_version_request_format);
TEST (tdisp_commands_test_get_version_response_format);
TEST (tdisp_commands_test_get_capabilities_request_format);
TEST (tdisp_commands_test_get_capabilities_response_format);
TEST (tdisp_commands_test_tdisp_lock_interface_request_format);
TEST (tdisp_commands_test_tdisp_lock_interface_response_format);
TEST (tdisp_commands_test_get_device_interface_report_request_format);
TEST (tdisp_commands_test_get_device_interface_report_response_format);
TEST (tdisp_commands_test_mmio_range_format);
TEST (tdisp_commands_test_device_interface_report_format);
TEST (tdisp_commands_test_get_device_interface_state_request_format);
TEST (tdisp_commands_test_get_device_interface_state_response_format);
TEST (tdisp_commands_test_tdisp_start_interface_request_format);
TEST (tdisp_commands_test_tdisp_start_interface_response_format);
TEST (tdisp_commands_test_tdisp_stop_interface_request_format);
TEST (tdisp_commands_test_tdisp_stop_interface_response_format);
TEST (tdisp_commands_test_tdisp_error_response_format);
TEST (tdisp_commands_test_tdisp_extended_error_data_format);
TEST (tdisp_commands_test_get_version);
TEST (tdisp_commands_test_get_version_multiple_query);
TEST (tdisp_commands_test_get_version_max_interface_count);
TEST (tdisp_commands_test_get_version_invalid_params);
TEST (tdisp_commands_test_get_version_request_lt_min_length);
TEST (tdisp_commands_test_get_version_invalid_version);
TEST (tdisp_commands_test_get_version_insufficient_output_buffer);
TEST (tdisp_commands_test_get_version_no_interface_context);
TEST (tdisp_commands_test_get_version_out_of_interface_context);
TEST (tdisp_commands_test_get_capabilities);
TEST (tdisp_commands_test_get_capabilities_invalid_params);
TEST (tdisp_commands_test_get_capabilities_request_lt_min_length);
TEST (tdisp_commands_test_get_capabilities_invalid_version);
TEST (tdisp_commands_test_get_capabilities_insufficient_output_buffer);
TEST (tdisp_commands_test_get_capabilities_fail);
TEST (tdisp_commands_test_lock_interface);
TEST (tdisp_commands_test_lock_interface_invalid_params);
TEST (tdisp_commands_test_lock_interface_request_lt_min_length);
TEST (tdisp_commands_test_lock_interface_invalid_version);
TEST (tdisp_commands_test_lock_interface_insufficient_output_buffer);
TEST (tdisp_commands_test_lock_interface_get_interface_context_fail);
TEST (tdisp_commands_test_lock_interface_generate_random_buffer_fail);
TEST (tdisp_commands_test_lock_interface_lock_interface_request_fail);
TEST (tdisp_commands_test_get_device_interface_state);
TEST (tdisp_commands_test_get_device_interface_state_invalid_params);
TEST (tdisp_commands_test_get_device_interface_state_lt_min_length);
TEST (tdisp_commands_test_get_device_interface_state_invalid_version);
TEST (tdisp_commands_test_get_device_interface_state_insufficient_response_buffer);
TEST (tdisp_commands_test_get_device_interface_state_fail);
TEST (tdisp_commands_test_start_interface);
TEST (tdisp_commands_test_start_interface_invalid_params);
TEST (tdisp_commands_test_start_interface_lt_min_length);
TEST (tdisp_commands_test_start_interface_invalid_version);
TEST (tdisp_commands_test_start_interface_no_interface_context);
TEST (tdisp_commands_test_start_interface_nonce_mismatch);
TEST (tdisp_commands_test_start_interface_fail);

TEST_SUITE_END;
