// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdarg.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <linux/types.h>
#include <linux/i2c.h>
#include <linux/i2c-dev.h>
#include "crypto/checksum.h"
#include "logging/debug_log.h"


/**
 * File descriptor for the I2C bus connected to the device.
 */
int i2c;

/**
 * The 7-bit I2C address of the target device.
 */
uint8_t addr = 0x69;

/**
 * The CMS to use for the operation.
 */
uint8_t cms_id = 0;

/**
 * Offset within the CMS to access.
 */
uint32_t cms_offset = 0;

/**
 * Flag to ignore validation errors when processing commands.  Protocol and bus errors still
 * trigger a failure.
 */
bool ignore_errors = false;

/**
 * Enable and disable PEC on reads/writes.
 */
bool pec = true;

/**
 * Force a PEC error on a raw write transaction.  This is only applicable if a PEC byte is being
 * generated for the command.
 */
bool force_pec_error = false;

/**
 * Flag indicating a read or write operation.
 */
bool is_read = true;

/**
 * Flag indicating that raw bytes of the command should be displayed.
 */
bool raw_bytes = false;

/**
 * Log read for a vendor defined CMS uses the Cerberus log format.
 */
bool is_cerberus_log = false;

/**
 * For reset commands, force the device into recovery mode.
 */
bool force_recovery = false;

/**
 * The command to execute.
 */
const char *command = NULL;

/**
 * The file name provided with the command.
 */
const char *file_name = NULL;

/**
 * Indicate the specified file should be used to output messages.
 */
bool file_out = false;

/**
 * Array of raw data provided to the command.
 */
uint32_t raw_data[255];

/**
 * Number of raw data entries provided.
 */
size_t raw_data_count = 0;

/**
 * Add a delay after sending block write commands before issuing another command.
 */
bool use_write_delay = false;

/**
 * The delay to add after a block write, in microseconds.
 */
uint32_t write_delay = 1000;

/**
 * Output verbosity.
 */
int verbose = 0;


/**
 * Get the current monotonic clock count value.
 *
 * @param current Output for the current system time.
 */
static void get_current_time (struct timespec *current)
{
	int status;

	status = clock_gettime (CLOCK_MONOTONIC, current);
	if (status != 0) {
		printf ("Failed to get the current time: %s\n", strerror (errno));
		exit (1);
	}
}

/**
 * Get the duration between two time values.
 *
 * @param start The start time for the time duration.
 * @param end The end time for the time duration.
 *
 * @return The elapsed time, in microseconds.  If either clock is null, the elapsed time will be 0.
 */
uint32_t get_time_duration (const struct timespec *start, const struct timespec *end)
{
	if ((end == NULL) || (start == NULL)) {
		return 0;
	}

	if (start->tv_sec > end->tv_sec) {
		return 0;
	}
	else if (start->tv_sec == end->tv_sec) {
		if (start->tv_nsec > end->tv_nsec) {
			return 0;
		}
		else {
			return (end->tv_nsec - start->tv_nsec) / 1000ULL;
		}
	}
	else {
		uint32_t duration = end->tv_nsec / 1000ULL;

		duration += (1000000000ULL - start->tv_nsec) / 1000ULL;
		duration += (end->tv_sec - start->tv_sec) * 1000000;

		return duration;
	}
}

/**
 * Write data to an open file.
 *
 * @param fd The file descriptor for the file.
 * @param data Data to write.
 * @param length Amount of data to write.
 */
void write_to_file (int fd, const char *data, int length)
{
	if (write (fd, data, length) < 0) {
		printf ("Failed to write to output file %s: %s\n", file_name, strerror (errno));
		exit (1);
	}
}

/**
 * Print a single message either to the console or to a file.
 *
 * @param fd The file descriptor for an open file, if the output should be to a file.  Ignored if
 * not using file output (determined by file_out).
 * @param fmt The formatting string to print.
 * @param ... Formatting arguments.
 */
void print_message (int fd, const char *fmt, ...)
{
	char line[256];
	int line_len;
	va_list args;

	va_start (args, fmt);

	line_len = vsnprintf (line, sizeof (line), fmt, args);
	if (line_len > (int) sizeof (line)) {
		line[255] = '\0';
		line_len = 255;
	}

	if (!file_out) {
		printf ("%s", line);
	}
	else {
		write_to_file (fd, line, line_len);
	}

	va_end (args);
}

/**
 * Print a binary array either to the console or to a file.
 *
 * @param fd The file descriptor for an open file, if the output should be to a file.  Ignored if
 * not using file output (determined by file_name).
 * @param data The buffer that contains the data to print.
 * @param start First index of the array to be printed.
 * @param end Last index of the array to be printed.
 * @param label Label to apply to the array.
 * @param tabs The tab depth for the array.
 */
void output_array (int fd, const uint8_t *data, int start, int end, const char *label,
	const char *tabs)
{
	int i;

	print_message (fd, "%s%s (%d):", tabs, label, (end - start) + 1);
	for (i = start; i <= end; i++) {
		if ((((i - start) % 16) == 0)) {
			print_message (fd, "\n%s\t", tabs);
		}

		print_message (fd, "0x%02x ", data[i]);
	}
	print_message (fd, "\n");
}

/**
 * Print an array of bytes.
 *
 * @param data The buffer that contains the data to print.
 * @param start First index of the array to be printed.
 * @param end Last index of the array to be printed.
 * @param label Label to apply to the array.
 * @param tabs The tab depth for the array.
 */
void print_byte_array (const uint8_t *data, int start, int end, const char *label,
	const char *tabs)
{
	output_array (-1, data, start, end, label, tabs);
}

/**
 * Print an a data buffer in hex with address markers.
 *
 * @param data The data to print.
 * @param length Length of the data.
 * @param start_offset Starting offset for the data.
 */
void hex_dump (const uint8_t *data, uint32_t length, uint32_t start_offset)
{
	const uint8_t *pos = data;
	uint32_t offset = start_offset;
	uint8_t i;

	if (start_offset & 0xf) {
		/* Offset is not 16-byte aligned. */
		printf ("\n%08x: ", (start_offset & ~0xf));
		for (i = 0; i < (start_offset & 0xf); i++) {
			printf ("-- ");
		}

		while ((i < 0x10) && (length > 0)) {
			printf ("%02x ", *pos);
			i++;
			pos++;
			offset++;
			length--;
		}
	}

	while (length > 0) {
		if (!(offset & 0xf)) {
			printf ("\n%08x: ", offset);
		}

		printf ("%02x ", *pos);
		pos++;
		offset++;
		length--;
	}

	printf ("\n\n");
}

/**
 * Execute and SMBus block read command against the target device.
 *
 * @param cmd The command code to send to the device.
 * @param payload Output buffer to the command payload.  No SMBus overhead will be returned.
 * @param min_length The minimum amount of data that is required from the device.  Less than this is
 * considered a failure.
 * @param length The amount of data to read from the device.  It may not all be valid if the device
 * doesn't have a full amount of data to send.
 *
 * @return The number of bytes returned by the device.
 */
uint8_t smbus_block_read (uint8_t cmd, uint8_t *payload, uint8_t min_length, uint8_t length)
{
	struct i2c_msg msgs[2];
	struct i2c_rdwr_ioctl_data xfer;
	int smbus_overhead = 1;
	uint8_t *rx_smbus;
	uint8_t crc;
	struct timespec start;
	struct timespec end;

	if (pec) {
		smbus_overhead++;
	}

	rx_smbus = malloc (length + smbus_overhead);
	if (rx_smbus == NULL) {
		printf ("Failed to allocate Rx buffer\n");
		exit (1);
	}

	msgs[0].addr = addr;
	msgs[0].buf = &cmd;
	msgs[0].len = 1;
	msgs[0].flags = 0;

	msgs[1].addr = addr;
	msgs[1].buf = rx_smbus;
	msgs[1].len = length + smbus_overhead;
	msgs[1].flags = I2C_M_RD;

	xfer.nmsgs = 2;
	xfer.msgs = msgs;

	get_current_time (&start);
	if (ioctl (i2c, I2C_RDWR, &xfer) < 0) {
		printf ("Failed SMBus block read: %s\n", strerror (errno));
		exit (1);
	}
	get_current_time (&end);

	if (verbose >= 1) {
		printf ("Read Cmd (%d us): %d\n", get_time_duration (&start, &end), cmd);

		if (verbose >= 2) {
			print_byte_array (rx_smbus, 0, length + smbus_overhead - 1, "SMBus Rx", "");
			printf ("\n");
		}
	}

	if (length < rx_smbus[0]) {
		printf ("WARNING: Incomplete block read (%d < %d)\n", length, rx_smbus[0]);
	}
	else if (min_length > rx_smbus[0]) {
		printf ("Invalid response length for command %d.  Rx %d bytes.\n", cmd, rx_smbus[0]);
		exit (1);
	}

	length = rx_smbus[0];
	memcpy (payload, &rx_smbus[1], length);

	if (pec) {
		uint8_t crc_addr = addr << 1;

		/* Write */
		crc = checksum_init_smbus_crc8 (crc_addr);
		crc = checksum_update_smbus_crc8 (crc, &cmd, 1);

		/* Read */
		crc_addr |= 1;
		crc = checksum_update_smbus_crc8 (crc, &crc_addr, 1);
		crc = checksum_update_smbus_crc8 (crc, rx_smbus, 1 + length);

		if (crc != rx_smbus[length + 1]) {
			printf ("PEC failed: CRC=0x%x, Rx=%x\n", crc, rx_smbus[length + 1]);
			exit (1);
		}
	}

	free (rx_smbus);
	return length;
}

/**
 * Execute an SMBus block write command against the target device.
 *
 * @param cmd The command code to send to the device.
 * @param payload Payload to send in the command.  This must not have any SMBus overhead included.
 * @param length Length of the payload.
 */
void smbus_block_write (uint8_t cmd, uint8_t *payload, uint8_t length)
{
	struct i2c_msg msgs[1];
	struct i2c_rdwr_ioctl_data xfer;
	int smbus_overhead = 2;
	uint8_t *tx_smbus;
	uint8_t crc;
	struct timespec start;
	struct timespec end;

	if (pec) {
		smbus_overhead++;
	}

	tx_smbus = malloc (length + smbus_overhead);
	if (tx_smbus == NULL) {
		printf ("Failed to allocate Tx buffer.\n");
		exit (1);
	}

	tx_smbus[0] = cmd;
	tx_smbus[1] = length;
	memcpy (&tx_smbus[2], payload, length);

	if (pec) {
		crc = checksum_init_smbus_crc8 (addr << 1);
		crc = checksum_update_smbus_crc8 (crc, tx_smbus, length + 2);

		tx_smbus[length + 2] = crc;
		if (force_pec_error) {
			tx_smbus[length + 2] ^= 0x55;
		}
	}

	msgs[0].addr = addr;
	msgs[0].buf = tx_smbus;
	msgs[0].len = length + smbus_overhead;
	msgs[0].flags = 0;

	xfer.nmsgs = 1;
	xfer.msgs = msgs;

	get_current_time (&start);
	if (ioctl (i2c, I2C_RDWR, &xfer) < 0) {
		printf ("Failed SMBus block write: %s\n", strerror (errno));
		exit (1);
	}
	get_current_time (&end);

	if (verbose >= 1) {
		printf ("Write Cmd (%d us): %d, Length: %d\n", get_time_duration (&start, &end), cmd,
			length);

		if (verbose >= 2) {
			print_byte_array (tx_smbus, 0, length + smbus_overhead - 1, "SMBus Tx", "");
			printf ("\n");
		}
	}

	free (tx_smbus);

	if (use_write_delay) {
		usleep (write_delay);
	}
}


/**
 * OCP recovery command codes.
 */
enum {
	PROT_CAP = 34,			/**< Recovery capabilities command */
	DEVICE_ID = 35,			/**< Device Identifier */
	DEVICE_STATUS = 36,		/**< Current device status */
	RESET = 37,				/**< Device reset control */
	RECOVERY_CTRL = 38,		/**< Recovery image control */
	RECOVERY_STATUS = 39,	/**< Recovery image status */
	HW_STATUS = 40,			/**< Hardware status information. */
	INDIRECT_CTRL = 41,		/**< Control indirect access to memory regions. */
	INDIRECT_STATUS = 42,	/**< Status of indirect memory access. */
	INDIRECT_DATA = 43,		/**< Data access to indirect memory regions. */
	VENDOR = 44,			/**< Vendor-defined command. */
};

/**
 * Write a command to the device that has requires no special processing of the input data.  The
 * entire input stream will be converted to an array of bytes.
 *
 * raw_data and raw_data_count must be initialized with the required data.
 */
void write_command_byte_array (uint8_t cmd)
{
	uint8_t data[255];
	size_t i;

	/* Only the LSB of each input word is relevant for this command. */
	for (i = 0; i < raw_data_count; i++) {
		data[i] = raw_data[i];
	}

	smbus_block_write (cmd, data, raw_data_count);
}

/**
 * Send the PROT_CAP command to the device and parse the response.
 *
 * @param raw Flag indicating the raw response data should be printed.
 */
void read_prot_cap (bool raw)
{
	uint8_t data[15];
	char magic[9];

	smbus_block_read (PROT_CAP, data, sizeof (data), sizeof (data));

	memcpy ((uint8_t*) magic, data, 8);
	magic[8] = '\0';

	printf ("PROT_CAP:\n");
	printf ("\tMagic String: %s\n", magic);
	printf ("\tVersion: %d.%d\n", data[8], data[9]);
	printf ("\tCapabilites: 0x%04x\n", *((uint16_t*) &data[10]));
	printf ("\t\tIdentification: %s\n", (data[10] & (1U << 0)) ? "Yes" : "No");
	printf ("\t\tForced Recovery: %s\n", (data[10] & (1U << 1)) ? "Yes" : "No");
	printf ("\t\tManagement Reset: %s\n", (data[10] & (1U << 2)) ? "Yes" : "No");
	printf ("\t\tDevice Reset: %s\n", (data[10] & (1U << 3)) ? "Yes" : "No");
	printf ("\t\tDevice Status: %s\n", (data[10] & (1U << 4)) ? "Yes" : "No");
	printf ("\t\tRecovery Memory Access: %s\n", (data[10] & (1U << 5)) ? "Yes" : "No");
	printf ("\t\tLocal C-Image: %s\n", (data[10] & (1U << 6)) ? "Yes" : "No");
	printf ("\t\tPush C-Image: %s\n", (data[10] & (1U << 7)) ? "Yes" : "No");
	printf ("\t\tInterface Isolation: %s\n", (data[11] & (1U << 0)) ? "Yes" : "No");
	printf ("\t\tHardware Status: %s\n", (data[11] & (1U << 1)) ? "Yes" : "No");
	printf ("\t\tVendor Command: %s\n", (data[11] & (1U << 2)) ? "Yes" : "No");
	printf ("\tTotal CMS: %d\n", data[12]);
	printf ("\tMax Response Time: %dus\n", 1U << data[13]);
	printf ("\tHeartbeat: %dus\n", (data[14] == 0) ? 0 : (1U << data[14]));
	printf ("\n");

	if (raw) {
		print_byte_array (data, 0, 14, "Raw Data", "\t");
		printf ("\n");
	}
}

/**
 * Capability bits indicating support for different commands.
 */
enum {
	SUPPORT_DEVICE_ID = (1U << 0),									/**< The DEVICE_ID command is supported. */
	SUPPORT_RESET = (1U << 1) | (1U << 2) | (1U << 3) | (1U << 8),	/**< The RESET command is supported. */
	SUPPORT_DEVICE_STATUS = (1U << 4),								/**< The DEVICE_STATUS command is supported. */
	SUPPORT_INDIRECT = (1U << 5) | (1U << 7),						/**< The INDIRECT commands are supported. */
	SUPPORT_HW_STATUS = (1U << 9),									/**< The HW_STATUS command is supported. */
	SUPPORT_VENDOR = (1U << 10),									/**< The VENDOR command is supported. */
};

/**
 * Retrieve the capabilites bitmask from the device.
 *
 * @return The device capabilities.
 */
uint16_t get_device_capabilities ()
{
	uint8_t data[15];

	smbus_block_read (PROT_CAP, data, sizeof (data), sizeof (data));

	if (strncmp ("OCP RECV", (char*) data, 8) == 0) {
		return (data[11] << 8) | data[10];
	}
	else {
		return 0;
	}
}

/**
 * Write the PROT_CAP command to the device.
 *
 * raw_data and raw_data_count must be initialized with the required data.
 */
void write_prot_cap ()
{
	/* This is a read-only command, so the contents don't really matter. */
	write_command_byte_array (PROT_CAP);
}

/**
 * Send the DEVICE_ID command to the device and parse the response.
 *
 * @param raw Flag indicating the raw response data should be printed.
 */
void read_device_id (bool raw)
{
	uint8_t data[255];
	char vendor[232];
	int bytes;

	bytes = smbus_block_read (DEVICE_ID, data, 24, sizeof (data));

	if (data[1] > 231) {
		printf ("%s: Response malformed.  Vendor string too long (%d)\n", __func__, data[1]);
		exit (1);
	}
	else if (bytes != (24 + data[1])) {
		printf ("%s: Invalid response length %d, with vender string length %d.\n", __func__,
			bytes, data[1]);
		exit (1);
	}

	memcpy ((uint8_t*) vendor, &data[24], data[1]);
	vendor[data[1]] = '\0';

	printf ("DEVICE_ID:\n");
	switch (data[0]) {
		case 0x0:
			printf ("\tPCI Vendor:\n");
			printf ("\t\tVendor ID: 0x%04x\n", *((uint16_t*) &data[2]));
			printf ("\t\tDevice ID:  0x%04x\n", *((uint16_t*) &data[4]));
			printf ("\t\tSubsystem Vendor ID:  0x%04x\n", *((uint16_t*) &data[6]));
			printf ("\t\tSubsystem Device ID:  0x%04x\n", *((uint16_t*) &data[8]));
			printf ("\t\tRevision ID:  0x%02x\n", data[10]);
			print_byte_array (data, 11, 23, "Pad", "\t\t");
			break;

		case 0x1:
			printf ("\tIANA:\n");
			printf ("\t\tEnterprise ID: 0x%08x\n", *((uint32_t*) &data[2]));
			print_byte_array (data, 6, 17, "Product Identifier", "\t\t");
			print_byte_array (data, 18, 23, "Pad", "\t\t");
			break;

		case 0x2:
			print_byte_array (data, 2, 17, "UUID", "\t");
			print_byte_array (data, 18, 23, "Pad", "\t");
			break;

		case 0x3:
			printf ("\tPnP Vendor:\n");
			printf ("\t\tVendor Identifier: 0x%02x%02x%02x\n", data[4], data[3], data[2]);
			printf ("\t\tProduct Identifier: 0x%08x\n", *((uint32_t*) &data[5]));
			print_byte_array (data, 9, 23, "Pad", "\t\t");
			break;

		case 0x4:
			printf ("\tACPI Vendor:\n");
			printf ("\t\tVendor Identifier: 0x%08x\n", *((uint32_t*) &data[2]));
			printf ("\t\tProduct Identifier: 0x%02x%02x%02x\n", data[8], data[7], data[6]);
			print_byte_array (data, 9, 23, "Pad", "\t\t");
			break;

		case 0xf:
			printf ("\tNVMe-MI:\n");
			printf ("\t\tVendor ID: 0x%04x\n", *((uint16_t*) &data[2]));
			print_byte_array (data, 4, 23, "Device Serial Number", "\t\t");
			break;

		default:
			printf ("\tReserved: 0x%02x\n", data[0]);
			print_byte_array (data, 2, 23, "Unknown ID", "\t\t");
			break;
	}
	if (data[1] != 0) {
		printf ("\tVendor String: %s\n", vendor);
	}
	printf ("\n");

	if (raw) {
		print_byte_array (data, 0, bytes - 1, "Raw Data", "\t");
		printf ("\n");
	}
}

/**
 * Write the DEVICE_ID command to the device.
 *
 * raw_data and raw_data_count must be initialized with the required data.
 */
void write_device_id ()
{
	/* This is a read-only command, so the contents don't really matter. */
	write_command_byte_array (DEVICE_ID);
}

/**
 * List of status messages for the device.
 */
const char *DEVICE_STATUS_STR[] = {
	[0x0] = "Status Pending",
	[0x1] = "Device Healthy",
	[0x2] = "Device Error",
	[0x3] = "Recovery Mode",
	[0x4] = "Recovery Pending",
	[0x5] = "Running Recovery Image",
	[0x6] = "Reserved",
	[0x7] = "Reserved",
	[0x8] = "Reserved",
	[0x9] = "Reserved",
	[0xa] = "Reserved",
	[0xb] = "Reserved",
	[0xc] = "Reserved",
	[0xd] = "Reserved",
	[0xe] = "Boot Failure",
	[0xf] = "Fatal Error"
};

/**
 * List of protocol error messages for the device.
 */
const char *PROTOCOL_ERROR_STR[] = {
	[0x0] = "No Error",
	[0x1] = "Unsupported Command",
	[0x2] = "Unsupported Paramater",
	[0x3] = "Length Write Error",
	[0x4] = "CRC Error",
	[0x5] = "Reserved",
	[0x6] = "Reserved",
	[0x7] = "Reserved",
	[0x8] = "Reserved",
	[0x9] = "Reserved",
	[0xa] = "Reserved",
	[0xb] = "Reserved",
	[0xc] = "Reserved",
	[0xd] = "Reserved",
	[0xe] = "Reserved",
	[0xf] = "Reserved",
};

/**
 * List of recovery reason codes.
 */
const char *RECOVERY_REASON_STR[] = {
	[0x00] = "No boot failure",
	[0x01] = "Generic hardware error",
	[0x02] = "Generic hardware soft error",
	[0x03] = "Self-test failure",
	[0x04] = "Missing or corrupt critical data",
	[0x05] = "Missing or corrupt key manifest",
	[0x06] = "Authentication failure on key manifest",
	[0x07] = "Anti-rollback failure on key manifest",
	[0x08] = "Missing or corrupt boot loader firmware image",
	[0x09] = "Authentication failure on boot loader firmware image",
	[0x0a] = "Anti-Rollback failure on boot loader firmware image",
	[0x0b] = "Missing or corrupt main firmware image",
	[0x0c] = "Authentication failure on main firmware image",
	[0x0d] = "Anti-Rollback failure on main firmware image",
	[0x0e] = "Missing or corrupt recovery firmware",
	[0x0f] = "Authentication failure on recovery firmware",
	[0x10] = "Anti-rollback failure on recovery firmware",
	[0x11] = "Forced recovery"
};

/**
 * Send the DEVICE_STATUS command to the device and parse the response.
 *
 * @param raw Flag indicating the raw response data should be printed.
 */
void read_device_status (bool raw)
{
	uint8_t data[255];
	int bytes;
	uint16_t reason;

	bytes = smbus_block_read (DEVICE_STATUS, data, 7, sizeof (data));

	if (data[6] > 249) {
		printf ("%s: Response malformed.  Vendor data too long (%d)\n", __func__, data[6]);
		exit (1);
	}
	else if (bytes != (7 + data[6])) {
		printf ("%s: Invalid response length %d, with vender length %d.\n", __func__, bytes,
			data[1]);
		exit (1);
	}

	reason = *((uint16_t*) &data[2]);

	printf ("DEVICE_STATUS:\n");
	printf ("\tStatus: 0x%02x%s%s\n", data[0], (data[0] <= 0xf) ? " -> " : "",
		(data[0] <= 0xf) ? DEVICE_STATUS_STR[data[0]] : "");
	printf ("\tProtocol Error: 0x%02x%s%s\n", data[1], (data[1] <= 0xf) ? " -> " : "",
		(data[1] <= 0xf) ? PROTOCOL_ERROR_STR[data[1]] : "");
	printf ("\tRecovery Reason Code: 0x%04x%s%s\n", reason, (reason <= 0x11) ? " -> " : "",
		(reason <= 0x11) ? RECOVERY_REASON_STR[reason] : "");
	printf ("\tHeartbeat: 0x%04x\n", *((uint16_t*) &data[4]));

	if (data[6] != 0) {
		printf ("\tVendor:\n");
		if (data[6] == 5) {
			/* Assume a vender message formatted per the Cerberus code. */
			printf ("\t\tFailure ID: 0x%02x\n", data[7]);
			printf ("\t\tError Code: 0x%08x\n", *((uint32_t*) &data[8]));
		}
		else {
			print_byte_array (data, 7, bytes - 1, "Status", "\t\t");
		}
	}

	printf ("\n");

	if (raw) {
		print_byte_array (data, 0, bytes - 1, "Raw Data", "\t");
		printf ("\n");
	}
}

/**
 * Write the DEVICE_STATUS command to the device.
 *
 * raw_data and raw_data_count must be initialized with the required data.
 */
void write_device_status ()
{
	/* This is a read-only command, so the contents don't really matter. */
	write_command_byte_array (DEVICE_STATUS);
}

/**
 * Check the device for any protocol errors.
 */
void check_protocol_error ()
{
	uint8_t data[255];

	smbus_block_read (DEVICE_STATUS, data, 7, sizeof (data));

	if (data[1] != 0) {
		printf ("Protocol Error: 0x%02x%s%s\n", data[1], (data[1] <= 0xf) ? " -> " : "",
			(data[1] <= 0xf) ? PROTOCOL_ERROR_STR[data[1]] : "");
		exit (1);
	}
}

/**
 * List of values for device reset control.
 */
const char *RESET_CONTROL_STR[] = {
	[0x0] = "No Reset",
	[0x1] = "Reset Device",
	[0x2] = "Reset Management",
};

/**
 * Read the RESET information and parse the response.
 *
 * @param raw Flag indicating the raw response data should be printed.
 */
void read_reset (bool raw)
{
	uint8_t data[3];

	smbus_block_read (RESET, data, sizeof (data), sizeof (data));

	printf ("RESET:\n");
	printf ("\tDevice Reset Control: 0x%02x%s%s\n", data[0], (data[0] <= 2) ? " -> " : "",
		(data[0] <= 2) ? RESET_CONTROL_STR[data[0]] : "");
	printf ("\tForced Recovery: %s\n",
		(data[1] == 0) ? "No" : ((data[1] == 0xf) ? "Yes" : "Invalid"));
	printf ("\tInterface Control: %s\n",
		(data[2] == 0) ? "Disable Mastering" : ((data[2] == 1) ? "Enable Mastering" : "Invalid"));
	printf ("\n");

	if (raw) {
		print_byte_array (data, 0, 2, "Raw Data", "\t");
		printf ("\n");
	}
}

/**
 * Write the RESET command to the device.
 *
 * raw_data and raw_data_count must be initialized with the required data.
 */
void write_reset ()
{
	/* There are no multi-byte fields, so just covert the entire buffer to bytes. */
	write_command_byte_array (RESET);
}

/**
 * Send the RESET command to the device.
 *
 * @param type The type of reset to perform.
 */
void send_reset (uint8_t type)
{
	uint8_t data[3];

	data[0] = type;
	data[1] = (force_recovery) ? 0xf : 0x0;
	data[2] = 0;

	smbus_block_write (RESET, data, sizeof (data));
}

/**
 * List of values for recovery image selection.
 */
const char *RECOVERY_IMAGE_STR[] = {
	[0x0] = "No operation",
	[0x1] = "Use recovery image from a memory window (CMS)",
	[0x2] = "Use recovery image stored on the device (C-Image)",
};

/**
 * Read the RECOVERY_CTRL information and parse the response.
 *
 * @param raw Flag indicating the raw response data should be printed.
 */
void read_recovery_ctrl (bool raw)
{
	uint8_t data[3];

	smbus_block_read (RECOVERY_CTRL, data, sizeof (data), sizeof (data));

	printf ("RECOVERY_CTRL:\n");
	printf ("\tComponent Memory Space: 0x%02x\n", data[0]);
	printf ("\tRecovery Image Selection: 0x%02x%s%s\n", data[1], (data[1] <= 2) ? " -> " : "",
		(data[1] <= 2) ? RECOVERY_IMAGE_STR[data[1]] : "");
	printf ("\tActivate Recovery Image: %s\n",
		(data[2] == 0) ? "No" : ((data[2] == 0xf) ? "Yes" : "Invalid"));
	printf ("\n");

	if (raw) {
		print_byte_array (data, 0, 2, "Raw Data", "\t");
		printf ("\n");
	}
}

/**
 * Write the RECOVERY_CTRL command to the device.
 *
 * raw_data and raw_data_count must be initialized with the required data.
 */
void write_recovery_ctrl ()
{
	/* There are no multi-byte fields, so just covert the entire buffer to bytes. */
	write_command_byte_array (RECOVERY_CTRL);
}

/**
 * Send the RECOVERY_CTRL command to configure the recovery CMS.
 *
 * @param cms The CMS region to enable for recovery
 * @param activate Flag indicating if the recovery image should be activated.
 */
void send_recovery_ctrl (uint8_t cms, bool activate)
{
	uint8_t data[3];

	data[0] = cms;
	data[1] = 0x1;
	data[2] = (activate) ? 0xf : 0x0;

	smbus_block_write (RECOVERY_CTRL, data, sizeof (data));
}

/**
 * List of recovery status messages for the device.
 */
const char *RECOVERY_STATUS_STR[] = {
	[0x0] = "Not in recovery mode",
	[0x1] = "Awaiting recovery image",
	[0x2] = "Booting recovery image",
	[0x3] = "Recovery successful",
	[0x4] = "Reserved",
	[0x5] = "Reserved",
	[0x6] = "Reserved",
	[0x7] = "Reserved",
	[0x8] = "Reserved",
	[0x9] = "Reserved",
	[0xa] = "Reserved",
	[0xb] = "Reserved",
	[0xc] = "Recovery failed",
	[0xd] = "Recovery image authentication error",
	[0xe] = "Error entering recovery mode",
	[0xf] = "Invalid component address space"
};

/**
 * Send the RECOVERY_STATUS command to the device and parse the response.
 *
 * @param raw Flag indicating the raw response data should be printed.
 */
void read_recovery_status (bool raw)
{
	uint8_t data[2];

	smbus_block_read (RECOVERY_STATUS, data, sizeof (data), sizeof (data));

	printf ("RECOVERY_STATUS:\n");
	printf ("\tStatus: 0x%02x%s%s\n", data[0], (data[0] <= 0xf) ? " -> " : "",
		(data[0] <= 0xf) ? RECOVERY_STATUS_STR[data[0]] : "");
	printf ("\tVendor: 0x%02x\n", data[1]);
	printf ("\n");

	if (raw) {
		print_byte_array (data, 0, 1, "Raw Data", "\t");
		printf ("\n");
	}
}

/**
 * Write the RECOVERY_STATUS command to the device.
 *
 * raw_data and raw_data_count must be initialized with the required data.
 */
void write_recovery_status ()
{
	/* This is a read-only command, so the contents don't really matter. */
	write_command_byte_array (RECOVERY_STATUS);
}

/**
 * Send an RECOVERY_STATUS command to check the device for any recovery image errors.
 */
void check_recovery_status ()
{
	uint8_t data[2];

	smbus_block_read (RECOVERY_STATUS, data, sizeof (data), sizeof (data));

	if (data[0] == 0xf) {
		printf ("Not a valid recovery image region\n");

		if (!ignore_errors) {
			exit (1);
		}
	}
}

/**
 * Send the HW_STATUS command to the device and parse the response.
 *
 * @param raw Flag indicating the raw response data should be printed.
 */
void read_hw_status (bool raw)
{
	uint8_t data[255];
	int bytes;
	uint16_t temp_val;
	int temperature;

	bytes = smbus_block_read (HW_STATUS, data, 5, sizeof (data));

	if (data[4] > 250) {
		printf ("%s: Response malformed.  Vendor data too long (%d)\n", __func__, data[4]);
		exit (1);
	}
	else if (bytes != (5 + data[4])) {
		printf ("%s: Invalid response length %d, with vender length %d.\n", __func__, bytes,
			data[1]);
		exit (1);
	}

	temp_val = *((uint16_t*) &data[2]);
	if (temp_val < 0x7f) {
		temperature = temp_val;
	}
	else if (temp_val > 0xc4) {
		temperature = (int16_t) temp_val;
	}
	else if ((temp_val == 0x80) || (temp_val == 0x81)) {
		temperature = temp_val << 8;
	}

	printf ("HW_STATUS:\n");
	printf ("\tStatus: 0x%02x\n", data[0]);
	printf ("\t\tDevice Temperature Is Critical: %s\n", (data[0] & (1U << 0)) ? "Yes" : "No");
	printf ("\t\tHardware Soft Error: %s\n", (data[0] & (1U << 1)) ? "Yes" : "No");
	printf ("\t\tHardware Fatal Error: %s\n", (data[0] & (1U << 2)) ? "Yes" : "No");
	printf ("Vendor Bitmask: 0x%02x\n", data[1]);

	if (temperature & 0x8000) {
		printf ("Composite Temperature: %s\n",
			(temp_val == 0x80) ? "No Data" : ((temp_val == 0x81) ? "Sensor Failure" : "Invalid"));
	}
	else {
		printf ("Composite Temperature: %d\n", temperature);
	}

	if (data[4] != 0) {
		print_byte_array (data, 5, bytes - 1, "Vendor", "\t");
	}
	printf ("\n");

	if (raw) {
		print_byte_array (data, 0, bytes - 1, "Raw Data", "\t");
		printf ("\n");
	}
}

/**
 * Write the HM_STATUS command to the device.
 *
 * raw_data and raw_data_count must be initialized with the required data.
 */
void write_hw_status ()
{
	/* This is a read-only command, so the contents don't really matter. */
	write_command_byte_array (HW_STATUS);
}

/**
 * Read the INDIRECT_CTRL information and parse the response.
 *
 * @param raw Flag indicating the raw response data should be printed.
 */
void read_indirect_ctrl (bool raw)
{
	uint8_t data[6];

	smbus_block_read (INDIRECT_CTRL, data, sizeof (data), sizeof (data));

	printf ("INDIRECT_CTRL:\n");
	printf ("\tComponent Memory Space: 0x%02x\n", data[0]);
	printf ("\tReserved: 0x%02x\n", data[1]);
	printf ("\tIndirect Memory Offset: 0x%08x\n", *((uint32_t*) &data[2]));
	printf ("\n");

	if (raw) {
		print_byte_array (data, 0, 5, "Raw Data", "\t");
		printf ("\n");
	}
}

/**
 * Write the INDIRECT_CTRL command to the device.
 *
 * raw_data and raw_data_count must be initialized with the required data.
 */
void write_indirect_ctrl ()
{
	uint8_t data[255];
	size_t bytes = 0;
	size_t remain = raw_data_count;

	if (remain > 0) {
		/* Component Memory Space */
		data[bytes] = raw_data[bytes];
		bytes++;
		remain--;
	}

	if (remain > 0) {
		/* Reserved */
		data[bytes] = raw_data[bytes];
		bytes++;
		remain--;
	}

	if (remain > 0) {
		/* Indirect Memory Offset */
		*((uint32_t*) &data[bytes]) = raw_data[bytes];
		bytes += 4;
		remain--;
	}

	for (; (bytes < 256) && (bytes < remain); bytes++) {
		/* Just convert any extra data as a byte array. */
		data[bytes] = raw_data[bytes];
	}

	smbus_block_write (INDIRECT_CTRL, data, bytes);
}

/**
 * Send the INDIRECT_CTRL command to configure the current CMS.
 *
 * @param cms The CMS region to enable.
 * @param offset Offset within the region.
 */
void send_indirect_ctrl (uint8_t cms, uint32_t offset)
{
	uint8_t data[6];

	data[0] = cms;
	data[1] = 0;
	*((uint32_t*) &data[2]) = offset;

	smbus_block_write (INDIRECT_CTRL, data, sizeof (data));
}

/**
 * List of types for indirect memory regions.
 */
const char *REGION_TYPE_STR[] = {
	[0x0] = "Code space for recovery (RW)",
	[0x1] = "Log using the OCP specified format (RO)",
	[0x2] = "Reserved",
	[0x3] = "Reserved",
	[0x4] = "Reserved",
	[0x5] = "Vendor defined region (RW)",
	[0x6] = "Vendor defined region (RO)",
	[0x7] = "Unsupported region",
	[0x8] = "Code space for recovery (RW), requires polling",
	[0x9] = "Log using the OCP specified format (RO), requires polling",
	[0xa] = "Reserved",
	[0xb] = "Reserved",
	[0xc] = "Reserved",
	[0xd] = "Vendor defined region (RW), requires polling",
	[0xe] = "Vendor defined region (RO), requires polling",
	[0xf] = "Unsupported region"
};

/**
 * Send the INDIRECT_STATUS command to the device and parse the response.
 *
 * @param raw Flag indicating the raw response data should be printed.
 */
void read_indirect_status (bool raw)
{
	uint8_t data[6];

	smbus_block_read (INDIRECT_STATUS, data, sizeof (data), sizeof (data));

	printf ("INDIRECT_STATUS:\n");
	printf ("\tStatus: 0x%02x\n", data[0]);
	printf ("\t\tOverflow CMS, Wrapped: %s\n", (data[0] & (1U << 0)) ? "Yes" : "No");
	printf ("\t\tRead Only Error: %s\n", (data[0] & (1U << 1)) ? "Yes" : "No");
	printf ("\t\tPolling CMS ACK: %s\n", (data[0] & (1U << 2)) ? "Yes" : "No");
	printf ("\tRegion Type: 0x%02x%s%s\n", data[1], (data[1] <= 0xf) ? " -> " : "",
		(data[1] <= 0xf) ? REGION_TYPE_STR[data[1]] : "");
	printf ("\tRegion Size: 0x%08x -> 0x%x bytes\n", *((uint32_t*) &data[2]),
		*((uint32_t*) &data[2]) << 2);
	printf ("\n");

	if (raw) {
		print_byte_array (data, 0, 5, "Raw Data", "\t");
		printf ("\n");
	}
}

/**
 * Write the INDIRECT_STATUS command to the device.
 *
 * raw_data and raw_data_count must be initialized with the required data.
 */
void write_indirect_status ()
{
	/* This is a read-only command, so the contents don't really matter. */
	write_command_byte_array (INDIRECT_STATUS);
}

/**
 * Send an INDIRECT_STATUS command to check the device for any indirect access errors and confirm
 * the expected region type.
 *
 * @param region_type An option region type code to compare against the active CMS.  If this is
 * negative, type checking will be skipped, but an unsupported region will still trigger an error.
 * @param fail_wrap Flag indicating the program should fail if a CMS wrap is detected.
 *
 * @return true if the region is the expected type or type checking was skipped.
 */
bool check_indirect_status (int region_type, bool fail_wrap)
{
	uint8_t data[6];

	smbus_block_read (INDIRECT_STATUS, data, sizeof (data), sizeof (data));

	if (fail_wrap && (data[0] & (1U << 0))) {
		printf ("Overflow memory region\n");
		exit (1);
	}

	if (data[0] & (1U << 1)) {
		printf ("Write to RO CMS\n");
		exit (1);
	}

	if ((data[1] & 7) == 0x7) {
		printf ("Unsupported CMS\n");

		if (!ignore_errors) {
			exit (1);
		}
	}

	return ((data[1] & 0xf) == region_type);
}

/**
 * Poll the INDIRECT_STATUS command waiting for the device to ACK.
 */
void wait_for_cms_ack ()
{
	uint8_t data[6];

	do {
		smbus_block_read (INDIRECT_STATUS, data, sizeof (data), sizeof (data));
	} while (!(data[0] & (1U << 2)));
}

/**
 * Query INDIRECT_STATUS to get the total size of the active CMS.
 *
 * @return The region size, reported in 4-byte units.
 */
uint32_t get_indirect_size ()
{
	uint8_t data[6];

	smbus_block_read (INDIRECT_STATUS, data, sizeof (data), sizeof (data));

	return *((uint32_t*) &data[2]);
}

/**
 * Read INDIRECT_DATA and parse the response.
 */
void read_indirect_data ()
{
	uint8_t data[255];
	int bytes;

	bytes = smbus_block_read (INDIRECT_DATA, data, 0, sizeof (data));

	print_byte_array (data, 0, bytes - 1, "INDIRECT_DATA", "");
	printf ("\n");
}

/**
 * Write the INDIRECT_DATA command to the device.
 *
 * raw_data and raw_data_count must be initialized with the required data.
 */
void write_indirect_data ()
{
	/* This command just sends an array of bytes. */
	write_command_byte_array (INDIRECT_DATA);
}

/**
 * Read the entire contents of a single CMS.
 *
 * @param cms The CMS to should be red.
 * @param offset An offset within the CMS to start reading.
 * @param file_out Output file for the data.  Null when using a memory buffer.
 * @param data_out Output for a memory buffer with the data.  Null when using a file.
 *
 * @return The number of bytes read from the CMS.
 */
uint32_t dump_cms_data (uint8_t cms, uint32_t offset, const char *file_out, uint8_t **data_out)
{
	uint32_t cms_size;
	uint32_t length;
	uint8_t *data;
	int fd;
	uint32_t pos;
	uint8_t cmd_data[252];

	send_indirect_ctrl (cms, offset);
	check_protocol_error ();
	check_indirect_status (-1, false);

	cms_size = get_indirect_size ();
	cms_size <<= 2;

	if (offset < cms_size) {
		length = cms_size - ((offset + 3) & ~0x3);
	}
	else {
		printf ("WARNING:  Offset beyond end of CMS %d with size %u\n", cms, cms_size);
		length = cms_size;
	}

	if (!file_out) {
		data = malloc (length);
		if (data == NULL) {
			printf ("Failed to allocate buffer for data\n");
			exit (1);
		}
	}
	else {
		fd = open (file_out, O_RDWR | O_CREAT,
			S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH);
		if (fd < 0) {
			printf ("Failed to open output file %s: %s\n", file_out, strerror (errno));
			exit (1);
		}
	}

	pos = 0;
	while (pos != length) {
		int bytes = smbus_block_read (INDIRECT_DATA, cmd_data, 0, sizeof (cmd_data));

		if (bytes == 0) {
			check_protocol_error ();
			check_indirect_status (-1, true);

			printf ("No data received from CMS %d at 0x%x\n", cms, offset + pos);
			exit (1);
		}

		if (!file_out) {
			memcpy (&data[pos], cmd_data, bytes);
		}
		else {
			if (write (fd, cmd_data, bytes) < 0) {
				printf ("Failed to write to output file %s: %s\n", file_out, strerror (errno));
				exit (1);
			}
		}

		pos += bytes;
	}

	if (file_out) {
		close (fd);
	}
	else {
		*data_out = data;
	}

	return length;
}

#pragma pack(push, 1)
/**
 * OCP Recovery log header format.
 */
struct ocp_log_entry_header {
	uint16_t log_magic;		/**< Start of entry marker.   This is 0xe5e5. */
	uint16_t length;		/**< Total length of the entry. */
	uint32_t entry_id;		/**< Unique entry identifier. */
	uint16_t format;		/**< Format of the message body. */
};
#pragma pack(pop)

/**
 * Parse a device log formatted per the OCP Recovery spec.
 *
 * @param data The log data.
 * @param length The amount of log data.
 */
void parse_ocp_log (uint8_t *data, uint32_t length)
{
	struct ocp_log_entry_header *header;
	int fd = -1;

	if (file_name) {
		fd = open (file_name, O_RDWR | O_CREAT,
			S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH);
		if (fd < 0) {
			printf ("Failed to open output file %s: %s\n", file_name, strerror (errno));
			exit (1);
		}
	}

	while (length >= sizeof (struct ocp_log_entry_header)) {
		header = (struct ocp_log_entry_header*) data;
		data += sizeof (header);
		length -= sizeof (header);

		if (header->log_magic != 0xe5e5) {
			print_message (fd, "Invalid log entry marker 0x%04x\n", header->log_magic);
			exit (1);
		}

		if (length < header->length) {
			print_message (fd, "Malformed message length 0x%04x, remaining 0x%04x\n",
				header->length, length);
			exit (1);
		}

		print_message (fd, "Entry: 0x%08x\n", header->entry_id);
		print_message (fd, "\tFormat:  0x%02x\n", header->format);
		output_array (fd, data, 0, header->length - 1, "Msg Body", "\t");

		data += header->length;
		length -= header->length;
	}

	if (length != 0) {
		print_message (fd, "Extra %u bytes of data at end of log\n", length);
	}

	if (file_name) {
		close (fd);
	}
}

/**
 * Parse a device log using Cerberus log formatting.
 *
 * @param data The log data.
 * @param length The amount of log data.
 */
void parse_cerberus_log (uint8_t *data, uint32_t length)
{
	struct debug_log_entry *msg;
	int fd = -1;

	if (file_name) {
		fd = open (file_name, O_RDWR | O_CREAT,
			S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH);
		if (fd < 0) {
			printf ("Failed to open output file %s: %s\n", file_name, strerror (errno));
			exit (1);
		}
	}

	while (length >= sizeof (struct debug_log_entry)) {
		msg = (struct debug_log_entry*) data;

		if (!LOGGING_IS_ENTRY_START (msg->header.log_magic)) {
			print_message (fd, "Invalid log entry marker 0x%02x\n", msg->header.log_magic);
			exit (1);
		}

		if (length < msg->header.length) {
			print_message (fd, "Malformed message length 0x%04x, remaining 0x%04x\n",
				msg->header.length, length);
			exit (1);
		}

		print_message (fd, "Entry: 0x%08x\n", msg->header.entry_id);
		print_message (fd, "\tHeader Format: 0x%02x\n", msg->header.log_magic);
		print_message (fd, "\tEntry Format:  0x%02x\n", msg->entry.format);
		print_message (fd, "\tSeverity: 0x%02x\n", msg->entry.severity);
		print_message (fd, "\tComponent: 0x%02x\n", msg->entry.component);
		print_message (fd, "\tMessage ID: 0x%02x\n", msg->entry.msg_index);
		print_message (fd, "\tArg1: 0x%08x\n", msg->entry.arg1);
		print_message (fd, "\tArg2: 0x%08x\n", msg->entry.arg2);
		print_message (fd, "\tTimestamp: 0x%llx\n", msg->entry.time);

		if (msg->header.length > sizeof (struct debug_log_entry)) {
			output_array (fd, data, sizeof (struct debug_log_entry), msg->header.length - 1,
				"Unknown Data", "\t");
		}

		data += msg->header.length;
		length -= msg->header.length;
	}

	if (length != 0) {
		print_message (fd, "Extra %u bytes of data at end of log\n", length);
	}

	if (file_name) {
		close (fd);
	}
}

/**
 * Read the VENDOR information and parse the response.
 */
void read_vendor ()
{
	uint8_t data[255];
	int bytes;

	bytes = smbus_block_read (VENDOR, data, 0, sizeof (data));

	print_byte_array (data, 0, bytes - 1, "VENDOR", "");
	printf ("\n");
}

/**
 * Write the VENDOR command to the device.
 *
 * raw_data and raw_data_count must be initialized with the required data.
 */
void write_vendor ()
{
	/* The format of this command is unknown.  Treat it as an array of bytes. */
	write_command_byte_array (VENDOR);
}


/**
 * Execute the 'load_img' command that sends a recovery image to the device.
 */
void command_load_image ()
{
	struct stat stat;
	int fd;
	bool valid;
	uint32_t max_length;
	uint8_t data[252];
	int bytes;

	fd = open (file_name, O_RDONLY);
	if (fd < 0) {
		printf ("Failed to open input file %s: %s\n", file_name, strerror (errno));
		exit (1);
	}

	if (fstat (fd, &stat) < 0) {
		printf ("Failed to check size of input file %s: %s\n", file_name, strerror (errno));
		exit (1);
	}

	send_indirect_ctrl (cms_id, cms_offset);
	check_protocol_error ();

	valid = check_indirect_status (0, false);
	if (!valid) {
		printf ("CMS %d is not a code memory region\n", cms_id);

		if (!ignore_errors) {
			exit (1);
		}
	}

	max_length = get_indirect_size ();
	if ((uint32_t) ((stat.st_size + 3) / 4) > max_length) {
		printf ("CMS %d is not large enough for the image:  CMS=%u, file=%u\n", cms_id, max_length,
			(uint32_t) ((stat.st_size + 3) / 4));

		if (!ignore_errors) {
			exit (1);
		}
	}

	do {
		bytes = read (fd, data, sizeof (data));
		if (bytes > 0) {
			smbus_block_write (INDIRECT_DATA, data, bytes);
		}
	} while (bytes > 0);

	if (bytes < 0) {
		printf ("Failed to read data from input file %s: %s\n", file_name, strerror (errno));
		exit (1);
	}

	check_protocol_error ();
	check_indirect_status (-1, false);

	close (fd);
}

/**
 * Execute the 'verify_img' command that confirms the expected data is in device memory.
 */
void command_verify_image ()
{
	struct stat stat;
	int fd;
	uint32_t max_length;
	uint8_t img_data[252];
	uint8_t device_data[252];
	int img_bytes;
	int device_bytes;

	fd = open (file_name, O_RDONLY);
	if (fd < 0) {
		printf ("Failed to open input file %s: %s\n", file_name, strerror (errno));
		exit (1);
	}

	if (fstat (fd, &stat) < 0) {
		printf ("Failed to check size of input file %s: %s\n", file_name, strerror (errno));
		exit (1);
	}

	send_indirect_ctrl (cms_id, cms_offset);
	check_protocol_error ();
	check_indirect_status (-1, false);

	max_length = get_indirect_size ();
	if ((uint32_t) ((stat.st_size + 3) / 4) > max_length) {
		printf ("CMS %d is not large enough for the image:  CMS=%u, file=%u\n", cms_id, max_length,
			(uint32_t) ((stat.st_size + 3) / 4));

		if (!ignore_errors) {
			exit (1);
		}
	}

	do {
		img_bytes = read (fd, img_data, sizeof (img_data));
		if (img_bytes > 0) {
			device_bytes = smbus_block_read (INDIRECT_DATA, device_data, 0, sizeof (device_data));

			if (device_bytes < img_bytes) {
				printf ("Data length mismatch\n");
				exit (1);
			}

			if (memcmp (img_data, device_data, img_bytes) != 0) {
				printf ("Device memory does not match file data\n");
				exit (1);
			}
		}
	} while (img_bytes > 0);

	if (img_bytes < 0) {
		printf ("Failed to read data from input file %s: %s\n", file_name, strerror (errno));
		exit (1);
	}

	check_protocol_error ();
	check_indirect_status (-1, true);

	close (fd);
}

/**
 * Execute the 'activate_img' command that instructs the device to activate a previously loaded
 * recovery image.
 */
void command_activate_image ()
{
	send_recovery_ctrl (cms_id, false);
	check_protocol_error ();
	check_recovery_status ();

	send_recovery_ctrl (cms_id, true);
}

/**
 * Execute the 'recover' command that sends a recovery image to the device and activates it.
 */
void command_recover ()
{
	command_load_image ();
	command_activate_image ();
}

/**
 * Execute the 'reset_device' command that issues a device reset.
 */
void command_reset_device ()
{
	send_reset (1);
}

/**
 * Execute the 'reset_management' command that issues a reset of the device management subsystem.
 */
void command_reset_management ()
{
	send_reset (2);
}

/**
 * Execute the 'read_data' command that reads the entire contents of a single CMS.
 */
void command_read_data ()
{
	uint8_t *data;
	uint32_t length;
	uint32_t offset = cms_offset;

	if (offset & 0x3) {
		printf ("NOTE: Aligning offset to a 4-byte boundary\n");
		offset &= ~0x3;
	}

	length = dump_cms_data (cms_id, offset, file_name, &data);

	if (!file_name) {
		hex_dump (data, length, offset);
		free (data);
	}
}

/**
 * Execute the 'read_log' command that reads and parses the contents of a log CMS.  If the region
 * type does not indicate the standard log format, it will be parsed as a Cerberus log if the
 * command argument was provided to enable this action.  Otherwise, the region will not be read.
 */
void command_read_log ()
{
	uint8_t *data;
	uint32_t length;
	bool is_log = false;
	bool is_cerberus = false;

	send_indirect_ctrl (cms_id, cms_offset);
	is_log = check_indirect_status (0x1, false);
	if (!is_log && is_cerberus_log) {
		is_cerberus = check_indirect_status (0x6, false);
	}

	if (!is_log && !is_cerberus) {
		printf ("CMS %d does not contain log data\n", cms_id);
		exit (1);
	}

	length = dump_cms_data (cms_id, cms_offset, NULL, &data);

	if (is_log) {
		parse_ocp_log (data, length);
	}
	else {
		parse_cerberus_log (data, length);
	}

	free (data);
}

/**
 * Execute the 'show_all' command to read all device commands and display the results.
 */
void command_show_all ()
{
	uint16_t capabilities = get_device_capabilities ();

	read_prot_cap (raw_bytes);

	if (capabilities & SUPPORT_DEVICE_ID) {
		read_device_id (raw_bytes);
	}

	if (capabilities & SUPPORT_DEVICE_STATUS) {
		read_device_status (raw_bytes);
	}

	if (capabilities & SUPPORT_RESET) {
		read_reset (raw_bytes);
	}

	read_recovery_ctrl (raw_bytes);
	read_recovery_status (raw_bytes);

	if (capabilities & SUPPORT_HW_STATUS) {
		read_hw_status (raw_bytes);
	}

	if (capabilities & SUPPORT_INDIRECT) {
		read_indirect_ctrl (raw_bytes);
		read_indirect_status (raw_bytes);
		read_indirect_data ();
	}

	if (capabilities & SUPPORT_VENDOR) {
		read_vendor ();
	}
}


/**
 * Print the application usage.
 */
void print_usage ()
{
	printf ("Usage: ocp_recovery -d <num> [OPTIONS] COMMAND [ARGS]\n");
}

/**
 * Print the detailed help for the command.
 */
void print_help ()
{
	printf ("This tool provides a way to communicate with and test devices that implement the\n");
	printf ("firmware recovery protocol specified by the OCP Security workgroup.  Details\n");
	printf ("about the protocol can be found at the OCP Security wiki.\n");
	printf ("\n");
	printf ("https://www.opencompute.org/wiki/Security\n");
	printf ("\n\n");

	print_usage ();

	printf ("\n");
	printf ("OPTIONS\n");
	printf ("  -a <hex> :  The 7-bit I2C address, in hex.  This follows the spec and defaults to 0x69.\n");
	printf ("  -b       :  Show raw response bytes in addition to parsed data.\n");
	printf ("  -c <num> :  The CMS to use for the operation.  This defaults to 0.\n");
	printf ("  -d <num> :  The I2C device number.  This is required.\n");
	printf ("  -e       :  Force a PEC error on a raw write command.\n");
	printf ("  -f       :  Ignore failed error checks during operation validation.\n");
	printf ("  -l       :  Indicate a vendor RO CMS region uses Cerberus logging format.\n");
	printf ("  -o <hex> :  The offset in a CMS to start reading or writing.  Defaults to 0.\n");
	printf ("  -p       :  Disable PEC bytes on block reads and writes.\n");
	printf ("  -r       :  Force the device into recovery mode during reset commands.\n");
	printf ("  -s       :  Add a delay after every write transaction.\n");
	printf ("  -S       :  Specify the amount of time, in usec, to delay after write transactions.  Defaults to 1000.\n");
	printf ("  -v       :  Verbose output for command processing.  Specify multiple times to increase.\n");
	printf ("  -w       :  Execute a raw write transaction.  Default is to execute a read.\n");
	printf ("  -h       :  Displays the help menu.\n");
	printf ("\n");
	printf ("COMMANDS\n");
	printf ("  recover <file>    : Load a binary image into the device and activate it.\n");
	printf ("  load_img <file>   : Write a binary file to device memory.\n");
	printf ("  verify_img <file> : Read device memory and compare it to a specified file.\n");
	printf ("  activate_img      : Activate an image loaded into device memory.\n");
	printf ("  read_log [file]   : Read and parse contents of a CMS log.  Optionally output to a file.\n");
	printf ("  read_data [file]  : Raw CMS data read.  Optionally output to a file.\n");
	printf ("  reset_device      : Issue a device reset.\n");
	printf ("  reset_mgmt        : Issue a management reset for the device.\n");
	printf ("  show_all          : Send a read request for every command supported by the device.\n");
	printf ("\n");
	printf ("RAW COMMANDS\n");
	printf ("  prot_cap        :  The PROT_CAP command.\n");
	printf ("  device_id       :  The DEVICE_ID command.\n");
	printf ("  device_status   :  The DEVICE_STATUS command.\n");
	printf ("  reset           :  The RESET command.\n");
	printf ("  recovery_ctrl   :  The RECOVERY_CTRL command.\n");
	printf ("  recovery_status :  The RECOVERY_STATUS command.\n");
	printf ("  hw_status       :  The HW_STATUS command.\n");
	printf ("  indirect_ctrl   :  The INDIRECT_CTRL command.\n");
	printf ("  indirect_status :  The INDIRECT_STATUS command.\n");
	printf ("  indirect_data   :  The INDIRECT_DATA command.\n");
	printf ("  vendor          :  The VENDOR command.\n");
	printf ("\n");
	printf ("  Raw commands give direct access to the associated OCP command.  On write\n");
	printf ("  requests, a series of hex values must be provided, one for each field of the\n");
	printf ("  command.  For indirect_data, it would take a list of bytes to write.\n");
	printf ("  Examples:\n");
	printf ("    reset 0x02 0x0f 0x00\n");
	printf ("    indirect_ctrl 0x01 0x1234\n");
	printf ("    indirect_data 0x00 0x01 0x02 0x03\n");
	printf ("\n");
	printf ("  Raw commands do not use the CMS arguments provided for the normal commands.\n");
	printf ("  This means that INDIRECT or RECOVERY commands will not recognize the CMS or\n");
	printf ("  offset arguments provided.  There is also no checking or protection against\n");
	printf ("  executing unsupported actions, such as writing to read only commands and\n");
	printf ("  regions.\n");
}

/**
 * Determine if the current command is a raw command.
 *
 * @return true if the command is a raw command.
 */
bool is_raw_command ()
{
	if (strcmp ("prot_cap", command) == 0) {
		return true;
	}
	else if (strcmp ("device_id", command) == 0) {
		return true;
	}
	else if (strcmp ("device_status", command) == 0) {
		return true;
	}
	else if (strcmp ("reset", command) == 0) {
		return true;
	}
	else if (strcmp ("recovery_ctrl", command) == 0) {
		return true;
	}
	else if (strcmp ("recovery_status", command) == 0) {
		return true;
	}
	else if (strcmp ("hw_status", command) == 0) {
		return true;
	}
	else if (strcmp ("indirect_ctrl", command) == 0) {
		return true;
	}
	else if (strcmp ("indirect_status", command) == 0) {
		return true;
	}
	else if (strcmp ("indirect_data", command) == 0) {
		return true;
	}
	else if (strcmp ("vendor", command) == 0) {
		return true;
	}

	return false;
}

/**
 * Entry point for the OCP recovery test application.
 *
 * @param argc Number of arguments provided to the application.
 * @param argv Argument list.
 *
 * @return 0 on success or 1 on failure.
 */
int main (int argc, char *argv[])
{
	char dev_name[64];
	const char *opts = "a:bc:d:efhlo:prsS:vw";
	int opt;
	int device_num = -1;

	while ((opt = getopt (argc, argv, opts)) != -1) {
		switch (opt) {
			case 'a':
				addr = strtol (optarg, NULL, 16);
				break;

			case 'b':
				raw_bytes = true;
				break;

			case 'c':
				cms_id = strtoul (optarg, NULL, 10);
				break;

			case 'd':
				device_num = strtol (optarg, NULL, 10);
				break;

			case 'e':
				force_pec_error = true;
				break;

			case 'f':
				ignore_errors = true;
				break;

			case 'l':
				is_cerberus_log = true;
				break;

			case 'o':
				cms_offset = strtoul (optarg, NULL, 16);
				break;

			case 'p':
				pec = false;
				break;

			case 'r':
				force_recovery = true;
				break;

			case 's':
				use_write_delay = true;
				break;

			case 'S':
				write_delay = strtoul (optarg, NULL, 10);
				break;

			case 'v':
				verbose++;
				break;

			case 'w':
				is_read = false;
				break;

			case 'h':
				print_help ();
				return 0;
		}
	}

	if (device_num < 0) {
		printf ("No I2C device specified.\n\n");
		print_usage ();
		return 1;
	}

	if (optind >= argc) {
		print_usage ();
		return 1;
	}

	command = argv[optind++];

	if ((strcmp ("recover", command) == 0) || (strcmp ("load_img", command) == 0) ||
		(strcmp ("verify_img", command) == 0)) {
		if (optind >= argc) {
			printf ("A file must be provided for this command.\n");
			return 1;
		}

		file_name = argv[optind++];
	}
	else if ((strcmp ("read_log", command) == 0) || (strcmp ("read_data", command) == 0)) {
		if (optind < argc) {
			file_name = argv[optind++];
			file_out = true;
		}
	}
	else if (is_raw_command ()) {
		if (optind < argc) {
			size_t i;

			raw_data_count = argc - optind;
			for (i = 0; i < raw_data_count; i++, optind++) {
				raw_data[i] = strtoul (argv[optind], NULL, 16);
			}
		}
		else if (!is_read) {
			printf ("No data provided for the command.\n");
			return 1;
		}
	}

	sprintf (dev_name, "/dev/i2c-%d", device_num);
	i2c = open (dev_name, O_RDWR);
	if (i2c < 0) {
		printf ("Failed to open I2C device %s: %s\n", dev_name, strerror (errno));
		return 1;
	}

	if (strcmp ("recover", command) == 0) {
		command_recover ();
	}
	else if (strcmp ("load_img", command) == 0) {
		command_load_image ();
	}
	else if (strcmp ("verify_img", command) == 0) {
		command_verify_image ();
	}
	else if (strcmp ("activate_img", command) == 0) {
		command_activate_image ();
	}
	else if (strcmp ("read_log", command) == 0) {
		command_read_log ();
	}
	else if (strcmp ("read_data", command) == 0) {
		command_read_data ();
	}
	else if (strcmp ("reset_device", command) == 0) {
		command_reset_device ();
	}
	else if (strcmp ("reset_mgmt", command) == 0) {
		command_reset_management ();
	}
	else if (strcmp ("show_all", command) == 0) {
		command_show_all ();
	}
	else if (strcmp ("prot_cap", command) == 0) {
		if (is_read) {
			read_prot_cap (raw_bytes);
		}
		else {
			write_prot_cap ();
		}
	}
	else if (strcmp ("device_id", command) == 0) {
		if (is_read) {
			read_device_id (raw_bytes);
		}
		else {
			write_device_id ();
		}
	}
	else if (strcmp ("device_status", command) == 0) {
		if (is_read) {
			read_device_status (raw_bytes);
		}
		else {
			write_device_status ();
		}
	}
	else if (strcmp ("reset", command) == 0) {
		if (is_read) {
			read_reset (raw_bytes);
		}
		else {
			write_reset (raw_bytes);
		}
	}
	else if (strcmp ("recovery_ctrl", command) == 0) {
		if (is_read) {
			read_recovery_ctrl (raw_bytes);
		}
		else {
			write_recovery_ctrl ();
		}
	}
	else if (strcmp ("recovery_status", command) == 0) {
		if (is_read) {
			read_recovery_status (raw_bytes);
		}
		else {
			write_recovery_status ();
		}
	}
	else if (strcmp ("hw_status", command) == 0) {
		if (is_read) {
			read_hw_status (raw_bytes);
		}
		else {
			write_hw_status ();
		}
	}
	else if (strcmp ("indirect_ctrl", command) == 0) {
		if (is_read) {
			read_indirect_ctrl (raw_bytes);
		}
		else {
			write_indirect_ctrl ();
		}
	}
	else if (strcmp ("indirect_status", command) == 0) {
		if (is_read) {
			read_indirect_status (raw_bytes);
		}
		else {
			write_indirect_status ();
		}
	}
	else if (strcmp ("indirect_data", command) == 0) {
		if (is_read) {
			read_indirect_data ();
		}
		else {
			write_indirect_data ();
		}
	}
	else if (strcmp ("vendor", command) == 0) {
		if (is_read) {
			read_vendor ();
		}
		else {
			write_vendor ();
		}
	}
	else {
		printf ("Uknown command.\n");
		return 1;
	}

	return 0;
}
