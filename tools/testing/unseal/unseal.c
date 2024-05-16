// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include "asn1/x509_mbedtls.h"
#include "attestation/aux_attestation.h"
#include "attestation/pcr_store.h"
#include "common/array_size.h"
#include "crypto/ecc_mbedtls.h"
#include "crypto/hash_mbedtls.h"
#include "keystore/keystore_null_static.h"
#include "mbedtls/base64.h"
#include "riot/riot_key_manager.h"


/**
 * ECC handler for ECDH unsealing.
 */
struct ecc_engine_mbedtls ecc;

/**
 * Hash handler for unsealing.
 */
struct hash_engine_mbedtls hash;

/**
 * X.509 handler for device certs.
 */
struct x509_engine_mbedtls x509;

/**
 * Empty keystore for device keys.
 */
const struct keystore_null keystore = keystore_null_static_init;

/**
 * Handler for the alias key used for unseal operations.
 */
struct riot_key_manager riot;

/**
 * Values to assign to the PCRs.
 */
uint8_t pcr_values[5][SHA256_HASH_LENGTH] = {{0}};

/**
 * Length of the PCR value.
 */
size_t pcr_length[5] = {
	SHA256_HASH_LENGTH, SHA256_HASH_LENGTH, SHA256_HASH_LENGTH, SHA256_HASH_LENGTH,
	SHA256_HASH_LENGTH
};

/**
 * Handler for PCR values used during attestation.
 */
struct pcr_store pcr;

/**
 * Handler for the unseal operation.
 */
struct aux_attestation unseal;


/**
 * Print utility usage and exit.
 *
 * @param code Exit code for the application.
 */
void print_usage (int code)
{
	printf ("Usage:  unseal -[0|1|2|3|4] <base64 pcr> <privkey.der> <RSA|ECDH> <None|SHA1|SHA256> "
		"<seed.bin> <cipher.bin> <sealing.bin> <hmac.bin>\n");
	exit (code);
}

/**
 * Container for unseal data read from an input file.
 */
struct unseal_data {
	uint8_t *data;	/**< The unseal data read from the file. */
	size_t length;	/**< The data length. */
};


/**
 * Read the contents of a binary file.  The application exits on an error.
 *
 * @param file The file to read.
 *
 * @return Dynamically allocated buffer with the file contents.
 */
struct unseal_data* read_file (const char *file)
{
	int fd;
	struct stat file_info;
	struct unseal_data *file_data;
	int status;

	file_data = malloc (sizeof (struct unseal_data));
	if (file_data == NULL) {
		printf ("Failed to allocate contain for %s\n");
		exit (1);
	}

	fd = open (file, 0);
	if (fd == -1) {
		printf ("Failed to open %s: %d\n", file, errno);
		exit (1);
	}

	status = fstat (fd, &file_info);
	if (status == -1) {
		printf ("Failed to get file %s size: %d\n", file, errno);
		exit (1);
	}

	file_data->length = file_info.st_size;
	file_data->data = malloc (file_data->length);
	if (file_data == NULL) {
		printf ("No memory for file %s data\n", file);
		exit (1);
	}

	status = read (fd, file_data->data, file_data->length);
	if (status == -1) {
		printf ("Failed to read file %s data: %d\n", file, errno);
		exit (1);
	}
	else if (status != (int) file_data->length) {
		printf ("Failed to read all file %s data\n", file);
		exit (1);
	}

	close (fd);

	return file_data;
}

/**
 * Initialize the unseal handler.  The application exits on an error.
 *
 * @param alias_key The private key to use for ECDH unseal operations.
 */
void init_unseal (const struct unseal_data *alias_key)
{
	struct riot_keys keys = {0};
	uint8_t measurement_count[] = {0, 0, 0, 0, 0};
	size_t i;
	int status;

	keys.alias_key = alias_key->data;
	keys.alias_key_length = alias_key->length;

	status = ecc_mbedtls_init (&ecc);
	if (status != 0) {
		printf ("ecc_mbedtls_init failed: 0x%x\n", status);
		exit (1);
	}

	status = hash_mbedtls_init (&hash);
	if (status != 0) {
		printf ("hash_mbedtls_init failed: 0x%x\n", status);
		exit (1);
	}

	status = x509_mbedtls_init (&x509);
	if (status != 0) {
		printf ("x509_mbedtls_init failed: 0x%x\n", status);
		exit (1);
	}

	status = riot_key_manager_init (&riot, &keystore.base, &keys, &x509.base);
	if (status != 0) {
		printf ("riot_key_manager_init failed: 0x%x\n", status);
		exit (1);
	}

	status = aux_attestation_init (&unseal, NULL, NULL, &riot, &ecc.base);
	if (status != 0) {
		printf ("aux_attestation_init failed: 0x%x\n", status);
		exit (1);
	}

	status = pcr_store_init (&pcr, measurement_count, ARRAY_SIZE (measurement_count));
	if (status != 0) {
		printf ("pcr_store_init failed: 0x%x\n", status);
		exit (1);
	}

	for (i = 0; i < ARRAY_SIZE (measurement_count); i++) {
		status = pcr_store_update_digest (&pcr, PCR_MEASUREMENT (i, 0), pcr_values[i],
			pcr_length[i]);
		if (status != 0) {
			printf ("pcr_store_update_digest failed for PCR %d: 0x%x\n", i, status);
			exit (1);
		}
	}
}

/**
 * Execute an unseal operation.
 *
 * @param argc The number of input argument.
 * @param argv Argument list.
 *
 * @return 0 if unseal was successful or 1 otherwise.
 */
int main (int argc, char *argv[])
{
	int opt;
	struct unseal_data *priv_key;
	enum aux_attestation_seed_type type;
	enum aux_attestation_seed_param param;
	struct unseal_data *seed;
	struct unseal_data *cipher;
	struct unseal_data *sealing;
	struct unseal_data *hmac;
	uint8_t unseal_out[AUX_ATTESTATION_KEY_256BIT];
	size_t i;
	int status;

	while ((opt = getopt (argc, argv, "0:1:2:3:4:")) != -1) {
		switch (opt) {
			case '0':
				status = mbedtls_base64_decode (pcr_values[0], sizeof (pcr_values[0]),
					&pcr_length[0], (uint8_t*) optarg, strlen (optarg));
				if (status != 0) {
					printf ("Failed to decode PCR0 value: -0x%x\n", -status);

					return 1;
				}
				break;

			case '1':
				status = mbedtls_base64_decode (pcr_values[1], sizeof (pcr_values[1]),
					&pcr_length[1], (uint8_t*) optarg, strlen (optarg));
				if (status != 0) {
					printf ("Failed to decode PCR1 value: -0x%x\n", -status);

					return 1;
				}
				break;

			case '2':
				status = mbedtls_base64_decode (pcr_values[2], sizeof (pcr_values[2]),
					&pcr_length[2], (uint8_t*) optarg, strlen (optarg));
				if (status != 0) {
					printf ("Failed to decode PCR2 value: -0x%x\n", -status);

					return 1;
				}
				break;

			case '3':
				status = mbedtls_base64_decode (pcr_values[3], sizeof (pcr_values[3]),
					&pcr_length[3], (uint8_t*) optarg, strlen (optarg));
				if (status != 0) {
					printf ("Failed to decode PCR3 value: -0x%x\n", -status);

					return 1;
				}
				break;

			case '4':
				status = mbedtls_base64_decode (pcr_values[4], sizeof (pcr_values[4]),
					&pcr_length[4], (uint8_t*) optarg, strlen (optarg));
				if (status != 0) {
					printf ("Failed to decode PCR4 value: -0x%x\n", -status);

					return 1;
				}
				break;

			default:
				printf ("Invalid argument");
				print_usage (1);
				break;
		}
	}

	if (argc < (optind + 7)) {
		print_usage (1);
	}

	if (strcmp ("RSA", argv[optind + 1]) == 0) {
		type = AUX_ATTESTATION_SEED_RSA;
	}
	else if (strcmp ("ECDH", argv[optind + 1]) == 0) {
		type = AUX_ATTESTATION_SEED_ECDH;
	}
	else {
		printf ("Invalid unseal seed type: %s\n", argv[optind + 1]);

		return 1;
	}

	if (type == AUX_ATTESTATION_SEED_RSA) {
		if (strcmp ("None", argv[optind + 2]) == 0) {
			param = AUX_ATTESTATION_PARAM_PKCS15;
		}
		else if (strcmp ("SHA1", argv[optind + 2]) == 0) {
			param = AUX_ATTESTATION_PARAM_OAEP_SHA1;
		}
		else if (strcmp ("SHA256", argv[optind + 2]) == 0) {
			param = AUX_ATTESTATION_PARAM_OAEP_SHA256;
		}
		else {
			printf ("Invalid RSA seed parameter type: %s\n", argv[optind + 2]);

			return 1;
		}
	}
	else {
		if (strcmp ("None", argv[optind + 2]) == 0) {
			param = AUX_ATTESTATION_PARAM_ECDH_RAW;
		}
		else if (strcmp ("SHA256", argv[optind + 2]) == 0) {
			param = AUX_ATTESTATION_PARAM_ECDH_SHA256;
		}
		else {
			printf ("Invalid ECDH seed parameter type: %s\n", argv[optind + 2]);

			return 1;
		}
	}

	if (type == AUX_ATTESTATION_SEED_RSA) {
		printf ("RSA unsealing unsupported\n");

		return 1;
	}

	priv_key = read_file (argv[optind + 0]);
	seed = read_file (argv[optind + 3]);
	cipher = read_file (argv[optind + 4]);
	sealing = read_file (argv[optind + 5]);
	hmac = read_file (argv[optind + 6]);

	if (hmac->length != SHA256_HASH_LENGTH) {
		printf ("HMAC length is not valid for HMAC-SHA256: %d\n", hmac->length);

		return 1;
	}

	if ((sealing->length % 64) != 0) {
		printf ("Sealing data must be a multiple of 64: %d\n", sealing->length);

		return 1;
	}

	init_unseal (priv_key);

	status = aux_attestation_unseal (&unseal, &hash.base, &pcr, AUX_ATTESTATION_KEY_256BIT,
		seed->data, seed->length, type, param, hmac->data, HMAC_SHA256, cipher->data,
		cipher->length, (const uint8_t (*)[64]) sealing->data, (sealing->length / 64), unseal_out,
		sizeof (unseal_out));
	if (status != 0) {
		printf ("Unseal FAILED: 0x%x\n", status);

		return 1;
	}

	for (i = 0; i < sizeof (unseal_out); i++) {
		printf ("%02x", unseal_out[i]);
	}
	printf ("\n");

	return 0;
}
