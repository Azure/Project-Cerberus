// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef CRYPTO_LOGGING_H_
#define CRYPTO_LOGGING_H_

/**
 * Cerberus crypto log messages - MAKE SURE IN SYNC WITH tools\cerberus_utility\cerberus_utility_commands.h!!
 */
enum {
	CRYPTO_LOG_MSG_MBEDTLS_AES_GCM_INIT_EC,					/**< mbedTLS failure during AES GCM init */
	CRYPTO_LOG_MSG_MBEDTLS_AES_GCM_CRYPT_EC,				/**< mbedTLS failure during AES GCM buffer encryt/decrypt */
	CRYPTO_LOG_MSG_MBEDTLS_AES_GCM_AUTH_DECRYPT_EC,			/**< mbedTLS failure during AES GCM buffer authenticated decryption */
	CRYPTO_LOG_MSG_MBEDTLS_PK_INIT_EC,						/**< mbedTLS failure during public key context init */
	CRYPTO_LOG_MSG_MBEDTLS_PK_PARSE_EC, 					/**< mbedTLS failure during private key parsing */
	CRYPTO_LOG_MSG_MBEDTLS_PK_PARSE_PUB_EC, 				/**< mbedTLS failure during public key parsing */
	CRYPTO_LOG_MSG_MBEDTLS_PK_WRITE_KEY_DER_EC, 			/**< mbedTLS failure during private key export to DER structure */
	CRYPTO_LOG_MSG_MBEDTLS_PK_WRITE_PUBKEY_DER_EC, 			/**< mbedTLS failure during public key export to DER structure */
	CRYPTO_LOG_MSG_MBEDTLS_PK_SIGN_EC, 						/**< mbedTLS failure during signing */
	CRYPTO_LOG_MSG_MBEDTLS_PK_VERIFY_EC,					/**< mbedTLS failure during signature verification */
	CRYPTO_LOG_MSG_MBEDTLS_ECP_GROUP_COPY_EC,				/**< mbedTLS failure during ECP group copy */
	CRYPTO_LOG_MSG_MBEDTLS_ECP_COPY_EC,						/**< mbedTLS failure during ECP copy */
	CRYPTO_LOG_MSG_MBEDTLS_ECP_CHECK_PUB_PRV_EC, 			/**< mbedTLS failure during ECP keypair check */
	CRYPTO_LOG_MSG_MBEDTLS_ECP_GROUP_LOAD_EC,				/**< mbedTLS failure during ECP group load */
	CRYPTO_LOG_MSG_MBEDTLS_ECP_MUL_EC,						/**< mbedTLS failure during ECP multiplication */
	CRYPTO_LOG_MSG_MBEDTLS_ECP_GEN_KEY_EC, 					/**< mbedTLS failure during ECP key pair generation */
	CRYPTO_LOG_MSG_MBEDTLS_MPI_READ_BIN_EC,					/**< mbedTLS failure during MPI import from binary */
	CRYPTO_LOG_MSG_MBEDTLS_MPI_WRITE_BIN_EC,				/**< mbedTLS failure during MPI export from binary */
	CRYPTO_LOG_MSG_MBEDTLS_ECDH_COMPUTE_SHARED_SECRET_EC,	/**< mbedTLS failure during ECDH shared secret computation */
	CRYPTO_LOG_MSG_MBEDTLS_CTR_DRBG_SEED_EC,				/**< mbedTLS failure during CTR DRBG initial seeding */
	CRYPTO_LOG_MSG_MBEDTLS_ASN1_WRITE_OID_EC,				/**< mbedTLS failure during ASN1 OID write */
	CRYPTO_LOG_MSG_MBEDTLS_ASN1_CLOSE_EC,					/**< mbedTLS failure during ASN1 object close */
	CRYPTO_LOG_MSG_MBEDTLS_ASN1_GET_TAG_EC,					/**< mbedTLS failure during ASN1 tag get */
	CRYPTO_LOG_MSG_MBEDTLS_ASN1_GET_INT_EC,					/**< mbedTLS failure during ASN1 int get */
	CRYPTO_LOG_MSG_MBEDTLS_X509_LOAD_KEY_EC,				/**< mbedTLS failure during X509 key load */
	CRYPTO_LOG_MSG_MBEDTLS_X509_CSR_SET_SUBJECT_EC,			/**< mbedTLS failure during X509 CSR subject name set */
	CRYPTO_LOG_MSG_MBEDTLS_X509_ADD_KEY_USAGE_EC,			/**< mbedTLS failure during X509 key usage addition */
	CRYPTO_LOG_MSG_MBEDTLS_X509_ADD_EXT_KEY_USAGE_EC,		/**< mbedTLS failure during X509 extended key usage addition */
	CRYPTO_LOG_MSG_MBEDTLS_X509_ADD_BASIC_CONSTRAINTS_EC,	/**< mbedTLS failure during X509 basic constraints addition */
	CRYPTO_LOG_MSG_MBEDTLS_X509_ADD_RIOT_EC,				/**< mbedTLS failure during X509 RIOT addition */
	CRYPTO_LOG_MSG_MBEDTLS_X509_CSR_DER_WRITE_EC,			/**< mbedTLS failure during X509 CSR DER write */
	CRYPTO_LOG_MSG_MBEDTLS_CRT_SET_SUBJECT_EC,				/**< mbedTLS failure during CRT subject set */
	CRYPTO_LOG_MSG_MBEDTLS_CRT_SET_ISSUER_EC,				/**< mbedTLS failure during CRT issuer set */
	CRYPTO_LOG_MSG_MBEDTLS_CRT_SET_VALIDITY_EC,				/**< mbedTLS failure during CRT validity set */
	CRYPTO_LOG_MSG_MBEDTLS_CRT_SET_AUTHORITY_EC,			/**< mbedTLS failure during CRT authority set */
	CRYPTO_LOG_MSG_MBEDTLS_CRT_WRITE_DER_EC,				/**< mbedTLS failure during CRT export as DER */
	CRYPTO_LOG_MSG_MBEDTLS_CRT_PARSE_DER_EC,				/**< mbedTLS failure during CRT parse as DER */
	CRYPTO_LOG_MSG_MBEDTLS_CRT_CERT_AUTHENTICATE_EC,		/**< mbedTLS failure during certificate authentication */
	CRYPTO_LOG_MSG_MBEDTLS_RSA_GEN_KEY_EC,					/**< mbedTLS failure during RSA key generation */
	CRYPTO_LOG_MSG_MBEDTLS_RSA_PKCS1_VERIFY_EC,				/**< mbedTLS failure during RSA PKCS1 verification */
	CRYPTO_LOG_MSG_MBEDTLS_RSA_PUBKEY_LOAD_EC,				/**< mbedTLS failure during RSA public key load */
	CRYPTO_LOG_MSG_MBEDTLS_RSA_PUBKEY_CHECK_EC,				/**< mbedTLS failure during RSA public key check */
	CRYPTO_LOG_MSG_MBEDTLS_RSA_OAEP_DECRYPT_EC,				/**< mbedTLS failure during RSA OAEP decryption */
	CRYPTO_LOG_MSG_MBEDTLS_X509_ADD_TCBINFO_EC,				/**< mbedTLS failure during X509 TCB Info addition */
	CRYPTO_LOG_MSG_MBEDTLS_X509_ADD_UEID_EC,				/**< mbedTLS failure during X509 UEID addition */
};


#endif //CRYPTO_LOGGING_H_
