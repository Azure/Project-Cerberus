// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef X509_OPENSSL_STATIC_H_
#define X509_OPENSSL_STATIC_H_

#include "x509_openssl.h"


/* Internal functions declared to allow for static initialization. */
int x509_openssl_create_csr (const struct x509_engine *engine, const uint8_t *priv_key,
	size_t key_length, enum hash_type sig_hash, const char *name, int type, const uint8_t *eku,
	size_t eku_length, const struct x509_extension_builder *const *extra_extensions,
	size_t ext_count, uint8_t **csr, size_t *csr_length);
int x509_openssl_create_self_signed_certificate (const struct x509_engine *engine,
	struct x509_certificate *cert, const uint8_t *priv_key, size_t key_length,
	enum hash_type sig_hash, const uint8_t *serial_num, size_t serial_length, const char *name,
	int type, const struct x509_extension_builder *const *extra_extensions, size_t ext_count);
int x509_openssl_create_ca_signed_certificate (const struct x509_engine *engine,
	struct x509_certificate *cert, const uint8_t *key, size_t key_length, const uint8_t *serial_num,
	size_t serial_length, const char *name, int type, const uint8_t *ca_priv_key,
	size_t ca_key_length, enum hash_type sig_hash, const struct x509_certificate *ca_cert,
	const struct x509_extension_builder *const *extra_extensions, size_t ext_count);
int x509_openssl_load_certificate (const struct x509_engine *engine, struct x509_certificate *cert,
	const uint8_t *der, size_t length);
void x509_openssl_release_certificate (const struct x509_engine *engine,
	struct x509_certificate *cert);
int x509_openssl_get_certificate_der (const struct x509_engine *engine,
	const struct x509_certificate *cert, uint8_t **der, size_t *length);
int x509_openssl_get_certificate_version (const struct x509_engine *engine,
	const struct x509_certificate *cert);
int x509_openssl_get_serial_number (const struct x509_engine *engine,
	const struct x509_certificate *cert, uint8_t *serial_num, size_t length);
int x509_openssl_get_public_key_type (const struct x509_engine *engine,
	const struct x509_certificate *cert);
int x509_openssl_get_public_key_length (const struct x509_engine *engine,
	const struct x509_certificate *cert);
int x509_openssl_get_public_key (const struct x509_engine *engine,
	const struct x509_certificate *cert, uint8_t **key, size_t *key_length);
int x509_openssl_init_ca_cert_store (const struct x509_engine *engine, struct x509_ca_certs *store);
void x509_openssl_release_ca_cert_store (const struct x509_engine *engine,
	struct x509_ca_certs *store);
int x509_openssl_add_root_ca (const struct x509_engine *engine, struct x509_ca_certs *store,
	const uint8_t *der, size_t length);
int x509_openssl_add_trusted_ca (const struct x509_engine *engine, struct x509_ca_certs *store,
	const uint8_t *der, size_t length);
int x509_openssl_add_intermediate_ca (const struct x509_engine *engine, struct x509_ca_certs *store,
	const uint8_t *der, size_t length);
int x509_openssl_authenticate (const struct x509_engine *engine,
	const struct x509_certificate *cert, const struct x509_ca_certs *store);


/**
 * Constant initializer for certificate generation APIs.
 */
#ifdef X509_ENABLE_CREATE_CERTIFICATES
#define	X509_OPENSSL_CREATE_CERTIFICATES \
	.create_csr = x509_openssl_create_csr, \
	.create_self_signed_certificate = x509_openssl_create_self_signed_certificate, \
	.create_ca_signed_certificate = x509_openssl_create_ca_signed_certificate,

#define	X509_OPENSSL_DER_API \
	.get_certificate_der = x509_openssl_get_certificate_der,
#else
#define	X509_OPENSSL_CREATE_CERTIFICATES
#define	X509_OPENSSL_DER_API
#endif

/**
 * Constant initializer for certificate authentication APIs.
 */
#ifdef X509_ENABLE_AUTHENTICATION
#define	X509_OPENSSL_AUTHENTICATION \
	.get_certificate_version = x509_openssl_get_certificate_version, \
	.get_serial_number = x509_openssl_get_serial_number, \
	.get_public_key_type = x509_openssl_get_public_key_type, \
	.get_public_key_length = x509_openssl_get_public_key_length, \
	.get_public_key = x509_openssl_get_public_key, \
	.init_ca_cert_store = x509_openssl_init_ca_cert_store, \
	.release_ca_cert_store = x509_openssl_release_ca_cert_store, \
	.add_root_ca = x509_openssl_add_root_ca ,\
	.add_trusted_ca = x509_openssl_add_trusted_ca, \
	.add_intermediate_ca = x509_openssl_add_intermediate_ca, \
	.authenticate = x509_openssl_authenticate,
#else
#define	X509_OPENSSL_AUTHENTICATION
#endif

/**
 * Constant initializer for the X.509 API.
 */
#define	X509_OPENSSL_API_INIT  { \
		X509_OPENSSL_CREATE_CERTIFICATES \
		.load_certificate = x509_openssl_load_certificate, \
		.release_certificate = x509_openssl_release_certificate, \
		X509_OPENSSL_DER_API \
		X509_OPENSSL_AUTHENTICATION \
	}


/**
 * Initialize a static instance for handling X.509 certificates using OpenSSL.  This can be a
 * constant instance.
 */
#define	x509_openssl_static_init	{ \
		.base = X509_OPENSSL_API_INIT, \
	}


#endif /* X509_OPENSSL_STATIC_H_ */
