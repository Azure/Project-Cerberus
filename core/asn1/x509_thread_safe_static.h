// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef X509_THREAD_SAFE_STATIC_H_
#define X509_THREAD_SAFE_STATIC_H_

#include "x509_thread_safe.h"


/* Internal functions declared to allow for static initialization. */
int x509_thread_safe_create_csr (const struct x509_engine *engine, const uint8_t *priv_key,
	size_t key_length, enum hash_type sig_hash, const char *name, int type, const uint8_t *eku,
	size_t eku_length, const struct x509_extension_builder *const *extra_extensions,
	size_t ext_count, uint8_t **csr, size_t *csr_length);
int x509_thread_safe_create_self_signed_certificate (const struct x509_engine *engine,
	struct x509_certificate *cert, const uint8_t *priv_key, size_t key_length,
	enum hash_type sig_hash, const uint8_t *serial_num, size_t serial_length, const char *name,
	int type, const struct x509_extension_builder *const *extra_extensions, size_t ext_count);
int x509_thread_safe_create_ca_signed_certificate (const struct x509_engine *engine,
	struct x509_certificate *cert, const uint8_t *key, size_t key_length, const uint8_t *serial_num,
	size_t serial_length, const char *name, int type, const uint8_t *ca_priv_key,
	size_t ca_key_length, enum hash_type sig_hash, const struct x509_certificate *ca_cert,
	const struct x509_extension_builder *const *extra_extensions, size_t ext_count);
int x509_thread_safe_load_certificate (const struct x509_engine *engine,
	struct x509_certificate *cert, const uint8_t *der, size_t length);
void x509_thread_safe_release_certificate (const struct x509_engine *engine,
	struct x509_certificate *cert);
int x509_thread_safe_get_certificate_der (const struct x509_engine *engine,
	const struct x509_certificate *cert, uint8_t **der, size_t *length);
int x509_thread_safe_get_certificate_version (const struct x509_engine *engine,
	const struct x509_certificate *cert);
int x509_thread_safe_get_serial_number (const struct x509_engine *engine,
	const struct x509_certificate *cert, uint8_t *serial_num, size_t length);
int x509_thread_safe_get_public_key_type (const struct x509_engine *engine,
	const struct x509_certificate *cert);
int x509_thread_safe_get_public_key_length (const struct x509_engine *engine,
	const struct x509_certificate *cert);
int x509_thread_safe_get_public_key (const struct x509_engine *engine,
	const struct x509_certificate *cert, uint8_t **key, size_t *key_length);
int x509_thread_safe_init_ca_cert_store (const struct x509_engine *engine,
	struct x509_ca_certs *store);
void x509_thread_safe_release_ca_cert_store (const struct x509_engine *engine,
	struct x509_ca_certs *store);
int x509_thread_safe_add_root_ca (const struct x509_engine *engine, struct x509_ca_certs *store,
	const uint8_t *der, size_t length);
int x509_thread_safe_add_trusted_ca (const struct x509_engine *engine, struct x509_ca_certs *store,
	const uint8_t *der, size_t length);
int x509_thread_safe_add_intermediate_ca (const struct x509_engine *engine,
	struct x509_ca_certs *store, const uint8_t *der, size_t length);
int x509_thread_safe_authenticate (const struct x509_engine *engine,
	const struct x509_certificate *cert, const struct x509_ca_certs *store);


/**
 * Constant initializer for certificate generation APIs.
 */
#ifdef X509_ENABLE_CREATE_CERTIFICATES
#define	X509_THREAD_SAFE_CREATE_CERTIFICATES \
	.create_csr = x509_thread_safe_create_csr, \
	.create_self_signed_certificate = x509_thread_safe_create_self_signed_certificate, \
	.create_ca_signed_certificate = x509_thread_safe_create_ca_signed_certificate,

#define	X509_THREAD_SAFE_DER_API \
	.get_certificate_der = x509_thread_safe_get_certificate_der,
#else
#define	X509_THREAD_SAFE_CREATE_CERTIFICATES
#define	X509_THREAD_SAFE_DER_API
#endif

/**
 * Constant initializer for certificate authentication APIs.
 */
#ifdef X509_ENABLE_AUTHENTICATION
#define	X509_THREAD_SAFE_AUTHENTICATION \
	.get_certificate_version = x509_thread_safe_get_certificate_version, \
	.get_serial_number = x509_thread_safe_get_serial_number, \
	.get_public_key_type = x509_thread_safe_get_public_key_type, \
	.get_public_key_length = x509_thread_safe_get_public_key_length, \
	.get_public_key = x509_thread_safe_get_public_key, \
	.init_ca_cert_store = x509_thread_safe_init_ca_cert_store, \
	.release_ca_cert_store = x509_thread_safe_release_ca_cert_store, \
	.add_root_ca = x509_thread_safe_add_root_ca ,\
	.add_trusted_ca = x509_thread_safe_add_trusted_ca, \
	.add_intermediate_ca = x509_thread_safe_add_intermediate_ca, \
	.authenticate = x509_thread_safe_authenticate,
#else
#define	X509_THREAD_SAFE_AUTHENTICATION
#endif

/**
 * Constant initializer for the X.509 API.
 */
#define	X509_THREAD_SAFE_API_INIT  { \
		X509_THREAD_SAFE_CREATE_CERTIFICATES \
		.load_certificate = x509_thread_safe_load_certificate, \
		.release_certificate = x509_thread_safe_release_certificate, \
		X509_THREAD_SAFE_DER_API \
		X509_THREAD_SAFE_AUTHENTICATION \
	}


/**
 * Initialize a static thread-safe wrapper for handling X.509 certificates.  This can be a constant
 * instance.
 *
 * There is no validation done on the arguments.
 *
 * @param state_ptr Variable context for the thread-safe engine.
 * @param target_ptr The target engine that will be used to execute operations.
 */
#define	x509_thread_safe_static_init(state_ptr, target_ptr)	{ \
		.base = X509_THREAD_SAFE_API_INIT, \
		.state = state_ptr, \
		.engine = target_ptr, \
	}


#endif	/* X509_THREAD_SAFE_STATIC_H_ */
