// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef X509_H_
#define X509_H_

#include <stdint.h>
#include <stddef.h>
#include "status/rot_status.h"
#include "hash.h"


/**
 * The maximum value that can be put into a path length constraint.
 */
#define	X509_CERT_MAX_PATHLEN		15

/*
 * The types of certificates that can be created.  This will dictate the different types of
 * extensions that are present.
 */
#define	X509_CERT_END_ENTITY		0	/* An end entity certificate. */
#define	X509_CERT_CA				1	/* A certificate that can be used to sign other certificates. */
#define	X509_CERT_CA_PATHLEN(x)		((x & X509_CERT_MAX_PATHLEN) + X509_CERT_CA)	/* A CA certificate with a specified path length constraint. */
#define	X509_CERT_CA_NO_PATHLEN		(X509_CERT_CA_PATHLEN (X509_CERT_MAX_PATHLEN) + 1)	/* A certificate with no path length constraint specified. */


/**
 * Helper macro to get the path length constraint from the type.
 */
#define	X509_CERT_PATHLEN(x)		(x - X509_CERT_CA)


/**
 * The OID for the legacy RIoT extension to X.509 certificates.
 */
#define	X509_RIOT_OID					"1.3.6.1.4.1.311.89.3.1"
#define	X509_RIOT_OID_RAW				"\x2b\x06\x01\x04\x01\x82\x37\x59\x03\x01"

/**
 * The OID for the TCB Info extension from TCG DICE.
 */
#define	X509_TCG_DICE_TCBINFO_OID		"2.23.133.5.4.1"
#define	X509_TCG_DICE_TCBINFO_OID_RAW	"\x67\x81\x05\x05\x04\x01"

/**
 * The OID for the UEID extension from TCG DICE.
 */
#define	X509_TCG_DICE_UEID_OID			"2.23.133.5.4.4"
#define	X509_TCG_DICE_UEID_OID_RAW		"\x67\x81\x05\x05\x04\x04"

/**
 * Information for the device UEID.
 */
struct x509_dice_ueid {
	const uint8_t *ueid;				/**< Raw data for the unique identifier. */
	size_t length;						/**< Length of the UEID data. */
};

/**
 * Information necessary to populate DICE X.509 extensions.
 */
struct x509_dice_tcbinfo {
	const char *version;				/**< Version identifier for the firmware. */
	uint32_t svn;						/**< Security state of the device. */
	const uint8_t *fw_id;				/**< The firmware ID hash. */
	enum hash_type fw_id_hash;			/**< The type of hash used to generate the firmware ID. */
	const struct x509_dice_ueid *ueid;	/**< Optional Device unique identifier.  If this is not
											null, a UEID extension will be added. */
};


/**
 * The possible types of public keys in a certificate.
 */
enum {
	X509_PUBLIC_KEY_ECC,		/**< An ECC public key. */
	X509_PUBLIC_KEY_RSA			/**< An RSA public key. */
};


/**
 * The maximum length for a certificate serial number.
 */
#define	X509_MAX_SERIAL_NUMBER	20


/**
 * The possible version numbers for X.509 certificates.
 */
enum {
	X509_VERSION_1 = 1,			/**< A version 1 certificate. */
	X509_VERSION_2 = 2,			/**< A version 2 certificate. */
	X509_VERSION_3 = 3,			/**< A version 3 certificate. */
};


/**
 * An X.509 certificate.  A certificate instance is only usable by the engine that initialized it.
 */
struct x509_certificate {
	void *context;		/**< The implementation context for the certificate. */
};

/**
 * A store for X.509 certificate authorities that can be used for certificate authentication.
 * Certificates contained in this store can either be a trusted root CA or an untrusted intermediate
 * CA that is rooted in a trusted CA in the store.  The CA certificate store is only usable by the
 * engine that initialized it.
 */
struct x509_ca_certs {
	void *context;		/**< The implementation context for an intermediate certificate store. */
};

/**
 * A platform-independent API for handling certificates.  X509 engine instances are not guaranteed
 * to be thread-safe.
 */
struct x509_engine {
#ifdef X509_ENABLE_CREATE_CERTIFICATES
	/**
	 * Generate a Certificate Signing Request for the public key of an asymmetric encryption
	 * key pair.
	 *
	 * Note:  There is currently no need to support EKU OIDs for end entity CSRs.  This situation is
	 * complicated by the fact that per RFC5280 there can be only one instance of each extension
	 * type in a certificate.  End entity certificates already have an EKU for client authentication
	 * that is marked critical.  This OID would need to be added to the list of EKUs, but it really
	 * should make the EKU not be critical, since the data would generally not be understood.  To
	 * avoid the complexity around creating these types of certificates and the implications of the
	 * non-standard OID, this type of CSR cannot be created.
	 *
	 * @param engine The X.509 engine to use to generate the CSR.
	 * @param priv_key The DER formatted private key to generate a CSR for.
	 * @param key_length The length of the private key.
	 * @param name The subject common name to apply to the CSR.
	 * @param type The type of certificate being requested for signing.
	 * @param eku An optional Extended Key Usage OID string that will be added to the CSR.  Set to
	 * null if no EKU OID is necessary.  If provided, this string must be a string for an encoded
	 * hex string of the OID.
	 * @param dice Optional information that can be provided to add a DICE extensions to the CSR.
	 * Set to null to not add any DICE extensions.
	 * @param csr Output buffer for the DER formatted CSR.  This is a dynamically allocated buffer,
	 * and it is the responsibility of the caller to free it.  This will return null in the case of
	 * an error.
	 * @param csr_length Output for the length of the CSR.
	 *
	 * @return 0 if the CSR was successfully generated or an error code.
	 */
	int (*create_csr) (struct x509_engine *engine, const uint8_t *priv_key, size_t key_length,
		const char *name, int type, const char *eku, const struct x509_dice_tcbinfo *dice,
		uint8_t **csr, size_t *csr_length);

	/**
	 * Generate a self-signed certificate for the public key of an asymmetric encryption key pair.
	 *
	 * @param engine The X.509 engine to use to generate the certificate.
	 * @param cert The instance to initialize as a self-signed certificate.
	 * @param priv_key The DER formatted private key to generate a certificate for.
	 * @param key_length The length of the private key.
	 * @param serial_num The serial number to assign to the certificate.
	 * @param serial_length The length of the serial number.
	 * @param name The subject common name to apply to the certificate.
	 * @param type The type of certificate to generate.
	 * @param dice Optional information that can be provided to add DICE extensions to the
	 * certificate.  Set to null to not add any DICE extensions.
	 *
	 * @return 0 if the certificate was successfully generated or an error code.
	 */
	int (*create_self_signed_certificate) (struct x509_engine *engine,
		struct x509_certificate *cert, const uint8_t *priv_key, size_t key_length,
		const uint8_t *serial_num, size_t serial_length, const char *name, int type,
		const struct x509_dice_tcbinfo *dice);

	/**
	 * Generate a cross-certificate (signed by a CA) for the public key of an asymmetric encryption
	 * key pair.
	 *
	 * @param engine The X.509 engine to use to generate the certificate.
	 * @param cert The certificate instance to initialize with CA signing.
	 * @param key The DER formatted key to generate the certificate for.  This can be either the
	 * public or private key.
	 * @param key_length The length of the key.
	 * @param serial_num The serial number to assign to the certificate.
	 * @param serial_length The length of the serial number.
	 * @param name The subject common name to apply to the certificate.
	 * @param type The type of certificate to generate.
	 * @param ca_priv_key The DER formatted private key of the CA.
	 * @param ca_key_length The length of the CA private key.
	 * @param ca_cert The certificate for the CA issuing the new certificate.
	 * @param dice Optional information that can be provided to add a DICE extensions to the
	 * certificate.  Set to null to not add any DICE extensions.
	 *
	 * @return 0 if the certificate was successfully generated or an error code.
	 */
	int (*create_ca_signed_certificate) (struct x509_engine *engine, struct x509_certificate *cert,
		const uint8_t *key, size_t key_length, const uint8_t *serial_num, size_t serial_length,
		const char *name, int type, const uint8_t* ca_priv_key, size_t ca_key_length,
		const struct x509_certificate *ca_cert, const struct x509_dice_tcbinfo *dice);
#endif

	/**
	 * Load an X.509 certificate encoded in DER format.
	 *
	 * @param engine The X.509 engine to use to load the certificate.
	 * @param cert The certificate instance to initialize.
	 * @param der The DER formatted certificate to load.
	 * @param length The length of the certificate data.
	 *
	 * @return 0 if the certificate was loaded successfully or an error code.
	 */
	int (*load_certificate) (struct x509_engine *engine, struct x509_certificate *cert,
		const uint8_t *der, size_t length);

	/**
	 * Release an X.509 certificate.
	 *
	 * @param engine The engine used to initialize the certificate.
	 * @param cert The certificate instance to release.
	 */
	void (*release_certificate) (struct x509_engine *engine, struct x509_certificate *cert);

#ifdef X509_ENABLE_CREATE_CERTIFICATES
	/**
	 * Encode a certificate in DER format.
	 *
	 * @param engine The X.509 engine used to initialize the certificate.
	 * @param cert The certificate to encode to DER.
	 * @param der Output buffer for the DER formatted certificate.  This is a dynamically allocated
	 * buffer, and it is the responsibility of the caller to free it.  This will return null in the
	 * case of an error.
	 * @param length Output for the length of the DER certificate.
	 *
	 * @return 0 if the certificate was successfully encoded or an error code.
	 */
	int (*get_certificate_der) (struct x509_engine *engine, const struct x509_certificate *cert,
		uint8_t **der, size_t *length);
#endif

#ifdef X509_ENABLE_AUTHENTICATION
	/**
	 * Get the version of a certificate.
	 *
	 * @param engine The X.509 engine that initialized the certificate.
	 * @param cert The certificate to query.
	 *
	 * @return The certificate version or an error code.  Use ROT_IS_ERROR to check the return
	 * value.
	 */
	int (*get_certificate_version) (struct x509_engine *engine,
		const struct x509_certificate *cert);

	/**
	 * Get the serial number of a certificate.
	 *
	 * @param engine The X.509 engine used to initialize the certificate.
	 * @param cert The certificate to query.
	 * @param serial_num Output buffer for the certificate serial number.  This should be at least
	 * X509_MAX_SERIAL_NUMBER bytes to have enough space for any serial number.
	 * @param length The length of the serial number buffer.
	 *
	 * @return The length of the serial number in the buffer or an error code.  Use ROT_IS_ERROR to
	 * check the return value.
	 */
	int (*get_serial_number) (struct x509_engine *engine, const struct x509_certificate *cert,
		uint8_t *serial_num, size_t length);

	/**
	 * Get the type of public key contained in the certificate.
	 *
	 * @param engine The X.509 engine used to initialize the certificate.
	 * @param cert The certificate to query.
	 *
	 * @return The public key type or an error code.  Use ROT_IS_ERROR to check the return value.
	 */
	int (*get_public_key_type) (struct x509_engine *engine, const struct x509_certificate *cert);

	/**
	 * Get the bit length of the public key contained in the certificate.  This represents the key
	 * strength, not the length of the encoded public key data.  For example, a certificate for an
	 * RSA 2k key would report 2048.
	 *
	 * @param engine The X.509 engine used to initialize the certificate.
	 * @param cert The certificate to query.
	 *
	 * @return The bit length of the public key or an error code.  Use ROT_IS_ERROR to check the
	 * return value.
	 */
	int (*get_public_key_length) (struct x509_engine *engine, const struct x509_certificate *cert);

	/**
	 * Extract the public key from a certificate.
	 *
	 * @param engine The X.509 engine used to initialize the certificate.
	 * @param cert The certificate that contains the desired public key.
	 * @param key Output buffer for the DER formatted public key.  This is a dynamically allocated
	 * buffer, and it is the responsibility of the caller to free it.  This will return null in the
	 * case of an error.
	 * @param key_length Output for the length of the public key buffer.
	 *
	 * @return 0 if the public key was successfully retrieved or an error code.
	 */
	int (*get_public_key) (struct x509_engine *engine, const struct x509_certificate *cert,
		uint8_t **key, size_t *key_length);

	/**
	 * Initialize an empty certificate store for CA certificates to use for X.509 path validation.
	 *
	 * @param engine The X.509 engine to use for creating the certificate store.
	 * @param store The CA certificate store to initialize.
	 *
	 * @return 0 if the certificate store was successfully initialized or an error code.
	 */
	int (*init_ca_cert_store) (struct x509_engine *engine, struct x509_ca_certs *store);

	/**
	 * Release a store for CA certificates.
	 *
	 * @param engine The X.509 engine that initialized the certificate store.
	 * @param store The CA certificate store to release.
	 */
	void (*release_ca_cert_store) (struct x509_engine *engine, struct x509_ca_certs *store);

	/**
	 * Add the certificate for a certificate authority that should be implicitly trusted when
	 * authenticating other certificates.  The root CA must be self-signed, and will be checked for
	 * validity prior to adding it as a trusted certificate.
	 *
	 * @param engine The X.509 engine used to initialize the certificate store.
	 * @param store The certificate store to add the root CA to.
	 * @param der The DER formatted certificate for the root CA.
	 * @param length The length of the certificate data.
	 *
	 * @return 0 if the certificate was successfully added or an error code.
	 */
	int (*add_root_ca) (struct x509_engine *engine, struct x509_ca_certs *store, const uint8_t *der,
		size_t length);

	/**
	 * Add the certificate for a certificate authority that can be used in path validation.  The
	 * certificate must be for a CA that is not self signed.  No verification is done on the
	 * certificate until it is used for path validation.
	 *
	 * Intermediate certificates must be added in validation order, with certificates signed by
	 * a root CA added first.
	 *
	 * @param engine The X.509 engine used to initialize the certificate store.
	 * @param store The certificate store to add the CA to.
	 * @param der The DER formatted certificate for the intermediate CA.
	 * @param length The length of the certificate data.
	 *
	 * @return 0 if the certificate was successfully added to the store or an error code.
	 */
	int (*add_intermediate_ca) (struct x509_engine *engine, struct x509_ca_certs *store,
		const uint8_t *der, size_t length);

	/**
	 * Determine if a certificate is valid and comes from a trusted source.
	 *
	 * @param engine The X.509 engine used to initialize both the certificate and the certificate
	 * store.
	 * @param cert The certificate to authenticate.
	 * @param store The set of certificate authorities that can be used to authenticate the
	 * certificate.
	 *
	 * @return 0 if the certificate is trusted or an error code.
	 */
	int (*authenticate) (struct x509_engine *engine, const struct x509_certificate *cert,
		const struct x509_ca_certs *store);
#endif
};


#define	X509_ENGINE_ERROR(code)		ROT_ERROR (ROT_MODULE_X509_ENGINE, code)

/**
 * Error codes that can be generated by an X.509 engine.
 */
enum {
	X509_ENGINE_INVALID_ARGUMENT = X509_ENGINE_ERROR (0x00),		/**< Input parameter is null or not valid. */
	X509_ENGINE_NO_MEMORY = X509_ENGINE_ERROR (0x01),				/**< Memory allocation failed. */
	X509_ENGINE_CSR_FAILED = X509_ENGINE_ERROR (0x02),				/**< The CSR was not created. */
	X509_ENGINE_SELF_SIGNED_FAILED = X509_ENGINE_ERROR (0x03),		/**< The self-signed certificate was not created. */
	X509_ENGINE_CA_SIGNED_FAILED = X509_ENGINE_ERROR (0x04),		/**< The CA-signed certificate was not created. */
	X509_ENGINE_LOAD_FAILED = X509_ENGINE_ERROR (0x05),				/**< The certificate DER was not loaded. */
	X509_ENGINE_CERT_DER_FAILED = X509_ENGINE_ERROR (0x06),			/**< The certificate was not encoded to DER. */
	X509_ENGINE_KEY_TYPE_FAILED = X509_ENGINE_ERROR (0x07),			/**< Failed to get the key type from the certificate. */
	X509_ENGINE_KEY_FAILED = X509_ENGINE_ERROR (0x08),				/**< Failed to get the key from the certificate. */
	X509_ENGINE_ROOT_CA_FAILED = X509_ENGINE_ERROR (0x09),			/**< The root CA was not added for path validation. */
	X509_ENGINE_INIT_STORE_FAILED = X509_ENGINE_ERROR (0x0a),		/**< The intermediate CA certificate store was not initialized. */
	X509_ENGINE_INTER_CA_FAILED = X509_ENGINE_ERROR (0x0b),			/**< The intermediate CA was not added for path validation. */
	X509_ENGINE_AUTH_FAILED = X509_ENGINE_ERROR (0x0c),				/**< An error unrelated to path validation caused authentication to fail. */
	X509_ENGINE_RIOT_NO_FWID = X509_ENGINE_ERROR (0x0d),			/**< No FWID provided for the RIoT extension. */
	X509_ENGINE_RIOT_UNSUPPORTED_HASH = X509_ENGINE_ERROR (0x0e),	/**< The RIoT FWID uses an unsupported hash algorithm. */
	X509_ENGINE_UNSUPPORTED_KEY_TYPE = X509_ENGINE_ERROR (0x0f),	/**< A certificate contains a key for an unsupported algorithm. */
	X509_ENGINE_UNKNOWN_KEY_TYPE = X509_ENGINE_ERROR (0x10),		/**< The type of key in a certificate could not be determined. */
	X509_ENGINE_UNSUPPORTED_SIG_TYPE = X509_ENGINE_ERROR (0x11),	/**< The certificate signature use an unsupported algorithm. */
	X509_ENGINE_NOT_CA_CERT = X509_ENGINE_ERROR (0x12),				/**< The certificate is not a CA. */
	X509_ENGINE_NOT_SELF_SIGNED = X509_ENGINE_ERROR (0x13),			/**< The certificate is not self-signed. */
	X509_ENGINE_IS_SELF_SIGNED = X509_ENGINE_ERROR (0x14),			/**< The certificate is self-signed. */
	X509_ENGINE_BAD_SIGNATURE = X509_ENGINE_ERROR (0x15),			/**< The certificate failed signature verification. */
	X509_ENGINE_CERT_NOT_VALID = X509_ENGINE_ERROR (0x16),			/**< Path validation for the certificate failed. */
	X509_ENGINE_RIOT_AUTH_FAILED = X509_ENGINE_ERROR (0x17),		/**< Path validation for the certificate succeeded, but the RIoT extension was not valid. */
	X509_ENGINE_HW_NOT_INIT = X509_ENGINE_ERROR (0x18),				/**< The X.509 hardware has not been initialized. */
	X509_ENGINE_CERT_SIGN_FAILED = X509_ENGINE_ERROR (0x19),		/**< Failure related to signing the certificate. */
	X509_ENGINE_LONG_SERIAL_NUM = X509_ENGINE_ERROR (0x1a),			/**< The certificate serial number exceeds the length supported by the engine. */
	X509_ENGINE_BIG_CERT_SIZE = X509_ENGINE_ERROR (0x1b),			/**< The certificate length exceeds the size supported by the engine. */
	X509_ENGINE_VERSION_FAILED = X509_ENGINE_ERROR (0x1c),			/**< Failed to get the version number from the certificate. */
	X509_ENGINE_SERIAL_NUM_FAILED = X509_ENGINE_ERROR (0x1d),		/**< Failed to get the serial number from the certificate. */
	X509_ENGINE_KEY_LENGTH_FAILED = X509_ENGINE_ERROR (0x1e),		/**< Failed to get the key length from the certificate. */
	X509_ENGINE_SMALL_SERIAL_BUFFER = X509_ENGINE_ERROR (0x1f),		/**< Insufficient buffer space for the serial number. */
	X509_ENGINE_LONG_OID = X509_ENGINE_ERROR (0x20),				/**< An OID is too long to be processed. */
	X509_ENGINE_DICE_NO_VERSION = X509_ENGINE_ERROR (0x21),			/**< No version information for the DICE extension. */
	X509_ENGINE_DICE_NO_UEID = X509_ENGINE_ERROR (0x22),			/**< No UEID information for the DICE extension. */
	X509_ENGINE_INVALID_SERIAL_NUM = X509_ENGINE_ERROR (0x23),		/**< Provided serial number is an invalid value. */
};


#endif /* X509_H_ */
