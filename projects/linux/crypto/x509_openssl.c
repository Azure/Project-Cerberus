// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/conf.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/asn1t.h>
#include <openssl/err.h>
#include "platform.h"
#include "crypto/x509_openssl.h"
#include "common/unused.h"


/**
 * OpenSSL data for managing CA certificates.
 */
struct x509_openssl_ca_store_context {
	X509_STORE *trusted;			/**< Store for Root CAs. */
	STACK_OF (X509) *intermediate;	/**< Store for intermediate CAs. */
};

/**
 * Structure of the RIoT FWID.
 */
typedef struct riot_fwid_st {
	ASN1_OBJECT *hash_alg;			/**< The algorithm used to generate the FWID. */
	ASN1_OCTET_STRING *fwid;		/**< The FWID hash data. */
	ASN1_ENCODING enc;				/**< ASN1 encoding. */
} RIOT_FWID;

DEFINE_STACK_OF (RIOT_FWID)
typedef STACK_OF (RIOT_FWID) RIOT_FWIDS;

/**
 * Structure of the RIoT Composite Identifier extension.
 */
typedef struct x509_riot_st {
	ASN1_INTEGER *version;			/**< The extension version. */
	X509_PUBKEY *device_id;			/**< The public key of the device ID. */
	RIOT_FWID *fwid;				/**< The FWID information. */
	ASN1_ENCODING enc;				/**< ASN1 encoding. */
} X509_RIOT;

/**
 * Structure of the DICE TCB Info extension.
 */
typedef struct x509_tcbinfo_st {
	GENERAL_NAMES *vendor;			/**< Device vendor information. */
	ASN1_IA5STRING *model;			/**< Model indentifier. */
	ASN1_IA5STRING *version;		/**< The firmware version. */
	ASN1_INTEGER *svn;				/**< The security state. */
	ASN1_INTEGER *layer;			/**< Firmware state information. */
	ASN1_INTEGER *index;			/**< Firmware state information. */
	RIOT_FWIDS *digests;			/**< The FWID information. */
	ASN1_ENCODING enc;				/**< ASN1 encoding. */
} X509_TCBINFO;

typedef struct x509_ueid_st {
	ASN1_OCTET_STRING *ueid;		/**< The UEID string. */
	ASN1_ENCODING enc;				/**< ASN1 encoding. */
} X509_UEID;

ASN1_SEQUENCE_enc (RIOT_FWID, enc, 0) = {
	ASN1_SIMPLE (RIOT_FWID, hash_alg, ASN1_OBJECT),
	ASN1_SIMPLE (RIOT_FWID, fwid, ASN1_OCTET_STRING)
} ASN1_SEQUENCE_END_enc (RIOT_FWID, RIOT_FWID)

IMPLEMENT_ASN1_FUNCTIONS (RIOT_FWID)

ASN1_SEQUENCE_enc (X509_RIOT, enc, 0) = {
	ASN1_SIMPLE (X509_RIOT, version, ASN1_INTEGER),
	ASN1_SIMPLE (X509_RIOT, device_id, X509_PUBKEY),
	ASN1_SIMPLE (X509_RIOT, fwid, RIOT_FWID),
} ASN1_SEQUENCE_END_enc (X509_RIOT, X509_RIOT)

IMPLEMENT_ASN1_FUNCTIONS (X509_RIOT)

ASN1_SEQUENCE_enc (X509_TCBINFO, enc, 0) = {
	ASN1_IMP_SEQUENCE_OF_OPT (X509_TCBINFO, vendor, GENERAL_NAME, 0),
	ASN1_IMP_OPT (X509_TCBINFO, model, ASN1_IA5STRING, 1),
	ASN1_IMP_OPT (X509_TCBINFO, version, ASN1_IA5STRING, 2),
	ASN1_IMP_OPT (X509_TCBINFO, svn, ASN1_INTEGER, 3),
	ASN1_IMP_OPT (X509_TCBINFO, layer, ASN1_INTEGER, 4),
	ASN1_IMP_OPT (X509_TCBINFO, index, ASN1_INTEGER, 5),
	ASN1_IMP_SEQUENCE_OF_OPT (X509_TCBINFO, digests, RIOT_FWID, 6)
} ASN1_SEQUENCE_END_enc (X509_TCBINFO, X509_TCBINFO)

IMPLEMENT_ASN1_FUNCTIONS (X509_TCBINFO)

ASN1_SEQUENCE_enc (X509_UEID, enc, 0) = {
	ASN1_SIMPLE (X509_UEID, ueid, ASN1_OCTET_STRING)
} ASN1_SEQUENCE_END_enc (X509_UEID, X509_UEID)

IMPLEMENT_ASN1_FUNCTIONS (X509_UEID)


#ifdef X509_ENABLE_CREATE_CERTIFICATES
/**
 * Load a DER formatted key.
 *
 * @param key The key instance that will be allocated.
 * @param der The DER formatted key to load.
 * @param length The length of the DER key.
 * @param require_priv Flag indicating if the key must be a private a key.
 *
 * @return 0 if the key was successfully loaded or an error code.
 */
static int x509_openssl_load_key (EVP_PKEY **key, const uint8_t *der, size_t length,
	bool require_priv)
{
	BIO *bio;
	int status;

	ERR_clear_error ();

	bio = BIO_new_mem_buf (der, length);
	if (bio == NULL) {
		status = ERR_get_error ();
		goto err_bio;
	}

	*key = d2i_PrivateKey_bio (bio, NULL);
	if (*key == NULL) {
		status = ERR_get_error ();
		if (require_priv) {
			goto err_key;
		}

		status = BIO_reset (bio);
		if (status <= 0) {
			status = ERR_get_error ();
			goto err_key;
		}

		*key = d2i_PUBKEY_bio (bio, NULL);
		if (*key == NULL) {
			status = ERR_get_error ();
			goto err_key;
		}
	}

	status = 0;

err_key:
	BIO_free (bio);
err_bio:
	return -status;
}

/**
 * Add a standard extension to a CSR to be included in the signed certificate.
 *
 * @param request The context for the CSR being generated.
 * @param extensions The set of extensions to update for the CSR.
 * @param nid The type of extension to add.
 * @param value The value to assign to the extension.
 *
 * @return 0 if the extension was added or an error code.
 */
static int x509_openssl_add_standard_csr_extension (X509_REQ *request,
	STACK_OF (X509_EXTENSION) *extenions, int nid, const char *value)
{
	X509V3_CTX ext_ctx;
	X509_EXTENSION *ext;
	int status;

	X509V3_set_ctx (&ext_ctx, NULL, NULL, request, NULL, 0);
	X509V3_set_ctx_nodb (&ext_ctx);

	ext = X509V3_EXT_conf_nid (NULL, &ext_ctx, nid, (char*) value);
	if (ext == NULL) {
		status = -ERR_get_error ();
		goto err_conf;
	}

	status = sk_X509_EXTENSION_push (extenions, ext);
	if (status == 0) {
		status = X509_ENGINE_NO_MEMORY;
		goto err_push;
	}

	return 0;

err_push:
	X509_EXTENSION_free (ext);
err_conf:
	return status;
}

/**
 * Add any extension to a CSR to be included in the signed certificate.
 *
 * @param request The context for the CSR being generated.
 * @param extensions The set of extensions to update for the CSR.
 * @param ext The extension to add to the CSR.
 * @param data The extension data.
 *
 * @return 0 if the extension was added or an error code.  On failure, the extension will be freed.
 */
static int x509_openssl_add_custom_csr_extension (X509_REQ *request,
	STACK_OF (X509_EXTENSION) *extensions, X509_EXTENSION *ext, ASN1_OCTET_STRING *data)
{
	X509V3_CTX ext_ctx;
	int status;

	X509V3_set_ctx (&ext_ctx, NULL, NULL, request, NULL, 0);
	X509V3_set_ctx_nodb (&ext_ctx);

	status = sk_X509_EXTENSION_push (extensions, ext);
	if (status == 0) {
		status = X509_ENGINE_NO_MEMORY;
		goto err_push;
	}

	ASN1_OCTET_STRING_free (data);
	return 0;

err_push:
	X509_EXTENSION_free (ext);
	ASN1_OCTET_STRING_free (data);
	return status;
}

/**
 * Set the firmware ID values in a RIoT FWID structure.
 *
 * @param riot The FWID structure to update.
 * @param fw_id The FWID value to set.
 * @param fw_id_hash The hash algorithm used to generate the FWID value.
 *
 * @return 0 if the FWID was updated successfully or an error code.
 */
static int x509_openssl_riot_fwid_set (RIOT_FWID *riot, const uint8_t *fw_id,
	enum hash_type fw_id_hash)
{
	ASN1_OBJECT *hash_oid;
	int fw_id_len;

	if (fw_id == NULL) {
		return X509_ENGINE_RIOT_NO_FWID;
	}

	switch (fw_id_hash) {
		case HASH_TYPE_SHA1:
			fw_id_len = SHA1_HASH_LENGTH;
			hash_oid = OBJ_nid2obj (EVP_MD_type (EVP_sha1 ()));
			break;

		case HASH_TYPE_SHA256:
			fw_id_len = SHA256_HASH_LENGTH;
			hash_oid = OBJ_nid2obj (EVP_MD_type (EVP_sha256 ()));
			break;

		default:
			return X509_ENGINE_RIOT_UNSUPPORTED_HASH;
	}

	if (hash_oid == NULL) {
		return -ERR_get_error ();
	}

	ASN1_OBJECT_free (riot->hash_alg);
	riot->hash_alg = hash_oid;

	if (ASN1_OCTET_STRING_set (riot->fwid, fw_id, fw_id_len) == 0) {
		return -ERR_get_error ();
	}

	return 0;
}

/**
 * Create an custom formatted X.509 extension.
 *
 * @param der The raw data for the extension.  This must a dynamically allocated buffer.
 * @param length The length of the extension data.
 * @param oid The OID to identify the extension.
 * @param ext Output for the new extension.
 * @param ext_data Output for the data object of the extension.
 *
 * @return 0 if the extension was created successfully or an error code.
 */
static int x509_openssl_create_custom_extension (uint8_t *der, size_t length, const char *oid,
	X509_EXTENSION **ext, ASN1_OCTET_STRING **ext_data)
{
	ASN1_OBJECT *ext_oid;
	int status = 0;

	ext_oid = OBJ_txt2obj (oid, 1);
	if (ext_oid == NULL) {
		return -ERR_get_error ();
	}

	*ext_data = ASN1_OCTET_STRING_new ();
	if (ext_data == NULL) {
		status = X509_ENGINE_NO_MEMORY;
		goto err_data;
	}

	status = ASN1_OCTET_STRING_set (*ext_data, der, length);
	if (status == 0) {
		status = -ERR_get_error ();
		goto err_data;
	}

	*ext = X509_EXTENSION_create_by_OBJ (NULL, ext_oid, 0, *ext_data);
	if (*ext == NULL) {
		status = -ERR_get_error ();
		goto err_ext;
	}

	ASN1_OBJECT_free (ext_oid);
	return 0;

err_ext:
	ASN1_OCTET_STRING_free (*ext_data);
err_data:
	ASN1_OBJECT_free (ext_oid);
	return status;
}

/**
 * Create a TCB Info X.509 extension.
 *
 * @param tcb Data to use to create the extension.
 * @param tcb_ext Output for the created extension.
 * @param tcb_data Output for the extension data object.
 *
 * @return 0 if the extension was created successfully or an error code.
 */
static int x509_openssl_create_tcbinfo_extension (const struct x509_dice_tcbinfo *tcb,
	X509_EXTENSION **tcb_ext, ASN1_OCTET_STRING **tcb_data)
{
	X509_TCBINFO *tcbinfo;
	RIOT_FWID *riot;
	int status;
	uint8_t *tcb_der = NULL;
	int tcb_der_len;

	if (tcb->version == NULL) {
		return X509_ENGINE_DICE_NO_VERSION;
	}

	tcbinfo = X509_TCBINFO_new ();
	if (tcbinfo == NULL) {
		status = -ERR_get_error ();
		goto err_tcb;
	}

	tcbinfo->version = ASN1_IA5STRING_new ();
	if (tcbinfo->version == NULL) {
		status = X509_ENGINE_NO_MEMORY;
		goto err_build;
	}

	tcbinfo->version->length = strlen (tcb->version);
	tcbinfo->version->data = (unsigned char*) strdup (tcb->version);
	if (tcbinfo->version->data == NULL) {
		status = X509_ENGINE_NO_MEMORY;
		goto err_build;
	}

	tcbinfo->svn = ASN1_INTEGER_new ();
	if (tcbinfo->svn == NULL) {
		status = X509_ENGINE_NO_MEMORY;
		goto err_build;
	}

	status = ASN1_INTEGER_set (tcbinfo->svn, tcb->svn);
	if (status == 0) {
		status = -ERR_get_error ();
		goto err_build;
	}

	tcbinfo->digests = sk_RIOT_FWID_new_null ();
	if (tcbinfo->digests == NULL) {
		status = X509_ENGINE_NO_MEMORY;
		goto err_build;
	}

	riot = RIOT_FWID_new ();
	if (riot == NULL) {
		status = X509_ENGINE_NO_MEMORY;
		goto err_build;
	}

	status = x509_openssl_riot_fwid_set (riot, tcb->fw_id, tcb->fw_id_hash);
	if (status != 0) {
		goto err_build;
	}

	status = sk_RIOT_FWID_push (tcbinfo->digests, riot);
	if (status == 0) {
		status = X509_ENGINE_NO_MEMORY;
		RIOT_FWID_free (riot);
		goto err_build;
	}

	tcb_der_len = i2d_X509_TCBINFO (tcbinfo, &tcb_der);
	if (tcb_der_len < 0) {
		status = -ERR_get_error ();
		goto err_build;
	}

	status = x509_openssl_create_custom_extension (tcb_der, tcb_der_len, X509_TCG_DICE_TCBINFO_OID,
		tcb_ext, tcb_data);
	if (status != 0) {
		goto err_ext;
	}

	X509_TCBINFO_free (tcbinfo);
	return 0;

err_ext:
	platform_free (tcb_der);
err_build:
	X509_TCBINFO_free (tcbinfo);
err_tcb:
	return status;
}

/**
 * Create a UEID X.509 extension.
 *
 * @param dice Data to use to create the extension.
 * @param ueid_ext Output for the created extension.
 * @param ueid_data Output for the extension data object.
 *
 * @return 0 if the extension was created successfully or an error code.
 */
static int x509_openssl_create_ueid_extension (const struct x509_dice_ueid *dice,
	X509_EXTENSION **ueid_ext, ASN1_OCTET_STRING **ueid_data)
{
	X509_UEID *ueid;
	int status;
	uint8_t *ueid_dup;
	uint8_t *ueid_der = NULL;
	int ueid_der_len;

	if ((dice->ueid == NULL) || (dice->length == 0)) {
		return X509_ENGINE_DICE_NO_UEID;
	}

	ueid = X509_UEID_new ();
	if (ueid == NULL) {
		status = -ERR_get_error ();
		goto err_ueid;
	}

	ueid->ueid = ASN1_OCTET_STRING_new ();
	if (ueid->ueid == NULL) {
		status = X509_ENGINE_NO_MEMORY;
		goto err_dup;
	}

	ueid_dup = platform_malloc (dice->length);
	if (ueid_dup == NULL) {
		status = X509_ENGINE_NO_MEMORY;
		goto err_dup;
	}

	memcpy (ueid_dup, dice->ueid, dice->length);

	status = ASN1_OCTET_STRING_set (ueid->ueid, ueid_dup, dice->length);
	if (status == 0) {
		status = -ERR_get_error ();
		platform_free (ueid_dup);
		goto err_dup;
	}

	ueid_der_len = i2d_X509_UEID (ueid, &ueid_der);
	if (ueid_der_len < 0) {
		status = -ERR_get_error ();
		goto err_dup;
	}

	status = x509_openssl_create_custom_extension (ueid_der, ueid_der_len, X509_TCG_DICE_UEID_OID,
		ueid_ext, ueid_data);
	if (status != 0) {
		goto err_ext;
	}

	X509_UEID_free (ueid);
	return 0;

err_ext:
	platform_free (ueid_der);
err_dup:
	X509_UEID_free (ueid);
err_ueid:
	return status;
}

static int x509_openssl_create_csr (struct x509_engine *engine, const uint8_t *priv_key,
	size_t key_length, const char *name, int type, const char *eku,
	const struct x509_dice_tcbinfo *dice, uint8_t **csr, size_t *csr_length)
{
	X509_REQ *request;
	EVP_PKEY *req_key;
	X509_NAME *subject;
	STACK_OF (X509_EXTENSION) *extensions;
	int status;
	char *key_usage;

	if (csr == NULL) {
		return X509_ENGINE_INVALID_ARGUMENT;
	}

	*csr = NULL;
	if ((engine == NULL) || (priv_key == NULL) || (name == NULL) || (csr_length == NULL) ||
		(key_length == 0)) {
		return X509_ENGINE_INVALID_ARGUMENT;
	}

	if ((type == X509_CERT_END_ENTITY) && (eku != NULL)) {
		return X509_ENGINE_NOT_CA_CERT;
	}

	ERR_clear_error ();

	request = X509_REQ_new ();
	if (request == NULL) {
		status = -ERR_get_error ();
		goto err_req;
	}

	status = x509_openssl_load_key (&req_key, priv_key, key_length, true);
	if (status != 0) {
		goto err_key;
	}

	status = X509_REQ_set_pubkey (request, req_key);
	if (status == 0) {
		status = -ERR_get_error ();
		goto err_req_key;
	}

	subject = X509_REQ_get_subject_name (request);
	status = X509_NAME_add_entry_by_txt (subject, "CN", MBSTRING_ASC, (unsigned char*) name,
		-1, -1, 0);
	if (status == 0) {
		status = -ERR_get_error ();
		goto err_req_key;
	}

	extensions = sk_X509_EXTENSION_new_null ();
	if (extensions == NULL) {
		status = X509_ENGINE_NO_MEMORY;
		goto err_req_key;
	}

	if (type) {
		key_usage = "critical,keyCertSign";
	}
	else {
		key_usage = "critical,digitalSignature,keyAgreement";
	}

	status = x509_openssl_add_standard_csr_extension (request, extensions, NID_key_usage,
		key_usage);
	if (status != 0) {
		goto err_ext;
	}

	if (type == X509_CERT_END_ENTITY) {
		status = x509_openssl_add_standard_csr_extension (request, extensions, NID_ext_key_usage,
			"critical,clientAuth");
		if (status != 0) {
			goto err_ext;
		}
	}

	if (eku != NULL) {
		ASN1_OBJECT *oid;
		uint8_t oid_der[256];
		uint8_t *oid_ptr = oid_der;
		char oid_str[256];

		oid_der[0] = 0x06;
		oid_der[1] = strlen (eku);
		if (oid_der[1] > sizeof (oid_der) - 2) {
			return X509_ENGINE_LONG_OID;
		}
		memcpy (&oid_der[2], eku, oid_der[1]);

		oid = d2i_ASN1_OBJECT (NULL, (const unsigned char**) &oid_ptr, oid_der[1] + 2);
		if (oid == NULL) {
			status = -ERR_get_error ();
			goto err_ext;
		}

		status = OBJ_obj2txt (oid_str, sizeof (oid_str), oid, 1);
		ASN1_OBJECT_free (oid);
		if (status > (int) sizeof (oid_str)) {
			status = X509_ENGINE_LONG_OID;
			goto err_ext;
		}

		status = x509_openssl_add_standard_csr_extension (request, extensions, NID_ext_key_usage,
			oid_str);
		if (status != 0) {
			goto err_ext;
		}
	}

	if (type) {
		char constraint[35];

		if (X509_CERT_PATHLEN (type) <= X509_CERT_MAX_PATHLEN) {
			sprintf (constraint, "critical,CA:TRUE,pathlen:%d", X509_CERT_PATHLEN (type));
		}
		else {
			strcpy (constraint, "critical,CA:TRUE");
		}

		status = x509_openssl_add_standard_csr_extension (request, extensions,
			NID_basic_constraints, constraint);
		if (status != 0) {
			goto err_ext;
		}
	}

	if (dice) {
		X509_EXTENSION *tcbinfo;
		X509_EXTENSION *ueid;
		ASN1_OCTET_STRING *ext_data;

		status = x509_openssl_create_tcbinfo_extension (dice, &tcbinfo, &ext_data);
		if (status != 0) {
			goto err_ext;
		}

		status = x509_openssl_add_custom_csr_extension (request, extensions, tcbinfo, ext_data);
		if (status != 0) {
			goto err_ext;
		}

		if (dice->ueid) {
			status = x509_openssl_create_ueid_extension (dice->ueid, &ueid, &ext_data);
			if (status != 0) {
				goto err_ext;
			}

			status = x509_openssl_add_custom_csr_extension (request, extensions, ueid, ext_data);
			if (status != 0) {
				goto err_ext;
			}
		}
	}

	status = X509_REQ_add_extensions (request, extensions);
	if (status == 0) {
		status = -ERR_get_error ();
		goto err_ext;
	}

	status = X509_REQ_sign (request, req_key, EVP_sha256 ());
	if (status == 0) {
		status = -ERR_get_error ();
		goto err_ext;
	}

	status = i2d_X509_REQ (request, csr);
	if (status >= 0) {
		*csr_length = status;
		status = 0;
	}
	else {
		status = -ERR_get_error ();
	}

err_ext:
	sk_X509_EXTENSION_pop_free (extensions, X509_EXTENSION_free);
err_req_key:
	EVP_PKEY_free (req_key);
err_key:
	X509_REQ_free (request);
err_req:
	return status;
}

/**
 * Add a standard X.509v3 extension to a certificate.
 *
 * @param cert The certificate to add the extension to.
 * @param issuer The issuing certificate instance.
 * @param nid The type of extension to add.
 * @param value The value to assign to the extension.
 *
 * @return 0 if the extension was added or an error code.
 */
static int x509_openssl_add_standard_v3_extension (X509 *cert, X509 *issuer, int nid,
	char *value)
{
	X509V3_CTX ext_ctx;
	X509_EXTENSION *ext;
	int status;

	X509V3_set_ctx (&ext_ctx, issuer, cert, NULL, NULL, 0);
	X509V3_set_ctx_nodb (&ext_ctx);

	ext = X509V3_EXT_conf_nid (NULL, &ext_ctx, nid, value);
	if (ext == NULL) {
		status = ERR_get_error ();
		goto err_conf;
	}

	status = X509_add_ext (cert, ext, -1);
	if (status == 0) {
		status = ERR_get_error ();
	}
	else {
		status = 0;
	}

	X509_EXTENSION_free (ext);
err_conf:
	return -status;
}

/**
 * Add DICE extensions to a certificate.
 *
 * @param cert The certificate to add the extensions to.
 * @param ca The certificate used for signing.
 * @param tcb The information for the DICE extensions.
 *
 * @return 0 if the extensions were added or an error code.
 */
static int x509_openssl_add_dice_extensions (X509 *cert, X509 *ca,
	const struct x509_dice_tcbinfo *tcb)
{
	X509_EXTENSION *tcb_ext;
	ASN1_OCTET_STRING *tcb_data;
	X509_EXTENSION *ueid_ext = NULL;
	ASN1_OCTET_STRING *ueid_data = NULL;
	int status;

	status = x509_openssl_create_tcbinfo_extension (tcb, &tcb_ext, &tcb_data);
	if (status != 0) {
		goto err_tcbinfo;
	}

	status = X509_add_ext (cert, tcb_ext, -1);
	if (status == 0) {
		status = -ERR_get_error ();
		goto err_tcbadd;
	}

	if (tcb->ueid) {
		status = x509_openssl_create_ueid_extension (tcb->ueid, &ueid_ext, &ueid_data);
		if (status != 0) {
			goto err_tcbadd;
		}

		status = X509_add_ext (cert, ueid_ext, -1);
		if (status == 0) {
			status = -ERR_get_error ();
			goto err_ueidadd;
		}
	}

	status = 0;

err_ueidadd:
	X509_EXTENSION_free (ueid_ext);
	ASN1_OCTET_STRING_free (ueid_data);
err_tcbadd:
	X509_EXTENSION_free (tcb_ext);
	ASN1_OCTET_STRING_free (tcb_data);
err_tcbinfo:
	return status;
}

/**
 * Create a new certificate.  This can be self-signed, or signed by a CA.
 *
 * @param cert The instance to initialize with the new certificate.
 * @param cert_key The key to use to create the certificate.  For self-signed certificates, this
 * must be a private key.
 * @param serial_num The serial number to assign to the certificate.
 * @param serial_length The length of the serial number.
 * @param name The common name for the certificate subject.
 * @param type The type of certificate to create.
 * @param ca_key The private key of the CA to use for certificate signing.  Set this to null for a
 * self-signed certificate.
 * @param ca_cert The certificate for the CA key.  This is unused for a self-signed certificate and
 * can be set to null.
 * @param dice DICE information to add to the certificate.  Set this to null to create a certificate
 * with no DICE extensions.
 *
 * @return 0 if the certificate was successfully created or an error code.
 */
static int x509_openssl_create_certificate (struct x509_certificate *cert, EVP_PKEY *cert_key,
	const uint8_t *serial_num, size_t serial_length, const char *name, int type, EVP_PKEY *ca_key,
	const struct x509_certificate *ca_cert, const struct x509_dice_tcbinfo *dice)
{
	X509 *x509;
	X509 *ca_x509;
	BIGNUM *serial;
	X509_NAME *subject;
	ASN1_TIME *validity;
	char *key_usage;
	int status;

	ERR_clear_error ();

	x509 = X509_new ();
	if (x509 == NULL) {
		status = -ERR_get_error ();
		goto err_cert;
	}

	if (ca_key) {
		ca_x509 = (X509*) ca_cert->context;
	}
	else {
		ca_x509 = x509;
	}

	status = X509_set_pubkey (x509, cert_key);
	if (status == 0) {
		status = -ERR_get_error ();
		goto err_req_key;
	}

	status = X509_set_version (x509, 2);
	if (status == 0) {
		status = -ERR_get_error ();
		goto err_req_key;
	}

	serial = BN_bin2bn (serial_num, serial_length, NULL);
	if (serial == NULL) {
		status = -ERR_get_error ();
		goto err_serial;
	}

	if (BN_is_zero (serial)) {
		status = X509_ENGINE_INVALID_SERIAL_NUM;
		goto err_serial;
	}

	if (BN_to_ASN1_INTEGER (serial, X509_get_serialNumber (x509)) == NULL) {
		status = -ERR_get_error ();
		goto err_serial;
	}

	subject = X509_get_subject_name (x509);
	status = X509_NAME_add_entry_by_txt (subject, "CN", MBSTRING_ASC, (unsigned char*) name,
		-1, -1, 0);
	if (status == 0) {
		status = -ERR_get_error ();
		goto err_serial;
	}

	subject = X509_get_subject_name (ca_x509);
	status = X509_set_issuer_name (x509, subject);
	if (status == 0) {
		status = -ERR_get_error ();
		goto err_serial;
	}

	validity = X509_get_notBefore (x509);
	status = ASN1_TIME_set_string (validity, "180101000000Z");
	if (status == 0) {
		status = -ERR_get_error ();
		goto err_serial;
	}

	validity = X509_get_notAfter (x509);
	status = ASN1_TIME_set_string (validity, "99991231235959Z");
	if (status == 0) {
		status = -ERR_get_error ();
		goto err_serial;
	}

	status = x509_openssl_add_standard_v3_extension (x509, ca_x509, NID_subject_key_identifier,
		"hash");
	if (status != 0) {
		goto err_serial;
	}

	status = x509_openssl_add_standard_v3_extension (x509, ca_x509,
		NID_authority_key_identifier, "keyid");
	if (status != 0) {
		goto err_serial;
	}

	if (type) {
		key_usage = "critical,keyCertSign";
	}
	else {
		key_usage = "critical,digitalSignature,keyAgreement";
	}

	status = x509_openssl_add_standard_v3_extension (x509, ca_x509, NID_key_usage, key_usage);
	if (status != 0) {
		goto err_serial;
	}

	if (type == X509_CERT_END_ENTITY) {
		status = x509_openssl_add_standard_v3_extension (x509, ca_x509, NID_ext_key_usage,
			"critical,clientAuth");
		if (status != 0) {
			goto err_serial;
		}
	}

	if (type) {
		char constraint[35];

		if (X509_CERT_PATHLEN (type) <= X509_CERT_MAX_PATHLEN) {
			sprintf (constraint, "critical,CA:TRUE,pathlen:%d", X509_CERT_PATHLEN (type));
		}
		else {
			strcpy (constraint, "critical,CA:TRUE");
		}

		status = x509_openssl_add_standard_v3_extension (x509, ca_x509, NID_basic_constraints,
			constraint);
		if (status != 0) {
			goto err_serial;
		}
	}

	if (dice) {
		status = x509_openssl_add_dice_extensions (x509, ca_x509, dice);
		if (status != 0) {
			goto err_serial;
		}
	}

	if (ca_key) {
		status = X509_sign (x509, ca_key, EVP_sha256 ());
	}
	else {
		status = X509_sign (x509, cert_key, EVP_sha256 ());
	}

	if (status == 0) {
		status = -ERR_get_error ();
		goto err_serial;
	}

	cert->context = x509;
	status = 0;

err_serial:
	BN_free (serial);
err_req_key:
	if (status != 0) {
		X509_free (x509);
	}
err_cert:
	return status;
}

static int x509_openssl_create_self_signed_certificate (struct x509_engine *engine,
	struct x509_certificate *cert, const uint8_t *priv_key, size_t key_length,
	const uint8_t *serial_num, size_t serial_length, const char *name, int type,
	const struct x509_dice_tcbinfo *dice)
{
	EVP_PKEY *cert_key;
	int status;

	if ((engine == NULL) || (cert == NULL) || (priv_key == NULL) || (serial_num == NULL) ||
		(name == NULL) || (key_length == 0) || (serial_length == 0)) {
		return X509_ENGINE_INVALID_ARGUMENT;
	}

	status = x509_openssl_load_key (&cert_key, priv_key, key_length, true);
	if (status != 0) {
		return status;
	}

	status = x509_openssl_create_certificate (cert, cert_key, serial_num, serial_length, name, type,
		NULL, NULL, dice);

	EVP_PKEY_free (cert_key);
	return status;
}

static int x509_openssl_create_ca_signed_certificate (struct x509_engine *engine,
	struct x509_certificate *cert, const uint8_t *key, size_t key_length, const uint8_t *serial_num,
	size_t serial_length, const char *name, int type, const uint8_t* ca_priv_key,
	size_t ca_key_length, const struct x509_certificate *ca_cert,
	const struct x509_dice_tcbinfo *tcb)
{
	EVP_PKEY *cert_key;
	EVP_PKEY *ca_key;
	int status;

	if ((engine == NULL) || (cert == NULL) || (key == NULL) || (serial_num == NULL) ||
		(name == NULL) || (ca_priv_key == NULL) || (ca_cert == NULL) || (key_length == 0) ||
		(serial_length == 0) || (ca_key_length == 0)) {
		return X509_ENGINE_INVALID_ARGUMENT;
	}

	status = x509_openssl_load_key (&cert_key, key, key_length, false);
	if (status != 0) {
		goto err_key;
	}

	status = x509_openssl_load_key (&ca_key, ca_priv_key, ca_key_length, true);
	if (status != 0) {
		goto err_ca_key;
	}

	status = x509_openssl_create_certificate (cert, cert_key, serial_num, serial_length, name, type,
		ca_key, ca_cert, tcb);

	EVP_PKEY_free (ca_key);
err_ca_key:
	EVP_PKEY_free (cert_key);
err_key:
	return status;
}
#endif

static int x509_openssl_load_certificate (struct x509_engine *engine, struct x509_certificate *cert,
	const uint8_t *der, size_t length)
{
	X509 *x509;
	BIO *bio;
	int status;

	if ((engine == NULL) || (cert == NULL) || (der == NULL) || (length == 0)) {
		return X509_ENGINE_INVALID_ARGUMENT;
	}

	ERR_clear_error ();

	bio = BIO_new_mem_buf (der, length);
	if (bio == NULL) {
		status = ERR_get_error ();
		goto err_bio;
	}

	x509 = d2i_X509_bio (bio, NULL);
	if (x509 == NULL) {
		status = ERR_get_error ();
		goto err_cert;
	}

	cert->context = x509;
	status = 0;

err_cert:
	BIO_free (bio);
err_bio:
	return -status;
}

static void x509_openssl_release_certificate (struct x509_engine *engine,
	struct x509_certificate *cert)
{
	UNUSED (engine);

	if (cert) {
		X509_free ((X509*) cert->context);
		memset (cert, 0, sizeof (struct x509_certificate));
	}
}

#ifdef X509_ENABLE_CREATE_CERTIFICATES
static int x509_openssl_get_certificate_der (struct x509_engine *engine,
	const struct x509_certificate *cert, uint8_t **der, size_t *length)
{
	int status;

	if (der == NULL) {
		return X509_ENGINE_INVALID_ARGUMENT;
	}

	*der = NULL;
	if ((engine == NULL) || (cert == NULL) || (length == NULL)) {
		return X509_ENGINE_INVALID_ARGUMENT;
	}

	ERR_clear_error ();

	status = i2d_X509 ((X509*) cert->context, der);
	if (status >= 0) {
		*length = status;
		status = 0;
	}
	else {
		status = -ERR_get_error ();
	}

	return status;
}
#endif

#ifdef X509_ENABLE_AUTHENTICATION
static int x509_openssl_get_certificate_version (struct x509_engine *engine,
	const struct x509_certificate *cert)
{
	if ((engine == NULL) || (cert == NULL)) {
		return X509_ENGINE_INVALID_ARGUMENT;
	}

	return X509_get_version ((X509*) cert->context) + 1;
}

static int x509_openssl_get_serial_number (struct x509_engine *engine,
	const struct x509_certificate *cert, uint8_t *serial_num, size_t length)
{
	ASN1_INTEGER *encoded;
	BIGNUM *serial;
	int bytes;

	if ((engine == NULL) || (cert == NULL) || (serial_num == NULL)) {
		return X509_ENGINE_INVALID_ARGUMENT;
	}

	ERR_clear_error ();

	encoded = X509_get_serialNumber ((X509*) cert->context);

	serial = ASN1_INTEGER_to_BN (encoded, NULL);
	if (serial == NULL) {
		return -ERR_get_error ();
	}

	if ((int) length < BN_num_bytes (serial)) {
		bytes = X509_ENGINE_SMALL_SERIAL_BUFFER;
		goto err_length;
	}

	bytes = BN_bn2bin (serial, serial_num);

err_length:
	BN_free (serial);
	return bytes;
}

static int x509_openssl_get_public_key_type (struct x509_engine *engine,
	const struct x509_certificate *cert)
{
	EVP_PKEY *key;
	int type;

	if ((engine == NULL) || (cert == NULL)) {
		return X509_ENGINE_INVALID_ARGUMENT;
	}

	ERR_clear_error ();

	key = X509_get_pubkey ((X509*) cert->context);
	if (key == NULL) {
		type = -ERR_get_error ();
		return type;
	}

	type = EVP_PKEY_base_id (key);
	switch (type) {
		case EVP_PKEY_RSA:
			type = X509_PUBLIC_KEY_RSA;
			break;

		case EVP_PKEY_EC:
			type = X509_PUBLIC_KEY_ECC;
			break;

		case EVP_PKEY_NONE:
			type = X509_ENGINE_UNKNOWN_KEY_TYPE;
			break;

		default:
			type = X509_ENGINE_UNSUPPORTED_KEY_TYPE;
	}

	EVP_PKEY_free (key);
	return type;
}

static int x509_openssl_get_public_key_length (struct x509_engine *engine,
	const struct x509_certificate *cert)
{
	EVP_PKEY *key;
	int bits;

	if ((engine == NULL) || (cert == NULL)) {
		return X509_ENGINE_INVALID_ARGUMENT;
	}

	ERR_clear_error ();

	key = X509_get_pubkey ((X509*) cert->context);
	if (key == NULL) {
		return -ERR_get_error ();
	}

	bits = EVP_PKEY_bits (key);

	EVP_PKEY_free (key);
	return bits;
}

static int x509_openssl_get_public_key (struct x509_engine *engine,
	const struct x509_certificate *cert, uint8_t **key, size_t *key_length)
{
	EVP_PKEY *cert_key;
	int status;

	if (key == NULL) {
		return X509_ENGINE_INVALID_ARGUMENT;
	}

	*key = NULL;
	if ((engine == NULL) || (cert == NULL) || (key_length == NULL)) {
		return X509_ENGINE_INVALID_ARGUMENT;
	}

	ERR_clear_error ();

	cert_key = X509_get_pubkey ((X509*) cert->context);
	if (cert_key == NULL) {
		status = ERR_get_error ();
		goto err_key;
	}

	status = i2d_PUBKEY (cert_key, key);
	if (status >= 0) {
		*key_length = status;
		status = 0;
	}
	else {
		status = ERR_get_error ();
	}

	EVP_PKEY_free (cert_key);
err_key:
	return -status;
}

static int x509_openssl_init_ca_cert_store (struct x509_engine *engine, struct x509_ca_certs *store)
{
	struct x509_openssl_ca_store_context *store_ctx;
	int status;

	if ((engine == NULL) || (store == NULL)) {
		return X509_ENGINE_INVALID_ARGUMENT;
	}

	store_ctx = platform_malloc (sizeof (struct x509_openssl_ca_store_context));
	if (store_ctx == NULL) {
		return X509_ENGINE_NO_MEMORY;
	}

	ERR_clear_error ();

	store_ctx->trusted = X509_STORE_new ();
	if (store_ctx->trusted == NULL) {
		status = -ERR_get_error ();
		goto ctx_free;
	}

	store_ctx->intermediate = sk_X509_new_null ();
	if (store_ctx->intermediate == NULL) {
		status = -ERR_get_error ();
		goto store_free;
	}

	store->context = store_ctx;
	return 0;

store_free:
	X509_STORE_free (store_ctx->trusted);
ctx_free:
	platform_free (store_ctx);

	return status;
}

static void x509_openssl_release_ca_cert_store (struct x509_engine *engine,
	struct x509_ca_certs *store)
{
	UNUSED (engine);

	if (store && store->context) {
		struct x509_openssl_ca_store_context *store_ctx = store->context;

		X509_STORE_free (store_ctx->trusted);
		sk_X509_pop_free (store_ctx->intermediate, X509_free);
		platform_free (store_ctx);
		memset (store, 0, sizeof (struct x509_ca_certs));
	}
}

static int x509_openssl_add_root_ca (struct x509_engine *engine, struct x509_ca_certs *store,
	const uint8_t *der, size_t length)
{
	struct x509_certificate cert;
	EVP_PKEY *cert_key;
	int status;

	if (store == NULL) {
		return X509_ENGINE_INVALID_ARGUMENT;
	}

	status = x509_openssl_load_certificate (engine, &cert, der, length);
	if (status != 0) {
		goto err_cert;
	}

	ERR_clear_error ();

	status = X509_check_ca ((X509*) cert.context);
	if (status == 0) {
		status = X509_ENGINE_NOT_CA_CERT;
		goto err_chk;
	}

	status = X509_check_issued ((X509*) cert.context, (X509*) cert.context);
	if (status != X509_V_OK) {
		status = X509_ENGINE_NOT_SELF_SIGNED;
		goto err_chk;
	}

	cert_key = X509_get_pubkey ((X509*) cert.context);
	if (cert_key == NULL) {
		status = -ERR_get_error ();
		goto err_chk;
	}

	status = X509_verify ((X509*) cert.context, cert_key);
	if (status == 1) {
		status = 0;
	}
	else {
		status = X509_ENGINE_BAD_SIGNATURE;
		goto err_sig;
	}

	status = X509_STORE_add_cert (((struct x509_openssl_ca_store_context*) store->context)->trusted,
		(X509*) cert.context);
	if (status == 0) {
		status = -ERR_get_error ();
		goto err_sig;
	}

	status = 0;

err_sig:
	EVP_PKEY_free (cert_key);
err_chk:
	x509_openssl_release_certificate (engine, &cert);
err_cert:
	return status;
}

static int x509_openssl_add_intermediate_ca (struct x509_engine *engine,
	struct x509_ca_certs *store, const uint8_t *der, size_t length)
{
	struct x509_certificate cert;
	int status;

	if (store == NULL) {
		return X509_ENGINE_INVALID_ARGUMENT;
	}

	status = x509_openssl_load_certificate (engine, &cert, der, length);
	if (status != 0) {
		goto err_cert;
	}

	status = X509_check_ca ((X509*) cert.context);
	if (status == 0) {
		status = X509_ENGINE_NOT_CA_CERT;
		goto err_chk;
	}

	status = X509_check_issued ((X509*) cert.context, (X509*) cert.context);
	if (status == X509_V_OK) {
		status = X509_ENGINE_IS_SELF_SIGNED;
		goto err_chk;
	}

	status = sk_X509_push (((struct x509_openssl_ca_store_context*) store->context)->intermediate,
		(X509*) cert.context);
	if (status == 0) {
		status = X509_ENGINE_NO_MEMORY;
		goto err_chk;
	}

	return 0;

err_chk:
	x509_openssl_release_certificate (engine, &cert);
err_cert:
	return status;
}

static int x509_openssl_authenticate (struct x509_engine *engine,
	const struct x509_certificate *cert, const struct x509_ca_certs *store)
{
	struct x509_engine_openssl *openssl = (struct x509_engine_openssl*) engine;
	struct x509_openssl_ca_store_context *store_ctx = NULL;
	X509_STORE_CTX *auth_ctx;
	int status;

	if ((openssl == NULL) || (cert == NULL) || (store == NULL)) {
		return X509_ENGINE_INVALID_ARGUMENT;
	}

	ERR_clear_error ();

	auth_ctx = X509_STORE_CTX_new ();
	if (auth_ctx == NULL) {
		status = -ERR_get_error ();
		goto err_ctx;
	}

	if (store) {
		store_ctx = store->context;
	}

	status = X509_STORE_CTX_init (auth_ctx, store_ctx->trusted, (X509*) cert->context,
		store_ctx->intermediate);
	if (status == 0) {
		status = -ERR_get_error ();
		goto err_init;
	}

	X509_verify_cert (auth_ctx);
	status = X509_STORE_CTX_get_error (auth_ctx);

	if (status != 0) {
		status = X509_ENGINE_CERT_NOT_VALID;
	}

err_init:
	X509_STORE_CTX_free (auth_ctx);
err_ctx:
	return status;
}
#endif

/**
 * Initialize an instance for handling X.509 certificates using OpenSSL.
 *
 * @param engine The X.509 engine to initialize.
 *
 * @return 0 if the X.509 engine was successfully initialized or an error code.
 */
int x509_openssl_init (struct x509_engine_openssl *engine)
{
	if (engine == NULL) {
		return X509_ENGINE_INVALID_ARGUMENT;
	}

	memset (engine, 0, sizeof (struct x509_engine_openssl));

#ifdef X509_ENABLE_CREATE_CERTIFICATES
	engine->base.create_csr = x509_openssl_create_csr;
	engine->base.create_self_signed_certificate = x509_openssl_create_self_signed_certificate;
	engine->base.create_ca_signed_certificate = x509_openssl_create_ca_signed_certificate;
#endif
	engine->base.load_certificate = x509_openssl_load_certificate;
	engine->base.release_certificate = x509_openssl_release_certificate;
#ifdef X509_ENABLE_CREATE_CERTIFICATES
	engine->base.get_certificate_der = x509_openssl_get_certificate_der;
#endif
#ifdef X509_ENABLE_AUTHENTICATION
	engine->base.get_certificate_version = x509_openssl_get_certificate_version;
	engine->base.get_serial_number = x509_openssl_get_serial_number;
	engine->base.get_public_key_type = x509_openssl_get_public_key_type;
	engine->base.get_public_key_length = x509_openssl_get_public_key_length;
	engine->base.get_public_key = x509_openssl_get_public_key;
	engine->base.init_ca_cert_store = x509_openssl_init_ca_cert_store;
	engine->base.release_ca_cert_store = x509_openssl_release_ca_cert_store;
	engine->base.add_root_ca = x509_openssl_add_root_ca;
	engine->base.add_intermediate_ca = x509_openssl_add_intermediate_ca;
	engine->base.authenticate = x509_openssl_authenticate;
#endif

	return 0;
}

/**
 * Release an OpenSSL X.509 engine.
 *
 * @param engine The X.509 engine to release.
 */
void x509_openssl_release (struct x509_engine_openssl *engine)
{

}
