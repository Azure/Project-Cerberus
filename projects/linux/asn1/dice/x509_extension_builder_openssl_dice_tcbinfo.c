// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <openssl/asn1t.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/x509v3.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "platform_api.h"
#include "x509_extension_builder_openssl_dice_tcbinfo.h"
#include "asn1/dice/tcg_dice_oid.h"
#include "asn1/dice/x509_extension_builder_dice_tcbinfo.h"
#include "common/unused.h"


/**
 * Structure of a DICE FWID.
 */
typedef struct dice_fwid_st {
	ASN1_OBJECT *hash_alg;		/**< The algorithm used to generate the FWID. */
	ASN1_OCTET_STRING *digest;	/**< The FWID digest. */
	ASN1_ENCODING enc;			/**< ASN1 encoding. */
} DICE_FWID;

DEFINE_STACK_OF (DICE_FWID)
typedef STACK_OF (DICE_FWID) DICE_FWID_LIST;

/**
 * Structure of a DICE Integrity Register.
 */
typedef struct dice_integrity_register_st {
	ASN1_IA5STRING *register_name;	/**< Name associated with the register. */
	ASN1_INTEGER *register_num;		/**< Number assigned to the register. */
	DICE_FWID_LIST *digests;		/**< A list of digests for the register. */
	ASN1_ENCODING enc;				/**< ASN1 encoding. */
} DICE_INTEGRITY_REGISTER;

DEFINE_STACK_OF (DICE_INTEGRITY_REGISTER)
typedef STACK_OF (DICE_INTEGRITY_REGISTER) DICE_IR_LIST;

/**
 * Structure of the DICE TcbInfo extension.
 */
typedef struct dice_tcbinfo_st {
	ASN1_UTF8STRING *vendor;			/**< The entity that created the measurement of the Target Environment (e.g., a TCI value). */
	ASN1_UTF8STRING *model;				/**< The product name associated with the measurement of the Target Environment. */
	ASN1_UTF8STRING *version;			/**< The revision string associated with the Target Environment. */
	ASN1_INTEGER *svn;					/**< The security version number associated with the Target Environment. */
	ASN1_INTEGER *layer;				/**< The DICE layer associated with this measurement of the Target Environment. */
	ASN1_INTEGER *index;				/**< A value that distinguishes different instances of the same type of Target Environment. */
	DICE_FWID_LIST *fwids;				/**< A list of FWID values. */
	ASN1_BIT_STRING *flags;				/**< A list of flags that enumerate potentially simultaneous operational states of the Target Environment. */
	ASN1_OCTET_STRING *vendor_info;		/**< Vendor supplied values that encode vendor, model, or device specific state. */
	ASN1_OCTET_STRING *type;			/**< A machine readable description of the measurement. */
	DICE_IR_LIST *integrity_registers;	/**< A list of named digests. */
	ASN1_ENCODING enc;					/**< ASN1 encoding. */
} DICE_TCBINFO;

ASN1_SEQUENCE_enc (DICE_FWID, enc, 0) = {
	ASN1_SIMPLE (DICE_FWID, hash_alg, ASN1_OBJECT),
	ASN1_SIMPLE (DICE_FWID, digest, ASN1_OCTET_STRING)
} ASN1_SEQUENCE_END_enc (DICE_FWID, DICE_FWID)

IMPLEMENT_ASN1_FUNCTIONS (DICE_FWID)

ASN1_SEQUENCE_enc (DICE_INTEGRITY_REGISTER, enc, 0) = {
	ASN1_SIMPLE (DICE_INTEGRITY_REGISTER, register_name, ASN1_IA5STRING),
	ASN1_SIMPLE (DICE_INTEGRITY_REGISTER, register_num, ASN1_INTEGER),
	ASN1_SEQUENCE_OF (DICE_INTEGRITY_REGISTER, digests, DICE_FWID)
} ASN1_SEQUENCE_END_enc (DICE_INTEGRITY_REGISTER, DICE_INTEGRITY_REGISTER)

IMPLEMENT_ASN1_FUNCTIONS (DICE_INTEGRITY_REGISTER)

ASN1_SEQUENCE_enc (DICE_TCBINFO, enc, 0) = {
	ASN1_IMP_OPT (DICE_TCBINFO, vendor, ASN1_UTF8STRING, 0),
	ASN1_IMP_OPT (DICE_TCBINFO, model, ASN1_UTF8STRING, 1),
	ASN1_IMP_OPT (DICE_TCBINFO, version, ASN1_UTF8STRING, 2),
	ASN1_IMP_OPT (DICE_TCBINFO, svn, ASN1_INTEGER, 3),
	ASN1_IMP_OPT (DICE_TCBINFO, layer, ASN1_INTEGER, 4),
	ASN1_IMP_OPT (DICE_TCBINFO, index, ASN1_INTEGER, 5),
	ASN1_IMP_SEQUENCE_OF_OPT (DICE_TCBINFO, fwids, DICE_FWID, 6),
	ASN1_IMP_OPT (DICE_TCBINFO, flags, ASN1_BIT_STRING, 7),
	ASN1_IMP_OPT (DICE_TCBINFO, vendor_info, ASN1_OCTET_STRING, 8),
	ASN1_IMP_OPT (DICE_TCBINFO, type, ASN1_OCTET_STRING, 9),
	ASN1_IMP_SEQUENCE_OF_OPT (DICE_TCBINFO, integrity_registers, DICE_INTEGRITY_REGISTER, 10),
} ASN1_SEQUENCE_END_enc (DICE_TCBINFO, DICE_TCBINFO)

IMPLEMENT_ASN1_FUNCTIONS (DICE_TCBINFO)


int x509_extension_builder_openssl_dice_tcbinfo_build (const struct x509_extension_builder *builder,
	struct x509_extension *extension)
{
	const struct x509_extension_builder_openssl_dice_tcbinfo *dice =
		(const struct x509_extension_builder_openssl_dice_tcbinfo*) builder;
	DICE_TCBINFO *tcbinfo;
	BIGNUM *svn;
	DICE_FWID *fwid;
	ASN1_OBJECT *fwid_oid;
	int fwid_len;
	size_t i;
	int status;
	uint8_t *tcb_der = NULL;
	int tcb_der_len;

	if ((dice == NULL) || (extension == NULL)) {
		return DICE_TCBINFO_EXTENSION_INVALID_ARGUMENT;
	}

	if (dice->tcb == NULL) {
		return DICE_TCBINFO_EXTENSION_INVALID_ARGUMENT;
	}

	if (dice->tcb->version == NULL) {
		return DICE_TCBINFO_EXTENSION_NO_VERSION;
	}

	if ((dice->tcb->svn == NULL) || (dice->tcb->svn_length == 0)) {
		return DICE_TCBINFO_EXTENSION_NO_SVN;
	}

	if ((dice->tcb->fwid_list == NULL) || (dice->tcb->fwid_count == 0)) {
		return DICE_TCBINFO_EXTENSION_NO_FWID_LIST;
	}

	tcbinfo = DICE_TCBINFO_new ();
	if (tcbinfo == NULL) {
		status = -ERR_get_error ();
		goto err_tcb;
	}

	if (dice->tcb->vendor != NULL) {
		tcbinfo->vendor = ASN1_UTF8STRING_new ();
		if (tcbinfo->vendor == NULL) {
			status = DICE_TCBINFO_EXTENSION_NO_MEMORY;
			goto err_build;
		}

		tcbinfo->vendor->length = strlen (dice->tcb->vendor);
		tcbinfo->vendor->data = (unsigned char*) strdup (dice->tcb->vendor);
		if (tcbinfo->vendor->data == NULL) {
			status = DICE_TCBINFO_EXTENSION_NO_MEMORY;
			goto err_build;
		}
	}

	if (dice->tcb->model != NULL) {
		tcbinfo->model = ASN1_UTF8STRING_new ();
		if (tcbinfo->model == NULL) {
			status = DICE_TCBINFO_EXTENSION_NO_MEMORY;
			goto err_build;
		}

		tcbinfo->model->length = strlen (dice->tcb->model);
		tcbinfo->model->data = (unsigned char*) strdup (dice->tcb->model);
		if (tcbinfo->model->data == NULL) {
			status = DICE_TCBINFO_EXTENSION_NO_MEMORY;
			goto err_build;
		}
	}

	tcbinfo->version = ASN1_UTF8STRING_new ();
	if (tcbinfo->version == NULL) {
		status = DICE_TCBINFO_EXTENSION_NO_MEMORY;
		goto err_build;
	}

	tcbinfo->version->length = strlen (dice->tcb->version);
	tcbinfo->version->data = (unsigned char*) strdup (dice->tcb->version);
	if (tcbinfo->version->data == NULL) {
		status = DICE_TCBINFO_EXTENSION_NO_MEMORY;
		goto err_build;
	}

	svn = BN_bin2bn (dice->tcb->svn, dice->tcb->svn_length, NULL);
	if (svn == NULL) {
		status = DICE_TCBINFO_EXTENSION_NO_MEMORY;
		goto err_build;
	}

	tcbinfo->svn = BN_to_ASN1_INTEGER (svn, NULL);
	BN_free (svn);
	if (tcbinfo->svn == NULL) {
		status = DICE_TCBINFO_EXTENSION_NO_MEMORY;
		goto err_build;
	}

	tcbinfo->layer = ASN1_INTEGER_new ();
	if (tcbinfo->layer == NULL) {
		status = DICE_TCBINFO_EXTENSION_NO_MEMORY;
		goto err_build;
	}

	status = ASN1_INTEGER_set_uint64 (tcbinfo->layer, dice->tcb->layer);
	if (status == 0) {
		status = DICE_TCBINFO_EXTENSION_NO_MEMORY;
		goto err_build;
	}

	tcbinfo->fwids = sk_DICE_FWID_new_null ();
	if (tcbinfo->fwids == NULL) {
		status = DICE_TCBINFO_EXTENSION_NO_MEMORY;
		goto err_build;
	}

	for (i = 0; i < dice->tcb->fwid_count; i++) {
		if (dice->tcb->fwid_list[i].digest == NULL) {
			status = DICE_TCBINFO_EXTENSION_NO_FWID;
			goto err_build;
		}

		switch (dice->tcb->fwid_list[i].hash_alg) {
			case HASH_TYPE_SHA1:
				fwid_len = SHA1_HASH_LENGTH;
				fwid_oid = OBJ_nid2obj (EVP_MD_type (EVP_sha1 ()));
				break;

			case HASH_TYPE_SHA256:
				fwid_len = SHA256_HASH_LENGTH;
				fwid_oid = OBJ_nid2obj (EVP_MD_type (EVP_sha256 ()));
				break;

			case HASH_TYPE_SHA384:
				fwid_len = SHA384_HASH_LENGTH;
				fwid_oid = OBJ_nid2obj (EVP_MD_type (EVP_sha384 ()));
				break;

			case HASH_TYPE_SHA512:
				fwid_len = SHA512_HASH_LENGTH;
				fwid_oid = OBJ_nid2obj (EVP_MD_type (EVP_sha512 ()));
				break;

			default:
				status = DICE_TCBINFO_EXTENSION_UNKNOWN_FWID;
				goto err_build;
		}

		if (fwid_oid == NULL) {
			status = -ERR_get_error ();
			goto err_build;
		}

		fwid = DICE_FWID_new ();
		if (fwid == NULL) {
			status = DICE_TCBINFO_EXTENSION_NO_MEMORY;
			goto err_build;
		}

		ASN1_OBJECT_free (fwid->hash_alg);
		fwid->hash_alg = fwid_oid;

		if (ASN1_OCTET_STRING_set (fwid->digest, dice->tcb->fwid_list[i].digest, fwid_len) == 0) {
			status = -ERR_get_error ();
			goto err_fwid;
		}

		status = sk_DICE_FWID_push (tcbinfo->fwids, fwid);
		if (status == 0) {
			status = DICE_TCBINFO_EXTENSION_NO_MEMORY;
			goto err_fwid;
		}
	}

	tcb_der_len = i2d_DICE_TCBINFO (tcbinfo, &tcb_der);
	if (tcb_der_len < 0) {
		status = -ERR_get_error ();
		goto err_build;
	}

	x509_extension_builder_init_extension_descriptor (extension, false,
		TCG_DICE_OID_TCBINFO_EXTENSION, TCG_DICE_OID_TCBINFO_EXTENSION_LENGTH, tcb_der,
		tcb_der_len);

	DICE_TCBINFO_free (tcbinfo);

	return 0;

err_fwid:
	DICE_FWID_free (fwid);
err_build:
	DICE_TCBINFO_free (tcbinfo);
err_tcb:

	return status;
}

void x509_extension_builder_openssl_dice_tcbinfo_free (const struct x509_extension_builder *builder,
	struct x509_extension *extension)
{
	UNUSED (builder);

	x509_extension_builder_free_extension_descriptor (extension);
}

/**
 * Initialize an extension builder for a TCG DICE TcbInfo extension.
 *
 * @param builder The extension builder to initialize.
 * @param tcb The firmware TCB to encode in the extension.  This does not need to be constant.  The
 * contents can be externally modified after initialization to change what will be encoded in the
 * extension.
 *
 * @return 0 if the extension builder was initialized successfully or an error code.
 */
int x509_extension_builder_openssl_dice_tcbinfo_init (
	struct x509_extension_builder_openssl_dice_tcbinfo *builder, const struct tcg_dice_tcbinfo *tcb)
{
	if ((builder == NULL) || (tcb == NULL)) {
		return DICE_TCBINFO_EXTENSION_INVALID_ARGUMENT;
	}

	memset (builder, 0, sizeof (struct x509_extension_builder_openssl_dice_tcbinfo));

	builder->base.build = x509_extension_builder_openssl_dice_tcbinfo_build;
	builder->base.free = x509_extension_builder_openssl_dice_tcbinfo_free;

	builder->tcb = tcb;

	return 0;
}

/**
 * Release the resources used by a TCG DICE TcbInfo extension builder.
 *
 * @param builder The extension builder to release.
 */
void x509_extension_builder_openssl_dice_tcbinfo_release (
	const struct x509_extension_builder_openssl_dice_tcbinfo *builder)
{
	UNUSED (builder);
}
