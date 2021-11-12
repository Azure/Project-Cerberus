/*
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See LICENSE in the project root.
 */
#include <stdint.h>
#include <stdbool.h>
#include "include/RiotDerEnc.h"
#include "include/RiotX509Bldr.h"
#include "include/RiotDerDec.h"
#include "crypto/x509.h"

#define ASRT(_X) if(!(_X))      {goto Error;}
#define CHK(_X)  if(((_X)) < 0) {goto Error;}

// OIDs.  Note that the encoder expects a -1 sentinel.
static int riotOID[] = { 1,3,6,1,4,1,311,89,3,1,-1 };
static int ecdsaWithSHA256OID[] = { 1,2,840,10045,4,3,2,-1 };
static int ecPublicKeyOID[] = { 1,2,840,10045,2,1,-1 };
static int prime256v1OID[] = { 1,2,840,10045,3,1,7,-1 };
static int keyUsageOID[] = { 2,5,29,15,-1 };
static int extKeyUsageOID[] = { 2,5,29,37,-1 };
static int extAuthKeyIdentifierOID[] = { 2,5,29,35,-1 };
static int extSubjectKeyIdentifierOID[] = { 2,5,29,14,-1 };
static int clientAuthOID[] = { 1,3,6,1,5,5,7,3,2,-1 };
static int sha1OID[] = { 1,3,14,3,2,26,-1 };
static int sha256OID[] = { 2,16,840,1,101,3,4,2,1,-1 };
static int commonNameOID[] = { 2,5,4,3,-1 };
static int countryNameOID[] = { 2,5,4,6,-1 };
static int orgNameOID[] = { 2,5,4,10,-1 };
static int basicConstraintsOID[] = { 2,5,29,19,-1 };
static int extensionRequestOID[] = { 1,2,840,113549,1,9,14,-1 };
static int tcbInfoOID[] = { 2,23,133,5,4,1,-1 };
static int ueidOID[] = { 2,23,133,5,4,4,-1 };

static int
GenerateGuidFromSeed(char* nameBuf, size_t *nameBufLen, const uint8_t* seed, size_t seedLen,
	struct hash_engine *hash, struct base64_engine *base64)
{
    uint8_t digest[SHA256_DIGEST_LENGTH];
    int     result;

	result = hash->calculate_sha256(hash, seed, seedLen, digest, sizeof (digest));
	if (result != 0) {
		return -1;
	}

    result = base64->encode(base64, digest, 16, (unsigned char *)nameBuf, *nameBufLen);
	if (result != 0) {
		return -1;
	}

	return 0;
}

static int
X509AddKeyUsageExtension(
	DERBuilderContext	*Tbs,
	int					type
)
{
	uint8_t keyUsage;
	uint8_t bits;

	if (type) {
		keyUsage = RIOT_X509_KEY_USAGE_CERT_SIGN;
		bits = 6;
	}
	else {
		keyUsage  = RIOT_X509_KEY_USAGE_END_ENTITY;
		bits = 5;
	}

    CHK(DERStartSequenceOrSet(Tbs, true));
    CHK(	DERAddOID(Tbs, keyUsageOID));
    CHK(	DERAddBoolean(Tbs, true));
    CHK(	DERStartEnvelopingOctetString(Tbs));
    CHK(		DERAddNamedBitString(Tbs, &keyUsage, 1, bits));
    CHK(	DERPopNesting(Tbs));
    CHK(DERPopNesting(Tbs));
    return 0;
Error:
    return -1;
}

static int
X509AddExtendedKeyUsageExtension(
	DERBuilderContext	*Tbs,
	int					type,
	const char			*oid
)
{
	if (type == X509_CERT_END_ENTITY) {
		CHK(DERStartSequenceOrSet(Tbs, true));
		CHK(	DERAddOID(Tbs, extKeyUsageOID));
		CHK(	DERAddBoolean(Tbs, true));
		CHK(	DERStartEnvelopingOctetString(Tbs));
		CHK(		DERStartSequenceOrSet(Tbs, true));
		CHK(			DERAddOID(Tbs, clientAuthOID));
		CHK(		DERPopNesting(Tbs));
		CHK(	DERPopNesting(Tbs));
		CHK(DERPopNesting(Tbs));
	}
	else if (oid != NULL) {
		CHK(DERStartSequenceOrSet(Tbs, true));
		CHK(	DERAddOID(Tbs, extKeyUsageOID));
		CHK(	DERStartEnvelopingOctetString(Tbs));
		CHK(		DERStartSequenceOrSet(Tbs, true));
		CHK(			DERAddEncodedOID(Tbs, oid));
		CHK(		DERPopNesting(Tbs));
		CHK(	DERPopNesting(Tbs));
		CHK(DERPopNesting(Tbs));
	}
    return 0;
Error:
    return -1;
}

static int
X509AddBasicConstraintsExtension(
	DERBuilderContext	*Tbs,
	int					type
)
{
	if (type) {
		CHK(DERStartSequenceOrSet(Tbs, true));
		CHK(	DERAddOID(Tbs, basicConstraintsOID));
		CHK(	DERAddBoolean(Tbs, true));
		CHK(	DERStartEnvelopingOctetString(Tbs));
		CHK(		DERStartSequenceOrSet(Tbs, true));
		CHK(			DERAddBoolean(Tbs, true));
		if (type < X509_CERT_CA_NO_PATHLEN) {
			CHK(		DERAddInteger(Tbs, type-1));
		}
		CHK(		DERPopNesting(Tbs));
		CHK(	DERPopNesting(Tbs));
		CHK(DERPopNesting(Tbs));
	}
    return 0;
Error:
    return -1;
}

static int
get_fw_id_info(
	size_t					*fw_id_len,
	int						**sha_oid,
	const uint8_t           *fw_id,
	const enum hash_type	fw_id_hash
)
{
	if (fw_id == NULL) {
		return X509_ENGINE_RIOT_NO_FWID;
	}

	switch (fw_id_hash) {
		case HASH_TYPE_SHA1:
			*fw_id_len = SHA1_DIGEST_LENGTH;
			*sha_oid = sha1OID;
			break;

		case HASH_TYPE_SHA256:
			*fw_id_len = SHA256_DIGEST_LENGTH;
			*sha_oid = sha256OID;
			break;

		default:
			return X509_ENGINE_RIOT_UNSUPPORTED_HASH;
	}
    return 0;
}

static int
X509AddRiotExtension(
	DERBuilderContext	*Tbs,
	const uint8_t		*DevIdPub,
	size_t				DevIdPubLen,
	const uint8_t		*Fwid,
	size_t				FwidLen,
	const int			*shaOID
)
{
    CHK(DERStartSequenceOrSet(Tbs, true));
    CHK(	DERAddOID(Tbs, riotOID));
    CHK(	DERStartEnvelopingOctetString(Tbs));
    CHK(		DERStartSequenceOrSet(Tbs, true));
    CHK(			DERAddInteger(Tbs, 1));
    CHK(			DERStartSequenceOrSet(Tbs, true));
    CHK(				DERStartSequenceOrSet(Tbs, true));
    CHK(					DERAddOID(Tbs, ecPublicKeyOID));
    CHK(					DERAddOID(Tbs, prime256v1OID));
    CHK(				DERPopNesting(Tbs));
	CHK(			DERAddBitString(Tbs, DevIdPub, DevIdPubLen));
    CHK(			DERPopNesting(Tbs));
    CHK(			DERStartSequenceOrSet(Tbs, true));
   	CHK(				DERAddOID(Tbs, shaOID));
   	CHK(				DERAddOctetString(Tbs, Fwid, FwidLen));
    CHK(			DERPopNesting(Tbs));
    CHK(		DERPopNesting(Tbs));
    CHK(	DERPopNesting(Tbs));
    CHK(DERPopNesting(Tbs));
    return 0;
Error:
    return -1;
}

static int
X509AddTcbInfoExtension(
	DERBuilderContext	           *Tbs,
	const struct x509_dice_tcbinfo *Tcb,
	int                            *shaOID,
	size_t                         FwidLen
)
{
	if (Tcb) {
		CHK(DERStartSequenceOrSet(Tbs, true));
		CHK(	DERAddOID(Tbs, tcbInfoOID));
		CHK(	DERStartEnvelopingOctetString(Tbs));
		CHK(		DERStartSequenceOrSet(Tbs, true));
		CHK(			DERAddString(Tbs, Tcb->version, 0x82));
		CHK(			DERAddTaggedInteger(Tbs, Tcb->svn, 0x83));
		CHK(			DERStartConstructed(Tbs, 0xA6));
		CHK(				DERStartSequenceOrSet(Tbs, true));
		CHK(					DERAddOID(Tbs, shaOID));
		CHK(					DERAddOctetString(Tbs, Tcb->fw_id, FwidLen));
		CHK(				DERPopNesting(Tbs));
		CHK(			DERPopNesting(Tbs));
		CHK(		DERPopNesting(Tbs));
		CHK(	DERPopNesting(Tbs));
		CHK(DERPopNesting(Tbs));
	}
    return 0;
Error:
    return -1;
}

static int
X509AddUeidExtension(
	DERBuilderContext	           *Tbs,
	const struct x509_dice_tcbinfo *Dice
)
{
	if (Dice && Dice->ueid) {
		CHK(DERStartSequenceOrSet(Tbs, true));
		CHK(	DERAddOID(Tbs, ueidOID));
		CHK(	DERStartEnvelopingOctetString(Tbs));
		CHK(		DERStartSequenceOrSet(Tbs, true));
		CHK(			DERAddOctetString(Tbs, Dice->ueid->ueid, Dice->ueid->length));
		CHK(		DERPopNesting(Tbs));
		CHK(	DERPopNesting(Tbs));
		CHK(DERPopNesting(Tbs));
	}
    return 0;
Error:
    return -1;
}

static int
X509AddSubjectKeyIdentifierExtension(
	DERBuilderContext	*Tbs,
	const uint8_t		*subjectKeyIdentifier
)
{
    CHK(DERStartSequenceOrSet(Tbs, true));
    CHK(	DERAddOID(Tbs, extSubjectKeyIdentifierOID));
    CHK(	DERStartEnvelopingOctetString(Tbs));
    CHK(		DERAddOctetString(Tbs, subjectKeyIdentifier, SHA1_DIGEST_LENGTH));
    CHK(	DERPopNesting(Tbs));
    CHK(DERPopNesting(Tbs));
    return 0;
Error:
    return -1;
}

static int
X509AddAuthorityKeyIdentifierExtension(
	DERBuilderContext	*Tbs,
	const uint8_t		*authKeyIdentifier
)
{
    CHK(DERStartSequenceOrSet(Tbs, true));
    CHK(	DERAddOID(Tbs, extAuthKeyIdentifierOID));
    CHK(	DERStartEnvelopingOctetString(Tbs));
    CHK(		DERStartSequenceOrSet(Tbs, true));
    CHK(			DERAddAuthKeyBitString(Tbs, authKeyIdentifier, SHA1_DIGEST_LENGTH));
    CHK(		DERPopNesting(Tbs));
    CHK(	DERPopNesting(Tbs));
    CHK(DERPopNesting(Tbs));
    return 0;
Error:
    return -1;
}

static int
X509AddX501Name(
	DERBuilderContext	*Context,
	const char			*CommonName,
	const char			*OrgName,
	const char			*CountryName
)
{
	CHK(DERStartSequenceOrSet(Context, true));

	if (CommonName) {
		CHK(DERStartSequenceOrSet(Context, false));
		CHK(	DERStartSequenceOrSet(Context, true));
		CHK(		DERAddOID(Context, commonNameOID));
		CHK(		DERAddUTF8String(Context, CommonName));
		CHK(	DERPopNesting(Context));
		CHK(DERPopNesting(Context));
	}

	if (CountryName) {
		CHK(DERStartSequenceOrSet(Context, false));
		CHK(	DERStartSequenceOrSet(Context, true));
		CHK(		DERAddOID(Context, countryNameOID));
		CHK(		DERAddUTF8String(Context, CountryName));
		CHK(	DERPopNesting(Context));
		CHK(DERPopNesting(Context));
	}

	if (OrgName) {
		CHK(DERStartSequenceOrSet(Context, false));
		CHK(	DERStartSequenceOrSet(Context, true));
		CHK(		DERAddOID(Context, orgNameOID));
		CHK(		DERAddUTF8String(Context, OrgName));
		CHK(	DERPopNesting(Context));
		CHK(DERPopNesting(Context));
	}

	CHK(DERPopNesting(Context));
	return 0;
Error:
	return -1;
}

static int
get_subject_key_info(
	RIOT_X509_PUBLIC_KEY	 *SubjectKey,
	const uint8_t			 *Key,
	const size_t			 KeyLen,
	struct hash_engine       *hash
)
{
	int status;

	status = DERDECGetPubKeyInfo(SubjectKey, Key, KeyLen);
	ASRT(status == RIOT_SUCCESS);

	status = hash->calculate_sha1 (hash, &SubjectKey->key[1], SubjectKey->length-1,
		SubjectKey->identifier, SHA1_DIGEST_LENGTH);
	ASRT(status == 0);

    return 0;
Error:
    return -1;
}

int
X509GetDeviceCertTBS(
	DERBuilderContext			   *Tbs,
	const RIOT_X509_TBS_DATA	   *TbsData,
	const uint8_t				   *DevIdKeyPub,
	size_t						   key_len,
	const uint8_t				   *RootKeyPubDigest,
	int							   type,
	const struct x509_dice_tcbinfo *dice
)
{
	int *sha_oid = NULL;
	size_t fw_id_len = 0;
	int status;

	if (dice) {
		if (dice->version == NULL) {
			return X509_ENGINE_DICE_NO_VERSION;
		}

		status = get_fw_id_info(&fw_id_len, &sha_oid, dice->fw_id, dice->fw_id_hash);
		if (status != 0) {
			return status;
		}

		if (dice->ueid && ((dice->ueid->ueid == NULL) || (dice->ueid->length == 0))) {
			return X509_ENGINE_DICE_NO_UEID;
		}
	}

    CHK(DERStartSequenceOrSet(Tbs, true));
    CHK(    DERAddShortExplicitInteger(Tbs, 2));
    CHK(    DERAddIntegerFromArray(Tbs, TbsData->SerialNum, TbsData->SerialLen));
    CHK(    DERStartSequenceOrSet(Tbs, true));
    CHK(        DERAddOID(Tbs, ecdsaWithSHA256OID));
    CHK(    DERPopNesting(Tbs));
    CHK(    X509AddX501Name(Tbs, TbsData->IssuerCommon, NULL, NULL));
    CHK(    DERStartSequenceOrSet(Tbs, true));
    CHK(        DERAddTime(Tbs, TbsData->ValidFrom));
    CHK(        DERAddTime(Tbs, TbsData->ValidTo));
    CHK(    DERPopNesting(Tbs));
    CHK(    X509AddX501Name(Tbs, TbsData->SubjectCommon, NULL, NULL));
    CHK(    DERStartSequenceOrSet(Tbs, true));
    CHK(        DERStartSequenceOrSet(Tbs, true));
    CHK(            DERAddOID(Tbs, ecPublicKeyOID));
    CHK(            DERAddOID(Tbs, prime256v1OID));
    CHK(        DERPopNesting(Tbs));
    CHK(        DERAddBitString(Tbs, DevIdKeyPub, key_len));
    CHK(    DERPopNesting(Tbs));
    CHK(    DERStartExplicit(Tbs, 3));
    CHK(        DERStartSequenceOrSet(Tbs, true));
	CHK(           X509AddSubjectKeyIdentifierExtension(Tbs, RootKeyPubDigest));
	CHK(           X509AddAuthorityKeyIdentifierExtension(Tbs, RootKeyPubDigest));
	CHK(           X509AddKeyUsageExtension(Tbs, type));
	CHK(           X509AddExtendedKeyUsageExtension(Tbs, type, NULL));
	CHK(           X509AddBasicConstraintsExtension(Tbs, type));
	CHK(           X509AddTcbInfoExtension(Tbs, dice, sha_oid, fw_id_len));
	CHK(           X509AddUeidExtension(Tbs, dice));
    CHK(        DERPopNesting(Tbs));
    CHK(    DERPopNesting(Tbs));
    CHK(DERPopNesting(Tbs));

    ASRT(DERGetNestingDepth(Tbs) == 0);
    return 0;
Error:
    return -1;
}

int
X509MakeDeviceCert(
	DERBuilderContext	*DeviceIDCert,
	RIOT_ECC_SIGNATURE	*TbsSig
)
// Create a Device Certificate given a ready-to-sign TBS region in the context
{
    uint8_t encBuffer[((BIGLEN - 1) * 4)];
    uint32_t encBufferLen = ((BIGLEN - 1) * 4);

    // Elevate the "TBS" block into a real certificate,
    // i.e., copy it into an enclosing sequence.
    CHK(DERTbsToCert(DeviceIDCert));
    CHK(    DERStartSequenceOrSet(DeviceIDCert, true));
    CHK(        DERAddOID(DeviceIDCert, ecdsaWithSHA256OID));
    CHK(    DERPopNesting(DeviceIDCert));
    CHK(    DERStartEnvelopingBitString(DeviceIDCert));
    CHK(        DERStartSequenceOrSet(DeviceIDCert, true));
                    BigValToBigInt(encBuffer, &TbsSig->r);
    CHK(            DERAddIntegerFromArray(DeviceIDCert, encBuffer, encBufferLen));
                    BigValToBigInt(encBuffer, &TbsSig->s);
    CHK(            DERAddIntegerFromArray(DeviceIDCert, encBuffer, encBufferLen));
    CHK(        DERPopNesting(DeviceIDCert));
    CHK(    DERPopNesting(DeviceIDCert));
    CHK(DERPopNesting(DeviceIDCert));

    ASRT(DERGetNestingDepth(DeviceIDCert) == 0);
    return 0;
Error:
    return -1;
}

int
X509GetCASignedCertTBS(
	DERBuilderContext					*Tbs,
	const RIOT_X509_TBS_DATA			*TbsData,
	const uint8_t						*CertKey,
	size_t								key_len,
	const uint8_t						*AuthKeyPub,
	size_t								auth_key_len,
	int									type,
	const struct x509_dice_tcbinfo		*dice,
	struct hash_engine		 			*hash
)
{
	RIOT_X509_PUBLIC_KEY subject_key;
	int *sha_oid = NULL;
	size_t fw_id_len = 0;
	uint8_t authKeyIdentifier[SHA1_DIGEST_LENGTH];
	int status;

	// generate authority key identifier
	status = hash->calculate_sha1 (hash, &AuthKeyPub[1], auth_key_len-1,
	 	authKeyIdentifier, sizeof (authKeyIdentifier));
  	if (status != 0) {
  		return status;
  	}

	// generate subject key identifier
	CHK(get_subject_key_info (&subject_key, CertKey, key_len, hash));

	if (dice) {
		if (dice->version == NULL) {
			return X509_ENGINE_DICE_NO_VERSION;
		}

		status = get_fw_id_info(&fw_id_len, &sha_oid, dice->fw_id, dice->fw_id_hash);
		if (status != 0) {
			return status;
		}

		if (dice->ueid && ((dice->ueid->ueid == NULL) || (dice->ueid->length == 0))) {
			return X509_ENGINE_DICE_NO_UEID;
		}
	}

    CHK(DERStartSequenceOrSet(Tbs, true));
    CHK(    DERAddShortExplicitInteger(Tbs, 2));
    CHK(    DERAddIntegerFromArray(Tbs, TbsData->SerialNum, TbsData->SerialLen));
    CHK(    DERStartSequenceOrSet(Tbs, true));
    CHK(        DERAddOID(Tbs, ecdsaWithSHA256OID));
    CHK(    DERPopNesting(Tbs));
    CHK(    X509AddX501Name(Tbs, TbsData->IssuerCommon, NULL, NULL));
    CHK(    DERStartSequenceOrSet(Tbs, true));
    CHK(        DERAddTime(Tbs, TbsData->ValidFrom));
    CHK(        DERAddTime(Tbs, TbsData->ValidTo));
    CHK(    DERPopNesting(Tbs));
    CHK(    X509AddX501Name(Tbs, TbsData->SubjectCommon, NULL, NULL));
	if (subject_key.src_key_type == X509_PUBLIC_ECC_OR_RSA_KEY) {
		CHK(	DERAddPublicKey(Tbs, CertKey, key_len));
	} else if (subject_key.src_key_type == X509_PRIVATE_ECC_KEY) {
 		CHK(    DERStartSequenceOrSet(Tbs, true));
    	CHK(        DERStartSequenceOrSet(Tbs, true));
    	CHK(            DERAddOID(Tbs, ecPublicKeyOID));
		CHK(            DERAddOID(Tbs, prime256v1OID));
    	CHK(        DERPopNesting(Tbs));
    	CHK(        DERAddBitString(Tbs, &subject_key.key[1], subject_key.length-1));
    	CHK(    DERPopNesting(Tbs));
	}
    CHK(    DERStartExplicit(Tbs, 3));
    CHK(        DERStartSequenceOrSet(Tbs, true));
	CHK(            X509AddSubjectKeyIdentifierExtension(Tbs, subject_key.identifier));
	CHK(            X509AddAuthorityKeyIdentifierExtension(Tbs, authKeyIdentifier));
	CHK(            X509AddKeyUsageExtension(Tbs, type));
	CHK(            X509AddExtendedKeyUsageExtension(Tbs, type, NULL));
	CHK(            X509AddBasicConstraintsExtension (Tbs, type));
	CHK(            X509AddTcbInfoExtension(Tbs, dice, sha_oid, fw_id_len));
	CHK(            X509AddUeidExtension(Tbs, dice));
    CHK(        DERPopNesting(Tbs));
    CHK(    DERPopNesting(Tbs));
    CHK(DERPopNesting(Tbs));

    ASRT(DERGetNestingDepth(Tbs) == 0);
    return 0;
Error:
    return -1;
}

int
X509GetAliasCertTBS(
	DERBuilderContext	 *Tbs,
	RIOT_X509_TBS_DATA	 *TbsData,
	RIOT_ECC_PUBLIC		 *AliasKeyPub,
	RIOT_ECC_PUBLIC		 *DevIdKeyPub,
	uint8_t				 *Fwid,
	size_t				 FwidLen,
	int					 type,
	struct hash_engine 	 *hash,
	struct base64_engine *base64
)
{
    int result;
    char guidBuffer[64];
    uint8_t encBuffer[65];
    size_t encBufferLen;
	uint8_t authKeyIdentifier[SHA1_DIGEST_LENGTH];
	int status;

    if (strcmp(TbsData->SubjectCommon, "*") == 0)
    {
        RiotCrypt_ExportEccPub(DevIdKeyPub, encBuffer, &encBufferLen);
        size_t bufLen = sizeof(guidBuffer);

        // Replace the common-name with a per-device GUID derived from the DeviceID public key
        result = GenerateGuidFromSeed(guidBuffer, &bufLen, encBuffer, encBufferLen, hash, base64);

        if (result < 0) {
            return result;
        }

        guidBuffer[bufLen-1] = 0;
        TbsData->SubjectCommon = guidBuffer;
    }

    CHK(DERStartSequenceOrSet(Tbs, true));
    CHK(    DERAddShortExplicitInteger(Tbs, 2));
    CHK(    DERAddIntegerFromArray(Tbs, TbsData->SerialNum, TbsData->SerialLen));
    CHK(    DERStartSequenceOrSet(Tbs, true));
    CHK(        DERAddOID(Tbs, ecdsaWithSHA256OID));
    CHK(    DERPopNesting(Tbs));
    CHK(    X509AddX501Name(Tbs, TbsData->IssuerCommon, TbsData->IssuerOrg, TbsData->IssuerCountry));
    CHK(    DERStartSequenceOrSet(Tbs, true));
    CHK(        DERAddTime(Tbs, TbsData->ValidFrom));
    CHK(        DERAddTime(Tbs, TbsData->ValidTo));
    CHK(    DERPopNesting(Tbs));
    CHK(    X509AddX501Name(Tbs, TbsData->SubjectCommon, TbsData->SubjectOrg, TbsData->SubjectCountry));
    CHK(    DERStartSequenceOrSet(Tbs, true));
    CHK(        DERStartSequenceOrSet(Tbs, true));
    CHK(            DERAddOID(Tbs, ecPublicKeyOID));
    CHK(            DERAddOID(Tbs, prime256v1OID));
    CHK(        DERPopNesting(Tbs));
                RiotCrypt_ExportEccPub(AliasKeyPub, encBuffer, &encBufferLen);
    CHK(        DERAddBitString(Tbs, encBuffer, encBufferLen));
    CHK(    DERPopNesting(Tbs));
            RiotCrypt_ExportEccPub(DevIdKeyPub, encBuffer, &encBufferLen);
	        status = hash->calculate_sha1 (hash, encBuffer, encBufferLen, authKeyIdentifier, SHA1_DIGEST_LENGTH);
			ASRT(status == 0);
    CHK(    DERStartExplicit(Tbs, 3));
    CHK(        DERStartSequenceOrSet(Tbs, true));
	CHK(            X509AddKeyUsageExtension(Tbs, type));
	CHK(            X509AddExtendedKeyUsageExtension(Tbs, type, NULL));
	CHK(            X509AddAuthorityKeyIdentifierExtension(Tbs, authKeyIdentifier));
	CHK(            X509AddRiotExtension(Tbs, encBuffer, encBufferLen, Fwid, FwidLen, sha256OID));
    CHK(        DERPopNesting(Tbs));
    CHK(    DERPopNesting(Tbs));
    CHK(DERPopNesting(Tbs));

    ASRT(DERGetNestingDepth(Tbs) == 0);
    return 0;
Error:
    return -1;
}

int
X509MakeAliasCert(
	DERBuilderContext	*AliasCert,
	RIOT_ECC_SIGNATURE	*TbsSig
)
// Create an Alias Certificate given a ready-to-sign TBS region in the context
{
    uint8_t encBuffer[((BIGLEN - 1) * 4)];
    size_t encBufferLen = ((BIGLEN - 1) * 4);

    // Elevate the "TBS" block into a real certificate,
    // i.e., copy it into an enclosing sequence.
    CHK(DERTbsToCert(AliasCert));
    CHK(    DERStartSequenceOrSet(AliasCert, true));
    CHK(        DERAddOID(AliasCert, ecdsaWithSHA256OID));
    CHK(    DERPopNesting(AliasCert));
    CHK(    DERStartEnvelopingBitString(AliasCert));
    CHK(        DERStartSequenceOrSet(AliasCert, true));
                    BigValToBigInt(encBuffer, &TbsSig->r);
    CHK(            DERAddIntegerFromArray(AliasCert, encBuffer, encBufferLen));
                    BigValToBigInt(encBuffer, &TbsSig->s);
    CHK(            DERAddIntegerFromArray(AliasCert, encBuffer, encBufferLen));
    CHK(        DERPopNesting(AliasCert));
    CHK(    DERPopNesting(AliasCert));
    CHK(DERPopNesting(AliasCert));

    ASRT(DERGetNestingDepth(AliasCert) == 0);
    return 0;
Error:
    return -1;
}

int
X509GetDEREccPub(
	DERBuilderContext	*Context,
	RIOT_ECC_PUBLIC		Pub
)
{
    uint8_t encBuffer[65];
    size_t encBufferLen;

    CHK(DERStartSequenceOrSet(Context, true));
    CHK(    DERStartSequenceOrSet(Context, true));
    CHK(        DERAddOID(Context, ecPublicKeyOID));
    CHK(        DERAddOID(Context, prime256v1OID));
    CHK(    DERPopNesting(Context));
            RiotCrypt_ExportEccPub(&Pub, encBuffer, &encBufferLen);
    CHK(    DERAddBitString(Context, encBuffer, encBufferLen));
    CHK(DERPopNesting(Context));

    ASRT(DERGetNestingDepth(Context) == 0);
    return 0;
Error:
    return -1;
}

int
X509GetDEREcc(
    DERBuilderContext   *Context,
    RIOT_ECC_PUBLIC      Pub,
    RIOT_ECC_PRIVATE     Priv
)
{
    uint8_t encBuffer[65];
    size_t encBufferLen;

    CHK(DERStartSequenceOrSet(Context, true));
    CHK(    DERAddInteger(Context, 1));
            BigValToBigInt(encBuffer, &Priv);
    CHK(    DERAddOctetString(Context, encBuffer, 32));
    CHK(    DERStartExplicit(Context, 0));
    CHK(        DERAddOID(Context, prime256v1OID));
    CHK(    DERPopNesting(Context));
    CHK(    DERStartExplicit(Context, 1));
                RiotCrypt_ExportEccPub(&Pub, encBuffer, &encBufferLen);
    CHK(        DERAddBitString(Context, encBuffer, encBufferLen));
    CHK(    DERPopNesting(Context));
    CHK(DERPopNesting(Context));

    ASRT(DERGetNestingDepth(Context) == 0);
    return 0;
Error:
    return -1;
}

int
X509GetDERCsrTbs(
    DERBuilderContext              *Context,
    RIOT_X509_TBS_DATA             *TbsData,
    uint8_t                        *DeviceIDPub,
	size_t                         key_len,
	int                            type,
	const char                     *oid,
	const struct x509_dice_tcbinfo *dice
)
{
	int *sha_oid = NULL;
	size_t fw_id_len = 0;
	int status;

	if (dice) {
		if (dice->version == NULL) {
			return X509_ENGINE_DICE_NO_VERSION;
		}

		status = get_fw_id_info(&fw_id_len, &sha_oid, dice->fw_id, dice->fw_id_hash);
		if (status != 0) {
			return status;
		}

		if (dice->ueid && ((dice->ueid->ueid == NULL) || (dice->ueid->length == 0))) {
			return X509_ENGINE_DICE_NO_UEID;
		}
	}

    CHK(DERStartSequenceOrSet(Context, true));
    CHK(    DERAddInteger(Context, 0));
    CHK(    X509AddX501Name(Context, TbsData->IssuerCommon, NULL, NULL));
    CHK(    DERStartSequenceOrSet(Context, true));
    CHK(        DERStartSequenceOrSet(Context, true));
    CHK(            DERAddOID(Context, ecPublicKeyOID));
    CHK(            DERAddOID(Context, prime256v1OID));
    CHK(        DERPopNesting(Context));
    CHK(        DERAddBitString(Context, DeviceIDPub, key_len));
    CHK(    DERPopNesting(Context));
	CHK(	DERStartExplicit(Context, 0));
    CHK(        DERStartSequenceOrSet(Context, true));
	CHK(            DERAddOID(Context, extensionRequestOID));
    CHK(            DERStartSequenceOrSet(Context,false));
    CHK(                DERStartSequenceOrSet(Context, true));
	CHK(                    X509AddKeyUsageExtension(Context, type));
	CHK(    	            X509AddExtendedKeyUsageExtension(Context, type, oid));
	CHK(                    X509AddBasicConstraintsExtension(Context, type));
	CHK(				    X509AddTcbInfoExtension(Context, dice, sha_oid, fw_id_len));
	CHK(                    X509AddUeidExtension(Context, dice));
    CHK(                DERPopNesting(Context));
    CHK(            DERPopNesting(Context));
    CHK(        DERPopNesting(Context));
    CHK(    DERPopNesting(Context));
    CHK(DERPopNesting(Context));

    ASRT(DERGetNestingDepth(Context) == 0);
    return 0;
Error:
    return -1;
}

int
X509GetDERCsr(
    DERBuilderContext   *Context,
    RIOT_ECC_SIGNATURE  *Signature
)
{
    uint8_t encBuffer[((BIGLEN - 1) * 4)];
    size_t encBufferLen = ((BIGLEN - 1) * 4);

    // Elevate the "TBS" block into a real certificate, i.e., copy it
    // into an enclosing sequence and then add the signature block.
    CHK(DERTbsToCert(Context));
    CHK(    DERStartSequenceOrSet(Context, true));
    CHK(        DERAddOID(Context, ecdsaWithSHA256OID));
    CHK(    DERPopNesting(Context));
    CHK(    DERStartEnvelopingBitString(Context));
    CHK(        DERStartSequenceOrSet(Context, true));
                    BigValToBigInt(encBuffer, &Signature->r);
    CHK(            DERAddIntegerFromArray(Context, encBuffer, encBufferLen));
                    BigValToBigInt(encBuffer, &Signature->s);
    CHK(            DERAddIntegerFromArray(Context, encBuffer, encBufferLen));
    CHK(        DERPopNesting(Context));
    CHK(    DERPopNesting(Context));
    CHK(DERPopNesting(Context));

    ASRT(DERGetNestingDepth(Context) == 0);
    return 0;
Error:
    return -1;
}

int
X509GetRootCertTBS(
    DERBuilderContext   *Tbs,
    RIOT_X509_TBS_DATA  *TbsData,
    RIOT_ECC_PUBLIC     *RootKeyPub
)
{
    uint8_t encBuffer[65];
    size_t encBufferLen;
    uint8_t keyUsage = RIOT_X509_KEY_USAGE_CERT_SIGN;

    CHK(DERStartSequenceOrSet(Tbs, true));
    CHK(    DERAddShortExplicitInteger(Tbs, 2));
    CHK(    DERAddIntegerFromArray(Tbs, TbsData->SerialNum, TbsData->SerialLen));
    CHK(    DERStartSequenceOrSet(Tbs, true));
    CHK(        DERAddOID(Tbs, ecdsaWithSHA256OID));
    CHK(    DERPopNesting(Tbs));
    CHK(    X509AddX501Name(Tbs, TbsData->IssuerCommon, TbsData->IssuerOrg, TbsData->IssuerCountry));
    CHK(    DERStartSequenceOrSet(Tbs, true));
    CHK(        DERAddTime(Tbs, TbsData->ValidFrom));
    CHK(        DERAddTime(Tbs, TbsData->ValidTo));
    CHK(    DERPopNesting(Tbs));
    CHK(    X509AddX501Name(Tbs, TbsData->SubjectCommon, TbsData->SubjectOrg, TbsData->SubjectCountry));
    CHK(    DERStartSequenceOrSet(Tbs, true));
    CHK(        DERStartSequenceOrSet(Tbs, true));
    CHK(            DERAddOID(Tbs, ecPublicKeyOID));
    CHK(            DERAddOID(Tbs, prime256v1OID));
    CHK(        DERPopNesting(Tbs));
                RiotCrypt_ExportEccPub(RootKeyPub, encBuffer, &encBufferLen);
    CHK(        DERAddBitString(Tbs, encBuffer, encBufferLen));
    CHK(    DERPopNesting(Tbs));
    CHK(    DERStartExplicit(Tbs, 3));
    CHK(        DERStartSequenceOrSet(Tbs, true));
    CHK(            DERStartSequenceOrSet(Tbs, true));
    CHK(                DERAddOID(Tbs, keyUsageOID));
    CHK(                DERStartEnvelopingOctetString(Tbs));
                            encBufferLen = 1;
    CHK(                    DERAddBitString(Tbs, &keyUsage, encBufferLen)); // Actually 6bits
    CHK(                DERPopNesting(Tbs));
    CHK(            DERPopNesting(Tbs));
    CHK(            DERStartSequenceOrSet(Tbs, true));
    CHK(                DERAddOID(Tbs, basicConstraintsOID));
    CHK(                DERAddBoolean(Tbs, true));
    CHK(                DERStartEnvelopingOctetString(Tbs));
    CHK(                    DERStartSequenceOrSet(Tbs, true));
    CHK(                        DERAddBoolean(Tbs, true));
    CHK(                        DERAddInteger(Tbs, 2));
    CHK(                    DERPopNesting(Tbs));
    CHK(                DERPopNesting(Tbs));
    CHK(            DERPopNesting(Tbs));
    CHK(        DERPopNesting(Tbs));
    CHK(    DERPopNesting(Tbs));
    CHK(DERPopNesting(Tbs));

    ASRT(DERGetNestingDepth(Tbs) == 0);
    return 0;
Error:
    return -1;
}

int
X509MakeRootCert(
    DERBuilderContext   *RootCert,
    RIOT_ECC_SIGNATURE  *TbsSig
)
// Create an Alias Certificate given a ready-to-sign TBS region in the context
{
    uint8_t encBuffer[((BIGLEN - 1) * 4)];
    size_t encBufferLen = ((BIGLEN - 1) * 4);

    // Elevate the "TBS" block into a real certificate,
    // i.e., copy it into an enclosing sequence.
    CHK(DERTbsToCert(RootCert));
    CHK(    DERStartSequenceOrSet(RootCert, true));
    CHK(        DERAddOID(RootCert, ecdsaWithSHA256OID));
    CHK(    DERPopNesting(RootCert));
    CHK(    DERStartEnvelopingBitString(RootCert));
    CHK(        DERStartSequenceOrSet(RootCert, true));
                    BigValToBigInt(encBuffer, &TbsSig->r);
    CHK(            DERAddIntegerFromArray(RootCert, encBuffer, encBufferLen));
                    BigValToBigInt(encBuffer, &TbsSig->s);
    CHK(            DERAddIntegerFromArray(RootCert, encBuffer, encBufferLen));
    CHK(        DERPopNesting(RootCert));
    CHK(    DERPopNesting(RootCert));
    CHK(DERPopNesting(RootCert));

    ASRT(DERGetNestingDepth(RootCert) == 0);
    return 0;
Error:
    return -1;
}
