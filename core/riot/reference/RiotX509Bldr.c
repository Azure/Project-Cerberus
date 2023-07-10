/*
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See LICENSE in the project root.
 */
#include <stdint.h>
#include <stdbool.h>
#include "include/RiotDerEnc.h"
#include "include/RiotX509Bldr.h"
#include "include/RiotDerDec.h"
#include "riot/tcg_dice.h"

#define ASRT(_X) if(!(_X))      {goto Error;}
#define CHK(_X)  if(((_X)) < 0) {goto Error;}

// OIDs.  Note that the encoder expects a -1 sentinel.
const int riotOID[] = { 1,3,6,1,4,1,311,89,3,1,-1 };
const int ecdsaWithSHA256OID[] = { 1,2,840,10045,4,3,2,-1 };
const int ecdsaWithSHA384OID[] = { 1,2,840,10045,4,3,3,-1 };
const int ecdsaWithSHA512OID[] = { 1,2,840,10045,4,3,4,-1 };
const int ecPublicKeyOID[] = { 1,2,840,10045,2,1,-1 };
const int prime256v1OID[] = { 1,2,840,10045,3,1,7,-1 };
const int keyUsageOID[] = { 2,5,29,15,-1 };
const int extKeyUsageOID[] = { 2,5,29,37,-1 };
const int extAuthKeyIdentifierOID[] = { 2,5,29,35,-1 };
const int extSubjectKeyIdentifierOID[] = { 2,5,29,14,-1 };
const int clientAuthOID[] = { 1,3,6,1,5,5,7,3,2,-1 };
const int sha1OID[] = { 1,3,14,3,2,26,-1 };
const int sha256OID[] = { 2,16,840,1,101,3,4,2,1,-1 };
const int sha384OID[] = { 2,16,840,1,101,3,4,2,2,-1 };
const int sha512OID[] = { 2,16,840,1,101,3,4,2,3,-1 };
const int commonNameOID[] = { 2,5,4,3,-1 };
const int countryNameOID[] = { 2,5,4,6,-1 };
const int orgNameOID[] = { 2,5,4,10,-1 };
const int basicConstraintsOID[] = { 2,5,29,19,-1 };
const int extensionRequestOID[] = { 1,2,840,113549,1,9,14,-1 };
const int tcbInfoOID[] = { 2,23,133,5,4,1,-1 };
const int ueidOID[] = { 2,23,133,5,4,4,-1 };

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
	int					Type
)
{
	uint8_t keyUsage;
	uint8_t bits;

	if (Type) {
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
	DERBuilderContext   *Tbs,
	int                 Type,
	const uint8_t       *Oid,
    size_t              OidLength
)
{
	if (Type == X509_CERT_END_ENTITY) {
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
	else if (Oid != NULL) {
		CHK(DERStartSequenceOrSet(Tbs, true));
		CHK(	DERAddOID(Tbs, extKeyUsageOID));
		CHK(	DERStartEnvelopingOctetString(Tbs));
		CHK(		DERStartSequenceOrSet(Tbs, true));
		CHK(			DERAddEncodedOID(Tbs, Oid, OidLength));
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
	int					Type
)
{
	if (Type) {
		CHK(DERStartSequenceOrSet(Tbs, true));
		CHK(	DERAddOID(Tbs, basicConstraintsOID));
		CHK(	DERAddBoolean(Tbs, true));
		CHK(	DERStartEnvelopingOctetString(Tbs));
		CHK(		DERStartSequenceOrSet(Tbs, true));
		CHK(			DERAddBoolean(Tbs, true));
		if (Type < X509_CERT_CA_NO_PATHLEN) {
			CHK(		DERAddInteger(Tbs, Type-1));
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
	const struct tcg_dice_tcbinfo *Tcb,
	const int                      *shaOID,
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
		CHK(					DERAddOctetString(Tbs, Tcb->fwid, FwidLen));
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

int
X509GetDeviceCertTBS(
    DERBuilderContext                   *Tbs,
    const RIOT_X509_TBS_DATA            *TbsData,
    const uint8_t                       *CertKey,
    size_t                              CertKeyLen,
    const uint8_t                       *SubjectKeyIdentifier,
    const uint8_t                       *AuthKeyIdentifier,
    int                                 Type,
    const struct tcg_dice_tcbinfo      *Dice
)
{
	const int *sha_oid = NULL;
	size_t fw_id_len = 0;

    // DEPRECATED
	// if (Dice) {
	// 	if (Dice->version == NULL) {
	// 		return X509_ENGINE_DICE_NO_VERSION;
	// 	}

	// 	status = get_fw_id_info(&fw_id_len, &sha_oid, Dice->fw_id, Dice->fw_id_hash);
	// 	if (status != 0) {
	// 		return status;
	// 	}

	// 	if (Dice->ueid && ((Dice->ueid->ueid == NULL) || (Dice->ueid->length == 0))) {
	// 		return X509_ENGINE_DICE_NO_UEID;
	// 	}
	// }

    CHK(DERStartSequenceOrSet(Tbs, true));
    CHK(    DERAddShortExplicitInteger(Tbs, 2));
    CHK(    DERAddIntegerFromArray(Tbs, TbsData->SerialNum, TbsData->SerialLen));
    CHK(    DERStartSequenceOrSet(Tbs, true));
    CHK(        DERAddOID(Tbs, TbsData->SignatureAlgorithm));
    CHK(    DERPopNesting(Tbs));
    CHK(    X509AddX501Name(Tbs, TbsData->IssuerCommon, NULL, NULL));
    CHK(    DERStartSequenceOrSet(Tbs, true));
    CHK(        DERAddTime(Tbs, TbsData->ValidFrom));
    CHK(        DERAddTime(Tbs, TbsData->ValidTo));
    CHK(    DERPopNesting(Tbs));
    CHK(    X509AddX501Name(Tbs, TbsData->SubjectCommon, NULL, NULL));
    CHK(    DERAddPublicKey(Tbs, CertKey, CertKeyLen));
    CHK(    DERStartExplicit(Tbs, 3));
    CHK(        DERStartSequenceOrSet(Tbs, true));
	CHK(           X509AddSubjectKeyIdentifierExtension(Tbs, SubjectKeyIdentifier));
	CHK(           X509AddAuthorityKeyIdentifierExtension(Tbs, AuthKeyIdentifier));
	CHK(           X509AddKeyUsageExtension(Tbs, Type));
	CHK(           X509AddExtendedKeyUsageExtension(Tbs, Type, NULL, 0));
	CHK(           X509AddBasicConstraintsExtension(Tbs, Type));
	CHK(           X509AddTcbInfoExtension(Tbs, Dice, sha_oid, fw_id_len));
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
	DERBuilderContext   *DeviceIDCert,
	const uint8_t       *TbsSig,
    size_t              SigLength,
    const int           *SigOID
)
// Create a Device Certificate given a ready-to-sign TBS region in the context
{
    // Elevate the "TBS" block into a real certificate,
    // i.e., copy it into an enclosing sequence.
    CHK(DERTbsToCert(DeviceIDCert));
    CHK(    DERStartSequenceOrSet(DeviceIDCert, true));
    CHK(        DERAddOID(DeviceIDCert, SigOID));
    CHK(    DERPopNesting(DeviceIDCert));
    CHK(    DERAddBitString(DeviceIDCert, TbsSig, SigLength));
    CHK(DERPopNesting(DeviceIDCert));

    ASRT(DERGetNestingDepth(DeviceIDCert) == 0);
    return 0;
Error:
    return -1;
}

int
X509GetCASignedCertTBS(
    DERBuilderContext                   *Tbs,
    const RIOT_X509_TBS_DATA            *TbsData,
    const uint8_t                       *CertKey,
    size_t                              CertKeyLen,
    const uint8_t                       *SubjectKeyIdentifier,
    const uint8_t                       *AuthKeyIdentifier,
    int                                 Type,
    const struct tcg_dice_tcbinfo      *Dice
)
{
	const int *sha_oid = NULL;
	size_t fw_id_len = 0;

    // DEPRECATED
	// if (dice) {
	// 	if (dice->version == NULL) {
	// 		return X509_ENGINE_DICE_NO_VERSION;
	// 	}

	// 	status = get_fw_id_info (&fw_id_len, &sha_oid, dice->fw_id, dice->fw_id_hash);
	// 	if (status != 0) {
	// 		return status;
	// 	}

	// 	if (dice->ueid && ((dice->ueid->ueid == NULL) || (dice->ueid->length == 0))) {
	// 		return X509_ENGINE_DICE_NO_UEID;
	// 	}
	// }

    CHK(DERStartSequenceOrSet(Tbs, true));
    CHK(    DERAddShortExplicitInteger(Tbs, 2));
    CHK(    DERAddIntegerFromArray(Tbs, TbsData->SerialNum, TbsData->SerialLen));
    CHK(    DERStartSequenceOrSet(Tbs, true));
    CHK(        DERAddOID(Tbs, TbsData->SignatureAlgorithm));
    CHK(    DERPopNesting(Tbs));
    CHK(    X509AddX501Name(Tbs, TbsData->IssuerCommon, NULL, NULL));
    CHK(    DERStartSequenceOrSet(Tbs, true));
    CHK(        DERAddTime(Tbs, TbsData->ValidFrom));
    CHK(        DERAddTime(Tbs, TbsData->ValidTo));
    CHK(    DERPopNesting(Tbs));
    CHK(    X509AddX501Name(Tbs, TbsData->SubjectCommon, NULL, NULL));
    CHK(    DERAddPublicKey(Tbs, CertKey, CertKeyLen));
    CHK(    DERStartExplicit(Tbs, 3));
    CHK(        DERStartSequenceOrSet(Tbs, true));
    CHK(            X509AddSubjectKeyIdentifierExtension(Tbs, SubjectKeyIdentifier));
    CHK(            X509AddAuthorityKeyIdentifierExtension(Tbs, AuthKeyIdentifier));
    CHK(            X509AddKeyUsageExtension(Tbs, Type));
    CHK(            X509AddExtendedKeyUsageExtension(Tbs, Type, NULL, 0));
    CHK(            X509AddBasicConstraintsExtension (Tbs, Type));
    CHK(            X509AddTcbInfoExtension(Tbs, Dice, sha_oid, fw_id_len));
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
	CHK(            X509AddExtendedKeyUsageExtension(Tbs, type, NULL, 0));
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
	const uint8_t                  *oid,
    size_t                         oid_len,
	const struct tcg_dice_tcbinfo *dice
)
{
	const int *sha_oid = NULL;
	size_t fw_id_len = 0;

    // DEPRECATED
	// if (dice) {
	// 	if (dice->version == NULL) {
	// 		return X509_ENGINE_DICE_NO_VERSION;
	// 	}

	// 	status = get_fw_id_info (&fw_id_len, &sha_oid, dice->fw_id, dice->fw_id_hash);
	// 	if (status != 0) {
	// 		return status;
	// 	}

	// 	if (dice->ueid && ((dice->ueid->ueid == NULL) || (dice->ueid->length == 0))) {
	// 		return X509_ENGINE_DICE_NO_UEID;
	// 	}
	// }

    CHK(DERStartSequenceOrSet(Context, true));
    CHK(    DERAddInteger(Context, 0));
    CHK(    X509AddX501Name(Context, TbsData->IssuerCommon, NULL, NULL));
    CHK(    DERAddPublicKey(Context, DeviceIDPub, key_len));
	CHK(	DERStartExplicit(Context, 0));
    CHK(        DERStartSequenceOrSet(Context, true));
	CHK(            DERAddOID(Context, extensionRequestOID));
    CHK(            DERStartSequenceOrSet(Context,false));
    CHK(                DERStartSequenceOrSet(Context, true));
	CHK(                    X509AddKeyUsageExtension(Context, type));
	CHK(    	            X509AddExtendedKeyUsageExtension(Context, type, oid, oid_len));
	CHK(                    X509AddBasicConstraintsExtension(Context, type));
	CHK(				    X509AddTcbInfoExtension(Context, dice, sha_oid, fw_id_len));
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
    const uint8_t       *Signature,
    size_t              SigLength,
    const int           *SigOID
)
{
    return X509MakeDeviceCert (Context, Signature, SigLength, SigOID);
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
