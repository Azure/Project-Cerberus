/*
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See LICENSE in the project root.
 */

#ifndef RIOTX509BLDR_H_
#define RIOTX509BLDR_H_

#include "RiotCrypt.h"
#include "RiotDerEnc.h"
#include "asn1/base64.h"
#include "asn1/x509.h"
#include "crypto/hash.h"
#include "riot/tcg_dice.h"

#ifdef __cplusplus
extern "C" {
#endif
// KeyUsage :: = BIT STRING {
//     digitalSignature(0),
//     nonRepudiation(1),
//     keyEncipherment(2),
//     dataEncipherment(3),
//     keyAgreement(4),
//     keyCertSign(5),
//     cRLSign(6)
// }
#define RIOT_X509_KEY_USAGE_CERT_SIGN 0x04		// keyCertSign
#define RIOT_X509_KEY_USAGE_END_ENTITY 0x88		// end-entity certificate
#define RIOT_X509_SNUM_LEN  0x08				// In bytes
#define RIOT_X509_MAX_KEY_LEN ((2048 * 2) / 8)	// max key size in bytes

// Const x509 "to be signed" data
typedef struct {
	uint8_t SerialNum[RIOT_X509_SNUM_LEN];
	int SerialLen;
	const char *IssuerCommon;
	const char *IssuerOrg;
	const char *IssuerCountry;
	const char *ValidFrom;
	const char *ValidTo;
	const char *SubjectCommon;
	const char *SubjectOrg;
	const char *SubjectCountry;
	const int *SignatureAlgorithm;
} RIOT_X509_TBS_DATA;


// Valid key types to use to generate the certificate key.
enum {
	X509_PUBLIC_ECC_OR_RSA_KEY = 0,
	X509_PRIVATE_ECC_KEY,
};

// Stores information about the certificate key. The source key may be an RSA
// public key or ECC key.
typedef struct {
	uint8_t key[RIOT_X509_MAX_KEY_LEN];
	size_t length;
	uint8_t identifier[SHA1_DIGEST_LENGTH];
	int src_key_type;
} RIOT_X509_PUBLIC_KEY;

// OIDs used in cert generation.
extern const int riotOID[];
extern const int ecdsaWithSHA256OID[];
extern const int ecdsaWithSHA384OID[];
extern const int ecdsaWithSHA512OID[];
extern const int ecPublicKeyOID[];
extern const int prime256v1OID[];
extern const int keyUsageOID[];
extern const int extKeyUsageOID[];
extern const int extAuthKeyIdentifierOID[];
extern const int extSubjectKeyIdentifierOID[];
extern const int clientAuthOID[];
extern const int sha1OID[];
extern const int sha256OID[];
extern const int sha384OID[];
extern const int sha512OID[];
extern const int commonNameOID[];
extern const int countryNameOID[];
extern const int orgNameOID[];
extern const int basicConstraintsOID[];
extern const int extensionRequestOID[];
extern const int tcbInfoOID[];
extern const int ueidOID[];


int X509GetDeviceCertTBS (
	DERBuilderContext *Tbs, const RIOT_X509_TBS_DATA *TbsData, const uint8_t *CertKey,
	size_t CertKeyLen, const uint8_t *SubjectKeyIdentifier, const uint8_t *AuthKeyIdentifier,
	int Type, const struct tcg_dice_tcbinfo *Dice);

int X509GetCASignedCertTBS (
	DERBuilderContext *Tbs, const RIOT_X509_TBS_DATA *TbsData, const uint8_t *CertKey,
	size_t CertKeyLen, const uint8_t *SubjectKeyIdentifier, const uint8_t *AuthKeyIdentifier,
	int Type, const struct tcg_dice_tcbinfo *Dice);

int X509MakeDeviceCert (
	DERBuilderContext *DeviceIDCert, const uint8_t *TbsSig, size_t sig_length, const int *sig_oid);

int X509GetAliasCertTBS (
	DERBuilderContext *Tbs,	RIOT_X509_TBS_DATA *TbsData, RIOT_ECC_PUBLIC *AliasKeyPub,
	RIOT_ECC_PUBLIC *DevIdKeyPub, uint8_t *Fwid, size_t FwidLen, int type, struct hash_engine *hash,
	struct base64_engine *base64);

int X509MakeAliasCert (
	DERBuilderContext *AliasCert, RIOT_ECC_SIGNATURE *TbsSig);

int X509GetDEREccPub (
	DERBuilderContext *Context, RIOT_ECC_PUBLIC Pub);

int X509GetDEREcc (
	DERBuilderContext *Context, RIOT_ECC_PUBLIC Pub, RIOT_ECC_PRIVATE Priv);

int X509GetDERCsrTbs (
	DERBuilderContext *Context, RIOT_X509_TBS_DATA *TbsData, uint8_t *DeviceIDPub, size_t key_len,
	int type, const uint8_t *oid, size_t oid_len, const struct tcg_dice_tcbinfo *dice);

int X509GetDERCsr (
	DERBuilderContext *Context, const uint8_t *Signature, size_t sig_length, const int *sig_oid);

int X509GetRootCertTBS (
	DERBuilderContext *Tbs, RIOT_X509_TBS_DATA *TbsData, RIOT_ECC_PUBLIC *RootKeyPub);

int X509MakeRootCert (
	DERBuilderContext *AliasCert, RIOT_ECC_SIGNATURE *TbsSig);

#ifdef __cplusplus
}
#endif


#endif	/* RIOTX509BLDR_H_ */
