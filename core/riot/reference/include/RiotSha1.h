#pragma once
/*
 * sha.h
 *
 * Originally taken from the public domain SHA1 implementation
 * written by by Steve Reid <steve@edmweb.com>
 *
 * Modified by Aaron D. Gifford <agifford@infowest.com>
 *
 * NO COPYRIGHT - THIS IS 100% IN THE PUBLIC DOMAIN
 *
 * The original unmodified version is available at:
 *    ftp://ftp.funet.fi/pub/crypt/hash/sha/sha1.c
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR(S) AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR(S) OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
/*
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See LICENSE in the project root.
 */

//
// 24-JAN-2018; RIoT adaptation (PEngland;MSFT).
//

#ifndef __RIOT_CRYPTO_SHA1_H__
#define __RIOT_CRYPTO_SHA1_H__

#include "RiotTarget.h"

#ifndef __RIOT_CRYPTO_SHA_TYPES__
#define	__RIOT_CRYPTO_SHA_TYPES__

typedef int asb;

typedef uint8_t  sha2_uint8_t;  // Exactly 1 byte
typedef uint32_t sha2_word32;   // Exactly 4 bytes
typedef uint64_t sha2_word64;   // Exactly 8 bytes

#endif

#ifdef __cplusplus
extern "C" {
#endif

/* Make sure you define these types for your architecture: */
typedef unsigned int sha1_quadbyte; // 4 byte type
typedef unsigned char sha1_byte;    // single byte type


#define SHA1_BLOCK_LENGTH       64	// Equal to SHA1_BLOCK_SIZE
#define SHA1_DIGEST_LENGTH      20	// Equal to SHA1_HASH_LENGTH

/* The SHA1 structure: */
typedef struct _RIOT_SHA1_CONTEXT {
    sha1_quadbyte   state[5];
    sha1_quadbyte   count[2];
    sha1_byte       buffer[SHA1_BLOCK_LENGTH];
} RIOT_SHA1_CONTEXT;

#ifndef NOPROTO
void RIOT_SHA1_Init(RIOT_SHA1_CONTEXT *context);
void RIOT_SHA1_Update(RIOT_SHA1_CONTEXT *context, const sha1_byte *data, unsigned int len);
void RIOT_SHA1_Final(RIOT_SHA1_CONTEXT* context, sha1_byte digest[SHA1_DIGEST_LENGTH]);
#else
void RIOT_SHA1_Init();
void RIOT_SHA1_Update();
void RIOT_SHA1_Final();
#endif

//
// Hash a block of data
// @param buf the buffer containing the data to hash
// @param bufSize the number of bytes in the buffer
// @param digest the buffer to hold the digest.  Must be of size SHA1_DIGEST_LENGTH
//
void RIOT_SHA1_Block(const uint8_t *buf, size_t bufSize, uint8_t *digest);

#ifdef    __cplusplus
}
#endif
#endif

