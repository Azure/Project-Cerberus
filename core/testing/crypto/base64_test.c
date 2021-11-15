// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "testing/crypto/base64_testing.h"


const uint8_t BASE64_DATA_BLOCK[] = {
	0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
	0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f,
	0x20,0x21,0x22,0x23,0x24,0x25,0x26,0x27,0x28,0x29,0x2a,0x2b,0x2c,0x2d,0x2e,0x2f
};

const size_t BASE64_DATA_BLOCK_LEN = sizeof (BASE64_DATA_BLOCK);

const uint8_t BASE64_ENCODED_BLOCK[] =
	"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4v";

const size_t BASE64_ENCODED_BLOCK_LEN = sizeof (BASE64_ENCODED_BLOCK);

const uint8_t BASE64_ENCODED_PAD_ONE[] =
	"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4=";

const size_t BASE64_ENCODED_PAD_ONE_LEN = sizeof (BASE64_ENCODED_PAD_ONE);

const uint8_t BASE64_ENCODED_PAD_TWO[] =
	"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLQ==";
const size_t BASE64_ENCODED_PAD_TWO_LEN = sizeof (BASE64_ENCODED_PAD_TWO);

const uint8_t BASE64_ENCODED_THREE_LESS[] =
	"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKiss";

const size_t BASE64_ENCODED_THREE_LESS_LEN = sizeof (BASE64_ENCODED_THREE_LESS);
