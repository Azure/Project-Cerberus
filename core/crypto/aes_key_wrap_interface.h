// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef AES_KEY_WRAP_INTERFACE_H_
#define AES_KEY_WRAP_INTERFACE_H_

#include <stddef.h>
#include <stdint.h>
#include "status/rot_status.h"


/**
 * Length of each block of input data that is processed per encryption operation when wrapping or
 * unwrapping the data.
 */
#define	AES_KEY_WRAP_INTERFACE_BLOCK_SIZE				8

/**
 * Get the aligned length of the input data, which includes any necessary padding.
 *
 * @param length Length of the data being wrapped.
 *
 * @return Length of the data aligned to the wrapping block size.
 */
#define	AES_KEY_WRAP_INTERFACE_ALIGNED_LENGTH(length)   \
	(((length) + (AES_KEY_WRAP_INTERFACE_BLOCK_SIZE - 1)) & \
		~(AES_KEY_WRAP_INTERFACE_BLOCK_SIZE - 1))

/**
 * Determine the length of wrapped data based on the input length.
 *
 * @param length Length of the data being wrapped.
 *
 * @return Length of the wrapped data.
 */
#define	AES_KEY_WRAP_INTERFACE_WRAPPED_LENGTH(length)   \
	(AES_KEY_WRAP_INTERFACE_ALIGNED_LENGTH (length) + AES_KEY_WRAP_INTERFACE_BLOCK_SIZE)


/**
 * Interface for handling key wrap/unwrap using AES.
 *
 * While the algorithm is called AES Key Wrap, the input data is opaque and can equally be used for
 * data that is not a key.
 */
struct aes_key_wrap_interface {
	/**
	 * Set the Key Encryption Key (KEK) to use for key wrapping.  Any existing KEK will be zeroized
	 * and replaced with the new one.
	 *
	 * @param aes_kw AES key wrap instance to configure with a KEK.
	 * @param kek The Key Encryption Key to use for wrapping.
	 * @param length Length of the Key Encryption Key.
	 *
	 * @return 0 if the KEK was set successfully or an error code.
	 */
	int (*set_kek) (const struct aes_key_wrap_interface *aes_kw, const uint8_t *kek, size_t length);

	/**
	 * Clear the Key Encryption Key (KEK) currently being used for wrapping.  A new KEK will need to
	 * be provided before additional wrapping can be executed.
	 *
	 * @param aes_kw AES key wrap instance whose KEK should be zeroized.
	 *
	 * @return 0 if the KEK was cleared successfully or an error code.
	 */
	int (*clear_kek) (const struct aes_key_wrap_interface *aes_kw);

	/**
	 * Wrap secret data using an AES Key Encryption Key (KEK).  The output will be encrypted and
	 * integrity protected.
	 *
	 * The KEK must have already been set.
	 *
	 * @param aes_kw AES key wrap instance to use for wrapping.
	 * @param data Input data that will be wrapped.
	 * @param length Length of the input data.
	 * @param wrapped Output buffer for the wrapped data.  This buffer length must be 8-byte aligned
	 * and provide at least 8 bytes more than the input.  In cases where the input is not 8-byte
	 * aligned, this must be large enough to hold padding bytes to align the input to 8 bytes.  It's
	 * possible for this to be the same buffer as the input, as long as it provides the extra space
	 * necessary for wrapping.  For more efficient operation when sharing a buffer, the wrapped
	 * buffer should start 8 bytes before the input buffer.  Using the same input and output buffers
	 * may destroy the input data even when there is an error.
	 * @param out_length Length of the output buffer.  The length of the wrapped data is fixed based
	 * on input length and can be determined using AES_KEY_WRAP_INTERFACE_WRAPPED_LENGTH().
	 *
	 * @return 0 if the data was wrapped successfully or an error code.
	 */
	int (*wrap) (const struct aes_key_wrap_interface *aes_kw, const uint8_t *data, size_t length,
		uint8_t *wrapped, size_t out_length);

	/**
	 * Unwrap secret data using an AES Key Encryption Key (KEK).  The output will be decrypted and
	 * the key integrity will be verified.
	 *
	 * The KEK must have already been set.
	 *
	 * @param aes_kw AES key wrap instance to use for unwrapping.
	 * @param wrapped Wrapped data that will be unwrapped.
	 * @param length Length of the wrapped data.
	 * @param data Output buffer for the unwrapped data.  The data will be at least 8 bytes shorter
	 * than the wrapped data.  If the unwrapped data length is not 8-byte aligned, the output length
	 * will be reduced further due to padding bytes.  It's possible for this to be the same buffer
	 * as the input.  For more efficient operation when sharing a buffer, the output buffer should
	 * start 8 bytes after the wrapped data.  Using the same input and output buffers may destroy
	 * the input data even when there is an error.
	 * @param out_length On input, this is the length of the output buffer.  Regardless of the final
	 * length of the unwrapped data, this must be no more than 8 bytes smaller than the wrapped
	 * buffer since the final length of the data will not be known until unwrapping has completed.
	 * On output, this is updated to represent the length of the unwrapped data.
	 *
	 * @return 0 if the data was unwrapped successfully or an error code.
	 */
	int (*unwrap) (const struct aes_key_wrap_interface *aes_kw, const uint8_t *wrapped,
		size_t length, uint8_t *data, size_t *out_length);
};


#define	AES_KEY_WRAP_ERROR(code)		ROT_ERROR (ROT_MODULE_AES_KEY_WRAP, code)

/**
 * Error codes that can be generated by AES key wrapping.
 */
enum {
	AES_KEY_WRAP_INVALID_ARGUMENT = AES_KEY_WRAP_ERROR (0x00),		/**< Input parameter is null or not valid. */
	AES_KEY_WRAP_NO_MEMORY = AES_KEY_WRAP_ERROR (0x01),				/**< Memory allocation failed. */
	AES_KEY_WRAP_SET_KEK_FAILED = AES_KEY_WRAP_ERROR (0x02),		/**< Failed to set a new KEK. */
	AES_KEY_WRAP_CLEAR_KEK_FAILED = AES_KEY_WRAP_ERROR (0x03),		/**< Failed to clear the existing KEK. */
	AES_KEY_WRAP_WRAP_FAILED = AES_KEY_WRAP_ERROR (0x04),			/**< Failed to wrap the secret data. */
	AES_KEY_WRAP_UNWRAP_FAILED = AES_KEY_WRAP_ERROR (0x05),			/**< Failed to unwrap the secret data. */
	AES_KEY_WRAP_NOT_BLOCK_ALIGNED = AES_KEY_WRAP_ERROR (0x06),		/**< The data length is not 64-bit aligned. */
	AES_KEY_WRAP_NOT_ENOUGH_DATA = AES_KEY_WRAP_ERROR (0x07),		/**< The data length is too short. */
	AES_KEY_WRAP_TOO_MUCH_DATA = AES_KEY_WRAP_ERROR (0x08),			/**< The requested data is longer than can be supported. */
	AES_KEY_WRAP_SMALL_OUTPUT_BUFFER = AES_KEY_WRAP_ERROR (0x09),	/**< The output buffer is too small for the provided data. */
	AES_KEY_WRAP_INTEGRITY_CHECK_FAIL = AES_KEY_WRAP_ERROR (0x0a),	/**< The integrity check detected corruption in the unwrapped data. */
	AES_KEY_WRAP_LENGTH_CHECK_FAIL = AES_KEY_WRAP_ERROR (0x0b),		/**< The output data length does not fall within expected bounds. */
	AES_KEY_WRAP_PADDING_CHECK_FAIL = AES_KEY_WRAP_ERROR (0x0c),	/**< Padding bytes in the unwrapped data are non-zero. */
	AES_KEY_WRAP_SELF_TEST_FAILED = AES_KEY_WRAP_ERROR (0x0d),		/**< An self-test of key wrap or unwrap failed. */
};


#endif	/* AES_KEY_WRAP_INTERFACE_H_ */
