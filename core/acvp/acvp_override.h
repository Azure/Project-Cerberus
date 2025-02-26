// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef ACVP_OVERRIDE_H_
#define ACVP_OVERRIDE_H_


/**
 * Define the include guards for Acvpparser header files in order to prevent multiple definitions
 * of the below macros.
 */
#define CONSTRUCTOR_H
#define LOGGER_H


/**
 * Define init functions to allow static ACVP Proto registration functions to be called externally.
 */
#define ACVP_DEFINE_CONSTRUCTOR(_func)  \
	static void _func(void);            \
	void _init_ ## _func(void);         \
	void _init_ ## _func(void)          \
	{                                   \
		_func();                        \
	}

/**
 * Override logger macros with no-ops to prevent ACVP Parser logging.
 */
#define logger(severity, fmt...)    \
	do { } while (0);

#define logger_binary(severity, bin, binlen, str)   \
	do { } while (0);


#endif	/* ACVP_OVERRIDE_H_ */
