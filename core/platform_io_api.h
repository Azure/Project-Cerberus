// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef PLATFORM_IO_API_H_
#define PLATFORM_IO_API_H_

/* This file contains the platform I/O abstraction API that can be used to decouple code from the
 * environment in which it will be run. If the platform provides native functions that provide
 * exactly the required functionality (such as in stdio), they can be mapped via a macro in the
 * platform_io.h file. Otherwise, the platform port will need to provide a suitable implementation
 * of the function. */

/* Include specifics for the platform I/O port. */
#include "platform_io.h"

/*******************************
 * I/O routines.
 *******************************/

#ifndef platform_printf
/**
 * Print to platform-defined "stdout". Equivalent to the stdio 'printf' call.
 *
 * @param fmt The printf format string.
 *
 * @return Number of characters printed.
 */
int platform_printf (const char *fmt, ...);
#endif

#ifndef NEWLINE
/**
 * What string to use for a new line in platform_printf.
 *
 * This macro must be defined to a string-literal as code depends on
 * string-literal concatenation, as in:
 *
 * ```c
 * platform_printf ("foo went bar" NEWLINE);
 * ```
 *
 * If none was provided in platform.h, use a line-feed, LF, aka '\n'.
 */
#define NEWLINE				"\n"
#endif


#endif	/* PLATFORM_IO_API_H_ */
