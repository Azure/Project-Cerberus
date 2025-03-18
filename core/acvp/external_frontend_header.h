// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef EXTERNAL_FRONTEND_HEADER_H
#define EXTERNAL_FRONTEND_HEADER_H

#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include "platform_api.h"
#include "acvp/acvp_override.h"


#define acvp_calloc(nmemb, size)	platform_calloc(nmemb, size)
#define acvp_malloc(size)			platform_malloc(size)
#define acvp_free(ptr)				platform_free(ptr)


#endif	/* EXTERNAL_FRONTEND_HEADER_H */
