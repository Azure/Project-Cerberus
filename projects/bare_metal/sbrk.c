// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdint.h>


/**
 * Version of _sbrk() to make sure it take into the account the end of allowable
 * heap space
 *
 * @param incr Number of bytes to extend current heap allocation
 * @return pointer to newly allocated chunk or -1 in case of error.
 */
void* _sbrk (int incr)
{
	extern char end;			/* Set by linker. */
	extern char __heap_limit;	/* Set by linker. */
	static uintptr_t heap_end = 0;
	uintptr_t prev_heap_end;

	if (heap_end == 0) {
		heap_end = (uintptr_t) &end;
	}

	if ((incr < 0) || (heap_end > (heap_end + incr))) {
		return (void*) -1;
	}

	if ((heap_end + incr) > (uintptr_t) &__heap_limit) {
		return (void*) -1;
	}

	prev_heap_end = heap_end;
	heap_end += incr;

	return (void*) prev_heap_end;
}
