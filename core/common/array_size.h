// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef ARRAY_SIZE_H_
#define ARRAY_SIZE_H_


/**
 * Determine the number of elements in arbitrary array.
 */
#ifndef ARRAY_SIZE
#define	ARRAY_SIZE(x)		(sizeof (x) / sizeof ((x)[0]))
#endif


#endif	/* ARRAY_SIZE_H_ */
