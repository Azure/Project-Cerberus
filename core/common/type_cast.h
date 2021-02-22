// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef TYPE_CAST_H_
#define TYPE_CAST_H_

#include <stdint.h>


/**
 * Cast a pointer of a base type to a pointer of type derived from that base type.  The base type
 * must exist as a member of the derived type structure.
 *
 * @param ptr Pointer to the base type that should be cast to the derived type.
 * @param type The derived type to cast to.
 * @param field The member within the derived type's structure for the base type.
 *
 * @return A pointer to the derived type.
 */
#define	TO_DERIVED_TYPE(ptr, type, field)	(type*) (((uintptr_t) ptr) - offsetof (type, field))


#endif /* TYPE_CAST_H_ */
