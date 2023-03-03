#ifndef ARRAY_SIZE_H_
#define ARRAY_SIZE_H_


/**
 * Determine the number of elements in arbitrary array.
 */
#define	ARRAY_SIZE(x)		(sizeof (x) / sizeof ((x)[0]))


#endif /* ARRAY_SIZE_H_ */
