/*
 * netsniff-ng - the packet sniffing beast
 * By Daniel Borkmann <daniel@netsniff-ng.org>
 * Copyright 2009, 2010 Daniel Borkmann.
 * Subject to the GPL.
 */

#ifndef ANON_H
#define ANON_H

/*
 * This is a macro for using anonymous functions in C. Be aware of not
 * accessing variables on the same scope where the function is defined
 * because this could lead to inconsistencies or worse, if you pass the
 * anonymous function as a return val, you could smack your stack frames.
 * So as a rule of thumb: Only use variables that really belong to the
 * function itself, never use vars from the ouside.
 */

#define anon(return_type, body_and_args) \
	({                               \
	return_type __fn__ body_and_args \
	__fn__;                          \
	})

/*
 * Example usage:
 *
 * qsort(&argv[1], argc - 1, sizeof(argv[1]),
 *       lambda(int, (const void * a, const void * b) {
 *               return strcmp(*(char * const *) a, *(char * const *) b);
 *       }));
 */

#endif /* ANON_H */
