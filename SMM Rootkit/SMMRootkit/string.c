#include "string.h"

size_t strlen(const CHAR8 *str)
{
  const CHAR8 *s;

  for (s = str; *s; ++s)
    ;
  return (s - str);
}

CHAR8 *strcat(CHAR8 *destination, const CHAR8 *source)
{
  // make ptr point to the end of destination string
  CHAR8 *ptr = destination + strlen(destination);

  // Appends characters of source to the destination string
  while (*source != '\0')
    *ptr++ = *source++;

  // null terminate destination string
  *ptr = '\0';

  // destination is returned by standard strcat()
  return destination;
}

INT32 memcmp(const VOID *str1, const VOID *str2, size_t count)
{
  register const UINT8 *s1 = (const UINT8 *)str1;
  register const UINT8 *s2 = (const UINT8 *)str2;

  while (count-- > 0)
  {
    if (*s1++ != *s2++)
      return s1[-1] < s2[-1] ? -1 : 1;
  }
  return 0;
}

CHAR8 tolower(UINT8 ch)
{
  if (ch >= 'A' && ch <= 'Z')
    ch = 'a' + (ch - 'A');
  return ch;
}

INT32 stricmp(const CHAR8 *s1, const CHAR8 *s2)
{
  const UINT8 *us1 = (const UINT8 *)s1,
              *us2 = (const UINT8 *)s2;

  while (tolower(*us1) == tolower(*us2++))
    if (*us1++ == '\0')
      return (0);
  return (tolower(*us1) - tolower(*--us2));
}

INT32 strcmp(const CHAR8 *s1, const CHAR8 *s2)
{
  for (; *s1 == *s2; ++s1, ++s2)
    if (*s1 == 0)
      return 0;
  return *(UINT8 *)s1 < *(UINT8 *)s2 ? -1 : 1;
}

INT32 strncmp(const CHAR8 *s1, const CHAR8 *s2, size_t n)
{
  while (n && *s1 && (*s1 == *s2))
  {
    ++s1;
    ++s2;
    --n;
  }
  if (n == 0)
  {
    return 0;
  }
  else
  {
    return (*(UINT8 *)s1 - *(UINT8 *)s2);
  }
}

const CHAR8 *strstr(const CHAR8 *X, const CHAR8 *Y)
{
  size_t n = strlen(Y);

  while (*X)
  {
    if (!memcmp(X, Y, n))
      return X;

    X++;
  }

  return 0;
}

CHAR8 *strdup(CHAR8 *src)
{
  CHAR8 *str;
  CHAR8 *p;
  INT32 len = 0;

  while (src[len])
    len++;
  str = malloc(len + 1);
  // gotta be safe, our malloc might actually fail :-)
  if (!str)
  {
    return NULL;
  }
  p = str;
  while (*src)
    *p++ = *src++;
  *p = '\0';
  return str;
}