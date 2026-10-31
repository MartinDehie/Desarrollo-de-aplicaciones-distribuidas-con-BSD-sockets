#ifndef MD5_H
#define MD5_H

#include <stddef.h>

/* Calcula el MD5 (RFC 1321) de los len bytes de data y lo escribe en hex
 * como string de 32 caracteres en minúscula terminado en '\0'. */
void md5_hex(const char *data, size_t len, char hex[33]);

#endif
