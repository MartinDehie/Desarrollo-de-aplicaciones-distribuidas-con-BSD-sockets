#ifndef MD5_HEX_H
#define MD5_HEX_H

#include <stddef.h> //para tener el "size_t"

/*
Calcula el MD5 de los len bytes de data con la implementación de la cátedra (md5.c) y lo escribe en hex como string
de 32 caracteres en minúscula terminado en '\0'. Se usa para firmar: md5(mensaje|secreto).
*/
            //mensaje a firmar  len(mensaje)     donde escribir el resultado (33 porq 32 caracteres hexa + el '\0' al final)
void md5_hex(const char *data, size_t len, char hex[33]);

#endif
