#ifndef FRAMING_H
#define FRAMING_H

#include <stddef.h>  //para el size_t

// Una PDU válida mide como mucho 122 bytes, pero las inválidas pueden ser más largas y también hay que delimitarlas
#define FRAMER_CAPACIDAD 4096 //numero grande a proposito para tener margen de error

/*
Acumula los bytes que llegan por TCP hasta poder separar PDUs completas (terminadas en \r\n).
Se vacía con len = 0: lo que queda en el buffer después de len se ignora.
*/
struct framer {
    char buffer[FRAMER_CAPACIDAD];
    size_t len; // Bytes acumulados que todavía no forman una PDU
};

/*
Agrega cant_bytes bytes al final del buffer.
Devuelve 0, o -1 si no entran (llegaron demasiados bytes sin \r\n). En ese caso el buffer queda como estaba. --> le deja la decision a "foward" de que hacer en ese caso
*/
int framer_agregar(struct framer *f, const char *datos, size_t cant_bytes);

/*
Si el buffer tiene una PDU completa (terminada en \r\n), la copia en pdu sin el \r\n y terminada en '\0', guarda su largo en *len y la saca del buffer.
El \r y el \n pueden haber llegado en recv distintos. 
pdu (no una PDU, sino el lugar donde se acumula lo q se recbe de TCP) tiene que medir al menos FRAMER_CAPACIDAD.

Devuelve 1 si sacó una PDU, o 0 si todavía no hay ninguna completa.
*/
int framer_siguiente(struct framer *f, char *pdu, size_t *len);

#endif
