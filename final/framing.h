#ifndef FRAMING_H
#define FRAMING_H
#include <stddef.h>

//Capacidad del buffer:
//Valor elegido arbitrariamente, coherente con el tamaño usado para la respuesta HTTP en http_ip.c
//Es necesario que pueda almacenar PDUs invalidas (mas de 122 bytes)
#define FRAMER_CAPACIDAD 4096
//Sirve para acumular los bytes que llegan por TCP, hasta poder separar PDUs completas
struct framer { 
    char buffer[FRAMER_CAPACIDAD];
    size_t len; //Bytes que aun no forman una PDU
};


/*Deja el framer vacio*/
void framer_init(struct framer *framer);

/*Agrega los bytes recibidos al final del buffer
Devuelve 0 si salió bien, -1 si no entran (osea que llegaron demasiados bytes sin un \r\n).*/
int framer_agregar(struct framer *framer, const char *datos, size_t cant_bytes);

/*Si el buffer tiene una PDU completa (osea que termina en \r\n), la copia en pdu, sin
el \r\n, le agrega un '\0', guarda su largo en *len y la saca del buffer
Devuelve 1 si saco una PDU, o 0 si todavia no hay ninguna completa*/
int framer_siguiente(struct framer *framer, char *pdu, size_t *len);

#endif
