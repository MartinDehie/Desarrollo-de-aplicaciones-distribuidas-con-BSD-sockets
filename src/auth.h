#ifndef AUTH_H
#define AUTH_H

#include "credentials.h"

// Clasificación de una respuesta del servidor
enum resultado {RESP_INVALIDA, RESP_PUERTO, RESP_ERROR};

/*
Clasifica una respuesta del servidor <CODE>|<ACTION>|<TEXT>|<SIGNATURE>, sin el \r\n final:
 - RESP_PUERTO: es 200|Port|<puerto> con la firma md5(<CODE>|<ACTION>|<TEXT>|<SECRET>) y un puerto entre 1 y 65535.
   Deja el puerto en *puerto.
 - RESP_ERROR: es un error 4xx firmado con 32 "0" (ante un error el servidor no conoce el secreto). Lo imprime en stderr.
 - RESP_INVALIDA: cualquier otra cosa (faltan campos, firma incorrecta, puerto inválido). Hay que descartarla en silencio.

Modifica msg: pisa los pipes con '\0' para separar los campos, así que después de llamarla msg ya no se puede imprimir entero.
*/
enum resultado procesar_respuesta(char *msg, const char *secreto, int *puerto);

/* 
Primer desafío. 
Manda por UDP al puerto PUERTO_UDP del servidor la PDU <USERNAME>|<IPv4ADDRESS>|md5(<USERNAME>|<IPv4ADDRESS>|<SECRET>) 
y espera la respuesta <CODE>|<ACTION>|<TEXT>|<SIGNATURE> durante TIMEOUT_SEG segundos en total. Descarta en silencio los datagramas
mal formados y los mal firmados, y en ese caso sigue esperando solo el tiempo que queda. Un error 4xx (firmado con 32 "0") se imprime en stderr y termina la espera.

Devuelve el puerto TCP de un 200|Port|<puerto> bien firmado, o -1 si hubo un error o venció el timeout.
*/
int autenticar(const struct credenciales *c, const char *ip_publica);

#endif
