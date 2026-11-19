#ifndef HTTP_IP_H
#define HTTP_IP_H

#include <stddef.h>

/*
Consulta la IP pública a api.ipify.org con un GET HTTP/1.0 escrito a mano sobre un socket TCP (sin bibliotecas HTTP).
Escribe la IP en Decimal Dot Notation (ej. "8.8.8.8") en ip; ip_len tiene que ser al menos INET_ADDRSTRLEN (16).

Devuelve 0 si salió bien, -1 si hubo error (el motivo se imprime en stderr).
*/
int obtener_ip_publica(char *ip, size_t ip_len);

#endif
