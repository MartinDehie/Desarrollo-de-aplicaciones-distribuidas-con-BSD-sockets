#ifndef HTTP_IP_H
#define HTTP_IP_H

#include <stddef.h>

/* Consulta la IP pública a api.ipify.org por HTTP usando un socket TCP propio.
 * Escribe la IP en Decimal Dot Notation (ej. "8.8.8.8") en ip; ip_len debe
 * ser al menos 16 (INET_ADDRSTRLEN).
 * Devuelve 0 si salió bien, -1 si hubo error (el motivo se imprime en stderr). */
int obtener_ip_publica(char *ip, size_t ip_len);

#endif
