#ifndef CREDENTIALS_H
#define CREDENTIALS_H

#include <netinet/in.h>

#define MAX_CAMPO 64
#define PUERTO_UDP 20262 // Puerto UDP del servidor, para autenticarse y para los reenvíos
#define TIMEOUT_SEG 10   // Espera máxima de la respuesta UDP y entre datos TCP

// Datos del archivo de credenciales que entrega la cátedra
struct credenciales {
    char servidor[INET_ADDRSTRLEN]; // IPv4 del servidor en Decimal Dot Notation
    char usuario[MAX_CAMPO];
    char secreto[MAX_CAMPO];        // Nunca viaja por la red, solo entra en las firmas
};

/*
  Lee el archivo ruta, que tiene 3 líneas: IP del servidor, usuario y secreto.
  Acepta finales de línea \n o \r\n. Rechaza las líneas vacías y las que no entran en su campo.
  Devuelve 0 si salió bien, -1 si hubo error (el motivo se imprime en stderr).
*/
int leer_credenciales(const char *ruta, struct credenciales *c);

#endif
