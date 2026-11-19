#include <stdio.h>
#include <stdlib.h>

#include "auth.h"
#include "credentials.h"
#include "http_ip.h"
#include "forward.h"

#define ARCHIVO_CREDENCIALES "usr_sig.txt"

int main(void) {
    struct credenciales c;

    // Falta el archivo o no tiene las 3 líneas válidas
    if (leer_credenciales(ARCHIVO_CREDENCIALES, &c) < 0) return EXIT_FAILURE;

    char ip[INET_ADDRSTRLEN];

    // No se pudo consultar api.ipify.org o no devolvió una IPv4
    if (obtener_ip_publica(ip, sizeof ip) < 0) return EXIT_FAILURE;
    
    printf("IP publica: %s\n", ip);

    int puerto = autenticar(&c, ip);

    // El servidor respondió con un error 4xx o no llegó una respuesta válida en 10 s
    if (puerto < 0) return EXIT_FAILURE;
    printf("Autentificacion exitosa. Puerto TCP asignado: %d\n", puerto);

    // No se pudo conectar al puerto TCP
    if (recibir_y_reenviar_pdus(&c, puerto) < 0) return EXIT_FAILURE;

    return EXIT_SUCCESS;
}
