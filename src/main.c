#include <stdio.h>
#include <stdlib.h>

#include "auth.h"
#include "credentials.h"
#include "http_ip.h"
#include "forward.h"

#define ARCHIVO_CREDENCIALES "usr_sig.txt"

int main(void) {
    struct credenciales c;
    //1. Lee "usr_sig.txt"
    // Falta el archivo o no tiene las 3 líneas válidas
    if (leer_credenciales(ARCHIVO_CREDENCIALES, &c) < 0) return EXIT_FAILURE;

    char ip[INET_ADDRSTRLEN];
    //2. IP publica (desafio 1)
    // No se pudo consultar api.ipify.org o no devolvió una IPv4
    if (obtener_ip_publica(ip, sizeof ip) < 0) return EXIT_FAILURE;
    
    printf("IP publica: %s\n", ip);
    //3. Autenticacion (desafio 1)
    int puerto = autenticar(&c, ip);

    // El servidor respondió con un error 4xx o no llegó una respuesta válida en 10 s
    if (puerto < 0) return EXIT_FAILURE;
    printf("Autentificacion exitosa. Puerto TCP asignado: %d\n", puerto);
    //4. Desafio 2
    // No se pudo conectar al puerto TCP
    if (recibir_y_reenviar_pdus(&c, puerto) < 0) return EXIT_FAILURE;

    return EXIT_SUCCESS;
}
