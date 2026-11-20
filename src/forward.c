#include "forward.h"

#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include "framing.h"
#include "md5_hex.h"
#include "pdu.h"

// Peor caso: usuario (63) + PDU (hasta FRAMER_CAPACIDAD - 2) + pipes, código y secreto o firma (hasta 69)
#define MAX_REENVIO (FRAMER_CAPACIDAD + 3 * MAX_CAMPO)

// Escribe <usuario>|<pdu>|<codigo>|<cola> en dst y devuelve el largo.
// La PDU va con memcpy y no con %s porque una PDU inválida puede traer un '\0' en el medio
static size_t armar(char *dst, const char *usuario, const char *pdu, size_t len, int codigo, const char *cola) {
    size_t n = (size_t)sprintf(dst, "%s|", usuario);
    memcpy(dst + n, pdu, len);
    n += len;
    n += (size_t)sprintf(dst + n, "|%d|%s", codigo, cola);
    return n;
}

static void reenviar_pdu(int s, const struct sockaddr_in *srv, const struct credenciales *c, const char *pdu, size_t len) {
    int codigo = validar_pdu(pdu, len, time(NULL));

    // Firmamos con el secreto y mandamos el mismo mensaje con la firma en su lugar
    char aux[MAX_REENVIO], msg[MAX_REENVIO], firma[33];
    md5_hex(aux, armar(aux, c->usuario, pdu, len, codigo, c->secreto), firma);
    size_t n = armar(msg, c->usuario, pdu, len, codigo, firma);

    if (sendto(s, msg, n, 0, (const struct sockaddr *)srv, sizeof *srv) < 0) perror("sendto");
    else printf(" -> reenviada con codigo %d\n", codigo);
}

int recibir_y_reenviar_pdus(const struct credenciales *c, int puerto) {
    // La IP ya la validó autenticar, así que no hace falta chequear inet_pton de nuevo
    struct sockaddr_in srv;
    memset(&srv, 0, sizeof srv);
    srv.sin_family = AF_INET;
    srv.sin_port = htons(puerto);
    inet_pton(AF_INET, c->servidor, &srv.sin_addr);

    int s_tcp = socket(AF_INET, SOCK_STREAM, 0);
    if (s_tcp < 0) {perror("socket"); return -1;} // Falló la creación del socket TCP

    // Sin timeout, recv quedaría bloqueado si el servidor deja de mandar sin cerrar la conexión
    struct timeval tv = {TIMEOUT_SEG, 0};
    setsockopt(s_tcp, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);

    // No se pudo conectar (por ejemplo, porque pasaron más de 10 s y el servidor cerró el puerto)
    if (connect(s_tcp, (struct sockaddr *)&srv, sizeof srv) < 0) {
        perror("connect");
        close(s_tcp);
        return -1;
    }
    printf("Conectado por TCP al puerto %d\n", puerto);

    int s_udp = socket(AF_INET, SOCK_DGRAM, 0);
    if (s_udp < 0) {perror("socket"); close(s_tcp); return -1;} // Falló la creación del socket UDP

    // Los reenvíos van a la misma IP, pero al puerto UDP
    struct sockaddr_in srv_udp = srv;
    srv_udp.sin_port = htons(PUERTO_UDP);

    struct framer f;
    f.len = 0;
    char datos[1024], pdu[FRAMER_CAPACIDAD];
    size_t len;
    int cant = 0;

    while (1) { // Recibimos hasta que el servidor cierre la conexión, haya un error o pasen 10 s sin datos
        ssize_t n = recv(s_tcp, datos, sizeof datos, 0);
        if (n < 0) {perror("recv"); break;} // Error o timeout
        if (n == 0) break;                    // El servidor cerró la conexión

        // Se acumularon FRAMER_CAPACIDAD bytes sin \r\n: eso no es una PDU, lo descartamos
        if (framer_agregar(&f, datos, (size_t)n) < 0) {
            fprintf(stderr, "Se descartan %zu bytes sin \\r\\n\n", f.len);
            f.len = 0;
            framer_agregar(&f, datos, (size_t)n);
        }

        // Un mismo recv puede completar varias PDUs
        while (framer_siguiente(&f, pdu, &len)) {
            cant++;
            printf("PDU %d (%zu bytes): %s\n", cant, len, pdu);

            // Con '|' rompería el formato del reenvío, y la consigna pide no mandarla
            if (memchr(pdu, '|', len) != NULL) {
                printf(" -> no se reenvia porque tiene |\n");
                continue;
            }
            reenviar_pdu(s_udp, &srv_udp, c, pdu, len);
        }
    }

    close(s_tcp);
    close(s_udp);

    // Lo que quedó sin \r\n no es una PDU delimitada, así que no se reenvía
    if (f.len > 0) printf("Descartamos %zu bytes finales sin \\r\\n\n", f.len);
    printf("Conexion TCP cerrada.\nPDUs recibidas: %d\n", cant);
    return 0;
}
