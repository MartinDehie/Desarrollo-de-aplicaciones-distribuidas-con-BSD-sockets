#include "http_ip.h"

#include <arpa/inet.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#define API_HOST "api.ipify.org"
#define API_PUERTO "80"
#define TIMEOUT_SEG 5

/* Abre una conexión TCP a host:puerto. Devuelve el socket o -1 */
static int conectar_tcp(const char *host, const char *puerto)
{
    struct addrinfo hints, *res, *rp;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET;       /* IPv4: el servidor de la cátedra valida una IPv4 */
    hints.ai_socktype = SOCK_STREAM; /* TCP */

    /* Resolución DNS del nombre del host */
    int err = getaddrinfo(host, puerto, &hints, &res);
    if (err != 0) {
        fprintf(stderr, "getaddrinfo(%s): %s\n", host, gai_strerror(err));
        return -1;
    }

    /* getaddrinfo puede devolver varias direcciones: probamos hasta que una conecte */
    int s = -1;
    for (rp = res; rp != NULL; rp = rp->ai_next) {
        s = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (s < 0)
            continue;

        /* Timeouts para no quedar bloqueados para siempre. En Linux,
         * SO_SNDTIMEO también limita cuánto puede tardar connect */
        struct timeval tv = { TIMEOUT_SEG, 0 };
        setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
        setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);

        if (connect(s, rp->ai_addr, rp->ai_addrlen) == 0)
            break;

        perror("connect");
        close(s);
        s = -1;
    }
    freeaddrinfo(res);

    if (s < 0)
        fprintf(stderr, "no se pudo conectar a %s:%s\n", host, puerto);
    return s;
}

/* Envía los len bytes completos: send puede enviar menos de lo pedido */
static int enviar_todo(int s, const char *buf, size_t len)
{
    size_t enviados = 0;
    while (enviados < len) {
        ssize_t n = send(s, buf + enviados, len - enviados, 0);
        if (n < 0) {
            perror("send");
            return -1;
        }
        enviados += (size_t)n;
    }
    return 0;
}

/* Lee hasta que el servidor cierra la conexión (recv devuelve 0).
 * TCP es un stream de bytes: la respuesta puede llegar repartida en
 * varios recv, así que no alcanza con llamarlo una sola vez. */
static int recibir_todo(int s, char *buf, size_t cap)
{
    size_t total = 0;
    while (total < cap - 1) {
        ssize_t n = recv(s, buf + total, cap - 1 - total, 0);
        if (n < 0) {
            perror("recv");
            return -1;
        }
        if (n == 0)
            break;
        total += (size_t)n;
    }
    buf[total] = '\0';
    return 0;
}

int obtener_ip_publica(char *ip, size_t ip_len)
{
    int s = conectar_tcp(API_HOST, API_PUERTO);
    if (s < 0)
        return -1;

    /* Usamos HTTP/1.0 para que el servidor cierre la conexión al terminar
     * (así sabemos dónde termina la respuesta) y no use chunked encoding */
    const char *pedido = "GET / HTTP/1.0\r\n"
                         "Host: " API_HOST "\r\n"
                         "\r\n";

    char resp[4096];
    if (enviar_todo(s, pedido, strlen(pedido)) < 0 ||
        recibir_todo(s, resp, sizeof resp) < 0) {
        close(s);
        return -1;
    }
    close(s);

    /* Línea de estado, ej. "HTTP/1.1 200 OK" */
    int codigo;
    if (sscanf(resp, "HTTP/%*d.%*d %d", &codigo) != 1 || codigo != 200) {
        fprintf(stderr, "respuesta HTTP inesperada de %s\n", API_HOST);
        return -1;
    }

    /* Los headers terminan en una línea vacía; después viene el body (la IP) */
    char *body = strstr(resp, "\r\n\r\n");
    if (body == NULL) {
        fprintf(stderr, "respuesta HTTP sin body\n");
        return -1;
    }
    body += 4;

    /* Nos quedamos con el body hasta el primer espacio o salto de línea */
    size_t largo = strcspn(body, " \t\r\n");
    if (largo == 0 || largo >= ip_len) {
        fprintf(stderr, "body HTTP inválido\n");
        return -1;
    }
    memcpy(ip, body, largo);
    ip[largo] = '\0';

    /* Validamos que sea una IPv4 en Decimal Dot Notation */
    struct in_addr tmp;
    if (inet_pton(AF_INET, ip, &tmp) != 1) {
        fprintf(stderr, "la respuesta no es una IPv4 válida: %s\n", ip);
        return -1;
    }

    return 0;
}
