#include "http_ip.h"

#include <arpa/inet.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#define API_HOST "api.ipify.org"
#define TIMEOUT_SEG 5

static int conectar_api(void) {
    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET; // IPv4: el servidor de la cátedra valida una IPv4
    hints.ai_socktype = SOCK_STREAM; // TCP

    // Resolución DNS del nombre
    int err = getaddrinfo(API_HOST, "80", &hints, &res);
    if (err != 0) {
        fprintf(stderr, "getaddrinfo(%s): %s\n", API_HOST, gai_strerror(err));
        return -1;
    }

    int s = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (s < 0) {perror("socket"); freeaddrinfo(res); return -1;} // Falló la creación del socket

    // Para no quedar colgados si la API no responde. En Linux, SO_SNDTIMEO también limita a connect
    struct timeval tv = {TIMEOUT_SEG, 0};
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);

    // No se pudo conectar
    if (connect(s, res->ai_addr, res->ai_addrlen) < 0) {
        perror("connect");
        close(s);
        s = -1;
    }
    freeaddrinfo(res);
    return s;
}

// TCP es un stream: la respuesta puede llegar repartida en varios recv, así que leemos hasta que el servidor cierra
static int recibir_todo(int s, char *buf, size_t cap) {
    size_t total = 0;
    while (total < cap - 1) {
        ssize_t n = recv(s, buf + total, cap - 1 - total, 0);
        if (n < 0) {perror("recv"); return -1;} // Error o timeout
        if (n == 0) break; // El servidor cerró la conexión
        
        total += (size_t)n;
    }
    buf[total] = '\0';
    return 0;
}

int obtener_ip_publica(char *ip, size_t ip_len) {
    int s = conectar_api();
    if (s < 0) return -1;

    // HTTP/1.0 para que el servidor cierre la conexión al terminar (así sabemos dónde termina la respuesta)
    const char *pedido = "GET / HTTP/1.0\r\nHost: " API_HOST "\r\n\r\n";
    char resp[4096];

    // send puede mandar menos bytes de los pedidos: con 40 bytes no pasa, pero si pasa lo tomamos como error
    if (send(s, pedido, strlen(pedido), 0) != (ssize_t)strlen(pedido) || recibir_todo(s, resp, sizeof resp) < 0) {
        fprintf(stderr, "falló la consulta HTTP a %s\n", API_HOST);
        close(s);
        return -1;
    }
    close(s);

    // Los headers terminan en una línea vacía; después viene el body (la IP)
    char *body = strstr(resp, "\r\n\r\n");
    if (body == NULL) {fprintf(stderr, "respuesta HTTP sin body\n"); return -1;}
    body += 4;

    // La IP va hasta el primer espacio o salto de línea, y tiene que entrar en ip
    size_t largo = strcspn(body, " \t\r\n");
    if (largo >= ip_len) {fprintf(stderr, "body HTTP inválido\n"); return -1;}
    memcpy(ip, body, largo);
    ip[largo] = '\0';

    // Lo que llegó tiene que ser una IPv4 en Decimal Dot Notation (también descarta un error HTTP o un body vacío)
    struct in_addr tmp;
    if (inet_pton(AF_INET, ip, &tmp) != 1) {
        fprintf(stderr, "la respuesta no es una IPv4 válida: %s\n", ip);
        return -1;
    }
    return 0;
}
