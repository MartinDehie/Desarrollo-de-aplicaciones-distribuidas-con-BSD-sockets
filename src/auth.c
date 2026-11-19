#include "auth.h"

#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include "md5.h"

#define MAX_MSG 512
#define FIRMA_ERROR "00000000000000000000000000000000"

// Milisegundos de un reloj que solo avanza (independiente del sistema)
static long ahora_ms(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec * 1000 + t.tv_nsec / 1000000;
}

enum resultado procesar_respuesta(char *msg, const char *secreto, int *puerto) {
    // Buscamos los 3 pipes que separan <CODE>|<ACTION>|<TEXT>|<SIGNATURE>. Si falta alguno, se descarta
    char *p1 = strchr(msg, '|');
    if (p1 == NULL) return RESP_INVALIDA;
    char *p2 = strchr(p1 + 1, '|');
    if (p2 == NULL) return RESP_INVALIDA;
    char *p3 = strchr(p2 + 1, '|');
    if (p3 == NULL) return RESP_INVALIDA;

    const char *firma = p3 + 1;

    /* La firma esperada es el MD5 de lo recibido hasta el último pipe más el secreto */
    char aux[MAX_MSG + MAX_CAMPO];
    int n = snprintf(aux, sizeof aux, "%.*s%s", (int)(p3 - msg + 1), msg, secreto);
    char esperada[33];
    md5_hex(aux, (size_t)n, esperada);

    *p1 = *p2 = *p3 = '\0';
    const char *code = msg, *action = p1 + 1, *text = p2 + 1;

    // Firma válida: la respuesta viene del servidor. Chequeamos formato: 200|Port|<puerto>
    if (strcmp(firma, esperada) == 0) {
        if (strcmp(code, "200") != 0 || strcmp(action, "Port") != 0) return RESP_INVALIDA; // No es 200|Port

        char *fin;
        long p = strtol(text, &fin, 10);
        if (*fin != '\0' || p < 1 || p > 65535) return RESP_INVALIDA; // Puerto inválido

        *puerto = (int)p;
        return RESP_PUERTO;
    }

    // Error del servidor (4xx): como no conoce el secreto, firma con 32 "0"
    if (code[0] == '4' && strcmp(firma, FIRMA_ERROR) == 0) {
        fprintf(stderr, "Error del servidor: %s %s\n", code, text);
        return RESP_ERROR;
    }

    return RESP_INVALIDA;
}

int autenticar(const struct credenciales *c, const char *ip_publica) {
    char aux[256], firma[33], pdu[256];

    // Firmamos con el secreto y mandamos el mismo mensaje con la firma en su lugar
    snprintf(aux, sizeof aux, "%s|%s|%s", c->usuario, ip_publica, c->secreto);
    md5_hex(aux, strlen(aux), firma);
    snprintf(pdu, sizeof pdu, "%s|%s|%s", c->usuario, ip_publica, firma);

    struct sockaddr_in srv;
    memset(&srv, 0, sizeof srv);
    srv.sin_family = AF_INET;
    srv.sin_port = htons(PUERTO_UDP);

    // La IP del archivo de credenciales no es una IPv4 válida
    if (inet_pton(AF_INET, c->servidor, &srv.sin_addr) != 1) {
        fprintf(stderr, "IP del servidor inválida: %s\n", c->servidor);
        return -1;
    }

    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) {perror("socket"); return -1;} // Falló la creación del socket

    printf("Enviando:  %s\n", pdu);
    if (sendto(s, pdu, strlen(pdu), 0, (struct sockaddr *)&srv, sizeof srv) < 0) {perror("sendto"); close(s); return -1;} // Falló el envío del datagrama

    long limite = ahora_ms() + TIMEOUT_SEG * 1000;

    int puerto = -1;

    // Esperamos hasta que llegue una respuesta válida, haya un error o se terminen los 10 s
    while (1) {
        long ms = limite - ahora_ms();
        
        // Pasaron 10 s sin respuesta válida
        if (ms <= 0) {
            fprintf(stderr, "Timeout: no llegó una respuesta válida en %d segundos\n", TIMEOUT_SEG);
            break;
        }

        // El timeout de recvfrom es lo que queda de los 10 s
        struct timeval tv = { ms / 1000, (ms % 1000) * 1000 };
        setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);

        char msg[MAX_MSG];
        ssize_t n = recvfrom(s, msg, sizeof msg - 1, 0, NULL, NULL);
        
        // Venció el timeout: volvemos arriba, donde ms ya es <= 0
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) continue;
        
        // Error de recvfrom
        if (n < 0) {perror("recvfrom"); break;}

        msg[n] = '\0';
        msg[strcspn(msg, "\r\n")] = '\0';

        // Puerto válido o error del servidor: dejamos de esperar. Si es inválida, seguimos
        if (procesar_respuesta(msg, c->secreto, &puerto) != RESP_INVALIDA) break;
    }

    close(s);
    return puerto;
}