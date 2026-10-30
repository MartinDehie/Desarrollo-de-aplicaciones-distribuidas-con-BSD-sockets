#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "http_ip.h"
#include "md5.h"

#define ARCHIVO_CREDENCIALES "usr_sig.txt"
#define PUERTO_UDP 20262
#define TIMEOUT_SEG 10
#define MAX_CAMPO 64
#define MAX_MSG 512
#define FIRMA_ERROR "00000000000000000000000000000000"

struct credenciales {
    char servidor[INET_ADDRSTRLEN];
    char usuario[MAX_CAMPO];
    char secreto[MAX_CAMPO];
};

/* Resultado de procesar una respuesta del servidor */
enum resultado {
    RESP_INVALIDA, /* mal formada o mal firmada: se descarta en silencio */
    RESP_PUERTO,   /* 200|Port|<puerto> con firma válida */
    RESP_ERROR     /* 4xx|Message|<texto> con firma de 32 "0" */
};

/* Lee una línea de f en dst, sin el \r\n final. Devuelve 0, o -1 si no hay
 * línea, está vacía o no entra en dst.
 * Se lee primero en un buffer grande: si fgets leyera directo en dst y la
 * línea ocupara justo cap - 1 caracteres, el '\n' quedaría sin leer y la
 * próxima llamada devolvería una línea vacía. */
static int leer_linea(FILE *f, char *dst, size_t cap)
{
    char linea[256];
    if (fgets(linea, sizeof linea, f) == NULL)
        return -1;
    linea[strcspn(linea, "\r\n")] = '\0';

    size_t largo = strlen(linea);
    if (largo == 0 || largo >= cap)
        return -1;
    memcpy(dst, linea, largo + 1);
    return 0;
}

/* Formato del archivo: IP del servidor, usuario y secreto, uno por línea */
static int leer_credenciales(const char *ruta, struct credenciales *c)
{
    FILE *f = fopen(ruta, "r");
    if (f == NULL) {
        perror(ruta);
        return -1;
    }
    int ok = leer_linea(f, c->servidor, sizeof c->servidor) == 0 &&
             leer_linea(f, c->usuario, sizeof c->usuario) == 0 &&
             leer_linea(f, c->secreto, sizeof c->secreto) == 0;
    fclose(f);

    if (!ok) {
        fprintf(stderr, "%s: se esperan 3 líneas (IP del servidor, usuario, secreto)\n", ruta);
        return -1;
    }

    /* El usuario solo puede tener caracteres [0-9A-Za-z] */
    for (const char *p = c->usuario; *p != '\0'; p++) {
        if (!isalnum((unsigned char)*p)) {
            fprintf(stderr, "%s: usuario con caracteres inválidos\n", ruta);
            return -1;
        }
    }
    return 0;
}

/* Milisegundos que faltan para llegar a limite (puede ser negativo) */
static long ms_restantes(const struct timespec *limite)
{
    struct timespec ahora;
    clock_gettime(CLOCK_MONOTONIC, &ahora);
    return (long)(limite->tv_sec - ahora.tv_sec) * 1000 +
           (limite->tv_nsec - ahora.tv_nsec) / 1000000;
}

/* Valida una respuesta <CODE>|<ACTION>|<TEXT>|<SIGNATURE> (sin \r\n final).
 * Modifica msg: reemplaza los pipes por '\0' para separar los campos. */
static enum resultado procesar_respuesta(char *msg, const char *secreto, int *puerto)
{
    /* Tiene que haber exactamente 4 campos, o sea 3 pipes. No usamos strtok
     * porque se saltea los campos vacíos */
    char *p1 = strchr(msg, '|');
    char *p2 = p1 ? strchr(p1 + 1, '|') : NULL;
    char *p3 = p2 ? strchr(p2 + 1, '|') : NULL;
    if (p3 == NULL || strchr(p3 + 1, '|') != NULL)
        return RESP_INVALIDA;

    const char *firma = p3 + 1;
    if (strlen(firma) != 32)
        return RESP_INVALIDA;

    /* Firma esperada: md5("<CODE>|<ACTION>|<TEXT>|<SECRET>"), es decir, lo
     * recibido hasta el último pipe inclusive seguido del secreto */
    char aux[MAX_MSG + MAX_CAMPO];
    int n = snprintf(aux, sizeof aux, "%.*s%s", (int)(p3 - msg + 1), msg, secreto);
    char esperada[33];
    md5_hex(aux, (size_t)n, esperada);

    *p1 = '\0';
    *p2 = '\0';
    *p3 = '\0';
    const char *code = msg, *action = p1 + 1, *text = p2 + 1;

    if (strcmp(firma, esperada) == 0) {
        if (strcmp(code, "200") != 0 || strcmp(action, "Port") != 0)
            return RESP_INVALIDA;

        char *fin;
        errno = 0;
        long p = strtol(text, &fin, 10);
        if (*text == '\0' || *fin != '\0' || errno != 0 || p < 1 || p > 65535)
            return RESP_INVALIDA;

        *puerto = (int)p;
        return RESP_PUERTO;
    }

    /* Ante un error el servidor no conoce el secreto y la firma son 32 "0" */
    if (code[0] == '4' && strcmp(firma, FIRMA_ERROR) == 0) {
        fprintf(stderr, "Error del servidor: %s %s\n", code, text);
        return RESP_ERROR;
    }
    return RESP_INVALIDA;
}

/* Primer desafío: se autentica por UDP y devuelve el puerto TCP que abrió el
 * servidor, o -1 si hubo un error o no llegó una respuesta válida a tiempo */
static int autenticar(const struct credenciales *c, const char *ip_publica)
{
    /* PDU: <USERNAME>|<IPv4ADDRESS>|md5(<USERNAME>|<IPv4ADDRESS>|<SECRET>) */
    char aux[256], firma[33], pdu[256];
    snprintf(aux, sizeof aux, "%s|%s|%s", c->usuario, ip_publica, c->secreto);
    md5_hex(aux, strlen(aux), firma);
    snprintf(pdu, sizeof pdu, "%s|%s|%s", c->usuario, ip_publica, firma);

    struct sockaddr_in srv;
    memset(&srv, 0, sizeof srv);
    srv.sin_family = AF_INET;
    srv.sin_port = htons(PUERTO_UDP);
    if (inet_pton(AF_INET, c->servidor, &srv.sin_addr) != 1) {
        fprintf(stderr, "IP del servidor inválida: %s\n", c->servidor);
        return -1;
    }

    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) {
        perror("socket");
        return -1;
    }

    printf("Enviando:  %s\n", pdu);
    if (sendto(s, pdu, strlen(pdu), 0, (struct sockaddr *)&srv, sizeof srv) < 0) {
        perror("sendto");
        close(s);
        return -1;
    }

    /* Esperamos como máximo TIMEOUT_SEG en total. Si llega una respuesta
     * inválida la descartamos y seguimos esperando solo el tiempo que queda */
    struct timespec limite;
    clock_gettime(CLOCK_MONOTONIC, &limite);
    limite.tv_sec += TIMEOUT_SEG;

    int puerto = -1;
    for (;;) {
        long ms = ms_restantes(&limite);
        if (ms <= 0) {
            fprintf(stderr, "Timeout: no llegó una respuesta válida en %d segundos\n",
                    TIMEOUT_SEG);
            break;
        }
        struct timeval tv = { ms / 1000, (ms % 1000) * 1000 };
        setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);

        char msg[MAX_MSG];
        struct sockaddr_in origen;
        socklen_t origen_len = sizeof origen;
        ssize_t n = recvfrom(s, msg, sizeof msg - 1, 0,
                             (struct sockaddr *)&origen, &origen_len);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
                continue; /* venció el timeout o nos interrumpieron: recalculamos */
            perror("recvfrom");
            break;
        }
        msg[n] = '\0';

        /* Solo aceptamos datagramas que vengan del servidor */
        if (origen.sin_addr.s_addr != srv.sin_addr.s_addr)
            continue;

        msg[strcspn(msg, "\r\n")] = '\0';
        char crudo[MAX_MSG];
        strcpy(crudo, msg);

        enum resultado r = procesar_respuesta(msg, c->secreto, &puerto);
        if (r == RESP_PUERTO) {
            printf("Recibido:  %s\n", crudo);
            break;
        }
        if (r == RESP_ERROR)
            break;
        /* RESP_INVALIDA: se descarta en silencio */
    }

    close(s);
    return puerto;
}

int main(int argc, char *argv[])
{
    if (argc > 2) {
        fprintf(stderr, "Uso: %s [archivo_credenciales]\n", argv[0]);
        return EXIT_FAILURE;
    }
    const char *ruta = argc == 2 ? argv[1] : ARCHIVO_CREDENCIALES;

    struct credenciales c;
    if (leer_credenciales(ruta, &c) < 0)
        return EXIT_FAILURE;

    char ip[INET_ADDRSTRLEN];
    if (obtener_ip_publica(ip, sizeof ip) < 0)
        return EXIT_FAILURE;
    printf("IP pública: %s\n", ip);

    int puerto = autenticar(&c, ip);
    if (puerto < 0)
        return EXIT_FAILURE;

    printf("Autenticación exitosa. Puerto TCP asignado: %d\n", puerto);
    return EXIT_SUCCESS;
}
