#include "auth.h"

#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include "md5_hex.h"

#define MAX_MSG 512
#define FIRMA_ERROR "00000000000000000000000000000000"

/*
Provista por la cátedra (codigo_ayuda/test_skip_single.c).
Skip the characters until the SINGLE DELIMITER character is found
0-terminate resulting word
Advance pointer to buffer to the last skipped position + delimiter.
Return found 0-terminated word.
*/
static char *skip_single(char **buf, const char *delimiters)
{
  char *p, *begin_word, *end_word, *end_delimiters;

  begin_word = *buf;

  end_word = begin_word + strcspn(begin_word, delimiters);

  // Take only ONE delimiter
  end_delimiters = end_word + 1;

  for (p = end_word; p < end_delimiters; p++) {
    *p = '\0';
  }

  *buf = end_delimiters;

  return begin_word;
}

/*
Provista por la cátedra (codigo_ayuda/unixtimestamp.c).
Subtract the `struct timeval' values X and Y, storing the result in RESULT.
Return 1 if the difference is negative, otherwise 0.
From: https://ftp.gnu.org/old-gnu/Manuals/glibc-2.2.5/html_node/Elapsed-Time.html
*/
static int timeval_subtract (struct timeval *result, struct timeval *x, struct timeval *y)
{
    // preserve *y
  struct timeval yy = *y;
  y = &yy;

  /* Perform the carry for the later subtraction by updating y. */
  if (x->tv_usec < y->tv_usec) {
    int nsec = (y->tv_usec - x->tv_usec) / 1000000 + 1;
    y->tv_usec -= 1000000 * nsec;
    y->tv_sec += nsec;
  }
  if (x->tv_usec - y->tv_usec > 1000000) {
    int nsec = (x->tv_usec - y->tv_usec) / 1000000;
    y->tv_usec += 1000000 * nsec;
    y->tv_sec -= nsec;
  }

  /* Compute the time remaining to wait.
     tv_usec is certainly positive. */
  result->tv_sec = x->tv_sec - y->tv_sec;
  result->tv_usec = x->tv_usec - y->tv_usec;

  /* Return 1 if result is negative. */
  return x->tv_sec < y->tv_sec;
}

enum resultado procesar_respuesta(char *msg, const char *secreto, int *puerto) {
    // Tienen que estar los 3 pipes que separan <CODE>|<ACTION>|<TEXT>|<SIGNATURE>. Si falta alguno, se descarta.
    // Se cuenta antes porque skip_single no avisa si no encuentra el delimitador: dejaría el puntero pasado el final del string
    int pipes = 0;
    for (const char *q = msg; *q != '\0'; q++) {if (*q == '|') pipes++;}
    if (pipes < 3) return RESP_INVALIDA;

    // Cada skip_single pisa un pipe con '\0' y deja p al principio del campo siguiente
    char *p = msg;
    const char *code = skip_single(&p, "|");
    const char *action = skip_single(&p, "|");
    const char *text = skip_single(&p, "|");
    const char *firma = p; // Lo que queda después del tercer pipe

    // La firma esperada es md5(<CODE>|<ACTION>|<TEXT>|<SECRET>)
    char aux[MAX_MSG + MAX_CAMPO];
    int n = snprintf(aux, sizeof aux, "%s|%s|%s|%s", code, action, text, secreto);
    char esperada[33];
    md5_hex(aux, (size_t)n, esperada);

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

    // Momento en que se terminan los 10 s de espera
    struct timeval limite;
    gettimeofday(&limite, NULL);
    limite.tv_sec += TIMEOUT_SEG;

    int puerto = -1;

    // Esperamos hasta que llegue una respuesta válida, haya un error o se terminen los 10 s
    while (1) {
        struct timeval ahora, resta;
        gettimeofday(&ahora, NULL);

        // resta = limite - ahora es lo que queda de los 10 s (timeval_subtract devuelve 1 si es negativa).
        // También cortamos si da justo 0, porque un SO_RCVTIMEO de 0 significa esperar para siempre
        if (timeval_subtract(&resta, &limite, &ahora) || (resta.tv_sec == 0 && resta.tv_usec == 0)) {
            fprintf(stderr, "Timeout: no llegó una respuesta válida en %d segundos\n", TIMEOUT_SEG);
            break;
        }

        // El timeout de recvfrom es lo que queda de los 10 s
        setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &resta, sizeof resta);

        char msg[MAX_MSG];
        ssize_t n = recvfrom(s, msg, sizeof msg - 1, 0, NULL, NULL);

        // Venció el timeout: volvemos arriba, donde resta ya da negativa o 0
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