#include "pdu.h"

#include <string.h>

#define TS_MAX 11
#define MSG_MAX 100
#define VENCIMIENTO 300

int validar_pdu(const char *pdu, size_t len, time_t hora_actual) {
    const char *amp = memchr(pdu, '&', len);
    if (amp == NULL) return 400; // Bad Request: no hay 2 campos

    const char *ts = pdu;
    size_t ts_len = (size_t)(amp - pdu);
    const char *msg = amp + 1;
    size_t msg_len = len - ts_len - 1;

    if (ts_len == 0) return 400; // Bad Request: timestamp vacío
    for (size_t i = 0; i < ts_len; i++) {if (ts[i] < '0' || ts[i] > '9') return 405;} // Invalid Timestamp
    if (ts_len > TS_MAX) return 407; // Timestamp Too Long

    long long t = 0; // El timestamp puede tener hasta 11 dígitos, no entra en un int
    for (size_t i = 0; i < ts_len; i++) {
        t = t * 10 + (ts[i] - '0');
    }
    if ((long long)hora_actual - t > VENCIMIENTO) return 406; // Expired Timestamp

    if (msg_len == 0) return 409; // Message Empty
    if (msg_len > MSG_MAX) return 410; // Message Too Long

    // Solo se permiten los caracteres que van del espacio a '}' en la tabla ASCII, salvo '&' y '|'
    for (size_t i = 0; i < msg_len; i++) {
        unsigned char ch = (unsigned char)msg[i];
        if (ch < ' ' || ch > '}' || ch == '&' || ch == '|') return 408; // Invalid Chars on Message
    }

    return 200;
}
