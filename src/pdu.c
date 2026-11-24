#include "pdu.h"

#include <string.h> //para memchr

//Definimos los limites establecidos por la consigna:
#define TS_MAX 11 //largo maximo del timestamp (11 caraceteres)
#define MSG_MAX 100 //largo maximo del mensaje (100 caracteres)
#define VENCIMIENTO 300 //antiguedad maxima del timestamp (300 segundos)

int validar_pdu(const char *pdu, size_t len, time_t hora_actual) {
    //1. Separamos los dos campos
    const char *amp = memchr(pdu, '&', len); //busca algo (en este caso el &) entre los bytes indicados, y devuelve donde se encuentra
    //Decision nuetsra: cortar en el primer & encontrado
    if (amp == NULL) return 400; // Bad Request: no hay 2 campos

    //2. Ahora armamos dos "vistas" de la PDU (una por campo, y no son copias, sino q apuntan a la PDU original)
    const char *ts = pdu; //timestamp
    size_t ts_len = (size_t)(amp - pdu); 
    const char *msg = amp + 1;
    size_t msg_len = len - ts_len - 1; //-1 por el &

    //3. Revisamos el timestamp
    if (ts_len == 0) return 400; // Bad Request: timestamp vacío
    //tiene algo q no es un digito q este entre 0 y 9:
    for (size_t i = 0; i < ts_len; i++) {if (ts[i] < '0' || ts[i] > '9') return 405;} // Invalid Timestamp
    //tiene mas de 11 caracteres:
    if (ts_len > TS_MAX) return 407; // Timestamp Too Long

    //Ahora convertimos el timestamp de texto a numero para poder comprarlo con la hora actual:
    long long t = 0; // El timestamp puede tener hasta 11 dígitos, no entra en un int
    for (size_t i = 0; i < ts_len; i++) {
        t = t * 10 + (ts[i] - '0');
    }
    if ((long long)hora_actual - t > VENCIMIENTO) return 406; // Expired Timestamp

    //4. Revisaos el mensaje
    if (msg_len == 0) return 409; // Message Empty
    if (msg_len > MSG_MAX) return 410; // Message Too Long (tiene mas de 100 caracetres)

    // Solo se permiten los caracteres que van del espacio a '}' en la tabla ASCII, salvo '&' y '|'
    for (size_t i = 0; i < msg_len; i++) {
        unsigned char ch = (unsigned char)msg[i]; //guarda el caracter como byte sin signo (asi cada byte vale lo q tiene q valer y se pueden hacer las comapraciones)
        if (ch < ' ' || ch > '}' || ch == '&' || ch == '|') return 408; // Invalid Chars on Message
    }

    return 200;
}
