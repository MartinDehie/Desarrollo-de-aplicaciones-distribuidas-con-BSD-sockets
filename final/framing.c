#include "framing.h"
#include <string.h>

void framer_init(struct framer *framer){ framer->len = 0;}

int framer_agregar(struct framer *framer, const char *datos, size_t cant_bytes){
    //Chequeamos que los nuevos datos entren:
    if(cant_bytes > (FRAMER_CAPACIDAD - framer->len)){ return -1;}

    //Copiamos los nuevos bytes despues de los que ya habia
    memcpy(framer->buffer + framer->len, datos, cant_bytes);
    framer->len += cant_bytes;
    return 0;
}

int framer_siguiente(struct framer *framer, char *pdu, size_t *len){
    //Comenzamos buscando el primer \r\n en todo lo que hay acumulado:
    //No nos sirve usar la funcion "strstr" porque el buffer no temrina en '\0'
    //Ademas de que el /r y el /n pueden haber llegado en recv diferentes
    for(size_t indx = 0; indx + 1 < framer->len; indx++){
        if((framer->buffer[indx] == '\r') &&(framer->buffer[indx + 1] == '\n')){
            //La PDU son los bytes anteriores al \r\n (indx - 1) + el '0'
            memcpy(pdu,framer->buffer, indx);
            pdu[indx] = '\0';
            *len = indx;
            //Y ahora corremos al principio del buffer lo que habia despues del \r\n:
            size_t bytes_restantes = framer->len - (indx + 2);
            memmove(framer->buffer, framer->buffer + indx + 2, bytes_restantes);
            framer->len = bytes_restantes;

            return 1;
        }
    }

    return 0;
}

