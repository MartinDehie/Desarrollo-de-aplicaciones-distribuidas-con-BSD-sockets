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

