#include "framing.h"

#include <string.h> //para memcpy y memmove

                                      //los nuevos q acaban de llegar     se pasa su longitud porq los datos de la red no son strings (podrina tener el '\0' en el medio)
int framer_agregar(struct framer *f, const char *datos, size_t cant_bytes) {
    // No entran en lo que queda libre del buffer
    //Obs: no lo escribimos como "f->len + cant_bytes > FRAMER_CAPACIDAD" porq el posible overflow, q diria q si entran cuando en realidad no
    if (cant_bytes > FRAMER_CAPACIDAD - f->len) return -1;

      //direc de la primea posicion libre
    memcpy(f->buffer + f->len, datos, cant_bytes);
    f->len += cant_bytes;
    return 0;
}

int framer_siguiente(struct framer *f, char *pdu, size_t *len) {
    // Buscamos el \r\n byte a byte porque el buffer no termina en '\0' (no sirve strstr)
    for (size_t i = 0; i + 1 < f->len; i++) {
        if (f->buffer[i] != '\r' || f->buffer[i + 1] != '\n') continue;

        //En el caso q si haya un '\r\n' adentro:

        memcpy(pdu, f->buffer, i); //copiamos la PDU (desde el principio del buffer a i - 1) al destino --> el '\r\n' no se copia
        pdu[i] = '\0';
        *len = i;

        // Corremos al principio lo que había después del \r\n (memmove porque las zonas se superponen)
        f->len -= i + 2; //calculamos  cuantos bytes quedan despues de sacar la PDU
              //a donde       desde donde       cuantos bytes
        memmove(f->buffer, f->buffer + i + 2, f->len);
        return 1;
    }
    return 0;
}
