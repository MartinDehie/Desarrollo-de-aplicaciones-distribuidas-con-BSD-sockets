#include "framing.h"

#include <string.h>

int framer_agregar(struct framer *f, const char *datos, size_t cant_bytes) {
    // No entran en lo que queda libre del buffer
    if (cant_bytes > FRAMER_CAPACIDAD - f->len) return -1;

    memcpy(f->buffer + f->len, datos, cant_bytes);
    f->len += cant_bytes;
    return 0;
}

int framer_siguiente(struct framer *f, char *pdu, size_t *len) {
    // Buscamos el \r\n byte a byte porque el buffer no termina en '\0' (no sirve strstr)
    for (size_t i = 0; i + 1 < f->len; i++) {
        if (f->buffer[i] != '\r' || f->buffer[i + 1] != '\n') continue;

        memcpy(pdu, f->buffer, i);
        pdu[i] = '\0';
        *len = i;

        // Corremos al principio lo que había después del \r\n (memmove porque las zonas se superponen)
        f->len -= i + 2;
        memmove(f->buffer, f->buffer + i + 2, f->len);
        return 1;
    }
    return 0;
}
