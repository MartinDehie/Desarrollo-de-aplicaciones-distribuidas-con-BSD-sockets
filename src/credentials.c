#include "credentials.h"

#include <stdio.h>
#include <string.h>

// Leemos en un buffer grande y no directo en dst: si la línea ocupara justo cap - 1
// caracteres, fgets dejaría el '\n' sin leer y la próxima línea saldría vacía
static int leer_linea(FILE *f, char *dst, size_t cap) { //f es "usr_sig.txt"
    char linea[256];

    // Se terminó el archivo antes de tiempo
    if (fgets(linea, sizeof linea, f) == NULL) return -1; //lee hasta el salto de linea incluido (por eso luego hay q sacarlo)

    // Cortamos en el primer \r o \n
    linea[strcspn(linea, "\r\n")] = '\0'; 

    size_t largo = strlen(linea);

    // Línea vacía o que no entra en dst junto con su '\0'
    if (largo == 0 || largo >= cap) return -1;

    memcpy(dst, linea, largo + 1);
    return 0;
}

int leer_credenciales(const char *ruta, struct credenciales *c) { 
    FILE *f = fopen(ruta, "r");

    // No existe el archivo o no se puede leer
    if (f == NULL) {
        perror(ruta);
        return -1;
    }

    //Validamos las cedenciales si hay 3 lineas no vacias y que entren en su campo 
    int ok = leer_linea(f, c->servidor, sizeof c->servidor) == 0 &&
             leer_linea(f, c->usuario, sizeof c->usuario) == 0 &&
             leer_linea(f, c->secreto, sizeof c->secreto) == 0;
    fclose(f);

    // Alguna de las 3 líneas faltó o era inválida
    if (!ok) {
        fprintf(stderr, "%s: se esperan 3 líneas (IP del servidor, usuario, secreto)\n", ruta);
        return -1;
    }

    return 0;
}
