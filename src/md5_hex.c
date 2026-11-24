#include "md5_hex.h"

#include "md5.h" // Implementación de MD5 provista por la cátedra

//Es la funcion que usamos para firmar durante todo el programa
void md5_hex(const char *data, size_t len, char hex[33]) {
    uint8_t digest[16] = { 0 }; //poenmos todos los elementos en 0 por si llegara a fallar MD5, para q no quede con basura
    md5((const uint8_t *)data, len, digest); //cast necesario por la firma de MD5 (basicmanete son los mismos chars pero ahora en bytes)
    //Para este ounto, "digest" tiene el MD5 en binario

    //Convetimos a hexadecimal:
    // El digesto son 16 bytes: 2 dígitos hexadecimales en minúscula por byte (porq 1 byte son 8 bits, y un digito hexa son 4 bits)
    static const char digitos[] = "0123456789abcdef"; //sirve como tabal de traduccion -> indica el caracter q corresponde a cada valor de 0 a 15 en hexa (esta en minuscula porq lo pide la cosnigna)
    for (int j = 0; j < 16; j++) { //recorre los 16 bytes del digesto
        //Por cada byte j, escribimos 2 caracteres
        hex[2 * j] = digitos[digest[j] >> 4]; //el primer caracter del byte (son los 4 bits de mas significantes) se escribe en las posiciones 0 y 1
        hex[2 * j + 1] = digitos[digest[j] & 0x0f]; //el segundo caracter (son los 4 bits menos signficativos)

        //Ej: 
            // byte 0 -> se escribe en las posiciones 0 y 1
            // byte 1 -> se escribe en las posiciones 2 y 3

    }//asi hasta completar los 32 caracteres

    //Lo ponemos justo depues del ultimo caracter, asi "hex" es un strign valido
    hex[32] = '\0';
}