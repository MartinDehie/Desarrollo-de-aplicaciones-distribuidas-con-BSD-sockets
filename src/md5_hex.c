#include "md5_hex.h"

#include "md5.h" // Implementación de MD5 provista por la cátedra

void md5_hex(const char *data, size_t len, char hex[33]) {
    uint8_t digest[16] = { 0 };
    md5((const uint8_t *)data, len, digest);

    // El digesto son 16 bytes: 2 dígitos hexadecimales en minúscula por byte
    static const char digitos[] = "0123456789abcdef";
    for (int j = 0; j < 16; j++) {
        hex[2 * j] = digitos[digest[j] >> 4];
        hex[2 * j + 1] = digitos[digest[j] & 0x0f];
    }
    hex[32] = '\0';
}