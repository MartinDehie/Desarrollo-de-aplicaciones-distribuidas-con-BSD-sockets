#include "md5.h"

#include <stdint.h>
#include <string.h>

/* Cantidad de bits a rotar en cada una de las 64 operaciones */
static const uint32_t S[64] = {
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
    5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20,
    4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
    6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21
};

/* Constantes de cada operación: K[i] = floor(|sin(i + 1)| * 2^32) */
static const uint32_t K[64] = {
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
    0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
    0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
    0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
    0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
    0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
    0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
    0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
    0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
};

/* Rotación circular a izquierda de 32 bits (n nunca es 0 ni 32) */
static uint32_t rotl(uint32_t x, uint32_t n)
{
    return (x << n) | (x >> (32 - n));
}

/* Procesa un bloque de 64 bytes y actualiza el estado h[4] */
static void md5_bloque(uint32_t h[4], const unsigned char bloque[64])
{
    /* El bloque se interpreta como 16 palabras de 32 bits en little-endian */
    uint32_t M[16];
    for (int i = 0; i < 16; i++) {
        M[i] = (uint32_t)bloque[4 * i]
             | (uint32_t)bloque[4 * i + 1] << 8
             | (uint32_t)bloque[4 * i + 2] << 16
             | (uint32_t)bloque[4 * i + 3] << 24;
    }

    uint32_t a = h[0], b = h[1], c = h[2], d = h[3];

    /* 4 rondas de 16 operaciones; cada ronda usa una función F, G, H o I
     * distinta y recorre las palabras M en un orden distinto (g) */
    for (int i = 0; i < 64; i++) {
        uint32_t f;
        int g;

        if (i < 16) {
            f = (b & c) | (~b & d);
            g = i;
        } else if (i < 32) {
            f = (d & b) | (~d & c);
            g = (5 * i + 1) % 16;
        } else if (i < 48) {
            f = b ^ c ^ d;
            g = (3 * i + 5) % 16;
        } else {
            f = c ^ (b | ~d);
            g = (7 * i) % 16;
        }

        f = f + a + K[i] + M[g];
        a = d;
        d = c;
        c = b;
        b = b + rotl(f, S[i]);
    }

    h[0] += a;
    h[1] += b;
    h[2] += c;
    h[3] += d;
}

void md5_hex(const char *data, size_t len, char hex[33])
{
    const unsigned char *p = (const unsigned char *)data;

    /* Estado inicial definido por el RFC */
    uint32_t h[4] = { 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476 };

    /* Bloques completos de 64 bytes */
    size_t i;
    for (i = 0; i + 64 <= len; i += 64)
        md5_bloque(h, p + i);

    /* Padding: bytes restantes + 0x80 + ceros hasta que la longitud sea
     * 56 mod 64 + longitud original en bits (8 bytes en little-endian).
     * Si al resto no le entran el 0x80 y los 8 bytes, hacen falta 2 bloques. */
    unsigned char ultimo[128] = { 0 };
    size_t resto = len - i;
    memcpy(ultimo, p + i, resto);
    ultimo[resto] = 0x80;

    size_t total = (resto < 56) ? 64 : 128;
    uint64_t bits = (uint64_t)len * 8;
    for (int j = 0; j < 8; j++)
        ultimo[total - 8 + j] = (unsigned char)(bits >> (8 * j));

    md5_bloque(h, ultimo);
    if (total == 128)
        md5_bloque(h, ultimo + 64);

    /* Salida: h[0..3] en little-endian, 2 dígitos hex por byte */
    static const char digitos[] = "0123456789abcdef";
    for (int j = 0; j < 16; j++) {
        unsigned char byte = (unsigned char)(h[j / 4] >> (8 * (j % 4)));
        hex[2 * j] = digitos[byte >> 4];
        hex[2 * j + 1] = digitos[byte & 0x0f];
    }
    hex[32] = '\0';
}
