#include "md5.h"

/**
 * Computes the MD5 hash of a given message.
 * * @param initial_msg Pointer to the input data.
 * @param initial_len Length of the input data in bytes.
 * @param digest      Pointer to a 16-byte array where the hash will be stored.
 */
void md5(const uint8_t *initial_msg, size_t initial_len, uint8_t *digest) {
    // 1. Initialize variables (MD5 buffer)
    uint32_t h0 = 0x67452301;
    uint32_t h1 = 0xefcdab89;
    uint32_t h2 = 0x98badcfe;
    uint32_t h3 = 0x10325476;

    // Pre-calculated per-round shift amounts
    const uint32_t r[] = {
        7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
        5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20,
        4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
        6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21
    };

    // Pre-calculated sine constants
    const uint32_t k[] = {
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

    // 2. Padding the message
    // Message length must be congruent to 448 (mod 512) bits, which means 56 (mod 64) bytes.
    size_t new_len = ((((initial_len + 8) / 64) + 1) * 64);
    uint8_t *msg = calloc(new_len, 1); // calloc pads with zeros automatically
    if (msg == NULL) {
        fprintf(stderr, "Memory allocation failed\n");
        return;
    }
    
    memcpy(msg, initial_msg, initial_len);
    msg[initial_len] = 0x80; // Append the "1" bit (which is 10000000 in binary, or 0x80)

    // Append original length in bits as a 64-bit little-endian integer
    uint64_t bits_len = (uint64_t)initial_len * 8;
    for (int i = 0; i < 8; i++) {
        msg[new_len - 8 + i] = (uint8_t)(bits_len >> (i * 8));
    }

    // 3. Processing the message in 512-bit (64-byte) chunks
    for (size_t offset = 0; offset < new_len; offset += 64) {
        // Break chunk into sixteen 32-bit little-endian words
        uint32_t w[16];
        for (int i = 0; i < 16; i++) {
            w[i] = (uint32_t)(msg[offset + i * 4]) |
                   ((uint32_t)(msg[offset + i * 4 + 1]) << 8) |
                   ((uint32_t)(msg[offset + i * 4 + 2]) << 16) |
                   ((uint32_t)(msg[offset + i * 4 + 3]) << 24);
        }

        uint32_t a = h0;
        uint32_t b = h1;
        uint32_t c = h2;
        uint32_t d = h3;

        // 4. Main loop (64 operations per chunk)
        for (uint32_t i = 0; i < 64; i++) {
            uint32_t f, g;

            if (i < 16) {
                f = (b & c) | ((~b) & d);
                g = i;
            } else if (i < 32) {
                f = (d & b) | ((~d) & c);
                g = (5 * i + 1) % 16;
            } else if (i < 48) {
                f = b ^ c ^ d;
                g = (3 * i + 5) % 16;
            } else {
                f = c ^ (b | (~d));
                g = (7 * i) % 16;
            }

            uint32_t temp = d;
            d = c;
            c = b;
            b = b + LEFTROTATE((a + f + k[i] + w[g]), r[i]);
            a = temp;
        }

        h0 += a;
        h1 += b;
        h2 += c;
        h3 += d;
    }

    free(msg); // Clean up dynamically allocated memory

    // 5. Build final output (little-endian conversion)
    uint32_t hash_state[4] = {h0, h1, h2, h3};
    for (int i = 0; i < 4; i++) {
        digest[i * 4]     = (uint8_t)(hash_state[i]);
        digest[i * 4 + 1] = (uint8_t)(hash_state[i] >> 8);
        digest[i * 4 + 2] = (uint8_t)(hash_state[i] >> 16);
        digest[i * 4 + 3] = (uint8_t)(hash_state[i] >> 24);
    }
}

