#include "md5.h"

//Codigo de la catedra!!!

//Implementa el algoritmo de MD5, el cual genera parte de lo q necesitamos para generar la firma para ocultar el secreto
//entre intercambios de emnsjaes a traves de la red

/**
 * Computes the MD5 hash of a given message --> es una funcion de hash
 * * @param initial_msg Pointer to the input data --> el mensaje a procesar visto como bytes
 * @param initial_len Length of the input data in bytes.
 * @param digest      Pointer to a 16-byte array where the hash will be stored --> quien llama tiene que pasar un lugar de al menos 16 bytes (en "md5_hex" es unit8_t digest[16])
 */

//No devuelve nada porq el resultado lo escribe en "digest"
void md5(const uint8_t *initial_msg, size_t initial_len, uint8_t *digest) {
    // 1. Initialize variables (MD5 buffer)
    //Estas variables de 32 vits son el estado del MD5, que al final van a ser el digesto/hash
    //Estos valores fijos estan definidos por el estandar de RFC, aunq hay un patron:
    uint32_t h0 = 0x67452301; //es 01 23 45 67 escrito al reves
    uint32_t h1 = 0xefcdab89; //es 89 ab cd ef al reves
    uint32_t h2 = 0x98badcfe;
    uint32_t h3 = 0x10325476;

    // Pre-calculated per-round shift amounts
    //Es una tabla de 64 numeros, los cuales indican cuantos lugares rotar en
    //cada una de las 64 operaciones del algoritmo 
    //Tiene 4 filas, una por cada ronda, con 16 operaciones por fila
    //Es "const" para que nunca cambien --> asegura reproducibilidad
    const uint32_t r[] = {
        7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, //ronda 1
        5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20, //ronda 2
        4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, //ronda 3
        6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21 //ronda 4
    };

    // Pre-calculated sine constants
    //Otra tabla de 64 constantes y, de nuevo, una por operacion
    //Cada valor se calculo haciendo k[i] = parte entera de |sen(i + 1)| x 2^(32)
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



    // 2. Padding the message --> relleno para el mensaje!
    // Message length must be congruent to 448 (mod 512) bits, which means 56 (mod 64) bytes.
    //MD5 procesa el mensaje en bloques de exactamente 64 bytes, asi que primero hay que agrandarlo 
    //hasta un muliplo de 64:
        //1. Agregar un byte 0x80 (= 10000000)
        //2. Agregar 0s hasta que falten exactamente 8 bytes para el proximo multiplo de 64
        //3. En esos ultimos 8 bytes hay que escribir el largo original del mensaje en bits
    size_t new_len = ((((initial_len + 8) / 64) + 1) * 64); //Calcula el tamaño final con relleno incluido = mensaje + 1 byte de 0x80 + 8 bytes para el largo = initial_length + 9 bytes, redondeado para arriba para multiplo de 64
    uint8_t *msg = calloc(new_len, 1); // calloc pads with zeros automatically --> memoria dinamica porq no se sbae de antemano el tamaño del mensaje q nos llegara
    if (msg == NULL) { //En el caso de que no haya memoria disponibel 
        fprintf(stderr, "Memory allocation failed\n");
        return; //digest no se llena
    }
    
    memcpy(msg, initial_msg, initial_len); //copia el mensaje original al principio del luga reservado
    msg[initial_len] = 0x80; // Append the "1" bit (which is 10000000 in binary, or 0x80) justo despues del mensaje

    // Append original length in bits as a 64-bit little-endian integer
    uint64_t bits_len = (uint64_t)initial_len * 8; //calculamos el tamaño original del emnsaje ne bits
    for (int i = 0; i < 8; i++) {  //y escribimos, de un byte a la vez, ese tamaño calculado en los ultimos 8 bytes (como explicamos arriba)
        msg[new_len - 8 + i] = (uint8_t)(bits_len >> (i * 8)); //el cast (uint8_t) a un byte se queda solo con los 8 bits menos significantes y descarta el resto (asi se va escribiendo en Little endian: 0xE0 -> E0 00 00 00 ...)
    }

    // 3. Processing the message in 512-bit (64-byte) chunks
    //Procesamos cada bloque de 64 bytes (recorre el mensaje rellenado de a 64 bytes)
    for (size_t offset = 0; offset < new_len; offset += 64) {
        // Break chunk (64 bytes) into sixteen 32-bit little-endian words (cada word es de 4 bytes)
        //Cada word se arma juntadno 4 bytes consecutivos, tambien en little endian
        uint32_t w[16];
        for (int i = 0; i < 16; i++) {
            w[i] = (uint32_t)(msg[offset + i * 4]) | //el OR pega cada uno de estos bytes que se estan calculando, uno al aldo del otro sin pisarse
                   ((uint32_t)(msg[offset + i * 4 + 1]) << 8) |
                   ((uint32_t)(msg[offset + i * 4 + 2]) << 16) |
                   ((uint32_t)(msg[offset + i * 4 + 3]) << 24);

            //ej: los 4 bytes son: 67 72 75 70
            //entocnes queda:
            //   0x00000067     (1er byte, sin correr)
            // | 0x00007200     (2º byte << 8)
            // | 0x00750000     (3º byte << 16)
            // | 0x70000000     (4º byte << 24)
            // = 0x70757267
        }

        //Copiamos el estado actual a estas 4 variables:
        uint32_t a = h0;
        uint32_t b = h1;
        uint32_t c = h2;
        uint32_t d = h3;

        // 4. Main loop (64 operations per chunk)
        //64 operaciones, divididas en 4 rondas de 16
        //En cada operacion se calculan 2 cosas:
            //1. f --> una combinacion de bits de b, c y d (la formula cambia segun la ronda)
            //2. g --> cual de las 16 palabras w se usa en esta operacion (el orden en que se recorren tambien cada segun la ronda)
        for (uint32_t i = 0; i < 64; i++) {
            uint32_t f, g;

            if (i < 16) { //Ronda 1 (operaciones 0 a 15)
                f = (b & c) | ((~b) & d);
                g = i; //es la unica ronda en la que las palabras se usan en orden (0, 2, 3, ..., 15). En el resto de las rondas se mezclan
            } else if (i < 32) { //Ronda 2 (operaciones 16 a 31)
                f = (d & b) | ((~d) & c);
                g = (5 * i + 1) % 16;
            } else if (i < 48) { //Ronda 3 (operaciones 32 a 47)
                f = b ^ c ^ d;
                g = (3 * i + 5) % 16;
            } else { //Ronda 4 (operaciones 48 a 63)
                f = c ^ (b | (~d));
                g = (7 * i) % 16;
            }
            //De esta forma, cada palabra del mensaje se usa 4 eces (una por ronda), en ordenes 
            //distintos, y cada byte del mensjae termina afectando a todo el resultado


            //Este siguiente paso se repite 64 veces:
                //1. Suma a + f + k[i] + w[g]: el estado, la combinacion de bits, la constante de esta vuelta y la palabra del mensaje
                //2. Rota esa suma r[i] lugares con LEFTROTATE
                //3. Le suma b, y eso pasa a ser el nuevo b
                //4. Las otras variables “rotan de lugar”: el d viejo pasa a a, el c viejo a d, y el b viejo a c
                    //Obs: se usa temp para no perder el valor de d antes de pisarlo
            uint32_t temp = d;
            d = c;
            c = b;
            b = b + LEFTROTATE((a + f + k[i] + w[g]), r[i]);
            a = temp;
        }
        //Al terminar las 64 vueltas de un bloque, suma el resultado al estado. Si hay otro bloque, arranca de este estado nuevo. 
        //Asi, cada bloque modifica lo que dejo el anterior, y el resultado final depende de todo el mensaje
        h0 += a;
        h1 += b;
        h2 += c;
        h3 += d;
    }

    free(msg); // Clean up dynamically allocated memory (porq ya se proceso todo el mensaje)

    // 5. Build final output (little-endian conversion)
    //Convierte los 4 numeros de 32 bits en 16 bytes y los escribe en digest:
    uint32_t hash_state[4] = {h0, h1, h2, h3}; //Pone h0 a h3 en un arreglo, para recorrerlos con el for 
    for (int i = 0; i < 4; i++) {
        //Cada numero se parte en 4 bytes, otra vez en little-endian: primero el byte de mas abajo (sin correr), despues el siguiente (>> 8), y asi. 
        //El cast (uint8_t) se queda con los 8 bits de abajo, igual que en el padding.
        digest[i * 4]     = (uint8_t)(hash_state[i]);
        digest[i * 4 + 1] = (uint8_t)(hash_state[i] >> 8);
        digest[i * 4 + 2] = (uint8_t)(hash_state[i] >> 16);
        digest[i * 4 + 3] = (uint8_t)(hash_state[i] >> 24);
    }

    //Es la operacion inversa a la de armar las palabras w: ahi se juntaban 4 bytes en un numero, y aca se parte un numero en 4 bytes
    //Con esto, digest tiene los 16 bytes del MD5. Lo que sigue es md5_hex, que los convierte en los 32 caracteres hexadecimales que pide la consigna
}

