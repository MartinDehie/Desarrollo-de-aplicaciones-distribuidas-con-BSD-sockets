#include <stdio.h> //para el fprintf y stderr
#include <stdlib.h> //para el calloc y free
#include <string.h> //para memcpy
#include <stdint.h> //para los tamaños exactos (ej: uint8_t, uint32_t, uint64_t) --> importante porq garantizan el mismo tamaño en cualquier maquina

//Codigo de la catedra!!!

// Macro to perform a left circular shift --> corre los bits c lugares a la izquierda, pero los que se caen por la izquierda vuelven a entrar por la derecha
//Un corrimiento común (<<) pierde bits. La rotación no pierde ninguno: los bits dan la vuelta
//Ej: x = 1011 0001, rotar 3 lugares:
//  x << 3       = 1000 1000   (los 3 bits de la izquierda, "101", se perdieron)
//  x >> (8-3)   = 0000 0101   (aca estan esos 3 bits, ahora a la derecha)
//donde se escriba en el codigo "LEFTROTATE(algo, n)", se va a reemplzar con esta formula de abajo
#define LEFTROTATE(x, c) (((x) << (c)) | ((x) >> (32 - (c))))

void md5(const uint8_t *initial_msg, size_t initial_len, uint8_t *digest);

//Obs: le falta el "#ifndef MD5_H ... #endif" que tienen todos nuestros .h (sirve para q no se incluya 2 veces)
//No lo tocamos porq es codigo de la catedra y porq como solo lo incluimos una vez en "md5_hex.c" no hay problema