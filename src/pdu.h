#ifndef PDU_H
#define PDU_H

#include <stddef.h> //para size_t
#include <time.h> //para time_t

/*
  Valida una PDU ya delimitada, sin el \r\n, con el formato <TIMESTAMP>&<MESSAGE> y devuelve su código de parseo: 200, 400 o 405 a 410.
  Recibe len y no usa strlen porque una PDU inválida puede traer un byte 0x00, que tiene que contar como carácter inválido (408) y no cortar la PDU.
 
  Decisiones donde la consigna no es explícita (justificadas en el informe):
   - Se corta en el primer '&'. Un '&' de más cae dentro del mensaje y da 408.
   - Sin '&' (no hay 2 campos) o con el timestamp vacío: 400.
   - Timestamp: 405 -> 407 -> 406. Si tiene caracteres inválidos no tiene sentido medir su largo, y si es demasiado largo no tiene sentido interpretarlo como hora.
   - Mensaje: 409 -> 410 -> 408.
   - "Más de 300 segundos" es estricto: 300 s exactos todavía es 200. Un timestamp en el futuro no está vencido, así que también es 200.
*/
int validar_pdu(const char *pdu, size_t len, time_t hora_actual);
#endif
