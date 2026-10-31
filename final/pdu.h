#ifndef PDU_H
#define PDU_H
#include <stddef.h>
#include <time.h>

/*Valida una PDU ya delimitada (sin el \r\n) de "len" bytes para chequear si el timestamp esta vencido
Devuelve el PARSE_CODE: 200, 400, 405, 406, 407, 408, 409 o 410*/
int validar_pdu(const char *pdu, size_t len, time_t hora_actual);

#endif