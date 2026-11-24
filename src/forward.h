#ifndef FORWARD_H
#define FORWARD_H

#include "credentials.h" //para struct credenciales, PUERTO_UDP, TIMEOUT_SEG y MAX_CAMPO

/*
Segundo desafío.
Se conecta por TCP al puerto que devolvió autenticar, delimita las PDUs del stream con un framer, las valida con
validar_pdu y reenvía cada una por UDP al puerto PUERTO_UDP del servidor con el formato
<USERNAME>|<PDU>|<PARSE_CODE>|md5(<USERNAME>|<PDU>|<PARSE_CODE>|<SECRET>).
No reenvía las PDUs que contienen '|' (romperían el formato del reenvío) ni los bytes que quedan sin \r\n al cerrarse
la conexión. Si se acumulan FRAMER_CAPACIDAD bytes sin \r\n, los descarta.
Termina cuando el servidor cierra la conexión o cuando pasan TIMEOUT_SEG segundos sin datos.

Devuelve 0, o -1 si no se pudo establecer la conexión.
*/
int recibir_y_reenviar_pdus(const struct credenciales *c, int puerto);

#endif
