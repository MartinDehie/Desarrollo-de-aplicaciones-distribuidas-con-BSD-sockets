#include "forward.h"

#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include "framing.h"
#include "md5_hex.h"
#include "pdu.h"

// Peor caso: usuario (63) + PDU (hasta FRAMER_CAPACIDAD - 2) + pipes, código y secreto o firma (hasta 69) = 4227 
#define MAX_REENVIO (FRAMER_CAPACIDAD + 3 * MAX_CAMPO) //--> = 4288 bytes 

// Escribe <usuario>|<pdu>|<codigo>|<cola> en dst y devuelve el largo.
// La PDU va con memcpy y no con %s porque una PDU inválida puede traer un '\0' en el medio
static size_t armar(char *dst, const char *usuario, const char *pdu, size_t len, int codigo, const char *cola) {
    size_t n = (size_t)sprintf(dst, "%s|", usuario); //escribimos el usuario y el primer pipe en dst
    memcpy(dst + n, pdu, len); //copia la pdu justo depsues de lo anterior
    n += len;
    n += (size_t)sprintf(dst + n, "|%d|%s", codigo, cola); //escribimos el resto: pipe, codigo, pipe y cola
    return n;
}

                      //socket UDP   direccion a donde mandar
static void reenviar_pdu(int s, const struct sockaddr_in *srv, const struct credenciales *c, const char *pdu, size_t len) {
    int codigo = validar_pdu(pdu, len, time(NULL)); //time(NULL) devuelve la hora actual

    // Firmamos con el secreto y mandamos el mismo mensaje con la firma en su lugar
        //aux --> texto con secreto para calcular la firma
        //firma --> 32 caracteres + '/0'
        //msg --> el texto con la firma para mandar
    char aux[MAX_REENVIO], msg[MAX_REENVIO], firma[33];
    //La sigueinte linea hace dos cosas:
        //1. armar(aux, ..., c->secreto) escribe en aux el texto con el secreto, por ejemplo grupo12|1795128626&Primer mensaje|200|33nBsee0, y devuelve su largo
        //2. Ese largo se usa directamente como segundo parametro de md5_hex, que calcula la firma de aux y la deja en firma
    md5_hex(aux, armar(aux, c->usuario, pdu, len, codigo, c->secreto), firma);
    //Ahora armamos el mensaje real, con la firma como cola, y guardamos su lago en n
    size_t n = armar(msg, c->usuario, pdu, len, codigo, firma);

    //Por ultimo, madmaos el datagrama UDP
    if (sendto(s, msg, n, 0, (const struct sockaddr *)srv, sizeof *srv) < 0) perror("sendto");
    else printf(" -> reenviada con codigo %d\n", codigo);
}

int recibir_y_reenviar_pdus(const struct credenciales *c, int puerto) {
    //1. Armamos la direccion TCP del servidor (de aca vamos a recibir las PDUs):
    // La IP ya la validó autenticar, así que no hace falta chequear inet_pton de nuevo
    struct sockaddr_in srv; //estructura para la direccion del servidor para TCP
    memset(&srv, 0, sizeof srv); //ponemos todo lo del struct en cero (nos evitamos basura)
    srv.sin_family = AF_INET; //IPv4
    srv.sin_port = htons(puerto); //el puerto es 30068
    inet_pton(AF_INET, c->servidor, &srv.sin_addr); //IP del servidor (167.114.129.206)

    //2. Creamos el socket TCP y nos conectamos:
    int s_tcp = socket(AF_INET, SOCK_STREAM, 0);
    if (s_tcp < 0) {perror("socket"); return -1;} // Falló la creación del socket TCP

    // Sin timeout recv quedaría bloqueado si el servidor deja de mandar sin cerrar la conexión. Por eso le ponemos un timeout de 10s
    struct timeval tv = {TIMEOUT_SEG, 0}; //establecemos un timeout de 10 seg para cada recv
    setsockopt(s_tcp, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);

    // No se pudo conectar (por ejemplo, porque pasaron más de 10 s y el servidor cerró el puerto)
    if (connect(s_tcp, (struct sockaddr *)&srv, sizeof srv) < 0) { //connect hace el 3way Handshake
        perror("connect");
        close(s_tcp);
        return -1;
    }
    printf("Conectado por TCP al puerto %d\n", puerto);


    //4. Creamos el socket UDP para los reenvios
    int s_udp = socket(AF_INET, SOCK_DGRAM, 0);
    if (s_udp < 0) {perror("socket"); close(s_tcp); return -1;} // Falló la creación del socket UDP --> tambien se cierra el TCP que ya estaba abierto

    // Los reenvíos van a la misma IP, pero al puerto UDP
    struct sockaddr_in srv_udp = srv; //Copia la estrucutra entera que habia definida para el de TCP, para luego (linea sig) cambiarle solo el puerto (al de UDP)
    srv_udp.sin_port = htons(PUERTO_UDP); //= 20262


    //5. Preparamos el framer
    struct framer f;
    f.len = 0;
    //datos --> donde recv deha lo q llega en cada llamda (hasta 1024 bytes por vez)
    //pdu --> donde "framer_siguiente" deja cada PDU
    char datos[1024], pdu[FRAMER_CAPACIDAD];
    size_t len; //el largo de cada PDU
    int cant = 0; //cuantas PDU recibimos en total

    //6. Establecemos el loop de recepcion:
    while (1) { // Recibimos hasta que el servidor cierre la conexión, haya un error o pasen 10 s sin datos
        ssize_t n = recv(s_tcp, datos, sizeof datos, 0); //recibe hasta 1024 bytes (q pueden ser una, mitad o varias PDUs)
        if (n < 0) {perror("recv"); break;} // Error o timeout
        if (n == 0) break;                    // El servidor cerró la conexión

        //Dentro del if agregamos los bytes al framer
        // Se acumularon FRAMER_CAPACIDAD bytes sin \r\n: eso no es una PDU, lo descartamos
        if (framer_agregar(&f, datos, (size_t)n) < 0) { //cuando devuelve -1 es que no entraron los nuevos bytes por completo en el framer
            fprintf(stderr, "Se descartan %zu bytes sin \\r\\n\n", f.len);
            f.len = 0; //vaciamos el framer
            framer_agregar(&f, datos, (size_t)n); //agrega los nuevos bytes recibidos
        }

        // Un mismo recv puede completar varias PDUs, entonces sacamos todas las completadas hasta el meomento:
        while (framer_siguiente(&f, pdu, &len)) { //cuando no hay mas completas, devuelve 0
            cant++;
            printf("PDU %d (%zu bytes): %s\n", cant, len, pdu);

            // Con '|' rompería el formato del reenvío, y la consigna pide no mandarla
            if (memchr(pdu, '|', len) != NULL) {
                printf(" -> no se reenvia porque tiene |\n");
                continue;
            }

            //Si no tiene '|', la valida, la firma y la manda
            reenviar_pdu(s_udp, &srv_udp, c, pdu, len);
        }
    }

    close(s_tcp); //este manda el FIN del cliente
    close(s_udp);

    // Lo que quedó sin \r\n no es una PDU delimitada, así que no se reenvía
    if (f.len > 0) printf("Descartamos %zu bytes finales sin \\r\\n\n", f.len);
    printf("Conexion TCP cerrada.\nPDUs recibidas: %d\n", cant);
    return 0;
}
