#include "http_ip.h"

#include <arpa/inet.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#define API_HOST "api.ipify.org" //es el servidor al que le pregutnamos por nuestra IP publica (traducc q hace el router al salir a Internet)
#define TIMEOUT_SEG 5 //es el max timepo de espera para "ipify"  --> diferente del que esta definido en "credentials.h" (ese vale 10s y lo pide la consigna)

static int conectar_api(void) {
    struct addrinfo hints, *res; //filtro para DNS (TCP y IPv4 --> lo definimos abajo)
    memset(&hints, 0, sizeof hints); //para que no haya basura en hints (porq o sino se interpreta como codigo erroneo)
    hints.ai_family = AF_INET; // IPv4: el servidor de la cátedra valida una IPv4 (entonces para que ipify nos de IPv4, nos conectamos a el por ese tipo)
    hints.ai_socktype = SOCK_STREAM; // TCP 

    // Resolución DNS del nombre
    int err = getaddrinfo(API_HOST, "80", &hints, &res); //como un nombre puede tener varias IPs, devuelve una lista enlzada de struct addrinfo
    if (err != 0) {
        fprintf(stderr, "getaddrinfo(%s): %s\n", API_HOST, gai_strerror(err)); //gai traduce el codigo de error a texto con su significado
        return -1;
    }

                             //IPv4             TCP         6 (num de protcolo de TCP)
    //sockett es un file descriptor (es el ID del socket para darselo a las otras funciones)
    int sockett = socket(res->ai_family, res->ai_socktype, res->ai_protocol); //crea el socket con el primer resultado de la lista
    //IMPORTANTE: aunq el DNS devuelva muchas IPs, nosotros decidimos solo probar la coenxion con la primera de la lista, porque
    //todas las IPs vienen del mismo proveedor (cloudfare), entonces si falla, fallan todas

    if (sockett < 0) {perror("socket"); freeaddrinfo(res); return -1;} // Falló la creación del socket

    // Para no quedar colgados si la API no responde. En Linux, SO_SNDTIMEO también limita a connect
    struct timeval tv = {TIMEOUT_SEG, 0};
                //opcion general    que cambiar  new value
    setsockopt(sockett, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv); //(receive timeout) por si un recv espera mas de 5s sin que ipify respondiera
    setsockopt(sockett, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv); //lo mismo para send timeout

    // No se pudo conectar
    // connect hace el 3way handshake de TCP (SYN -> SYN-ACK --> ACK) con el servidor
                      //dir de dest (IP de ipify + port 80) --> como getaddrinfo la armo, no hace falta htons ni inte_pton (eso para cuando se arma manualmente)
    if (connect(sockett, res->ai_addr, res->ai_addrlen) < 0) {
        perror("connect");
        close(sockett);
        sockett = -1;
    }
    freeaddrinfo(res); //conectado el socket o no, necesitamos liberar la lista que get hizo antes
    return sockett; //0 si el socket se conecto
}

// TCP es un stream: la respuesta de ipify puede llegar repartida en varios recv, así que leemos hasta que el servidor cierra (cierra
//gracias a que pedimos el GET con HTTP/1.0)
static int recibir_todo(int s, char *buf, size_t cap) {
    size_t total = 0; //tmb como guia para saber donde escribir lo proximo q llega (offset para el puntero)
    while (total < cap - 1) { //"cap - 1" y no "cap" porque hay que reservar un lugar al final para el "\0" que agregamos mas adelante 
                      //socket del q recibe los datos
        ssize_t n = recv(s, buf + total, cap - 1 - total, 0); //0 para indicar q no hay opciones especiales
        if (n < 0) {perror("recv"); return -1;} // Error o timeout
        if (n == 0) break; // El servidor cerró la conexión
        
        total += (size_t)n; //cast para evitar warnings (y no pasa nada porq a esta altura ya sabemos q es positivo)
    }
    buf[total] = '\0'; //necesario para que "buf" sea un string valido 
    return 0;
}

                                // = INET_ADDRSTRLEN = 16
int obtener_ip_publica(char *ip, size_t ip_len) {
    //1. Nos conectamos (DNS + socket + handshake)
    int s = conectar_api();
    if (s < 0) return -1;

    //2. Armamos el pedido HTTP
    // HTTP/1.0 para que el servidor cierre la conexión al terminar (así sabemos dónde termina la respuesta)
    const char *pedido = "GET / HTTP/1.0\r\nHost: " API_HOST "\r\n\r\n"; //IMP: es el pedido HTTP a mano q pide la consigna
    //Queda asi cuando se compila: "GET / HTTP/1.0\r\nHost: api.ipify.org\r\n\r\n"
    //Sin el ultimo par "\r\n" el servidor se quedaria esperando a mas headers
    char resp[4096]; //donde de va a guardar la respuesta de ipify (sobra lugar)

    //3. Mandamos el pedido y recibimos la respuesta
    // send puede mandar menos bytes de los pedidos: con 40 bytes no pasa, pero si pasa lo tomamos como error
    if (send(s, pedido, strlen(pedido), 0) != (ssize_t)strlen(pedido) || recibir_todo(s, resp, sizeof resp) < 0) { //recibimos la rta en "resp"
        fprintf(stderr, "falló la consulta HTTP a %s\n", API_HOST);
        close(s);
        return -1;
    }
    close(s); //Aunq salio todo bien cerramos el socket porq ya tenemos la rta en "resp"

    //4. Encontramos el body de la respuesta
    // Los headers terminan en una línea vacía; después viene el body (la IP)
    char *body = strstr(resp, "\r\n\r\n"); //podemos usar strstr porque en "recibir_todo" ya le pusimos el "\0" a "resp"
    if (body == NULL) {fprintf(stderr, "respuesta HTTP sin body\n"); return -1;} //la rta no tiene el formato q esperabamos
    body += 4; //"body" apunta al comienzo del "\r\n\r\n", entocnes pasamos a apuntar al primer caracter del body

    //5. Recortamos la IP
    // La IP va hasta el primer espacio o salto de línea, y tiene que entrar en ip
    size_t largo = strcspn(body, " \t\r\n"); //cuenta cuantos caracteres hay hasta nates q aparezca alguno de esos indicados
    if (largo >= ip_len) {fprintf(stderr, "body HTTP inválido\n"); return -1;}
    //a donde, desde donde, cunatos bytes
    memcpy(ip, body, largo);
    ip[largo] = '\0'; //para que "ip" sea un stirng valido

    //6. Validamos que sea una IPv4
    // Lo que llegó tiene que ser una IPv4 en Decimal Dot Notation (también descarta un error HTTP o un body vacío)
    struct in_addr tmp;
    if (inet_pton(AF_INET, ip, &tmp) != 1) { //este chequeo que hacemos sirve para comepnsar la falta de chequeo del codigo 200 OK de la rta (que no hacemos)
        fprintf(stderr, "la respuesta no es una IPv4 válida: %s\n", ip);
        return -1;
    }
    return 0;
}
