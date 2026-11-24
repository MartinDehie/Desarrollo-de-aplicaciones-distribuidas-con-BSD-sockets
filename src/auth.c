#include "auth.h"

#include <arpa/inet.h> //inet_pton y htons
#include <errno.h> //errnp, EAGAIN y EWOULDBLOCK --> para saber por q fallo recvfrom
#include <stdio.h> //printf, fprintf, snprintf, perror
#include <stdlib.h> //strtol --> para convertir el texto del puerto a numero
#include <string.h> //strcspn, strcmp, strlen, setsockopt
#include <sys/socket.h> //socket, sendto, recvfrom y setsockopt
#include <sys/time.h> //gettimeofday y struct timeval --> para medir los 10s
#include <unistd.h> //close

#include "md5_hex.h" //para las firmas!!

#define MAX_MSG 512 //tamaño del buffer donde se escribe la rta del servdior (una rta valida mide aprox 50 bytes)
#define FIRMA_ERROR "00000000000000000000000000000000" //la firma de 32 ceros q usa el servidor cuando responde con un error

/*
Provista por la cátedra (codigo_ayuda/test_skip_single.c).
Skip the characters until the SINGLE DELIMITER character is found
0-terminate resulting word
Advance pointer to buffer to the last skipped position + delimiter.
Return found 0-terminated word.
*/
//La rta del servidor es un texto con 4 campos separados por pipes
//Para validarla, hay que separar esos campos
//Esta funcion saca un campo por vez (cada vez q la llamamos, nos devuelve el campo actual y avanza al siguiente)
static char *skip_single(char **buf, const char *delimiters) //los delimiters en este TP son siempre los "|"
{
  //Resumen: avanza hasta encontrar un delimitador, termina la palbra con '/0', deja el 
  //puntero despues del delimitador y devuelve la palabra
  //Devuelve: un puntero al campo encontrado

  //**buf es un puntero a un puntero --> ¿Por q?:
    //Quien llama tiene un puntero (p) que apunta a por donde va dentro del mensaje
    //Esta funcion tiene que mover ese puntero al campo sig, para q la proxima llamda siga desde ahi
    //Para modificar una variable de quien llama, hay q recibir su direccion. Y como la variable es un puntero, su direccion es un puntero a puntero

  char *p, *begin_word, *end_word, *end_delimiters; //helpers

  begin_word = *buf; // = lo que hay en la direccion "buf" = el puntero de quien llama (por donde va) --> el campo empieza aca


  //strcspn cuenta cuantos caracetres hay hasta el primer pipe (largo del campo)
  //Sumado a "begin_word", da un puntero al pipe (donde temrina el campo)
  //Si no hay ningun pipe, strcspn cuenta hasta el final del string, y "end_word" queda apuntando al "\0" del final
  end_word = begin_word + strcspn(begin_word, delimiters);

  // Take only ONE delimiter:
  //Termina apuntadno al comienzo del sig campo
  //Al tomar un solo delimitador, se respetan los campos vacios 
    //Ej: 200||30068 -> el campo del medio sale como un string vacio en vez de saltearse
  end_delimiters = end_word + 1;

  //Como "end_delimiters" es "end_word + 1", el loop da una sola vuelta, y escribe un '\0' donde estaba el pipe
  //Asi el campo queda terminado como string
  //Equivale a: *end_word = '/0'
  for (p = end_word; p < end_delimiters; p++) {
    *p = '\0';
  }

  *buf = end_delimiters; //mueve el puntero de quien llama al campo siguiente

  return begin_word; //devuelve el comienzo del campo (el cual ya termina en '\0')
}

/*
Provista por la cátedra (codigo_ayuda/unixtimestamp.c).
Subtract the `struct timeval' values X and Y, storing the result in RESULT.
Return 1 if the difference is negative, otherwise 0.
From: https://ftp.gnu.org/old-gnu/Manuals/glibc-2.2.5/html_node/Elapsed-Time.html
*/
//Necesaria para calcular los 10s q nos pide la consigna q esperemos al servidor
//Es necesaria etsa funcion porq los tiempos de "limite" y "ahora" estan guardados en una struct timeval
//Y al hacer "limite" - "ahora" tal vez sea necesarios prestarse entre segundos y microsegundos
                                          // = x - y            "limite"           "ahora"
static int timeval_subtract (struct timeval *result, struct timeval *x, struct timeval *y)
{
    // preserve *y
  struct timeval yy = *y;
  y = &yy;

  /* Perform the carry for the later subtraction by updating y. */
  //este es el "pedir prestado" --> pasa cuando los microseg de x son menores q los de y, porq la resta de microseg daria negativa
      //solucion: le saca a "y" microsegundos y le suma segundos
  if (x->tv_usec < y->tv_usec) {
    int nsec = (y->tv_usec - x->tv_usec) / 1000000 + 1; //cuantos segundos hay q pedir prestados
    y->tv_usec -= 1000000 * nsec;
    y->tv_sec += nsec;
  }
  //Este es el caso contrario: si la resta de microsegundos diera mas de un segundo entero
  //Pasa solo si alguno de los tiempos tiene los microseugndos fuera de su rango normal (pero a nosotros con gettimeofday no nos va a pasar)
  //Entonces, en lugar de pedir prestado, se devuelven segundos
  if (x->tv_usec - y->tv_usec > 1000000) {
    int nsec = (x->tv_usec - y->tv_usec) / 1000000;
    y->tv_usec += 1000000 * nsec;
    y->tv_sec -= nsec;
  }

  /* Compute the time remaining to wait.
     tv_usec is certainly positive (gracias al ajuste de arriba). */
  //Se hace la resta cada parte por separado:
  result->tv_sec = x->tv_sec - y->tv_sec;
  result->tv_usec = x->tv_usec - y->tv_usec;

  /* Return 1 if result is negative. */
  return x->tv_sec < y->tv_sec;
  //¿Y si la retsa da excatamente 0? --> devuelve 0 ("no negativa"), pero es un caso aparte q manejamos en "autenticar"
}
 

                        //rta recibida      para recalcular la firma    donde escribir el puerto si la rta es valida
enum resultado procesar_respuesta(char *msg, const char *secreto, int *puerto) {
  //1. Verificamos que hayan al menos 3 pipes:
    // Tienen que estar los 3 pipes que separan <CODE>|<ACTION>|<TEXT>|<SIGNATURE>. Si falta alguno, se descarta.
    // Se cuenta antes porque skip_single no avisa si no encuentra el delimitador: dejaría el puntero pasado el final del string
    int pipes = 0;
    //Entonces recorremos el string con un puntero q, avanzandolo mientras q el caracter actual no sea el final del string ('\0'), contando los pipes
    for (const char *q = msg; *q != '\0'; q++) {if (*q == '|') pipes++;}
    if (pipes < 3) return RESP_INVALIDA;

  //2. Separamos los campos:
    // Cada skip_single pisa un pipe con '\0' y deja p al principio del campo siguiente
    char *p = msg;
    const char *code = skip_single(&p, "|"); //se pasa el puntero con & para q lo vaya moviendo
    const char *action = skip_single(&p, "|");
    const char *text = skip_single(&p, "|");
    const char *firma = p; // Lo que queda después del tercer pipe

  //3. Calculamos la firma esperada:
    // La firma esperada es md5(<CODE>|<ACTION>|<TEXT>|<SECRET>)
            //512          64
    char aux[MAX_MSG + MAX_CAMPO];
           //snprintf arma el texto volviendo a poner los pipes que "skip_single" habia reemplazado por '\0'
    int n = snprintf(aux, sizeof aux, "%s|%s|%s|%s", code, action, text, secreto); //n es el largo del string q armo
    char esperada[33]; //aca se guarda la firma (que se calcula abajo) = 32 caracteres + '\0'
    md5_hex(aux, (size_t)n, esperada);

  //4. Chequeamos la firma:
    // Firma válida: la respuesta viene del servidor. Chequeamos formato: 200|Port|<puerto>
    if (strcmp(firma, esperada) == 0) { //Si se cumple, la rta es autentica (viene del servidor y nadie la modifico)
        if (strcmp(code, "200") != 0 || strcmp(action, "Port") != 0) return RESP_INVALIDA; // No es 200|Port (osea que no hubo exito)
        //Este es un caso raro, porq el servidor firma correctamnete solo las rtas de exito (y si llegamos a este punto
        //signfica q la firma era la correcta), pero por las dudas no lo damos por sentado

        char *fin; //termina sienod un puntero al primer caracter q strtol no pudo converitr y, po lo tanto, dejo de trabajar ahi
                                //base decimal
        long p = strtol(text, &fin, 10); //convierte un texto en un numero
        //este numero p es != del puntero p de arriba, este p es el numero del puerto
        if (*fin != '\0' || p < 1 || p > 65535) return RESP_INVALIDA; // Puerto inválido

        *puerto = (int)p;
        return RESP_PUERTO;
    }
  //5. Si la firma no coincide:
    // Error del servidor (4xx): como no conoce el secreto, firma con 32 "0"
    if (code[0] == '4' && strcmp(firma, FIRMA_ERROR) == 0) {
        fprintf(stderr, "Error del servidor: %s %s\n", code, text);
        return RESP_ERROR; //"auntenticar" DEJA DE ESEPERAR!!
    }

    //"autenticar" sigue esperando
    return RESP_INVALIDA; //la respuesta esta mal firmada o no tiene el formato correcto
}


//Esta es la funcion q encapsula todo lo q hicimos para resolver el primer desafio!!
//puertoTCP  puntero a la struct q lleno "leer_credenciales"       IP q obtuvimos en "obtener_ip_publica"
int autenticar(const struct credenciales *c, const char *ip_publica) {
  //1. Armamos el pedido firmado:
    //aux --> texto con secreto para calcular la firma
    //    --> 256 sobran: usuario (hasta 63) + IP (hasta 15) + secreto o firma (hasta 63) + 2 pipes
    //firma --> 32 caracteres + '/0'
    //pdu --> el pedido real q se manda
    char aux[256], firma[33], pdu[256];

    // Firmamos con el secreto y mandamos el mismo mensaje con la firma en su lugar
    snprintf(aux, sizeof aux, "%s|%s|%s", c->usuario, ip_publica, c->secreto); //arma aux con el formato de la consigna: <USERNAME>|<IPv4ADDRESS>|<SECRET>
    md5_hex(aux, strlen(aux), firma); //calcula la firma con aux
      //se puede usar srlen porq no tiene ningun '\0' en el medio (y eso lo sabemos porq lo armamos nosotros)
    snprintf(pdu, sizeof pdu, "%s|%s|%s", c->usuario, ip_publica, firma); //armamos el pedido real: <USERNAME>|<IPv4ADDRESS>|<FIRMA>

  //2. Armamos la direccion del servidor
    struct sockaddr_in srv; //es una estructura que guarda una direccion IPv4 + un puerto --> aca vamos a enviar el datagrama
    memset(&srv, 0, sizeof srv); //completamso todos sus taributos con cero
    srv.sin_family = AF_INET; //indica que es una direccion IPv4
    srv.sin_port = htons(PUERTO_UDP); //puerto = 20262 (el de la consigna) --> le aplicamos htons apra q este en big endian (como exige la red) (porq MAC y PC lo pone en little endian)

    // La IP del archivo de credenciales no es una IPv4 válida:
    //Lo comprobamos con la funcion "inte_pton", que convierte la IP del servidor de texto a binario y la guarda en srv.sin_addr
    if (inet_pton(AF_INET, c->servidor, &srv.sin_addr) != 1) {
        fprintf(stderr, "IP del servidor inválida: %s\n", c->servidor);
        return -1;
    }

  //3. Creamos el socket y mandamos el pedido:
    int s = socket(AF_INET, SOCK_DGRAM, 0); //el socket es de UDP (el 0 es para indicar q el protocolo sea el default = UDP)
    if (s < 0) {perror("socket"); return -1;} // Falló la creación del socket

    printf("Enviando:  %s\n", pdu);
                                        //puntero generico (acepta IPv4, IPv6, etc)
    if (sendto(s, pdu, strlen(pdu), 0, (struct sockaddr *)&srv, sizeof srv) < 0) {perror("sendto"); close(s); return -1;} // Falló el envío del datagrama

  //4. Fijamos el momento limite de espera para la respeusta (porque UDP no confirma si le llego o no, a diferencia de TCP q si lo hace)
    // Momento en que se terminan los 10 s de espera --> plazo ABSOLUTO! porq no se mueve aunq lleguen respuestas imvalidas
    struct timeval limite;
    gettimeofday(&limite, NULL); //hora actual
    limite.tv_sec += TIMEOUT_SEG; //le sumamos 10s para q se convierta en el real limte de espera

    int puerto = -1; //arranca como error y solo cambia si llega una rta valida 
  
  //5. Esperamos la respuesta
    // Esperamos hasta que llegue una respuesta válida, haya un error o se terminen los 10s
    while (1) {
        struct timeval ahora, resta;
        gettimeofday(&ahora, NULL);

        // resta = limite - ahora es lo que queda de los 10 s (timeval_subtract devuelve 1 si es negativa).
        // También cortamos si da justo 0, porque un SO_RCVTIMEO de 0 significa esperar para siempre
        if (timeval_subtract(&resta, &limite, &ahora) || (resta.tv_sec == 0 && resta.tv_usec == 0)) {
            fprintf(stderr, "Timeout: no llegó una respuesta válida en %d segundos\n", TIMEOUT_SEG);
            break;
        }

        // El timeout de recvfrom es lo que queda de los 10 s 
        setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &resta, sizeof resta); //--> es lo q hace q no nos pasemos de los 10s en total!

        char msg[MAX_MSG];
              //socket   guardar_lo_recibido   max (dejando lugar para el '\0')    opciones=ninguna      donde guardar quien lo mando     el tamaño de eso
        ssize_t n = recvfrom(s, msg, sizeof msg - 1, 0, NULL, NULL); //recibe un datagrama UDP --> n es cuantos bytes q tiene el datgrama (como es mediante UDP, el recfrom recibe un datagrama completo --> no hace falta framming como en TCP)

        // Venció el timeout: volvemos arriba, donde resta ya da negativa o 0
        //"errno" es una variable global donde el sistema deja el codigo del utlimo error
        //Cuando vence el timeout de SO_RCVTIMEO, errno vale EAGAIN o EWOULDBLOCK. Son 2 nombres que significan lo mismo 
        //(“no hay datos, proba de nuevo mas tarde”). Chequeamos los 2 porque, segun el sistema operativo, se usa uno u otro
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) continue;
        
        // Error de recvfrom
        if (n < 0) {perror("recvfrom"); break;}

        msg[n] = '\0'; // lo ponemos despues del ultimo byte recidog (y hay luagr gracias al -1 en recvfrom)
        msg[strcspn(msg, "\r\n")] = '\0'; //La consigna no dice q la rta termine con eso, pero es por las dudas q el servidor lo agregue (asi la firma no falla)

        // Puerto válido o error del servidor: dejamos de esperar. Si es inválida, seguimos
        if (procesar_respuesta(msg, c->secreto, &puerto) != RESP_INVALIDA) break; //--> este es el descarte silencioso q pide la consigna!!
    }

    close(s);
    return puerto;
    //Despues en el main comparamos este valor, y si es -1, el programa se termina. Sino, pasamos al segundo desafio
}