# TP D: Desarrollo de aplicaciones distribuidas con BSD sockets

UdeSA - i310 Redes y Comunicación


## Compilación primera parte

checkpoint/

make

Genera el ejecutable `cliente`. 

./cliente

## Archivo de credenciales

El programa lee las credenciales de `usr_sig.txt`, en el directorio desde el
que se ejecuta. Tiene 3 líneas:

<IP del servidor>
<usuario>
<secreto>

## Compilacion TP completo (segunda parte)

final/

make

Genera el ejecutable `cliente`.

./cliente

Usa el mismo archivo de credenciales `usr_sig.txt` (mirar arriba). 

Ademas de autentificarse (primera parte), el cliente se coencta por TCP al puerto recibido, delimita las pdus que envia el servidor (framing por \r\n), las valida y las reenvia firmadas por UDP. Las PDUs que contienen `|` y los bytes finales sin \r\n no se reenvian.

Archivos agregados en `final/` respecto de `checkpoint/`:
- `framing.c/.h`: delimitacion de PDUs sobre el stream TCP
- `pdu.c/.h`: validacion de cada PDU y calculo del codigo de parseo
