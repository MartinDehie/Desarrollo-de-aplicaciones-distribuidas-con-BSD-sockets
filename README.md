# TPD: Desarrollo de aplicaciones distribuidas con BSD sockets

i310 Redes y Comunicacion — Universidad de San Andres

Grupo 12 (usuario `grupo12`): Martín De Hie, Maximo Barral, Sol Garcia Pereyra

Cliente que resuelve los 2 desafios del TP contra el servidor de la catedra:

1. **Autenticacion**: obtiene la IP publica con un pedido HTTP escrito a mano, se autentica por UDP con una firma MD5
   y recibe un puerto TCP
2. **Framing y reenvio**: se conecta a ese puerto, delimita las PDUs que llegan por el stream TCP, las valida y
   reenvia cada una firmada por UDP con su codigo de parseo.

El detalle de la implementacion, las pruebas y las respuestas a las preguntas estan en `informe/informe.pdf`.

## Requisitos

- Linux o macOS
- `gcc` y `make`

## Compilacion

Desde la raiz del repositorio:

```
make
```

Genera el ejecutable `cliente` en la raíz. Compila sin warnings con `-Wall -Wextra`.

Para borrar los archivos generados:

```
make clean
```

## Archivo de credenciales

El cliente lee las credenciales de un archivo llamado `usr_sig.txt`, en la carpeta desde la que se ejecuta.
No esta en el repositorio porque tiene el secreto (esta en `.gitignore`), asi que hay que crearlo antes de
ejecutar. Ese archivo tiene 3 lineas:

```
<IP del servidor>
<usuario>
<secreto>
```

Por ejemplo, para crearlo en la raiz del repositorio:

```
printf '167.114.129.206\ngrupo12\n<secreto>\n' > usr_sig.txt
```

## Ejecucion

Desde la raiz del repositorio, con `usr_sig.txt` en la misma carpeta:

```
./cliente
```

El cliente muestra cada paso: la IP publica, el pedido de autenticacion, el puerto TCP asignado y, por cada PDU
recibida, su contenido y el codigo con el que se reenvio (o la razon por la que no se reenvio). Termina con codigo
de salida 0 si completo los dos desafios, y distinto de 0 si hubo un error (su motivo se imprime en `stderr`).

La autenticacion usa UDP en el puerto 20262 y el segundo desafio usa un puerto TCP no estandar.

## Estructura del repositorio

| Carpeta o archivo | Contenido |
|---|---|
| `src/` | Cadigo fuente del cliente |
| `Makefile` | Compilacian del cliente |
| `informe/` | Informe en LaTeX (`informe.tex`) y en PDF (`informe.pdf`) |
| `capturas/` | Captura de Wireshark de la corrida contra el servidor de la cátedra (`Final.pcapng`) e imagenes usadas en el informe |
| `codigo_ayuda_2026s1/` | Codigo de ayuda dado por la catedra, como referencia. El cliente usa su MD5 y 2 de sus funciones |

### Modulos de `src/`

| Archivo | Responsabilidad |
|---|---|
| `main.c` | Encadena los pasos: credenciales, IP publica, autenticacion y reenvio |
| `credentials.c/.h` | Lectura del archivo de credenciales |
| `http_ip.c/.h` | IP publica con un `GET / HTTP/1.0` a `api.ipify.org` sobre un socket TCP |
| `auth.c/.h` | Primer desafo: autenticacion por UDP y verificacion de la respuesta |
| `md5.c/.h` | MD5 del codigo de ayuda de la catedra, sin modificaciones |
| `md5_hex.c/.h` | Conversion del digesto MD5 a 32 caracteres hexadecimales en minuscula |
| `forward.c/.h` | Segundo desaio: recepcion por TCP, delimitacion, validacion y reenvio por UDP |
| `framing.c/.h` | Delimitacion de PDUs por `\r\n` sobre el stream TCP |
| `pdu.c/.h` | Validacion de cada PDU y calculo de su codigo de parseo |