----------------------------------------------------------------------------------------------------
Con respecto a test_pdu_candidate.c

Esta función contempla casos de multiples PDUs en una sola comunicación TCP, algo que no está en el protocolo pero funciona igualmente

Hay un array donde se ve pueden hacer pruebas. Notar que el tamaño luego se usa abajo en un loop que simula el loop de lectura.

  char *test_buffers[7] = {
    "GET / HTTP/1.0\r\n\r\n",
    "GET / HTTP/1.1\r\nHeader: value\r\n\r\n",
    "GET / HTTP/1.0\r\nHeader\r\n\r\nPOST / HTTP/1.0\r\nHeader\r\n\r\n",
    "GET /",
    " HTTP/1.0\r\n\r\nPOST /",
    " HTTP/1.1\r\n\r\n",
    "GET / HTTP\n"
  };


  /*  This for() emulates the reading loop */
  int i;
  for (i=0; i < 7; i++)


Se compila así:
$ gcc -Wall test_pdu_candidate.c
Se ejecuta así:
$ ./a.out


----------------------------------------------------------------------------------------------------
Con respecto a test_skip_single.c

Se compila así:
$ gcc -Wall test_skip_single.c
Se ejecuta así:
$ ./a.out  "string a delimitar con delimitadores"

----------------------------------------------------------------------------------------------------
Con respecto a unixtimestamp.c

Se compila así:
$ gcc -Wall unixtimestamp.c
Se ejecuta así:
$ ./a.out


----------------------------------------------------------------------------------------------------
con respecto a test_md5/test_md5.c

$ cd test_md5
$ make
$ ./test_md5 "asba"
MD5("asba") = 154ea795fb744639489d46ed04c137a4
y para validar
$ echo -ne "asba" |md5sum
154ea795fb744639489d46ed04c137a4  -

