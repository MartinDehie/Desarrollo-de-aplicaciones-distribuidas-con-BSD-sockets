#include "md5.h"

// ==========================================================
// Usage Example
// ==========================================================
int main( int argc, char *argv[] ) {
    uint8_t digest[16];

  if (argc < 2) {
	  printf("Uso: %s \"<frase>\"\n", argv[0]);
	  return 1;
  }
  // Compute the hash
  // md5((const uint8_t *)test_string, strlen(test_string), digest);
  md5((const uint8_t *) argv[1], strlen(argv[1]), digest);

  // Print the result in hexadecimal
  printf("MD5(\"%s\") = ", argv[1]);
  for (int i = 0; i < 16; i++) {
    printf("%02x", digest[i]);
  }
  printf("\n");

  return 0;
}
