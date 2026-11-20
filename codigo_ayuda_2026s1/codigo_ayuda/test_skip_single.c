/* Useful function for parsing a Protocol Data Unit that use delimiters */
#include <stdio.h>
#include <stdlib.h>
#include <string.h> /* needed for memset() */

static char *skip_single(char **buf, const char *delimiters);

int main(int argc, char *argv[])
{
  if (argc < 2) {
    printf("Uso: %s \"string to parse\"\n", argv[0]);
    return 1;
  }
  // char pdu_candidate[1000];
  char *pdu_candidate;
  pdu_candidate = malloc(1000);
  memset(pdu_candidate, 0, 1000);

  strcpy( pdu_candidate, argv[1]);
  printf("pdu_candidate = '%s'\n", pdu_candidate);

  printf("Delimiter is \" \"\n");
  for (int i=0 ; i <4; i++ ) {
    printf("%d '%s'\n", i, skip_single( &pdu_candidate, " ") );
    printf("pdu_candidate = '%s'\n", pdu_candidate);
  }

  return 0;
}


// Skip the characters until the SINGLE DELIMITER character is found
// 0-terminate resulting word
// Advance pointer to buffer to the last skipped position + delimiter.
// Return found 0-terminated wor.
static char *skip_single(char **buf, const char *delimiters)
{
  char *p, *begin_word, *end_word, *end_delimiters;

  begin_word = *buf;

  end_word = begin_word + strcspn(begin_word, delimiters);

  // Take only ONE delimiter
  end_delimiters = end_word + 1;

  for (p = end_word; p < end_delimiters; p++) {
    *p = '\0';
  }

  *buf = end_delimiters;

  return begin_word;
}

