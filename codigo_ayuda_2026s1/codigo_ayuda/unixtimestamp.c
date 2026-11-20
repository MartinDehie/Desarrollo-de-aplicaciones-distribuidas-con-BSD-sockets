/* Get system timestamp with up to microseconds resolution
 * Binary byte order considerations 
 * Hexadecimal dump of buffer
 * */
#include <stdio.h>
#include <sys/time.h>  /* needed for gettimeofday() */
#include <unistd.h>    /* needed for usleep() */
#include <ctype.h>     /* needed for isprint() */
#include <arpa/inet.h> /* needed for htonl() ,etc */



#ifndef HEXDUMP_COLS
#define HEXDUMP_COLS 16
#endif 
void hexdump(void *mem, unsigned int len);
int timeval_subtract (struct timeval *result, struct timeval *x, struct timeval *y);

int main(int argc, char *argv[])
{
  struct timeval tv1, tv2, tv_res;
  gettimeofday(&tv1, NULL);
  usleep(20000);
  gettimeofday(&tv2, NULL);

  timeval_subtract(&tv_res, &tv2, &tv1); /* tv2 - tv1 */
  printf("The current EPOCH time is %ld.%06ld\n", tv1.tv_sec, tv1.tv_usec);
  printf("Elapsed time is %ld.%06ld\n", tv_res.tv_sec, tv_res.tv_usec);

  printf("Size of tv_sec %lu Bytes\n", sizeof(tv1.tv_sec));
  printf("Size of tv_usec %lu Bytes\n", sizeof(tv1.tv_usec));
  printf("Size of timeval %lu Bytes\n", sizeof(tv1));


  /* Particularidades de timeval_subtract */

  struct timeval testData00 = { 0, 0 };
  struct timeval testData01 = { 0, 1 };
  struct timeval diff;
  int res;

  printf("\n\nParticularidades de timeval_subtract\n");

  res = timeval_subtract(&diff, &testData00, &testData00);
  printf("%ld.%06ld - %ld.%06ld => %d %ld:%ld\n", testData00.tv_sec, testData00.tv_usec, testData00.tv_sec, testData00.tv_usec, res, diff.tv_sec, diff.tv_usec);

  res = timeval_subtract(&diff, &testData01, &testData01);
  printf("%ld.%06ld - %ld.%06ld => %d %ld:%ld\n", testData01.tv_sec, testData01.tv_usec, testData01.tv_sec, testData01.tv_usec, res, diff.tv_sec, diff.tv_usec);

  res = timeval_subtract(&diff, &testData01, &testData00);
  printf("%ld.%06ld - %ld.%06ld => %d %ld:%ld\n", testData01.tv_sec, testData01.tv_usec, testData00.tv_sec, testData00.tv_usec, res, diff.tv_sec, diff.tv_usec);

  res = timeval_subtract(&diff, &testData00, &testData01);
  printf("%ld.%06ld - %ld.%06ld => %d %ld:%ld\n", testData00.tv_sec, testData00.tv_usec, testData01.tv_sec, testData01.tv_usec, res, diff.tv_sec, diff.tv_usec);


  printf("\nRepresentacion binaria\n");
  struct timeval testData02 = { 1026, 1 };
  printf("tv.tv_sec = %ld\n", testData02.tv_sec);
  hexdump((void*) &testData02.tv_sec, sizeof(testData02.tv_sec) );
  printf("\ntv.tv_usec = %ld\n", testData02.tv_usec);
  hexdump((void*) &testData02.tv_usec, sizeof(testData02.tv_usec) );
  printf("\nstruct tv:\n");
  hexdump((void*) &testData02, sizeof(testData02) );


  printf("\nRepresentacion binaria truncada (Host Order)\n");
  uint32_t aux_longint;
  printf("tv.tv_sec = %ld\n", testData02.tv_sec);
  aux_longint = testData02.tv_sec;
  hexdump((void*) &aux_longint, sizeof(aux_longint) );

  printf("\ntv.tv_usec = %ld\n", testData02.tv_usec);
  aux_longint = testData02.tv_usec;
  hexdump((void*) &aux_longint, sizeof(aux_longint) );


  printf("\nRepresentacion binaria (Network Byte Order)\n");
  // struct timeval testData02 = { 1026, 1 };
  printf("tv.tv_sec = %ld\n", testData02.tv_sec);
  aux_longint = htonl((uint32_t) testData02.tv_sec);
  hexdump((void*) &aux_longint, sizeof(aux_longint) );

  printf("\ntv.tv_usec = %ld\n", testData02.tv_usec);
  aux_longint = htonl((uint32_t) testData02.tv_usec);
  hexdump((void*) &aux_longint, sizeof(aux_longint) );
  

  return 0;
}


/* Subtract the `struct timeval' values X and Y,
   storing the result in RESULT.
   Return 1 if the difference is negative, otherwise 0.  
   From: https://ftp.gnu.org/old-gnu/Manuals/glibc-2.2.5/html_node/Elapsed-Time.html
   */

int timeval_subtract (struct timeval *result, struct timeval *x, struct timeval *y)
{
    // preserve *y
  struct timeval yy = *y;
  y = &yy;

  /* Perform the carry for the later subtraction by updating y. */
  if (x->tv_usec < y->tv_usec) {
    int nsec = (y->tv_usec - x->tv_usec) / 1000000 + 1;
    y->tv_usec -= 1000000 * nsec;
    y->tv_sec += nsec;
  }
  if (x->tv_usec - y->tv_usec > 1000000) {
    int nsec = (x->tv_usec - y->tv_usec) / 1000000;
    y->tv_usec += 1000000 * nsec;
    y->tv_sec -= nsec;
  }

  /* Compute the time remaining to wait.
     tv_usec is certainly positive. */
  result->tv_sec = x->tv_sec - y->tv_sec;
  result->tv_usec = x->tv_usec - y->tv_usec;

  /* Return 1 if result is negative. */
  return x->tv_sec < y->tv_sec;
}



// http://grapsus.net/blog/post/Hexadecimal-dump-in-C
void hexdump(void *mem, unsigned int len)
{
  unsigned int i, j;

  for(i = 0; i < len + ((len % HEXDUMP_COLS) ? (HEXDUMP_COLS - len % HEXDUMP_COLS) : 0); i++)
  {
    /* print offset */
    if(i % HEXDUMP_COLS == 0)
    {
      printf("0x%06x: ", i);
    }

    /* print hex data */
    if(i < len)
    {
      printf("%02x ", 0xFF & ((char*)mem)[i]);
    }
    else /* end of block, just aligning for ASCII dump */
    {
      printf("   ");
    }

    /* print ASCII dump */
    if(i % HEXDUMP_COLS == (HEXDUMP_COLS - 1))
    {
      for(j = i - (HEXDUMP_COLS - 1); j <= i; j++)
      {
        if(j >= len) /* end of block, not really printing */
        {
          putchar(' ');
        }
        else if(isprint(((char*)mem)[j])) /* printable char */
        {
          putchar(0xFF & ((char*)mem)[j]);
        }
        else /* other char */
        {
          putchar('.');
        }
      }
      putchar('\n');
    }
  }
}
