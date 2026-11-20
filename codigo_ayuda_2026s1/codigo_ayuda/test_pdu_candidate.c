#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <string.h> /* needed for memset() */

#define MAX_PDU_SIZE         10000

#define ARRAY_SIZE 3

#define PDU_CANDIDATE_LINE_OK	 1
#define PDU_ERROR_BAD_FORMAT	-1
#define PDU_NEED_MORE_DATA       0


/* Comment or uncomment the following macro for detailed debugging */
/* #define DBG_RECEIVED_DATA */

/* Protoypes */
int processReceivedData(char *buffer, int buffersize, int *buffer_ptr, char *pdu_candidate, int *pdu_candidate_ptr);
int recv_mockup(int new_s, void *buffer, size_t len , int flags, char* read_simulation_payload);

/* Main */
int main(int argc, char* argv[])
{
  /* Not used but useful for pedagogical purposes */
  int new_s = 0; // socket

  /* Read Buffer for TCP socket */
  char buffer[3000];
  /* number of input bytes read */
  int inbytes=-1;
  /* PDU candidate status */
  int pdu_status;
  /* Pointers used for PDU parsing */
  int buffer_ptr, pdu_candidate_ptr;
  /* Buffer used to store PDU candidate, it can be filled by several TCP segments */
  char pdu_candidate[MAX_PDU_SIZE+1];

  /* Initialization */
  pdu_candidate_ptr = 0;
  memset(pdu_candidate,0,sizeof(pdu_candidate));

  /* Buffer array for TCP read mockup */
  char *test_buffers[ARRAY_SIZE] = {
    "GET / HTTP/",
    "1.0\r\nPOST / HTTP/1.0\r\n",
    "GET / HTTP/1.0\r\nHEAD /image.png HTTP/1.0\r\n"
  };

  /*  This for() emulates the reading loop */
  int i;
  for (i=0; i < ARRAY_SIZE; i++)
  {
    // Read mockup of a TCP socket new_s
    printf("recv_mockup %d\n", i);
    inbytes = recv_mockup(new_s, buffer, sizeof(buffer),0, test_buffers[i]);
    buffer_ptr = 0; // after reading, buffer pointer is reseted to 0

    // This loop processes data and its existence provides
    // - complete and partial PDU parsing
    while (inbytes - buffer_ptr -1  > 0)
    {
      pdu_status = processReceivedData((char *) buffer, inbytes, &buffer_ptr, (char *) pdu_candidate, &pdu_candidate_ptr);
      if (pdu_status == PDU_CANDIDATE_LINE_OK)
      {
        /* Here we should try to parse the candidate PDU */
        printf( "try_parse PDU\n");    // Just for debug, erase it if convenient
        printf("%s\n", pdu_candidate); // Just for debug, erase it if convenient
        // try_parse((char *) pdu_candidate, pdu_candidate_ptr,  &new_s);
        // Memory cleaning
        pdu_candidate_ptr = 0;
        memset(pdu_candidate,0,sizeof(pdu_candidate));
      }
      else if (pdu_status == PDU_ERROR_BAD_FORMAT)
      {
        printf("ERROR clean memory buffer\n"); // Just for debug, erase it if convenient
        // Memory cleaning
        pdu_candidate_ptr = 0;
        memset(pdu_candidate,0,sizeof(pdu_candidate));
      }
      else
      {
        // Just for debug, erase it if convenient
        printf("%s\n", pdu_candidate);
        printf("No delimiter found. Probably need another buffer read\n");
      }
      // Just for debug, erase it if convenient
      fprintf(stderr,"processReceivedData = %d\n", pdu_status);
      fprintf(stderr,"inbytes=%d  buffer_ptr=%d\n", inbytes, buffer_ptr);
    }
  }

  return 0;
}

/*
 * This function frames the received data into candidate PDU
 * which will be tested for correcteness later on
 * This function was meant to delimit pipelined PDU (i.e. multiple PDU in one TCP segment/buffer)
 *
 * buffer: buffer which stores last read from socket
 * buffersize: how many bytes (char) buffer holds
 * buffer_ptr: offset position at which it will read buffer "buffer"
 * pdu_candidate: buffer which stores byte hoping to have enough information to
 *   build a candidate PDU (find PDU delimiter)
 * pdu_candidate_ptr: offset position at which it will read buffer "pdu_candidate"
 */
int processReceivedData(char *buffer, int buffersize, int *buffer_ptr, char *pdu_candidate, int *pdu_candidate_ptr)
{
  // Position pdu_candidate pointer
  pdu_candidate += *pdu_candidate_ptr;
  // Position buffer pointer
  buffer += *buffer_ptr;

  int i;
  int chunk = (buffersize - *buffer_ptr);
  for (i=0; i < chunk; i++)
  {
    (*buffer_ptr)++; // must be before a return gets hit

    #ifdef DBG_RECEIVED_DATA
      if ( *buffer >= 32 && *buffer <=126 )
        fprintf(stderr,"Processing char (%d) '%c'\n", *buffer, *buffer);
      else
        fprintf(stderr,"Processing char (%d) \n", *buffer);
      if ( *pdu_candidate >= 32 && *pdu_candidate <=126 )
        fprintf(stderr,"pdu_candidate char (%d) '%c'\n", *pdu_candidate, *pdu_candidate);
      else
        fprintf(stderr,"pdu_candidate char (%d)\n", *pdu_candidate);
      fprintf(stderr,"buffer_ptr '%d'  pdu_candidate_ptr '%d'\n", *buffer_ptr, *pdu_candidate_ptr);
    #endif


    // Old scenario where we need 4 bytes for PDU delimiter and we printed them for pedagogical purposes
    // if ( *pdu_candidate_ptr >= 3 )
    //   printf("  %d-%d-%d-%d\n", *(pdu_candidate-2), *(pdu_candidate-1), *(pdu_candidate), *buffer );

    // PDU candidate criteria: \r\n
    if ( *pdu_candidate_ptr >= 2 && *(pdu_candidate)=='\r' && *buffer == '\n' )
    {
      pdu_candidate++; // Advance pointer for next PDU (in 2016 was not a requirement)
      *pdu_candidate++ = *buffer;
      (*pdu_candidate_ptr)++;
      #ifdef DBG_RECEIVED_DATA
         fprintf(stderr,"CRLF detected PDU_CANDIDATE_LINE_OK\n");
      #endif
      return PDU_CANDIDATE_LINE_OK;
    }
    else if (*buffer != 13 && *buffer != 10 && (*buffer < 32 || *buffer >126) ) // http://www.asciitable.com/
    {
      // If we are inside here: there are forbidden characters
      // pdu_candidate_ptr must be taken care outside this function
      #ifdef DBG_RECEIVED_DATA
        fprintf(stderr,"Char outside of allowed range PDU_ERROR_BAD_FORMAT (%d)\n", *buffer);
      #endif
      return PDU_ERROR_BAD_FORMAT;
    }
    else
    {
      #ifdef DBG_RECEIVED_DATA
      if ( *buffer >= 32 && *buffer <=126 )
        fprintf(stderr,"Char (%d) '%c' processed OK\n", *buffer, *buffer);
      else
        fprintf(stderr,"Char (%d) processed OK\n", *buffer);
      #endif
      if (*pdu_candidate != '\0') { pdu_candidate++; }
      *pdu_candidate = *buffer;
      (*pdu_candidate_ptr)++;
    }
    buffer++;
  }
  return PDU_NEED_MORE_DATA;
}

/*
 * This function emulates for pedagocial purposes recv() system call
 * it has an extra argument, which is what we want to simulate to receive
 */
int recv_mockup(int new_s, void *buffer, size_t len , int flags, char* read_simulation_payload)
{
  strcpy(buffer, read_simulation_payload);
  return strlen(buffer);
}
