/**********************************************************************/ 
/*        ELE8094 SwA Assessed Practical 2 2016                       */
/*                                                                    */
/* OpenSSL heartleed bug                                              */
/*                                                                    */
/*                                                                    */
/* Insert Name:                                                       */
/* Insert Student Number:                                             */
/*                                                                    */
/**********************************************************************/  

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TLS1_HB_REQUEST         0x01
#define TLS1_HB_RESPONSE        0x02
#define TLS1_RT_HEARTBEAT       0x18

#define n2s(c,s)        ((s=(((unsigned int)(c[0]))<< 8)| \
                            (((unsigned int)(c[1]))    )),c+=2)
#define s2n(s,c)        ((c[0]=(unsigned char)(((s)>> 8)&0xff), \
                          c[1]=(unsigned char)(((s)    )&0xff)),c+=2)

typedef struct ssl3_record_st
{
  unsigned char *data;    /* pointer to the record data */
  unsigned int length;
} SSL3_RECORD;

typedef struct ssl3_state_st
{
  SSL3_RECORD rrec; /* each decoded record goes in here */
} SSL3_STATE;

typedef struct ssl_st
{
 struct ssl3_state_st *s3;
}SSL;

int tls1_process_heartbeat(SSL *s);
int RAND_pseudo_bytes(unsigned char *buf, int num);
int ssl3_write_bytes(SSL *s, int type, const void *buf_, int len);

int main()
{
  unsigned char ssl_s3_rrec_data[] = {0x01,0x00,0x02,0xAA};
  SSL mySSL = {0};
  SSL3_STATE myS3 = {0};
  myS3.rrec.data = &ssl_s3_rrec_data[0];
  myS3.rrec.length = 1+2+ssl_s3_rrec_data[2]+16;
  mySSL.s3 = &myS3;

  /*Main function used to simulate malicious heartbeatRequest message*/ 

  /* ELE8094: write code to call into the tls1_process_heartbeat 
              and print your output */

  tls1_process_heartbeat(&mySSL);

  /* ELE8094:  fix the memcpy bug and print your output demonstrating
               that the message buffer overflow cannot occur */

  return 0;
}


int tls1_process_heartbeat(SSL *s)
{

  unsigned char *p = &s->s3->rrec.data[0], *pl;
  unsigned short hbtype;
  unsigned int payload;
  unsigned int padding = 16; /* Use minimum padding */

  /* Read type and payload length first */
  hbtype = *p++;
  n2s(p, payload);

  /*Fix implemented which checks the heartbeat payload length value
  matches the actual payload length */

  if (1 + 2 + 16 > s->s3->rrec.length){
  printf("payload = 0, silently discarded\n");
  return 0;
  }
  /*first if statement checks if the payload = 0, if so it is silently discarded*/
  
  if (1 + 2 + payload + 16 > s->s3->rrec.length){
  printf("payload is greater than payload length, silently discarded\n");
  return 0;
  }
  /*Second if statement checks if payload is greater than payload length, 
  if so it is silently discarded*/
  
  pl = p;

  /* ELE8094: callback removed */    
  if (hbtype == TLS1_HB_REQUEST)
  {
    unsigned char *buffer, *bp;
    int r;

    /* Allocate memory for the response, size is 1 bytes
     * message type, plus 2 bytes payload length, plus
     * payload, plus padding
     */

    /*ELE8094: standard malloc used */
    buffer = malloc(1 + 2 + payload + padding);
    bp = buffer;

    /* Enter response type, length and copy payload */
    *bp++ = TLS1_HB_RESPONSE;
    s2n(payload, bp);
    memcpy(bp, pl, payload);
    bp += payload;

    /* ELE8094: stubbed function to be completed below */
    RAND_pseudo_bytes(bp, padding);

    /* ELE8094: stubbed function to be completed below */
    r = ssl3_write_bytes(s, TLS1_RT_HEARTBEAT, buffer, 3 + payload + padding);

    /* ELE8094: callback removed */

    /* ELE8094: standard free used */
    free(buffer);

    if (r < 0)
      return r;
  }
  else if (hbtype == TLS1_HB_RESPONSE)
  {
    /* ELE8094 : this part of code not needed so removed */
  }
  return 0;
}

int RAND_pseudo_bytes(unsigned char *buf, int num)
{

  /* write a piece of code that calls to 
     "/dev/urandom" to grab some random data
     and return that random data */

  FILE *fp = NULL;
  fp = fopen("/dev/urandom", "r");
  fread(buf, 1, num, fp);
  fclose(fp);
  

  return 0;
}

int ssl3_write_bytes(SSL *s, int type, const void *buf_, int len)
{

  /* write a function to print your buffer to stdout */
  unsigned char *pX;
  pX = (unsigned char*)buf_;
  for(int i =0; i<len; i++){
  	printf("[%04d] : %u\n", i, pX[i]);
  }

  return 0;
}
