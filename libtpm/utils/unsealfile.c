/********************************************************************************/
/*										*/
/*			     	TPM Unseal a Data File				*/
/*			     Written by J. Kravitz, S. Berger			*/
/*		       IBM Thomas J. Watson Research Center			*/
/*	      $Id: unsealfile.c 4702 2013-01-03 21:26:29Z kgoldman $		*/
/*										*/
/* All rights reserved.								*/
/* 										*/
/* Redistribution and use in source and binary forms, with or without		*/
/* modification, are permitted provided that the following conditions are	*/
/* met:										*/
/* 										*/
/* Redistributions of source code must retain the above copyright notice,	*/
/* this list of conditions and the following disclaimer.			*/
/* 										*/
/* Redistributions in binary form must reproduce the above copyright		*/
/* notice, this list of conditions and the following disclaimer in the		*/
/* documentation and/or other materials provided with the distribution.		*/
/* 										*/
/* Neither the names of the IBM Corporation nor the names of its		*/
/* contributors may be used to endorse or promote products derived from		*/
/* this software without specific prior written permission.			*/
/* 										*/
/* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS		*/
/* "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT		*/
/* LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR	*/
/* A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT		*/
/* HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,	*/
/* SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT		*/
/* LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,	*/
/* DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY	*/
/* THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT		*/
/* (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE	*/
/* OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.		*/
/********************************************************************************/

#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include "tpmfunc.h"

   
static void printUsage(void);

int main(int argc, char *argv[])
   {
   int ret;
   struct stat sbuf;
   unsigned char databuff[256];    /* data buffer */
   uint32_t  datalen;          /* size of data */
   uint32_t keyhandle = 0;         /* handle of parent key */
   unsigned char passhash1[20];    /* hash of parent key password */
   unsigned char passhash2[20];    /* hash of data       password */
   unsigned char blob[4096];       /* sealed blob */
   unsigned int  bloblen;          /* blob length */
   unsigned char *passptr1;
   unsigned char *passptr2;
   FILE *infile;
   FILE *outfile;
   char *datpass = NULL;
   char *keypass = NULL;
   int i;
   const char *datafilename = NULL;
   const char *sealfilename = NULL;
   
   TPM_setlog(0);                  /* turn off verbose output */
   
   for (i=1 ; i<argc ; i++) {
       if (!strcmp(argv[i],"-pwdk")) {
	   i++;
	   if (i >= argc) {
	       printf("Missing parameter for option -pwdk.\n");
	       printUsage();
	   }
	   keypass = argv[i];
       }
       else if (!strcmp(argv[i],"-pwdd")) {
	   i++;
	   if (i >= argc) {
	       printf("Missing parameter for option -pwdd.\n");
	       printUsage();
	   }
	   datpass = argv[i];
       }
       else if (strcmp(argv[i],"-hk") == 0) {
	   i++;
	   if (i < argc) {
	       /* convert key handle from hex */
	       if (1 != sscanf(argv[i], "%x", &keyhandle)) {
		   printf("Invalid -hk argument '%s'\n",argv[i]);
		   printUsage();
	       }
	       if (keyhandle == 0) {
		   printf("Invalid -hk argument '%s'\n",argv[i]);
		   printUsage();
	       }		 
	   }
	   else {
	       printf("-hk option needs a value\n");
	       printUsage();
	   }
       }
       else if (strcmp(argv[i],"-if") == 0) {
	   i++;
	   if (i < argc) {
	       sealfilename = argv[i];
	   }
	   else {
	       printf("-if option needs a value\n");
	       printUsage();
	   }
       }
       else if (strcmp(argv[i],"-of") == 0) {
	   i++;
	   if (i < argc) {
	       datafilename = argv[i];
	   }
	   else {
	       printf("-of option needs a value\n");
	       printUsage();
	   }
       }
       else if (!strcmp(argv[i], "-h")) {
	   printUsage();
       }
       else if (!strcmp(argv[i], "-v")) {
	   TPM_setlog(1);
       }
       else {
	   printf("\n%s is not a valid option\n", argv[i]);
	   printUsage();
       }
   }
   if ((keyhandle == 0) ||
       (datafilename == NULL) ||
       (sealfilename == NULL)) {
       printf("Missing argument\n");
       printUsage();
   }

   /*
   ** use the SHA1 hash of the password string as the Key Authorization Data
   */
   if (keypass != NULL)
      {
      TSS_sha1((unsigned char *)keypass,strlen(keypass),passhash1);
      passptr1 = passhash1;
      }
   else passptr1 = NULL;
   /*
   ** use the SHA1 hash of the password string as the Blob Authorization Data
   */
   if (datpass != NULL)
      {
      TSS_sha1((unsigned char *)datpass,strlen(datpass),passhash2);
      passptr2 = passhash2;
      }
   else passptr2 = NULL;
   /*
   ** get size of blob file
   */
   stat(sealfilename,&sbuf);
   bloblen = (int)sbuf.st_size;
   /*
   ** read the blob file
   */
   infile = fopen(sealfilename,"rb");
   if (infile == NULL)
      {
	  printf("Unable to open input file '%s'\n",sealfilename);
	  exit(-4);
      }
   ret = fread(blob,1,bloblen,infile);
   if (ret != (int)bloblen)
      {
	  printf("I/O Error while reading input file '%s'\n",sealfilename);
	  exit(-5);
      }
   ret = TPM_Unseal(keyhandle,            /* KEY Entity Value */
                  passptr1,               /* Key Password */
                  passptr2,               /* blob password */
                  blob,bloblen,           /* encrypted blob, blob length */
                  databuff,&datalen);     /* buffer for decrypted data, int for length */
   if (ret != 0)
      {
      printf("Error %s from TPM_Unseal\n",TPM_GetErrMsg(ret));
      exit(ret);
      }
   outfile = fopen(datafilename,"wb");
   if (outfile == NULL)
      {
	  printf("Unable to open output file '%s'\n",datafilename);
	  exit(-7);
      }
   ret = fwrite(databuff,1,datalen,outfile);
   if (ret != (int)datalen)
      {
	  printf("I/O Error while writing output file '%s'\n",datafilename);
	  exit(-8);
      }
   fclose(outfile);
   exit(0);
   }
   
static void printUsage()
   {
   printf("Usage: unsealfile [options] -hk <key handle in hex> -if <input file> -of <outputfile>\n");
   printf("\n");
   printf("   Where the arguments are...\n");
   printf("    -hk <keyhandle>   is the key handle in hex\n");
   printf("    -if <input file>  is the file containing the data to be unsealed\n");
   printf("    -of <output file> is the file to contain the unsealed data\n");
   printf("\n");
   printf("   Where the <options> are...\n");
   printf("    -pwdk <keypass>      to specify the key use password\n");
   printf("    -pwdd <datpass>      to specify the data use password\n");
   printf("    -h                print usage information (this message)\n");
   exit(-1);
   }
