/********************************************************************************/
/*										*/
/*			     	TPM Sign a Data File				*/
/*			     Written by J. Kravitz, S. Berger			*/
/*		       IBM Thomas J. Watson Research Center			*/
/*	      $Id: signfile.c 4702 2013-01-03 21:26:29Z kgoldman $		*/
/*										*/
/* (c) Copyright IBM Corporation 2006, 2010.					*/
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
#include <unistd.h>
#include "tpmfunc.h"
#include <openssl/sha.h>

static void ParseArgs(int argc, char *argv[]);

static char *keypass = NULL;
static char *datafilename  = NULL;
static char *sigfilename = NULL;
static uint32_t keyhandle = 0;             /* handle of parent key */

/* local prototypes */
static void printUsage(void);

int main(int argc, char *argv[])
   {
   int ret;
   unsigned char databuff[65535];  /* data read work buffer */
   unsigned char passhash[20];     /* hash of parent key password */
   unsigned char datahash[20];     /* hash of data file */
   unsigned char sig[4096];        /* resulting signature */
   uint32_t  siglen;               /* signature length */
   unsigned char *passptr;
   SHA_CTX sha;
   FILE *infile;
   FILE *sigfile;
   
   
   TPM_setlog(0);                  /* turn off verbose output */

   ParseArgs(argc, argv);

   if ((keyhandle == 0) ||
       (datafilename == NULL) ||
       (sigfilename == NULL)) {
       printf("Missing parameter\n");
       printUsage();
   }
   /*
   ** use the SHA1 hash of the password string as the Key Authorization Data
   */
   if (keypass != NULL) {
       TSS_sha1((unsigned char *)keypass,strlen(keypass),passhash);
       passptr = passhash;
   }
   else {
       passptr = NULL;
   }
   /*
   ** read and hash the data file
   */
   infile = fopen(datafilename,"rb");
   if (infile == NULL)
      {
	  printf("Unable to open input file '%s'\n",datafilename);
	  exit(2);
      }
   SHA1_Init(&sha);
   for (;;)
      {
      ret = fread(databuff,1,sizeof databuff,infile);
      if (ret < 0)
         {
	     printf("I/O Error while reading input file '%s'\n",datafilename);
	     exit(3);
         }
      SHA1_Update(&sha,databuff,ret);
      if (ret < (int)sizeof(databuff)) break;
      }
   fclose(infile);
   SHA1_Final(datahash,&sha);
   ret = TPM_Sign(keyhandle,              /* Key Handle */
                  passptr,                /* key Password */
                  datahash,sizeof (datahash),     /* data to be signed, length */
                  sig,&siglen);           /* buffer to receive sig, int to receive sig length */
   if (ret != 0)
      {
      printf("Error %s from TPM_Sign\n",TPM_GetErrMsg(ret));
      exit(1);
      }
   sigfile = fopen(sigfilename,"wb");
   if (sigfile == NULL)
      {
	  printf("Unable to open output file '%s'\n",sigfilename);
	  exit(4);
      }
   ret = fwrite(sig,1,siglen,sigfile);
   if (ret != (int)siglen)
      {
	  printf("I/O Error while writing output file '%s'\n",sigfilename);
	  exit(5);
      }
   fclose(sigfile);
   exit(0);
   }
   
/**************************************************************************/
/*                                                                        */
/*  Parse Arguments                                                       */
/*                                                                        */
/**************************************************************************/
static void ParseArgs(int argc, char *argv[])
{
    int i;
    
    for (i=1 ; i<argc ; i++) {
       if (!strcmp(argv[i], "-pwdk")) {
	   i++;
	   if (i < argc) {
	       keypass = argv[i];
	   }
	   else {
	       printf("Missing parameter to -pwdk\n");
	       printUsage();
	   }
       }
       else if (strcmp(argv[i],"-hk") == 0) {
	   i++;
	   if (i < argc) {
	       /* convert key handle from hex */
	       if (1 != sscanf(argv[i], "%x", &keyhandle)) {
		   printf("Invalid -hk argument '%s'\n",argv[i]);
		   exit(2);
	       }
	       if (keyhandle == 0) {
		   printf("Invalid -hk argument '%s'\n",argv[i]);
		   exit(2);
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
	       datafilename = argv[i];
	   }
	   else {
	       printf("-if option needs a value\n");
	       printUsage();
	       exit(2);
	   }
       }
       else if (strcmp(argv[i],"-os") == 0) {
	   i++;
	   if (i < argc) {
	       sigfilename = argv[i];
	   }
	   else {
	       printf("-os option needs a value\n");
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
    return;
}

static void printUsage()
   {
   printf("Usage: signfile [options] -hk <key handle in hex> -if <input file> -os <output file>\n");
   printf("\n");
   printf("   Where the arguments are...\n");
   printf("    -hk <keyhandle>   is the key handle in hex\n");
   printf("    -if <input file>  is the file containing the data to be signed\n");
   printf("    -os <output file> is the file to contain the signature\n");
   printf("\n");
   printf("   Where the <options> are...\n");
   printf("    -pwdk <keypass>   to specify the key use password\n");
   printf("    -h                print usage information (this message)\n");
   exit(1);
   }
