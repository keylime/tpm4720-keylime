/********************************************************************************/
/*										*/
/*			     	TPM UnBind Utility				*/
/*			     Written by J. Kravitz, S. Berger			*/
/*		       IBM Thomas J. Watson Research Center			*/
/*	      $Id: unbindfile.c 4702 2013-01-03 21:26:29Z kgoldman $		*/
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
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <openssl/sha.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include "tpmfunc.h"

   
static void printUsage(void);


/**************************************************************************/
/*                                                                        */
/*  Main Program                                                          */
/*                                                                        */
/**************************************************************************/
int main(int argc, char *argv[])
   {
   int ret;
   unsigned char * databuff = NULL;/* encrypted data read work buffer */
   unsigned char * blob = NULL;    /* unencrypted blob */
   int datlen;
   uint32_t bloblen;
   uint32_t handle = 0;            /* handle of binding key */
   unsigned char passhash[20];     /* hash of parent key password */
   unsigned char *passptr;
   struct stat sbuf;
   FILE *infile;
   const char *datafilename = NULL;
   FILE *outfile;
   char *keypass = NULL;
   const char *ofilename = NULL;
   int i;
   
   TPM_setlog(0);                  /* turn off verbose output */

  
   /* get the command line arguments */
   for (i=1 ; i<argc ; i++) {
	if (strcmp(argv[i],"-hk") == 0) {
	    i++;
	    if (i < argc) {
		/* convert key handle from hex */
		if (1 != sscanf(argv[i], "%x", &handle)) {
		    printf("Invalid -hk argument '%s'\n",argv[i]);
		    exit(2);
		}
		if (handle == 0) {
		    printf("Invalid -hk argument '%s'\n",argv[i]);
		    exit(2);
		}		 
	    }
	    else {
		printf("-hk option needs a value\n");
		printUsage();
	    }
	}
	else if (!strcmp(argv[i], "-pwdk")) {
	    i++;
	    if (i < argc) {
		keypass = argv[i];
	    }
	    else {
		printf("Missing parameter to -pwdk\n");
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
	else if (strcmp(argv[i],"-of") == 0) {
	   i++;
	   if (i < argc) {
	       ofilename = argv[i];
	   }
	   else {
	       printf("-of option needs a value\n");
	       printUsage();
	       exit(2);
	   }
       }
       else if (strcmp(argv[i],"-v") == 0) {
	   TPM_setlog(1);
       }
       else if (strcmp(argv[i],"-h") == 0) {
	   printUsage();
	   exit(2);
       }
       else {
	   printf("\n%s is not a valid option\n",argv[i]);
	   printUsage();
	   exit(2);
       }
   }
   /* verify command line arguments */
   if ((handle == 0) ||
       (datafilename == NULL) ||
       (ofilename == NULL) ) {
       printf("Missing arguments\n");
       exit(-1);
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
   ** get size of data file
   */
   stat(datafilename, &sbuf);
   datlen = (int)sbuf.st_size;
   databuff = malloc(datlen);
   if (NULL == databuff) {
      exit(-1);
   }
   blob = malloc(datlen);
   if (NULL == blob) {
      free(databuff);
      exit(-1);
   }
   /*
   ** read the data file
   */
   infile = fopen(datafilename,"rb");
   if (infile == NULL)
      {
	  printf("Unable to open data file '%s'\n",datafilename);
	  free(blob);
	  free(databuff);
	  exit(-3);
      }
   ret = fread(databuff,1,datlen,infile);
   fclose(infile);
   if (ret != datlen)
      {
      printf("Unable to read data file\n");
      free(blob);
      free(databuff);
      exit(-4);
      }
   ret = TPM_UnBind(handle,passptr,databuff,datlen,blob,&bloblen);
   if (ret != 0)
      {
      printf("Error '%s' from TPM_UnBind\n",TPM_GetErrMsg(ret));
      free(blob);
      free(databuff);
      exit(ret);
      }
   outfile = fopen(ofilename,"wb");
   if (outfile == NULL)
      {
	  printf("Unable to open output file '%s'\n",ofilename);
	  free(blob);
	  free(databuff);
	  exit(-5);
      }
   ret = fwrite(blob,1,bloblen,outfile);
   if (ret != (int)bloblen)
      {
	  printf("Error writing output file '%s'\n",ofilename);
	  fclose(outfile);
	  free(blob);
	  free(databuff);
	  exit(-6);
      }
   fclose(outfile);
   free(blob);
   free(databuff);
   exit(0);
   }


static void printUsage()
{
   printf("Usage: unbindfile [options] -hk <key handle in hex> -if <input file> -of <outputfile>\n");
   printf("\n");
   printf("   Where the arguments are...\n");
   printf("    -hk <keyhandle>   is the key handle in hex\n");
   printf("    -if <input file>  is the file containing the data to be unbound\n");
   printf("    -of <output file> is the file to contain the unbound data\n");
   printf("\n");
   printf("   Where the <options> are...\n");
   printf("    -pwdk <keypass>   to specify the key use password\n");
   printf("    -h                print usage information (this message)\n");
   exit(-1);
}
