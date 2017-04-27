/********************************************************************************/
/*										*/
/*			     	TPM Read Public Key				*/
/*			     Written by J. Kravitz, S. Berger			*/
/*		       IBM Thomas J. Watson Research Center			*/
/*	      $Id: getpubkey.c 4702 2013-01-03 21:26:29Z kgoldman $		*/
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

#include "tpmfunc.h"

static void printUsage(const char *prg)
{
    printf("\n");
    printf("%s -ha <key handle> -pwdk keypassword\n", prg);
    printf("\n");
    printf("\n");
}

int main(int argc, char *argv[])
{
   int ret = 0;
   int i;
   unsigned char pass1hash[20];
   unsigned char *aptr = NULL;
   pubkeydata pubkey;
   RSA *rsa;                       /* OpenSSL format Public Key */
   const char *keypass = NULL;
   uint32_t keyHandle = 0;
   
   TPM_setlog(0); /* turn off verbose output */

    for (i=1 ; i<argc ; i++) {
        if (!strcmp(argv[i], "-pwdk")) {
	    i++;
	    if (i < argc) {
                keypass = argv[i];
            } else {
                printf("Missing parameter to -pwdk\n");
	        printUsage(argv[0]);
	        exit(1);
	    }
        }
        else if (!strcmp(argv[i], "-ha")) {
	    i++;
	    if (i < argc) {
                if (sscanf(argv[i],"%x",&keyHandle) != 1) {
                    printf("Could not parse the key handle.\n");
                    exit(1);
                }
	    } else {
	        printf("Missing parameter to -ha\n");
	        printUsage(argv[0]);
	        exit(1);
	    }
        }
        else if (!strcmp(argv[i], "-h")) {
            printUsage(argv[0]);
            exit(0);
        }
        else if (!strcmp(argv[i], "-v")) {
            TPM_setlog(1);
        }
        else {
            printf("\n%s is not a valid option\n", argv[i]);
            printUsage(argv[0]);
            exit(1);
        }
    }

    if (keyHandle == 0) {
        printf("Missing key handle.\n");
        printUsage(argv[0]);
        exit(1);
    }

    if (keypass) {
        TSS_sha1((unsigned char *)keypass ,strlen(keypass), pass1hash);
        aptr = pass1hash;
    }
    ret = TPM_GetPubKey(keyHandle, aptr, &pubkey);
    if (ret != 0) {
        printf("Error %s from TPM_GetPubKey\n",
               TPM_GetErrMsg(ret));
        exit(-2);
    }

   /*
   ** convert the returned public key to OpenSSL format and
   ** export it to a file
   */
   rsa = TSS_convpubkey(&pubkey);
   if (rsa == NULL) {
      printf("Error from TSS_convpubkey\n");
      exit(-3);
   }

   printf("Pubkey keylength %d\nModulus:",pubkey.pubKey.keyLength);
   for(i=0;i<(int)pubkey.pubKey.keyLength;i++){
       if(!(i%16))
           printf("\n");
       printf("%02X ",pubkey.pubKey.modulus[i]);
   }
   printf("\n");

   exit(0);
}

