/********************************************************************************/
/*										*/
/*			     	TPM Test of TPM Quote				*/
/*			     Written by J. Kravitz, S. Berger			*/
/*		       IBM Thomas J. Watson Research Center			*/
/*	      $Id: quote.c 4702 2013-01-03 21:26:29Z kgoldman $			*/
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
#include <sys/types.h>
#include <unistd.h>
#include <string.h>
#ifdef TPM_POSIX
#include <netinet/in.h>
#endif
#ifdef TPM_WINDOWS
#include <winsock2.h>
#endif
#include "tpmfunc.h"
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>


static int printUsage()
{
    printf("Usage: checkquote\n"
	   "-aik <file containing key length and aik modulus> \n"
	   "-quote <quote.bin>\n"
       "-nonce <random value>\n"
	   "[-repeat <number of iterations>]\n");
    return -1;
}

uint32_t TPM_ValidatePCRCompositeSignatureNoCap(TPM_PCR_COMPOSITE *tpc,
                                           unsigned char *antiReplay,
                                           RSA *rsa,
                                           struct tpm_buffer *signature,
                                           uint16_t sigscheme);

#ifndef SHARED_LIB
#define outStream stdout
int main(int argc, char *argv[])
#else
#define exit(rc) return rc;	
int checkquote_main(FILE *outStream, int argc, char *argv[])
#endif	
{
    int ret;			/* general return value */
    unsigned char nonce[TPM_NONCE_SIZE];	/* nonce data */
    static char *nonceval = NULL; /* nonce value passed in by user */
    STACK_TPM_BUFFER(signature);
    TPM_PCR_COMPOSITE tpc;
    STACK_TPM_BUFFER (ser_tpc);
    STACK_TPM_BUFFER (ser_tqi);
    int i;
    uint16_t sigscheme = TPM_SS_RSASSAPKCS1v15_SHA1;
   	unsigned int numPCRs=0;
   	RSA *rsa = NULL;
   	FILE *keyfile = NULL;
   	EVP_PKEY *pkey;
   	unsigned int repeat = 1;

    const char *keyFilename = NULL;
    const char *quoteFilename = NULL;
    FILE *fp = NULL;
    
    TPM_setlog(0);		/* turn off verbose output from TPM driver */
    for (i=1 ; i<argc ; i++) {
	if (!strcmp(argv[i], "-aik")) {
	    i++;
	    if (i < argc) {
		keyFilename = argv[i];
	    }
	    else {
		printf("Missing parameter to -aik\n");
		return printUsage();
	    }
	}
	else if (!strcmp(argv[i], "-quote")) {
	    i++;
	    if (i < argc) {
		quoteFilename = argv[i];
	    }
	    else {
		printf("Missing parameter to -quote\n");
		return printUsage();
	    }
	}
    else if (!strcmp(argv[i],"-nonce")) {
        i++;
        if (i < argc) {
        nonceval = argv[i];
        }
        else {
        printf("Missing parameter to -nonce\n");
        return printUsage();
        }
    }
    else if (!strcmp(argv[i],"-repeat")) {
        i++;
        if (i < argc) {
        repeat = atoi(argv[i]);
        }
        else {
        printf("Missing parameter to -repeat\n");
        return printUsage();
        }
    }
	else if (!strcmp(argv[i], "-h")) {
	    return printUsage();
	}
	else if (!strcmp(argv[i], "-v")) {
	    TPM_setlog(1);
	}
	else {
	    printf("\n%s is not a valid option\n", argv[i]);
	    return printUsage();
	}
    }
    
    if ((quoteFilename == NULL) ||
	(keyFilename == NULL) ||
	nonceval == NULL) {
	printf("Missing argument\n");
	return printUsage();
    }
    
    /*  hash nonceval to create nonce data */
    TSS_sha1((unsigned char *)nonceval,strlen(nonceval),nonce);

    /* read in quote from file */
    if((fp = fopen(quoteFilename,"r"))==0) {
    printf("Error opening file %s.\n",quoteFilename);
    exit(-1);
    }
    if(fread(&signature,sizeof(uint32_t),3,fp)<3) {
    printf("Error reading signature header.\n");
    exit(-1);
    }
    if(signature.used>sizeof(signature.buffer)) {
    printf("Error invalid signature: bytes used %u is larger than the buffer %lu.\n",signature.used,sizeof(signature.buffer));
    exit(-1);
    }
    if(fread(&signature.buffer,sizeof(char),signature.used,fp)<signature.used) {
    printf("Error read signature data.\n");
    exit(-1);
    }
    if(fread(&tpc,sizeof(TPM_PCR_COMPOSITE),1,fp)<1) {
    printf("Error reading PCR composite.\n");
    exit(-1);
    }
    if((tpc.pcrValue.buffer=(BYTE*)malloc(sizeof(BYTE)*tpc.pcrValue.size))==NULL) {
    printf("unable to allocate memory for PCR buffer.\n");
    exit(-1);
    }
	if(fread(tpc.pcrValue.buffer,sizeof(BYTE),tpc.pcrValue.size,fp)<tpc.pcrValue.size) {
    printf("Error reading PCR value.\n");
    exit(-1);
    }
    fclose(fp);

   /*
   ** read the key file
   */
   keyfile = fopen(keyFilename,"rb");
   if (keyfile == NULL)
      {
	  printf("Unable to open public key file '%s'\n",keyFilename);
	  exit(6);
      }
   pkey = PEM_read_PUBKEY(keyfile,NULL,NULL,NULL);
   fclose(keyfile);
   if (pkey == NULL)
      {
	  printf("I/O Error while reading public key file '%s'\n",keyFilename);
	  exit(7);
      }
        unsigned int j =0;
    for(j=0;j<repeat;j++) {
   rsa = EVP_PKEY_get1_RSA(pkey);
   if (rsa == NULL)
      {
      printf("Error while converting public key \n");
      exit(8);
      }
    
    ret = TPM_ValidatePCRCompositeSignatureNoCap(&tpc,
					    nonce,
					    rsa,
					    &signature,
					    sigscheme);
	}
    if (ret) {
	printf("Error %s from validating the signature over the PCR composite.\n",
	       TPM_GetErrMsg(ret));
	exit(ret);
    }  
    
    fprintf(outStream, "Verification against AIK succeeded\n");
    fprintf(outStream, "PCR contents from quote:\n");
	
    for(i=0;i<tpc.select.sizeOfSelect*CHAR_BIT;i++) {
	    if((tpc.select.pcrSelect[i/8] & (1<<(i&0x7)))>0) {
		    unsigned int j=0;
		    /* check tpc.pcrValue.size */
		    if(TPM_HASH_SIZE*(numPCRs+1)>tpc.pcrValue.size) {
			    fprintf(outStream, "Error: malformed PCR structure\n");
			    exit(-1);
		    }
		    fprintf(outStream, "PCR %.2d ",i);
		    for(j=0;j<TPM_HASH_SIZE;j++) {
			    fprintf(outStream, "%.2x",tpc.pcrValue.buffer[TPM_HASH_SIZE*numPCRs+j]);
		    }
		    fprintf(outStream, "\n");
		    numPCRs++;
	    }
    }
    
    free(tpc.pcrValue.buffer);
    exit(ret);
}

