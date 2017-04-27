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

int GetRSAKey(RSA **rsa,
	      X509 *x509Certificate);
uint32_t TPM_ValidatePCRCompositeSignatureRSA(TPM_PCR_COMPOSITE *tpc,
					      unsigned char *antiReplay,
					      RSA *rsaKey,
					      struct tpm_buffer *signature,
					      uint16_t sigscheme);

static void printUsage(void);

//void printHash(char *name, void *ptr, unsigned int len);

int main(int argc, char *argv[])
{
    int ret;			/* general return value */
    unsigned char nonce[TPM_NONCE_SIZE];	/* nonce data */
    static char *nonceval = NULL; /* nonce value passed in by user */

    STACK_TPM_BUFFER(signature);
    pubkeydata pubkey;	/* public key structure */
    STACK_TPM_BUFFER (ser_tpc);
    STACK_TPM_BUFFER (ser_tqi);
    STACK_TPM_BUFFER (response);
    int i;
    uint16_t sigscheme = TPM_SS_RSASSAPKCS1v15_SHA1;
    TPM_STORE_PUBKEY_EMB verifiedPubkey;
   	STACK_TPM_BUFFER( serQuoteInfo )
   	RSA *rsa;			/* openssl RSA public key */

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
		printUsage();
	    }
	}
	else if (!strcmp(argv[i], "-quote")) {
	    i++;
	    if (i < argc) {
		quoteFilename = argv[i];
	    }
	    else {
		printf("Missing parameter to -quote\n");
		printUsage();
	    }
	}
    else if (!strcmp(argv[i],"-nonce")) {
        i++;
        if (i < argc) {
        nonceval = argv[i];
        }
        else {
        printf("Missing parameter to -nonce\n");
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
    
    if ((quoteFilename == NULL) ||
	(keyFilename == NULL) ||
	(nonceval == NULL)) {
	printf("Missing argument\n");
	printUsage();
    }
    
    /*  hash nonceval to create nonce data */
    TSS_sha1((unsigned char *)nonceval,strlen(nonceval),nonce);

    /* read in quote from file */
    if((fp = fopen(quoteFilename,"r"))==0) {
    printf("Error opening file %s.\n",quoteFilename);
    exit(-1);
    }    
    if(fread(&serQuoteInfo,sizeof(struct tpm_buffer),1,fp)<1) {
    printf("Error reading serQuoteInfo.\n");
    exit(-1);
    }
    if(fread(&signature,sizeof(struct tpm_buffer),1,fp)<1) {
    printf("Error reading signature.\n");
    exit(-1);
    }
    if(fread(&pubkey,sizeof(pubkey),1,fp)<1) {
    printf("Error reading pubkey.\n");
    exit(-1);
    }
    fclose(fp);
    
    /* read and then check aik in structure against the one passed in */
    if((fp = fopen(keyFilename,"r"))==0) {
    printf("Error opening file %s.\n",keyFilename);
    exit(-1);
    }
    if(fread(&verifiedPubkey.keyLength,sizeof(uint32_t),1,fp)<1) {
    printf("Error reading pub key len\n");
    exit(-1);
    }
    if(sizeof(BYTE)*verifiedPubkey.keyLength>sizeof(verifiedPubkey.modulus)) {
    printf("Error verified aik malformed, length %lu > %lu",sizeof(BYTE)*verifiedPubkey.keyLength,sizeof(verifiedPubkey.modulus));
    exit(-1);
    }
    if(fread(&verifiedPubkey.modulus,sizeof(BYTE),verifiedPubkey.keyLength,fp)<verifiedPubkey.keyLength) {
    printf("Error reading verified public key.\n");
    exit(-1);
    }
    fclose(fp);
    
    if(verifiedPubkey.keyLength!=pubkey.pubKey.keyLength ||
       memcmp(&verifiedPubkey.modulus,&pubkey.pubKey.modulus,sizeof(BYTE)*verifiedPubkey.keyLength)!=0) {
    printf("Error public key in quote does not match key specified by -aik: %s\n",keyFilename);
    exit(-1);
    } 	
        
    /*
	** convert to an OpenSSL RSA public key
	*/
	rsa = TSS_convpubkey(&pubkey);
	
	ret = TPM_ValidateSignature(sigscheme,
	                            &serQuoteInfo,
	                            &signature,
	                            rsa);
	if (ret != 0) {
		printf("Verification failed\n");
	} else {
		printf("Verification succeeded\n");
	}
    
    
    /*
	printf("PCR contents from quote:\n");
	
	for(i=0;i<tpc.select.sizeOfSelect*CHAR_BIT;i++) {
		if((tpc.select.pcrSelect[i/8] & (1<<(i&0x7)))>0) {
		unsigned int j=0;
		// check tpc.pcrValue.size 
		if(TPM_HASH_SIZE*(numPCRs+1)>tpc.pcrValue.size) {
			printf("Error: malformed PCR structure\n");
			exit(-1);
		}
		printf("PCR %.2d ",i);
		for(j=0;j<TPM_HASH_SIZE;j++) {
			printf("%.2x",tpc.pcrValue.buffer[TPM_HASH_SIZE*numPCRs+j]);
		}
		printf("\n");
		numPCRs++;
		}
	}
    
    free(tpc.pcrValue.buffer);
    */
    
    
    exit(ret);
}

static void printUsage()
{
    printf("Usage: checkquote\n"
	   "-aik <file containing key length and aik modulus> \n"
	   "-quote <quote.bin>\n"
       "-nonce <random value>\n");
    exit(-1);
}

// void printHash(char *name, void *ptr, unsigned int len) {
// 	unsigned char print[TPM_HASH_SIZE];
// 	TSS_sha1((unsigned char *)ptr,len,print);
// 	unsigned int i =0;
// 	
// 	printf("%s:\t",name);
// 	for(i=0;i<TPM_HASH_SIZE;i++) {
// 		printf("%.2X ",print[i]);
// 	}
// 	printf("\n");
// }
