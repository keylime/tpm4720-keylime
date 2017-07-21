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
#include <errno.h>
#endif
#ifdef TPM_WINDOWS
#include <winsock2.h>
#endif
#include "tpmfunc.h"
#include "tpmutil.h"
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include "deepquote.h"    

static void printUsage()
{
    printf("Usage: quote\n"
	   "[-noverify]\n"
	   	   "-vk   <vTPM key handle for quote in hex>\n"
           "-vm   <vTPM pcr mask in hex>\n"
           "-hm   <hTPM pcr mask in hex>\n"
           "-pwdo <owner password>\n"
           "[-oq   <destination file for quote>]\n"
           "-nonce <random value>\n");
    exit(-1);
}


int main(int argc, char *argv[])
{
    int ret;			                    /* general return value */
    uint32_t keyhandle = 0;	                /* handle of quote key */
    int setkh = 0;
    unsigned int vpcrmask = 0;              /* virtual pcr register mask */
    unsigned int hpcrmask = 0;              /* hardware pcr register mask */
    unsigned char owner_hash[TPM_HASH_SIZE]; /* hash of owner password */
    unsigned char key_hash[TPM_HASH_SIZE]; /* hash of key password */
    unsigned char vq_nonce[TPM_NONCE_SIZE];    /* nonce data */
    unsigned char dq_nonce[TPM_NONCE_SIZE];    /* nonce data */
    static char *nonceval = NULL;           /* nonce value passed in by user */
    static char *ownerpw = NULL;            /* key password */
    static char *outputname = NULL;         /* file to write out the quote to */
    STACK_TPM_BUFFER (ser_tpc);
    STACK_TPM_BUFFER (ser_tqi);
    STACK_TPM_BUFFER (vinfo);
    uint32_t pcrs;
    TPM_PCR_SELECTION vtps;
    TPM_PCR_SELECTION htps;
    static char *keypass = NULL;
    unsigned char *key_hash_ptr;
    int i;
    DeepQuoteInfo dqi = {0,};
    STACK_TPM_BUFFER(signature);
    TPM_PCR_COMPOSITE tpc;
	SHA_CTX sha;
	
    TPM_setlog(0);	 /* turn off verbose output from TPM driver */
    for (i=1 ; i<argc ; i++) {
	if (strcmp(argv[i],"-vk") == 0) {
	    i++;
	    if (i < argc) {
		/* convert key handle from hex */
		if (1 != sscanf(argv[i], "%x", &keyhandle)) {
		    printf("Invalid -vk argument '%s'\n",argv[i]);
		    exit(2);
		}
		setkh =1;		 
	    }
	    else {
		printf("-vk option needs a value\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-vm") == 0) {
	    i++;
	    if (i < argc) {
			/* convert key handle from hex */
			if (1 != sscanf(argv[i], "%x", &vpcrmask)) {
			    printf("Invalid -vm argument '%s'\n",argv[i]);
			    exit(2);
			}
	    }
	    else {
		printf("-vm option needs a value\n");
		printUsage();
	    }
	}
	else if (!strcmp(argv[i], "-pwdo")) {
	    i++;
	    if (i < argc) {
		ownerpw = argv[i];
	    }
	    else {
		printf("Missing parameter to -pwdo\n");
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
	else if (!strcmp(argv[i], "-oq")) {
	    i++;
	    if (i < argc) {
		outputname = argv[i];
	    }
	    else {
		printf("Missing parameter to -oq\n");
		printUsage();
	    }
	}
        else if (strcmp(argv[i],"-hm") == 0) {
            i++;
            if (i < argc) {
                /* convert key handle from hex */
                if (1 != sscanf(argv[i], "%x", &hpcrmask)) {
                    printf("Invalid -hm argument '%s'\n",argv[i]);
                    exit(2);
                }
            }
            else {
                printf("-hm option needs a value\n");
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
    
    /* Check for required arguments */
    //CHECK_ARG(vpcrmask, "-vm");
    CHECK_ARG(setkh,"-vk");
    CHECK_ARG(hpcrmask, "-hm");
    CHECK_ARG(nonceval, "-nonce");
    CHECK_ARG(ownerpw,  "-pwdo");

    if(outputname==NULL)
    	outputname = "deepquote.bin";

    /* get the SHA1 hash of the password string for use as the Key Authorization Data */
    TSS_sha1((unsigned char *)ownerpw, strlen(ownerpw), owner_hash);
    
    /* get the SHA1 hash of the password string for use as the Key Authorization Data */
    if (keypass != NULL) {
        TSS_sha1((unsigned char *)keypass, strlen(keypass), key_hash);
        key_hash_ptr = key_hash;
    }
    else {
        key_hash_ptr = NULL;
    }
    
    /* hash nonceval to create nonce data */
    TSS_sha1((unsigned char *)nonceval,strlen(nonceval),vq_nonce);

    
    ret = TPM_GetNumPCRRegisters(&pcrs);
    if (ret != 0) 
	printExit("Error reading number of PCR registers.\n");

    if (pcrs > TPM_NUM_PCR) 
	printExit("Library does not support that many PCRs.\n");

    /* Convert selection to bitmask */
    vtps.sizeOfSelect = pcrs / 8;
    for (i = 0; i < vtps.sizeOfSelect; i++) {
	vtps.pcrSelect[i] = (vpcrmask & 0xff);
	vpcrmask >>= 8;
    }    
    /*
    ** perform the TPM Quote function
    */
    ret = TPM_Quote(keyhandle,	/* KEY handle */
		    key_hash_ptr,	/* Key Password (hashed), or null */
		    vq_nonce,	        /* nonce data */
		    &vtps,	        /* specify PCR registers */
		    &tpc,		/* pointer to pcr composite */
		    &signature);/* buffer to receive result, int to receive result length */
    if (ret != 0) {
	printf("Error '%s' from TPM_Quote\n", TPM_GetErrMsg(ret));
	exit(ret);
    }

    /* take the quote sig and TPC and hash them into the nonce for the deepquote */
	SHA1_Init(&sha);
	SHA1_Update(&sha, vq_nonce,     TPM_NONCE_SIZE);
	SHA1_Update(&sha, &signature,  sizeof(signature));
	SHA1_Update(&sha, &tpc.select,  sizeof(TPM_PCR_SELECTION));
	SHA1_Update(&sha, tpc.pcrValue.buffer, tpc.pcrValue.size);
	SHA1_Final(dq_nonce, &sha);

    /* Convert hw pcr selection to bitmask */
    htps.sizeOfSelect = pcrs / 8;
    for (i = 0; i < htps.sizeOfSelect; i++) {
        htps.pcrSelect[i] = (hpcrmask & 0xff);
        hpcrmask >>= 8;
    }

    /* do not propagate vtpm pcrs, we'll put it into the nonce */
    memset(&vtps.pcrSelect,0,vtps.sizeOfSelect);

    /*
    ** perform the TPM DeepQuote function
    */
    ret = TPM_DeepQuote(owner_hash,    /* Owner Password (hashed) */
                        dq_nonce,        /* nonce data */
                        &vtps,        /* specify vPCR registers */
                        &htps,        /* specify hardware PCR registers */
			&dqi);        /* Deep quote buffer to receive info */
    if (ret != 0) {
	fprintf(stderr, "Error '%s' from TPM_DeepQuote\n", TPM_GetErrMsg(ret));
	exit(ret);
    }

    /* Do a round trip on WriteDeepQuoteBin and ValidateDeepQuoteBin to test out the code */
    if ((ret = TPM_WriteDeepQuoteBin(outputname, &htps, &dqi, &signature, &tpc)) != 0) {
	fprintf(stderr, "Failed to open '%s\n'", outputname);
	return ret;
    }
    fprintf(stdout, "Wrote '%s'\n", outputname);

    return 0;
}
