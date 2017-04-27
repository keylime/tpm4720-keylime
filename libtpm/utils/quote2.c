/********************************************************************************/
/*										*/
/*			     	TPM Test of TPM Quote2				*/
/*			     Written by J. Kravitz, S. Berger			*/
/*		       IBM Thomas J. Watson Research Center			*/
/*	      $Id: quote2.c 4702 2013-01-03 21:26:29Z kgoldman $		*/
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

static void printUsage(void);

int main(int argc, char *argv[])
{
	int ret;			/* general return value */
	uint32_t keyhandle = 0;		/* handle of quote key */
	unsigned int  pcrmask = 0;	/* pcr register mask */
	unsigned char passhash1[TPM_HASH_SIZE];	/* hash of key password */
	unsigned char data[TPM_HASH_SIZE];/* nonce data */
	
	STACK_TPM_BUFFER(signature);
	pubkeydata  pubkey;		/* public key structure */
	RSA *rsa;			/* openssl RSA public key */
	unsigned char *passptr;
	TPM_PCR_SELECTION selection;
	TPM_PCR_INFO_SHORT s1;
	TPM_QUOTE_INFO2 quoteinfo;
	STACK_TPM_BUFFER( serQuoteInfo )
	uint32_t pcrs;
	int i;
	uint16_t sigscheme = TPM_SS_RSASSAPKCS1v15_SHA1;
	TPM_BOOL addVersion = FALSE;
	STACK_TPM_BUFFER(versionblob);
	static char *keypass = NULL;

	
	TPM_setlog(0);    /* turn off verbose output from TPM driver */
	for (i=1 ; i<argc ; i++) {
	    if (strcmp(argv[i],"-hk") == 0) {
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
	    else if (strcmp(argv[i],"-bm") == 0) {
		i++;
		if (i < argc) {
		    /* convert key handle from hex */
		    if (1 != sscanf(argv[i], "%x", &pcrmask)) {
			printf("Invalid -bm argument '%s'\n",argv[i]);
			exit(2);
		    }
		}
		else {
		    printf("-bm option needs a value\n");
		    printUsage();
		}
	    }
	    else if (!strcmp(argv[i], "-vinfo")) {
		addVersion = TRUE;
		printf("Adding version info.\n");
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
	    (pcrmask == 0)) {
	    printf("Missing argument\n");
	    printUsage();
	}
	memset(&s1, 0x0, sizeof(s1));	
	/*
	** Parse and process the command line arguments
	*/
	/* get the SHA1 hash of the password string for use as the Key Authorization Data */
	if (keypass != NULL) {
	    TSS_sha1((unsigned char *)keypass,strlen(keypass),passhash1);
		passptr = passhash1;
	} else {
		passptr = NULL;
	}
	/* for testing, use the password hash as the test nonce */
	memcpy(data,passhash1,TPM_HASH_SIZE);
	
	ret = TPM_GetNumPCRRegisters(&pcrs);
	if (ret != 0) {
		printf("Error reading number of PCR registers.\n");
		exit(-1);
	}
	if (pcrs > TPM_NUM_PCR) {
		printf("Library does not support that many PCRs.\n");
		exit(-1);
	}

	memset(&selection, 0x0, sizeof(selection));
	selection.sizeOfSelect = pcrs / 8;
	for (i = 0; i < selection.sizeOfSelect; i++) {
		selection.pcrSelect[i] = (pcrmask & 0xff);
		pcrmask >>= 8;
	}

	/*
	** perform the TPM Quote function
	*/
	ret = TPM_Quote2(keyhandle,	/* key handle */
	                 &selection,	/* specify PCR registers */
	                 addVersion,    /* add Version */
	                 passptr,	/* Key Password (hashed), or null */
	                 data,		/* nonce data */
	                 &s1,		/* pointer to pcr info */
	                 &versionblob,	/* pointer to TPM_CAP_VERSION_INFO */
	                 &signature);	/* buffer to receive result, int to receive result length */
	if (ret != 0) {
		printf("Error '%s' from TPM_Quote2\n",TPM_GetErrMsg(ret));
		exit(ret);
	}
	/*
	** Get the public key and convert to an OpenSSL RSA public key
	*/
	ret = TPM_GetPubKey(keyhandle,passptr,&pubkey);
	if (ret != 0) {
		printf("quote2: Error '%s' from TPM_GetPubKey\n",TPM_GetErrMsg(ret));
		exit(ret);
	}
	rsa = TSS_convpubkey(&pubkey);
	
	
	/*
	** fill the quote info structure and calculate the hashes needed for verification
	*/
	quoteinfo.tag = TPM_TAG_QUOTE_INFO2;
	memcpy(&(quoteinfo.fixed),"QUT2",4);
	quoteinfo.infoShort = s1;
	memcpy(&(quoteinfo.externalData),data,TPM_NONCE_SIZE);

	/* create the hash of the quoteinfo structure for signature verification */
	ret = TPM_WriteQuoteInfo2(&serQuoteInfo, &quoteinfo);
	if ( ( ret & ERR_MASK ) != 0) {
		exit(-1);
	}

	/* append version information if given in response */
	if (addVersion) {
	    memcpy(serQuoteInfo.buffer + serQuoteInfo.used,
	           versionblob.buffer,
	           versionblob.used);
	    serQuoteInfo.used += versionblob.used;
	}
	
	ret = TPM_ValidateSignature(sigscheme,
	                            &serQuoteInfo,
	                            &signature,
	                            rsa);
	if (ret != 0) {
		printf("Verification failed\n");
	} else {
		printf("Verification succeeded\n");
	}
	RSA_free(rsa);
	exit(ret);
}

static void printUsage(void)
{
    printf("Usage: quote2 [options] -hk <key handle in hex> -bm <pcr mask in hex>\n"
	   "              [-pwdk <key password>]\n"
	   "\n"
	   "Available options:\n"
	   "-vinfo    : have TPM_CAP_VERSION_INFO returned in the response\n"
	   "\n");
    exit(-1);
}
