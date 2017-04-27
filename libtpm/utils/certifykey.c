/********************************************************************************/
/*										*/
/*			     	TPM Certify a key				*/
/*			     Written by S. Berger				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*	      $Id: certifykey.c 4702 2013-01-03 21:26:29Z kgoldman $		*/
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
#include <openssl/rsa.h>

   
static void ParseArgs(int argc, char *argv[]);
static void printUsage(void);

static char * keypass = NULL;
static char * certkeypass = NULL;
static char * msa_list_filename = NULL;
static uint32_t keyhandle = 0;                       /* handle of key */
static uint32_t certkeyhandle = 0;                   /* handle of certifying key */
static char *outputfile = NULL;


int main(int argc, char *argv[]) {
	int ret;
	unsigned char passhash[TPM_HASH_SIZE];	  /* hash of parent key password */
	unsigned char passhash2[TPM_HASH_SIZE];	  /* hash of parent key password */
	unsigned char *passptr;
	unsigned char *passptr2;
	TPM_MSA_COMPOSITE msaList;
	STACK_TPM_BUFFER(signature);
	STACK_TPM_BUFFER(certifyInfo_ser);
	pubkeydata pubkey;
	RSA *rsa;
	
	TPM_setlog(0);						/* turn off verbose output */
	ParseArgs(argc, argv);

	if ((keyhandle == 0) ||
	    (certkeyhandle == 0) ||
	    (outputfile == NULL)) {
	    printf("Missing argument\n");
	    printUsage();
	}
	/*
	** use the SHA1 hash of the password string as the Key Authorization Data
	*/
	if (keypass != NULL) {
		TSS_sha1(keypass,strlen(keypass),passhash);
		passptr = passhash;
	} else {
		passptr = NULL;
	}
	if (certkeypass != NULL) {
		TSS_sha1(certkeypass, strlen(certkeypass), passhash2);
		passptr2 = passhash2;
	} else {
		passptr2 = NULL;
	}
	if (NULL != msa_list_filename) {
		ret = TPM_ReadMSAFile(msa_list_filename, &msaList);
		if ( ( ret & ERR_MASK ) != 0 ) {
			printf("Error while reading msa list file.\n");
			exit(-1);
		}
	}
	if (NULL != passptr2 && NULL == passptr && NULL == msa_list_filename) {
		printf("You must provide a file to read the msa list from.\n");
		exit(-1);
	}
	if ( (NULL != passptr2 && NULL != msa_list_filename) ||
	      NULL != msa_list_filename ) {
		unsigned char migPubDigest[TPM_DIGEST_SIZE];
		ret = TPM_HashMSAComposite(&msaList, migPubDigest);
		if ( ( ret & ERR_MASK ) != 0) {
			printf("Error calculating hash over msa list.\n");
			exit(-1);
		}
		ret = TPM_CertifyKey2(certkeyhandle,
		                      keyhandle,
		                      migPubDigest,
		                      passptr2,
		                      passptr,
		                      &certifyInfo_ser,
		                      &signature);
		if (ret != 0) {
			printf("Error %s from TPM_CertifyKey2\n",
			       TPM_GetErrMsg(ret));
			exit(ret);
		}
	} else {
		ret = TPM_CertifyKey(certkeyhandle,
		                     keyhandle,
		                     passptr2,
		                     passptr,
		                     &certifyInfo_ser,
		                     &signature);
		if (ret != 0) {
			printf("Error %s from TPM_CertifyKey\n",
			       TPM_GetErrMsg(ret));
			exit(ret);
		}
	}

	ret = TPM_WriteFile(outputfile, certifyInfo_ser.buffer,
	                    certifyInfo_ser.used);
	if ((ret & ERR_MASK)) {
		printf("Error '%s' while writing file.\n",
		       TPM_GetErrMsg(ret));
	}

	ret = TPM_GetPubKey(certkeyhandle, passptr2, &pubkey);
	if (ret != 0) {
		printf("Error %s from GetPubKey(0x%08X).\n",
		       TPM_GetErrMsg(ret), certkeyhandle);
		exit(ret);
	}
	rsa = TSS_convpubkey(&pubkey);
	if (NULL == rsa) {
		printf("Could not convert key into RSA key format.\n");
		exit(-1);
	}
	/* validate signature */
	ret = TPM_ValidateSignature(TPM_SS_RSASSAPKCS1v15_SHA1,
	                            &certifyInfo_ser,
	                            &signature,
	                            rsa);
	if (ret != 0) {
		printf("Error validating the signature.\n");
		ret = -1;
	}
	
	RSA_free(rsa);
	exit(ret);
}

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
	else if (!strcmp(argv[i], "-pwdc")) {
	    i++;
	    if (i < argc) {
		certkeypass = argv[i];
	    }
	    else {
		printf("Missing parameter to -pwdc\n");
		printUsage();
	    }
	}
	else if (!strcmp(argv[i], "-msa")) {
	    i++;
	    if (i < argc) {
		msa_list_filename = argv[i];
	    }
	    else {
		printf("Missing parameter to -msa\n");
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
	else if (strcmp(argv[i],"-hc") == 0) {
	    i++;
	    if (i < argc) {
		/* convert key handle from hex */
		if (1 != sscanf(argv[i], "%x", &certkeyhandle)) {
		    printf("Invalid -hc argument '%s'\n",argv[i]);
		    exit(2);
		}
		if (certkeyhandle == 0) {
		    printf("Invalid -hc argument '%s'\n",argv[i]);
		    exit(2);
		}		 
	    }
	    else {
		printf("-hc option needs a value\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-of") == 0) {
	    i++;
	    if (i < argc) {
		outputfile = argv[i];
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
    return;
}



static void printUsage()
{
	printf("Usage: certifykey [options] <-hk key handle in hex> <-hc certifying key handle> -of <output file>\n"
	       "\n"
	       "Where the arguments are...\n"
	       "-hk <keyhandle>	             is the key handle in hex\n"
	       "-hc <certifying key handle>  handle of the key used for certification\n"
	       "-of <output file>            file where to write the certify info blob into\n"
	       "\n"
	       "Where the <options> are...\n"
	       " -pwdk <keypass>         to specify the key use password\n"
	       " -pwdc <cert. keypass>   to specify the key use password for the certifying key\n"
	       " -msa <msa list>         to specify a list with MSA entries; see cmk_approvema\n"
	       " -h                     print usage information (this message)\n");
	exit(-1);
}
