/********************************************************************************/
/*										*/
/*			 Create Revocable Endorsement Key                       */
/*			     Written by Stefan Berger				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*	      $Id: createrevek.c 4702 2013-01-03 21:26:29Z kgoldman $		*/
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

#ifdef TPM_POSIX
#include <netinet/in.h>
#endif
#ifdef TPM_WINDOWS
#include <winsock2.h>
#endif

#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/evp.h>


#include "tpm.h"
#include "tpmutil.h"
#include "tpmfunc.h"

/* local prototypes */


static void usage(){
	printf("Usage: createrevek [-pwdk password] [-v]\n"
	       "\n"
	       "-pwdk password : The password to be used with revoketrust\n"
	       "-v             : to enable verbose output\n"
	       "\n");
	exit(-1);
}

int main(int argc, char *argv[])
{
	int ret = 0;
	TPM_BOOL reset = TRUE;
	unsigned char *passptr1;
	char * password = NULL;
	unsigned char passhash1[20];    /* hash of password */
	pubkeydata pubek;
	int i = 1;
	
	TPM_setlog(0);
	
	while (i  < argc) {
	    if (!strcmp(argv[i],"-pwdk")) {
		i++;
		if (i >= argc) {
		    printf("Parameter missing for -pwdk option!\n");
		    usage();
		}
		reset = FALSE;
		password = argv[i];
	    }
	    else if (!strcmp(argv[i],"-v")) {
		TPM_setlog(1);
	    }
	    else if (!strcmp(argv[i],"-h")) {
		usage();
	    }
	    else {
		printf("\n%s is not a valid option\n",argv[i]);
		usage();
	    }
	    i++;
	}

	if (password != NULL) {
		TSS_sha1(password,strlen(password),passhash1);
		passptr1 = passhash1;
	}
	else {
	    passptr1 = NULL;
	}

	ret = TPM_CreateRevocableEK(reset, passptr1, &pubek);
	if (0 != ret) {
		printf("Error %s from TPM_CreateRevocableEK\n",
		       TPM_GetErrMsg(ret));
	} else {
		EVP_PKEY *pkey = NULL;                  /* OpenSSL public key */
		FILE * keyfile;
		RSA * rsa;
		/*
		 ** convert the returned public key to OpenSSL format and
		 ** export it to a file
		 */
		rsa = TSS_convpubkey(&pubek);
		if (rsa == NULL) {
			printf("Error from TSS_convpubkey\n");
			exit(-3);
		}
		OpenSSL_add_all_algorithms();
		pkey = EVP_PKEY_new();
		if (pkey == NULL) {
		    printf("Unable to create EVP_PKEY\n");
		    exit(-4);
		}
		ret = EVP_PKEY_assign_RSA(pkey,rsa);
		if (ret == 0) {
		    printf("Unable to assign public key to EVP_PKEY\n");
		    exit(-5);
		}
		keyfile = fopen("pubek.pem","wb");
		if (keyfile == NULL) {
			printf("Unable to create public key file\n");
			exit(-6);
		}
		ret = PEM_write_PUBKEY(keyfile,pkey);
		if (ret == 0) {
			printf("Unable to write public key file\n");
			exit(-7);
		}
		printf("pubek.pem successfully written\n");
		printf("Pubek keylength %d\nModulus:",pubek.pubKey.keyLength);
		for(i=0;i<(int)pubek.pubKey.keyLength;i++){
			if(!(i%16))
				printf("\n");
			printf("%02X ",pubek.pubKey.modulus[i]);
		}
		printf("\n");
		fclose(keyfile);
		EVP_PKEY_free(pkey);
		ret = 0;
	}
 	exit(ret);
}

