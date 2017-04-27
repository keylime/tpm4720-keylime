/********************************************************************************/
/*										*/
/*			     	TPM Certify the self test			*/
/*			     Written by S. Berger				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*	      $Id: certifyselftest.c 4702 2013-01-03 21:26:29Z kgoldman $	*/
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

#include "tpm.h"
#include "tpmutil.h"
#include <tpmfunc.h>

static void usage() {
	printf("Usage: certifyselftest -h <key handle> [-p <key password>] [-v]\n"
	       "\n"
	       "-v    : turns on verbose mode\n"
	       "\n");
}

int main(int argc, char *argv[])
{
	int ret;
	int verbose = FALSE;
	int i = 1;
	char * keypass = NULL;
	unsigned char keyAuth[TPM_HASH_SIZE];
	unsigned char * keyAuthPtr = NULL;
	uint32_t keyhandle = -1;
	STACK_TPM_BUFFER(signature);
	unsigned char antiReplay[TPM_NONCE_SIZE];
	
	TPM_setlog(0);
	TSS_gennonce(antiReplay);
	
	while (i < argc) {
		if (!strcmp("-h",argv[i])) {
			i++;
			if (i < argc) {
				sscanf(argv[i],"%x",&keyhandle);
			} else {
				printf("Missing parameter for -h.\n");
				usage();
				exit(-1);
			}
		} else
		if (!strcmp("-p",argv[i])) {
			i++;
			if (i < argc) {
				keypass = argv[i];
			} else {
				printf("Missing parameter for -p.\n");
				usage();
				exit(-1);
			}
		} else
		if (!strcmp("-v",argv[i])) {
			verbose = TRUE;
			TPM_setlog(1);
		} else {
		    printf("\n%s is not a valid option\n",argv[i]);
		    usage();
		    exit(-1);
		}
		i++;
	}
	(void)verbose;
	
	if (-1 == (int)keyhandle) {
		printf("Missing command line parameter -h.\n");
		usage();
		exit(1);
	}

	if (NULL != keypass) {
		TSS_sha1(keypass,strlen(keypass),keyAuth);
		keyAuthPtr = keyAuth;
	}

	ret = TPM_CertifySelfTest(keyhandle,
	                          keyAuthPtr,
	                          antiReplay,
	                          &signature);

	if (0 != ret) {
		printf("Error %s from Certifyselftest.\n",
		       TPM_GetErrMsg(ret));
	} else {
		STACK_TPM_BUFFER(serial);
		pubkeydata pubkey;
		RSA *rsa;
		uint32_t ordinal_no = htonl(TPM_ORD_CertifySelfTest);

		ret = TPM_GetPubKey(keyhandle, keyAuthPtr, &pubkey);
		if (ret != 0) {
			printf("Could not get public key of signing key.\n");
			exit(-1);
		}
		rsa = TSS_convpubkey(&pubkey);
		if (!rsa) {
			printf("Could not convert public key.\n");
			exit(-1);
		}
		
		memcpy(&serial.buffer[0], "Test Passed", 11);
		memcpy(&serial.buffer[11], antiReplay, 20);
		memcpy(&serial.buffer[20+11],
		                           &ordinal_no, 4);
		serial.used = 11+20+4;
		                           
		
		ret = TPM_ValidateSignature(TPM_SS_RSASSAPKCS1v15_SHA1,
		                            &serial,
		                            &signature,
		                            rsa);
		if (ret != 0) {
			printf("Error validating signature.\n");
			exit(-1);
		}
		printf("Signature verification successful.\n");
	}
	exit(ret);
}
