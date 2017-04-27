/********************************************************************************/
/*										*/
/*			     	TPM Get the signed audit digest			*/
/*			     Written by S. Berger				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*	      $Id: getauditdigestsigned.c 4702 2013-01-03 21:26:29Z kgoldman $	*/
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
	printf("Usage: getauditdigestsigned -h <key handle> [-p <key password>] -s <start ordinal>  [-v]\n"
	       "\n"
	       "-s    : option to pass the start ordinal for the audit\n"
	       "-v    : turns on verbose mode\n"
	       "\n");
	exit(-1);
}

int main(int argc, char *argv[])
{
	uint32_t startOrdinal = -1;
	int ret;
	int verbose = FALSE;
	TPM_COUNTER_VALUE counter;
	int i = 1;
	char * keypass = NULL;
	unsigned char keyAuth[TPM_HASH_SIZE];
	unsigned char * keyAuthPtr = NULL;
	uint32_t keyhandle = -1;
	STACK_TPM_BUFFER(signature);
	unsigned char digest[TPM_DIGEST_SIZE];
	unsigned char ordinalDigest[TPM_DIGEST_SIZE];
	unsigned char antiReplay[TPM_NONCE_SIZE];
	
	TPM_setlog(0);
	TSS_gennonce(antiReplay);
	
	while (i < argc) {
		if (!strcmp("-s",argv[i])) {
			i++;
			if (i < argc) {
				sscanf(argv[i],"%d",&startOrdinal);
			} else {
				printf("Missing parameter for -s.\n");
				usage();
			}
		} else
		if (!strcmp("-h",argv[i])) {
			i++;
			if (i < argc) {
				sscanf(argv[i],"%x",&keyhandle);
			} else {
				printf("Missing parameter for -h.\n");
				usage();
			}
		} else
		if (!strcmp("-p",argv[i])) {
			i++;
			if (i < argc) {
				keypass = argv[i];
			} else {
				printf("Missing parameter for -p.\n");
				usage();
			}
		} else
		if (!strcmp("-v",argv[i])) {
			verbose = TRUE;
			TPM_setlog(1);
		} else {
		        printf("\n%s is not a valid option\n", argv[i]);
			usage();
		}
		i++;
	}
	(void)verbose;

	if (-1 == (int)startOrdinal ||
	    -1 == (int)keyhandle) {
		printf("Missing command line parameter.\n");
		usage();
	}

	if (NULL != keypass) {
		TSS_sha1(keypass,strlen(keypass),keyAuth);
		keyAuthPtr = keyAuth;
	}
	ret = TPM_GetAuditDigestSigned(keyhandle,
	                               FALSE,
	                               keyAuthPtr,
	                               antiReplay,
	                               &counter,
	                               digest,
	                               ordinalDigest,
	                               &signature);

	if (0 != ret) {
		printf("Error %s from GetAuditDigestSigned.\n",
		       TPM_GetErrMsg(ret));
	} else {
		TPM_SIGN_INFO tsi;
		STACK_TPM_BUFFER(tsi_ser);
		STACK_TPM_BUFFER(serial);
		STACK_TPM_BUFFER(ctr_ser);
		pubkeydata pubkey;
		RSA *rsa;

		i = 0;
		printf("AuditDigest   : ");
		while (i < (int)sizeof(digest)) {
			printf("%02X",digest[i]);
			i++;
		}
		printf("\n");
	
		i = 0;
		printf("OrdinalDigest : ");
		while (i < (int)sizeof(digest)) {
			printf("%02X",ordinalDigest[i]);
			i++;
		}
		printf("\n");

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
		
		tsi.tag = TPM_TAG_SIGNINFO;
		memcpy(tsi.fixed, "ADIG", 4);
		memcpy(tsi.replay, antiReplay, sizeof(antiReplay));
		/* D4=ordinalDigest */
		TPM_WriteCounterValue(&ctr_ser, &counter);
		memcpy(&serial.buffer[0], digest, sizeof(digest));
		memcpy(&serial.buffer[sizeof(digest)],
		                          ctr_ser.buffer, ctr_ser.used);
		memcpy(&serial.buffer[sizeof(digest)+ctr_ser.used],
		                          ordinalDigest, sizeof(ordinalDigest));
		serial.used = sizeof(digest) + ctr_ser.used + sizeof(ordinalDigest);
		tsi.data.size = serial.used;
		tsi.data.buffer = serial.buffer; 
		ret = TPM_WriteSignInfo(&tsi_ser, &tsi);
		if ((ret & ERR_MASK)) {
			printf("Error serializing TPM_SIGN_INFO.\n");
			exit(-1);
		}
		ret = TPM_ValidateSignature(TPM_SS_RSASSAPKCS1v15_SHA1,
		                            &tsi_ser,
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
