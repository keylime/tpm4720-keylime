/********************************************************************************/
/*										*/
/*		    TCPA Apply a time stamp to a blob                           */
/*			     Written by Stefan Berger				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*	      $Id: tickstampblob.c 4702 2013-01-03 21:26:29Z kgoldman $		*/
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
#include "tpmfunc.h"

/* local prototypes */

static void printUsage() {
	printf("Usage: tickstampblob -ic <blob> -hk <keyhandle> [-pwdk <usage password>]\n"
	       "\n"
	       "-ic <blob>      : Some arbitrary message to sign.\n"
	       "-hk <keyhandle> : The keyhandle in hex of a key that can do signing.\n"
	       "-pwdk <usage pwd> : key usage password, if key has one\n"
	       "-ss der|info     : validate signature according to DER or INFO signing\n"
	       "                 scheme\n"
	       "\n");
	exit(-1);
}


int main(int argc, char *argv[])
{
	int ret = 0;
	unsigned char tickBuff[TPM_CURRENT_TICKS_SIZE];
	STACK_TPM_BUFFER(signature);
	unsigned char usageAuth[TPM_DIGEST_SIZE];
	unsigned char digestToStamp[TPM_DIGEST_SIZE];
	unsigned char antiReplay[TPM_NONCE_SIZE];
	char * message = NULL;
	uint32_t keyhandle = -1;
	char * usagePass = NULL;
	unsigned char * passptr1 = NULL;
	uint16_t sigscheme = TPM_SS_RSASSAPKCS1v15_SHA1;
	int i =	0;
	TPM_setlog(0);

	i = 1;
	TSS_gennonce(antiReplay);

	while (i < argc) {
		
		if (!strcmp("-ic",argv[i])) {
			i++;
			if (i < argc) {
				message = argv[i];
			} else {
				printf("Missing mandatory parameter for -ic.\n");
				printUsage();
			}
		} else
		if (!strcmp("-pwdk",argv[i])) {
			i++;
			if (i < argc) {
				usagePass = argv[i];
			} else {
				printf("Missing mandatory parameter for -pwdk.\n");
				printUsage();
			}
		} else
		if (!strcmp("-hk",argv[i])) {
			i++;
			if (i < argc) {
				sscanf(argv[i],"%x",&keyhandle);
			} else {
				printf("Missing mandatory parameter for -hk.\n");
				printUsage();
			}
		} else
		if (!strcmp(argv[i], "-ss")) {
		    i++;
		    if (i < argc) {
			if (!strcmp(argv[i], "info")) {
			    sigscheme = TPM_SS_RSASSAPKCS1v15_INFO;
			}
			else if (!strcmp(argv[i], "der")) {
			    sigscheme = TPM_SS_RSASSAPKCS1v15_DER;
			}
			else {
			    printf("Bad parameter for -ss\n");
			    printUsage();
			}
		    }
		    else {
			printf("Missing parameter for -ss\n");
			printUsage();
		    }
		} else
		if (!strcmp("-v",argv[i])) {
			TPM_setlog(1);
		} else
		    if (!strcmp("-h",argv[i])) {
			printUsage();
		} else {
			printf("\n%s is not a valid option\n", argv[i]);
			printUsage();
		}
		i++;
	}

	if (NULL == message ||
	    -1 == (int)keyhandle) {
		printf("Missing parameter.\n");
		printUsage();
	}
	
	TSS_sha1(message,strlen(message),digestToStamp);
	if (NULL != usagePass) {
		TSS_sha1(usagePass, strlen(usagePass), usageAuth);
		passptr1 = usageAuth;
	}

	ret = TPM_TickStampBlob(keyhandle,
	                        digestToStamp,
	                        passptr1,
	                        antiReplay,
	                        tickBuff,
	                        &signature);
	if (0 != ret) {
		printf("Error %s from TPM_TickStampBlob\n",
		       TPM_GetErrMsg(ret));
	} else {
		TPM_SIGN_INFO tsi;
		RSA *rsa;
		STACK_TPM_BUFFER( tsi_ser);
		STACK_TPM_BUFFER( serial );
		pubkeydata pubkey;	/* public key structure */

		ret = TPM_GetPubKey(keyhandle, passptr1, &pubkey);
		if (ret != 0) {
		          printf("tickstampblob: Error '%s' from TPM_GetPubKey\n", TPM_GetErrMsg(ret));
		          exit(-6);
                }
		rsa = TSS_convpubkey(&pubkey);
		if ( NULL == rsa) {
		          printf("Could not convert public key.\n");
		          exit(-7);
		}
		tsi.tag = TPM_TAG_SIGNINFO;
		memcpy(tsi.fixed, "TSTP", 4);
		memcpy(tsi.replay, antiReplay, TPM_NONCE_SIZE);
		memcpy(&serial.buffer[0], digestToStamp, sizeof(digestToStamp));
		memcpy(&serial.buffer[sizeof(digestToStamp)],
		                          tickBuff,
		                          sizeof(tickBuff));
                serial.used = sizeof(digestToStamp) + sizeof(tickBuff);
                tsi.data.size = serial.used;
                tsi.data.buffer = serial.buffer;

                ret = TPM_WriteSignInfo(&tsi_ser, &tsi);
                if ((ret & ERR_MASK)) {
                        printf("Error serializing the SignInfo structure.\n");
                        exit(-8);
                }
		
		ret = TPM_ValidateSignature(sigscheme,
		                            &tsi_ser,
		                            &signature,
		                            rsa);
                if ( ret != 0) {
                          printf("Error validating the signature.\n");
                          exit(-1);
                }
	}
 	exit(ret);
}
