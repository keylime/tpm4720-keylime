/********************************************************************************/
/*										*/
/*			     	TPM CMK_ApproveMA                             	*/
/*			     Written by S. Berger				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*	      $Id: cmk_createticket.c 4702 2013-01-03 21:26:29Z kgoldman $	*/
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
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
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

/* local prototypes */


static void usage() {
	printf("Usage: cmk_createticket -pwdo <owner password> -ik <keyfile>\n"
	       "                        -ic <message> -is <signature file> -ot <filename> [-v]\n"
	       "\n"
	       " -pwdo pwd    : the TPM owner password\n"
	       " -ik filename : a file containing a public key\n"
	       " -ic message  : message to be verified\n"
	       " -is filename : signature file name\n"
	       " -ot filename : signature ticket file\n"
	       " -v           : to enable verbose output\n"
	       "\n"
	       "Examples:\n"
	       "cmk_createticket -pwdo aaa -ik stkey.key -of ticket.bin \n");
}


int main(int argc, char *argv[])
{
	unsigned char passhash1[TPM_HASH_SIZE];
	unsigned char ticket[TPM_HASH_SIZE];
	char * ownerpass = NULL;
	char * filename = NULL;
	char * keyfile = NULL;
	int ret;
	int verbose = FALSE;
	
	unsigned char signedData[TPM_HASH_SIZE];
	keydata key;
	char * signature_file = NULL;
	unsigned char * signatureValue = NULL;
	uint32_t signatureValueSize = 0;
	
	char * message = NULL;
	
	int i = 1;
	
	TPM_setlog(0);
	
	while (i < argc) {
		if (!strcmp("-pwdo",argv[i])) {
			i++;
			if (i < argc) {
				ownerpass = argv[i];
			} else {
				printf("Missing parameter for -pwdo.\n");
				usage();
				exit(-1);
			}
		} else
		if (!strcmp("-ot",argv[i])) {
			i++;
			if (i < argc) {
				filename = argv[i];
			} else {
				printf("Missing parameter for -ot.\n");
				usage();
				exit(-1);
			}
		} else
		if (!strcmp("-ik",argv[i])) {
			i++;
			if (i < argc) {
				keyfile = argv[i];
			} else {
				printf("Missing parameter for -ik.\n");
				usage();
				exit(-1);
			}
		} else
		if (!strcmp("-ic",argv[i])) {
			i++;
			if (i < argc) {
				message = argv[i];
			} else {
				printf("Missing parameter for -ic.\n");
				usage();
				exit(-1);
			}
		} else
		if (!strcmp("-is",argv[i])) {
		        i++;
			if (i < argc) {
			    signature_file = argv[i];
			} else {
			    printf("Missing parameter for -is.\n");
			    usage();
			    exit(-1);
			}
		} else
		if (!strcmp("-v",argv[i])) {
			verbose = TRUE;
			TPM_setlog(1);
		} else
		if (!strcmp("-h",argv[i])) {
		        usage();
		        exit(-1);
		} else {
		        printf("\n%s is not a valid option\n",argv[i]);
			usage();
			exit(-1);
		}
		i++;
	}

	(void)verbose;

	if (NULL == ownerpass ||
	    NULL == filename  ||
	    NULL == keyfile   ||
	    NULL == message   ||
	    NULL == signature_file) {
		printf("Missing argument.\n");
		usage();
		exit(-1);
	}
	
	TSS_sha1(ownerpass,strlen(ownerpass),passhash1);
	TSS_sha1(message, strlen(message), signedData);
	ret = TPM_ReadFile(signature_file,
	                   &signatureValue,
	                   &signatureValueSize);
	if ((ret & ERR_MASK) != 0) {
		printf("Error occurred while trying to load the signature file.\n");
		exit(-1);
	}
	
	/*
	 * Read the key...
	 */
	ret = TPM_ReadKeyfile(keyfile, &key);
	if ((ret & ERR_MASK) != 0) {
		printf("Error occurred while trying to load the key.\n");
		exit(-1);
	}
	
   	ret = TPM_CMK_CreateTicket(&key,
   	                           signedData,
	                           signatureValue, signatureValueSize,
	                           passhash1,
	                           ticket);

	if (0 != ret) {
		printf("CMK_CreateTicket returned error %s.\n",
		       TPM_GetErrMsg(ret));
	} else {
		FILE * f = fopen(filename, "wb+");
		if (f != NULL) {
			if (TPM_DIGEST_SIZE == fwrite(ticket, 1, TPM_DIGEST_SIZE, f)) {
				printf("Successfully wrote ticket to %s.\n",
				       filename);
			}
			fclose(f);
			
		} else {
			printf("Could not open file %s for writing.\n",
			       filename);
		}
	}

	exit(ret);
}
