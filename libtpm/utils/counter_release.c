/********************************************************************************/
/*										*/
/*			    TCPA Release a counter				*/
/*			     Written by Stefan Berger				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*	      $Id: counter_release.c 4702 2013-01-03 21:26:29Z kgoldman $	*/
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
#include <unistd.h>

#ifdef TPM_POSIX
#include <netinet/in.h>
#endif
#ifdef TPM_WINDOWS
#include <winsock2.h>
#endif

#include "tpm.h"
#include "tpmutil.h"
#include "tpmfunc.h"
#include "tpm_constants.h"
#include "tpm_structures.h"


static void usage() {
	printf("Usage: counter_release -ix id [-v]\n");
	printf("\n");
	printf("One of these authorizations:\n");
	printf("[-pwdo  <owner password>\n");
	printf("[-pwdof <owner authorization file name>\n");
	printf("[-pwdc  <counter password\n");
	printf(" -ix id          : The id of the counter.\n");
	printf(" -v              : Enable verbose output.\n");
	printf("\n");
	printf("Examples:\n");
	printf("counter_release -pwdo aaa -ix 5\n"
	       "counter_release -ix 5 -pwdc ctr1\n");
	exit(-1);
}

int main(int argc, char * argv[])
{
    uint32_t ret;
    int i;
    const char * ownerPassword = NULL;
    const char *ownerAuthFilename = NULL;
    const char * counterPassword = NULL;
    unsigned char * ownerAuthPtr = NULL;
    unsigned char * counterAuthPtr = NULL;
    unsigned char ownerAuth[TPM_HASH_SIZE];
    unsigned char counterAuth[TPM_HASH_SIZE];	
    uint32_t id = -1;
	
    TPM_setlog(0);
	
    for (i=1 ; i<argc ; i++) {
	if (!strcmp("-pwdo",argv[i])) {
	    i++;
	    if (i < argc) {
		ownerPassword = argv[i];
	    } else {
		printf("Missing parameter for -pwdo.\n");
		usage();
	    }
	}
	else if (strcmp(argv[i],"-pwdof") == 0) {
	    i++;
	    if (i < argc) {
		ownerAuthFilename = argv[i];
	    }
	    else {
		printf("Missing parameter for -pwdof.\n");
		usage();
	    }
	}
	else if (!strcmp("-pwdc",argv[i])) {
	    i++;
	    if (i < argc) {
		counterPassword = argv[i];
	    } else {
		printf("Missing parameter for -pwdc.\n");
		usage();
	    }
	}
	else if (!strcmp("-ix",argv[i])) {
	    i++;
	    if (i < argc) {
		id = atoi(argv[i]);
	    } else {
		printf("Missing mandatory parameter for -ix.\n");
		usage();
	    }
	}
	else if (!strcmp("-v",argv[i])) {
	    TPM_setlog(1);
	}
	else if (!strcmp("-h",argv[i])) {
	    usage();
	}
	else {
	    printf("\n%s is not a valid option\n",argv[i]);
	    usage();
	}
    }

    if ((int)id < 0) {
	printf("Input parameter -idx missing or invalid\n");
	usage();
    }

    /* use the SHA1 hash of the password string as the Owner Authorization Data */
    if (ownerPassword != NULL) {
	TSS_sha1((unsigned char *)ownerPassword,
		 strlen(ownerPassword),
		 ownerAuth);
	ownerAuthPtr = ownerAuth;
    }
    /* get the ownerAuth from a file */
    else if (ownerAuthFilename != NULL) {
	unsigned char *buffer = NULL;
	uint32_t buffersize;
	ret = TPM_ReadFile(ownerAuthFilename, &buffer, &buffersize);
	if ((ret & ERR_MASK)) {
	    printf("Error reading %s.\n", ownerAuthFilename);
	    exit(-1);
	}
	if (buffersize != sizeof(ownerAuth)) {
	    printf("Error reading %s, size %u should be %lu.\n",
		   ownerAuthFilename, buffersize, (unsigned long)sizeof(ownerAuth));
	    exit(-1);
	}
	memcpy(ownerAuth, buffer, sizeof(ownerAuth));
	ownerAuthPtr = ownerAuth;
	free(buffer);
    }
    else if (counterPassword != NULL) {
	TSS_sha1((unsigned char *)counterPassword,
				  strlen(counterPassword),
				  counterAuth);
	counterAuthPtr = counterAuth;
    }
    else {
	printf("Input authorization -pwdo or -pwdof or -pwdc missing\n");
	usage();
    }


    if (counterAuthPtr != NULL) {
	ret= TPM_ReleaseCounter(id, counterAuthPtr);
	if (ret != 0) {
	    printf("Got error '%s' (0x%x) from TPM_ReleaseCounter.\n",
		   TPM_GetErrMsg(ret),
		   ret);
	}
    }
    else {
	ret = TPM_ReleaseCounterOwner(id, ownerAuthPtr);
	if (ret != 0) {
	    printf("Got error '%s' (0x%x) from TPM_ReleaseCounterOwner.\n",
		   TPM_GetErrMsg(ret),
		   ret);
	}
    }

    if (ret == 0) {
	printf("Successfully released the counter.\n");
    }

    return ret;
}
