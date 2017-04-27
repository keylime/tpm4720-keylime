/********************************************************************************/
/*										*/
/*			    TCPA Create a counter				*/
/*			     Written by Stefan Berger				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*	      $Id: counter_create.c 4702 2013-01-03 21:26:29Z kgoldman $	*/
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
#include "tpm_error.h"


static void usage() {
	printf("Usage: counter_create -pwdo <owner password> -la label -pwdc cntrpwd [-v]\n");
	printf("\t[-pwdo <owner password> -pwdof <owner authorization file name>\n");
	printf("\n");
	printf(" -pwdo           : The TPM owner password \n");
	printf(" -pwdof          : The TPM owner authorization file\n");
	printf(" -pwdc           : The counter password.\n");
	printf(" -la             : The label of the counter.\n");
	printf(" -v              : Enable verbose output.\n");
	printf("\n");
	printf("Examples:\n");
	printf("counter_create -pwdo ooo -la 1 -pwdc MyCounter\n");
	exit(-1);
}

int main(int argc, char * argv[])
{
    uint32_t ret;
    int i =	0;
    char * ownerPassword = NULL;
    const char *ownerAuthFilename = NULL;
    unsigned char ownerAuth[20];
    char * counterPassword = NULL;
    unsigned char counterAuth[20];	
    uint32_t parhandle;             /* handle of parent key */
    uint32_t label = 0xffffffff;
    uint32_t counterId = 0;
    unsigned char counterValue[TPM_COUNTER_VALUE_SIZE];
	
    i = 1;
	
    TPM_setlog(0);
	
    while (i < argc) {
	if (!strcmp("-pwdo",argv[i])) {
	    i++;
	    if (i < argc) {
		ownerPassword = argv[i];
	    } else {
		printf("Missing parameter for -pwdo\n");
		usage();
	    }
	}
	else if (strcmp(argv[i],"-pwdof") == 0) {
	    i++;
	    if (i < argc) {
		ownerAuthFilename = argv[i];
	    }
	    else {
		printf("-pwdof option needs a value\n");
		usage();
	    }
	}
	else if (!strcmp("-la",argv[i])) {
	    i++;
	    if (i < argc) {
		label = atoi(argv[i]);
	    } else {
		printf("Missing parameter for -la\n");
		usage();
	    }
	}
	else if (!strcmp("-pwdc",argv[i])) {
	    i++;
	    if (i < argc) {
		counterPassword = argv[i];
	    } else {
		printf("Missing parameter for -pwdc\n");
		usage();
	    }
	}
	else if (!strcmp("-v",argv[i])) {
	    TPM_setlog(1);
	}
	else if (!strcmp(argv[i], "-h")) {
	    usage();
	}
	else {
	    printf("\n%s is not a valid option\n",argv[i]);
	    usage();
	}
	i++;
    }
    if ((ownerPassword == NULL) && (ownerAuthFilename == NULL)) {
	printf("\nMissing -pwdo or -pwdof argument\n");
	usage();
    }
    if ((ownerPassword != NULL) && (ownerAuthFilename != NULL)) {
	printf("\nCannot have -pwdo and -pwdof arguments\n");
	usage();
    }

    if ((counterPassword == NULL) ||
	(label == 0xffffffff)) {
	printf("Input parameters -la or -pwdc wrong or missing!\n");
	usage();
    }
    printf("Using ownerPassword : %s\n", ownerPassword);
    printf("Using counterPassword: %s\n", counterPassword);
	
    parhandle = 0x00000000;	/* dummy value, owner */

    /* use the SHA1 hash of the password string as the Owner Authorization Data */
    if (ownerPassword != NULL) {
	TSS_sha1((unsigned char *)ownerPassword,
		 strlen(ownerPassword),
		 ownerAuth);
    }
    /* get the ownerAuth from a file */
    else {
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
	free(buffer);
    }

    TSS_sha1(counterPassword, strlen(counterPassword), counterAuth);

    /*
     * Create a counter
     */
    for (i = 0 , ret = TPM_RETRY ; (ret == TPM_RETRY) && (i < 7) ; i++) {
	ret = TPM_CreateCounter(parhandle,
				ownerAuth,
				label,
				counterAuth,
				&counterId,
				counterValue);
	/* must be able to increment once every 5 seconds */
	if (ret == TPM_RETRY) {
#ifdef TPM_POSIX
	    sleep(1);
#endif
#ifdef TPM_WINDOWS 
	    Sleep(1000); 
#endif
	}
    }	 
    if (0 != ret) {
	printf("Got error %s (0x%x) from TPM_CreateCounter.\n",
	       TPM_GetErrMsg(ret),
	       ret);
    } else {
		
	printf("New counter id: %d\n",counterId);
	i = 0;
	printf("Counter start value: ");
	while (i < TPM_COUNTER_VALUE_SIZE) {
	    printf("%02X",counterValue[i]);
	    i++;
	}
	printf("\n");
    }

    return ret;
}
