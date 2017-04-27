/********************************************************************************/
/*										*/
/*			     	TPM Write into a DIR (data integrity register)	*/
/*			     Written by S. Berger				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*	      $Id: dirwrite.c 4702 2013-01-03 21:26:29Z kgoldman $		*/
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
#include "tpm.h"
#include "tpmutil.h"
#include <tpmfunc.h>



static void printUsage() {
    printf("Usage: dirwrite -pwdo <ownerpass> -in <index> -ic <message>\n"
	   "\n"
	   "   [-pwdo <owner password> -pwdof <owner authorization file name>\n"
	   "-in  index     : The index of the DIR to write into; give hex number\n"
	   "-ic  message   : The message to write into; the SHA1 of this message will be calculated\n"
	   "\n"
	   "Examples:\n"
	   "dirwrite  -pwdo ooo -in 0 -ic test\n");
    exit(2);
}



int main(int argc, char *argv[])
{
    int ret;
    int i;
    unsigned char   msghash[TPM_HASH_SIZE];
    unsigned char ownerAuth[TPM_HASH_SIZE];
    const char * ownerPassword = NULL;
    const char *ownerAuthFilename = NULL;
    const char * message = NULL;
    unsigned char * ownerAuthPtr = NULL;
    int index = -1;
	
    TPM_setlog(0);

    for (i=1 ; i<argc ; i++) {
	if (!strcmp(argv[i], "-pwdo")) {
	    i++;
	    if (i < argc) {
		ownerPassword = argv[i];
	    }
	    else {
		printf("Missing parameter to -pwdo\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-pwdof") == 0) {
	    i++;
	    if (i < argc) {
		ownerAuthFilename = argv[i];
	    }
	    else {
		printf("-pwdof option needs a value\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-in") == 0) {
	    i++;
	    if (i < argc) {
		if (1 != sscanf(argv[i],"%x",&index)) {
		    printf("Invalid -in argument '%s'\n",argv[i]);
		    exit(2);
		}
	    }
	    else {
		printf("-in option needs a value\n");
		printUsage();
	    }
	}
	else if (!strcmp(argv[i],"-ic")) {
	    i++;
	    if (i >= argc) {
		printf("Parameter missing for '-ic'!\n");
		printUsage();
	    }
	    message = argv[i];
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
    if ((ownerPassword == NULL) && (ownerAuthFilename == NULL)) {
	printf("\nMissing -pwdo or -pwdof argument\n");
	printUsage();
    }
    if ((ownerPassword != NULL) && (ownerAuthFilename != NULL)) {
	printf("\nCannot have -pwdo and -pwdof arguments\n");
	printUsage();
    }
    if (index == -1) {
	printf("Missing -in parameter\n");
	printUsage();
    }
    if (message == NULL) {
	printf("Missing -ic parameter\n");
	printUsage();
    }
    /* use the SHA1 hash of the password string as the Owner Authorization Data */
    if (ownerPassword != NULL) {
	TSS_sha1((unsigned char *)ownerPassword,
		 strlen(ownerPassword),
		 ownerAuth);
	ownerAuthPtr = ownerAuth;
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
	ownerAuthPtr = ownerAuth;
	free(buffer);
    }

    TSS_sha1((unsigned char *)message,strlen(message),msghash);
	
    ret = TPM_DirWriteAuth(index, msghash, ownerAuthPtr);

    if (0 != ret) {
	printf("DirWriteAuth returned error '%s'.\n",
	       TPM_GetErrMsg(ret));
    }
	
    exit(ret);
}

