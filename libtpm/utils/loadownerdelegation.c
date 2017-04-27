/********************************************************************************/
/*										*/
/*			     	TPM Load Owner Delegation			*/
/*			     Written by S. Berger				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*	      $Id: loadownerdelegation.c 4702 2013-01-03 21:26:29Z kgoldman $	*/
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

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
                     
#include "tpm.h"
#include "tpmutil.h"
#include <tpmfunc.h>

static void usage()
{
    printf("Usage: loadownerdelegation -row index -if filename\n"
	   "\t[-pwdo <owner password> -pwdof <owner authorization file name>\n"
	   "\t[-v]"
	   "\n"
	   "-pwdo : password of the TPM owner\n"
	   "-pwdof: authorization file of the TPM owner\n"
	   "-row  : delegate row index\n"
	   "-if   : owner delegation file name\n"
	   "\n");
    exit(-1);
}


int main(int argc, char *argv[])
{
    uint32_t ret = 0;
    char * filename = NULL;
    int i;
    char *ownerPassword = NULL;
    const char *ownerAuthFilename = NULL;
    unsigned char ownerAuth[TPM_HASH_SIZE];
    unsigned char *ownerHashPtr = NULL;
    struct stat _stat;
    uint32_t index = 0xffffffff;

    TPM_setlog(0);

    for (i=1 ; i<argc ; i++) {
	if (!strcmp("-pwdo",argv[i])) {
	    i++;
	    if (i < argc) {
		ownerPassword = argv[i];
	    }
	    else {
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
		printf("Missing parameter for -pwdo.f\n");
		usage();
	    }
	}
	else if (!strcmp("-row",argv[i])) {
	    i++;
	    if (i < argc) {
		if (1 != sscanf(argv[i], "%x", &index)) {
		    printf("Could not parse the -row value.\n");
		    usage();
		}
	    }
	    else {
		printf("Missing argument after -row\n");
		usage();
	    }
	}
	else if (strcmp(argv[i],"-if") == 0) {
	    i++;
	    if (i < argc) {
		filename = argv[i];
	    }
	    else {
		printf("-if option needs a value\n");
	    }
	}
	else if (!strcmp("-v",argv[i])) {
	    TPM_setlog(1);
	} 
	else if (!strcmp("-h",argv[i])) {
	    usage();
	}
	else {
	    printf("\n%s is not a valid option\n", argv[i]);
	    usage();
	}
    }
    if (index == 0xfffffff) {
	printf("Missing the -row parameter!\n");
	usage();
    }
    if (filename == NULL) {
	printf("Missing the -if parameter!\n");
	usage();
    }
    if ((ownerPassword != NULL) && (ownerAuthFilename != NULL)) {
	printf("\nCannot have -pwdo and -pwdof arguments\n");
	usage();
    }

    /* use the SHA1 hash of the password string as the Owner Authorization Data */
    if (ownerPassword != NULL) {
	TSS_sha1((unsigned char *)ownerPassword,
		 strlen(ownerPassword),
		 ownerAuth);
	ownerHashPtr = ownerAuth;
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
	ownerHashPtr = ownerAuth;
	free(buffer);
    }

    if (0 == stat(filename, &_stat)) {
	unsigned char *blob = malloc(_stat.st_size);
	uint32_t blobSize = _stat.st_size;
	FILE *f;
	if (NULL == blob) {
	    printf("Could not allocate memory!\n");
	    exit(-1);
	}
		
	f = fopen(filename, "rb");
	if (NULL == f) {
	    printf("Could not open file for reading.\n");
	    exit(-1);
	}
		
	if (blobSize != fread(blob, 1, blobSize, f)) {
	    printf("Could not read the file.\n");
	    fclose(f);
	    exit(-1);
	}
	fclose(f);
	ret = TPM_Delegate_LoadOwnerDelegation(index,
					       ownerHashPtr,
					       blob, blobSize);

	if ( ret  != 0) {
	    printf("Error '%s' from Delegate_LoadOwnerDelegation.\n",
		   TPM_GetErrMsg(ret));
	    exit(-1);
	}
	else {
	    printf("Successfully loaded the blob.\n");
	}
	
    }
    else {
	printf("Error, file %s not accessible.\n",filename);
    }

    exit(ret);
}
