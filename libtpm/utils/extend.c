/********************************************************************************/
/*										*/
/*			    TCPA Extend a PCR   				*/
/*			     Written by Stefan Berger				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*	      $Id: extend.c 4702 2013-01-03 21:26:29Z kgoldman $		*/
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
#include "tpmfunc.h"

/* local prototypes */


static void usage(){
	printf("Usage: Extend -ix pcrIndex [-ic message | -if filename] \n"
              "\n"
	       "-ix index    : the number of the PCR register to use\n"
	       "-ic message  : Arbitrary command line message that will be digested and\n"
	       "               used to extend the PCR with.\n"
	       "-if filename : The file to measure and extend the PCR with\n"
	       "\n");
	exit(-1);
}

int main(int argc, char *argv[])
{
    int ret = 0;
    char * message = NULL;
    char * filename = NULL;
    unsigned char msghash[20];    /* hash of message */
    uint32_t index = -1;
    unsigned char buffer[20];
	
    int i = 1;
    TPM_setlog(0);      /* turn off verbose output */
    while (i  < argc) {
	if (!strcmp(argv[i],"-ix")) {
	    i++;
	    if (i >= argc) {
		printf("Parameter missing for '-ix'!\n");
		usage();
	    }
	    index = atoi(argv[i]);
	}
	else if (!strcmp(argv[i],"-ic")) {
	    i++;
	    if (i >= argc) {
		printf("Parameter missing for '-ic'!\n");
		usage();
	    }
	    message = argv[i];
	}
	else if (!strcmp(argv[i],"-if")) {
	    i++;
	    if (i >= argc) {
		printf("Parameter missing for '-if'\n");
		usage();
	    }
	    filename = argv[i];
	}
	else if (!strcmp(argv[i],"-v")) {
	    TPM_setlog(1);
	}
	else if (!strcmp(argv[i],"-h")) {
	    usage();
	} else {
	    printf("\n%s is not a valid option\n", argv[i]);
	    usage();
	}
	i++;
    }

    if (message && filename) {
	printf("You must only provide one option '-if' or '-ic'.\n");
	exit(-1);
    }

    if (message != NULL) {
	TSS_sha1(message,strlen(message),msghash);
    } else
        if (filename != NULL) {
	    ret = TSS_SHAFile(filename, msghash);
	    if (0 != ret) {
		printf("Error %s from SHAFile.\n",
		       TPM_GetErrMsg(ret));
		exit(-1);
	    }
	} else {
	    usage();
	}
	
    if ((int)index < 0) { 
	usage();
    }

    ret = TPM_Extend(index, msghash, buffer);
    if (0 != ret) {
	printf("Error %s from TPM_Extend\n",
	       TPM_GetErrMsg(ret));
    } else {
	i = 0;
	printf("New value of PCR[%d]: ",index);
	while (i < TPM_HASH_SIZE) {
	    printf("%02x",buffer[i]);
	    i++;
	}
	printf("\n");
    }
    exit(ret);
}
