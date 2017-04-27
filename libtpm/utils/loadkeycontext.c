/********************************************************************************/
/*										*/
/*			     	TPM Load TPM key context			*/
/*			     Written by S. Berger				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*	      $Id: loadkeycontext.c 4702 2013-01-03 21:26:29Z kgoldman $	*/
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

static void usage() {
    printf("Usage: loadkeycontext -if filename\n");
    printf("\n");
    printf("-if filename  : the filename of the file holding the key context\n");
    printf("\n");
    exit(-1);
}


int main(int argc, char *argv[])
{
	int ret;
	char * filename = NULL;
	uint32_t handle = 0;
	unsigned char * mycontext = NULL;
	uint32_t contextSize = 0;
	STACK_TPM_BUFFER(context);
	int i = 1;

	TPM_setlog(0);

	while (i < argc) {
	    if (!strcmp("-if",argv[i])) {
		i++;
		if (i < argc) {
		    filename = argv[i];
		} else {
		    printf("Missing parameter for -if.\n");
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
		printf("\n%s is not a valid option\n", argv[i]);
		usage();
	    }
	    i++;
	}
	if (NULL == filename) {
	        printf("Missing -if argument.\n");
		usage();
		exit(-1);
	}

	ret = TPM_ReadFile(filename,
	                   &mycontext, &contextSize);
	if ( (ret & ERR_MASK) != 0) {
		printf("Error while reading context file.\n");
		exit(-1);
	}
	SET_TPM_BUFFER(&context, mycontext, contextSize);
	ret = TPM_LoadKeyContext(&context,
			         &handle);

	if (0 != ret) {
		printf("LoadKeyContext returned error '%s'.\n",
		       TPM_GetErrMsg(ret));
	} else {
		printf("New Handle = %08X\n",handle);
	}
	free(mycontext);
	exit(ret);
}
