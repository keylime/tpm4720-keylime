/********************************************************************************/
/*										*/
/*			    Get the context count of a context blob		*/
/*			     Written by Stefan Berger				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*	      $Id: getcontextcount.c 4702 2013-01-03 21:26:29Z kgoldman $	*/
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


static void print_usage(void)
{
    printf("Usage: getcontextcount [-v] -if <filename>\n"
           "\tParses the context blob and prints the context count\n"
           "\n"
           "-v          : enables verbose mode\n"
           "\n");
    exit(-1);
}

int main(int argc, char *argv[])
{
	int ret = 0;
	char *filename = NULL;
	int i = 1;
	unsigned char * buffer;
	uint32_t buffersize;
	TPM_CONTEXT_BLOB context;
	STACK_TPM_BUFFER(tpmbuffer)

	TPM_setlog(0);
	while (i  < argc) {
	    if (!strcmp("-if",argv[i])) {
		i++;
		if (i < argc) {
		    filename = argv[i];
		} else {
		    printf("Missing parameter for -if.\n");
		    print_usage();
		}
	    }
	    else if (!strcmp(argv[i],"-v")) {
		TPM_setlog(1);
	    }
	    else if (!strcmp("-h",argv[i])) {
		print_usage();
	    }
	    else if (!strcmp(argv[i],"-h")) {
		print_usage();
	    }
	    else {
		printf("\n%s is not a valid option\n", argv[i]);
		print_usage();
	    }
	    i++;
	}
	if (NULL == filename) {
	    printf("Missing -if argument.\n");
	    print_usage();
	}

	ret = TPM_ReadFile(filename, &buffer, &buffersize);
	
	if (ret != 0) {
	        printf("Error while reading file '%s'.\n",filename);
	        exit(-1);
	}

	SET_TPM_BUFFER(&tpmbuffer, buffer, buffersize);
	ret = TPM_ReadContextBlob(&tpmbuffer, 0, &context);
	if ((ret & ERR_MASK)) {
	        printf("Error while parsing the context blob.\n");
	        exit(-1);
	}
	
	printf("ContextCount: 0x%08X\n",context.contextCount);
	ret = 0;

 	exit(ret);
}

