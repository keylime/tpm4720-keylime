/********************************************************************************/
/*										*/
/*			     	TPM SetOperatorAuth                      	*/
/*			     Written by S. Berger				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*	      $Id: setoperatorauth.c 4702 2013-01-03 21:26:29Z kgoldman $	*/
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

static void usage() {
	printf("Usage: setoperatorauth -pwdo <operator password> [-e]\n");
	printf("\n");
	printf(" -pwdo pwd : the TPM operator password\n");
	printf(" -v        : to enable verbose output\n");
	printf("\n");
	printf("Examples:\n");
	printf("setoperatorauth -pwdo aaa \n");
	exit(-1);
}


int main(int argc, char *argv[])
{
	unsigned char passhash1[20];
	char * operpass = NULL;
	int ret;
	
	int i = 1;
	
	TPM_setlog(0);
	
	while (i < argc) {
		if (!strcmp("-pwdo",argv[i])) {
			i++;
			if (i < argc) {
				operpass = argv[i];
			} else {
				printf("Missing parameter for -pwdo.\n");
				usage();
			}
		} else
		if (!strcmp("-v",argv[i])) {
			TPM_setlog(1);
		} else
		    if (!strcmp("-h",argv[i])) {
			usage();
		} else {
			printf("\n%s is not a valid option\n", argv[i]);
			usage();
		}
		i++;
	}

	if (NULL == operpass) {
	    printf("Missing -pwdo argument.\n");
	    usage();
	}
	
	if (NULL != operpass) {
		TSS_sha1(operpass,strlen(operpass),passhash1);
	}
	
   
	ret = TPM_SetOperatorAuth(passhash1);


	if (0 != ret) {
            printf("TPM_SetOperatorAuth returned error '%s' (%d).\n",
		       TPM_GetErrMsg(ret),
		       ret);
	}
	

	exit(ret);
}

