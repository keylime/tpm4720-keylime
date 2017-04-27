/********************************************************************************/
/*										*/
/*			     	TPM Save TPM context				*/
/*			     Written by S. Berger				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*	      $Id: savecontext.c 4702 2013-01-03 21:26:29Z kgoldman $		*/
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
	printf("Usage: savecontext -ha handle -rt <resource type> -la label -of <filename> [-v]\n");
	printf("\n");
	printf(" -ha handle   : the handle of the resource to save\n");
	printf(" -rt res.type : the type of the resource to save\n");
	printf("\t 1 - key\n");
	printf("\t 2 - auth\n");
	printf("\t 4 - transport\n");
	printf("\t 5 - context\n");
	printf(" -la label    : the label of the TPM\n");
	printf(" -of filename    : the filename where to write the context into\n");
	printf(" -v          : to enable verbose output\n");
	printf("\n");
	printf("Examples:\n");
	printf("./savecontext -ha 0xabc -rt 1 -la testlabel -of context1.sav\n");
	exit(-1);
}


int main(int argc, char *argv[])
{
	unsigned char labelhash[20];
	int ret;
	char * filename = NULL;
	char * label = NULL;
	uint32_t handle = 0xffffffff;
	uint32_t restype = 0;
	STACK_TPM_BUFFER(context);

	int i = 1;

	TPM_setlog(0);

	while (i < argc) {
		if (!strcmp("-rt",argv[i])) {
			i++;
			if (i < argc) {
				sscanf(argv[i],"%x",&restype);
			} else {
				printf("Missing parameter for -rt.\n");
				usage();
			}
		} else
		if (!strcmp("-of",argv[i])) {
			i++;
			if (i < argc) {
				filename = argv[i];
			} else {
				printf("Missing parameter for -of.\n");
				usage();
			}
		} else
		if (!strcmp("-la",argv[i])) {
			i++;
			if (i < argc) {
				label = argv[i];
			} else {
				printf("Missing parameter for -la.\n");
				usage();
			}
		} else
		if (!strcmp("-ha",argv[i])) {
			i++;
			if (i < argc) {
				sscanf(argv[i],"%x",&handle);
			} else {
				printf("Missing parameter for -ha.\n");
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

	if (NULL == filename || 0xffffffff == handle || NULL == label) {
		printf("Missing argument.\n"); 
		usage(); 
	}
	
	if (NULL != label) {
		TSS_sha1(label,strlen(label),labelhash);
	}
	
   
	ret  = TPM_SaveContext(handle, restype, (char *)labelhash, &context);

	if (0 != ret) {
		printf("SaveContext returned error '%s' (%d).\n",
		       TPM_GetErrMsg(ret),
		       ret);
	} else {
		FILE * f = fopen(filename, "wb");
		if (NULL != f) {
			fwrite(context.buffer,context.used,1,f);
			fclose(f);
		}
	}
	

	exit(ret);
}

