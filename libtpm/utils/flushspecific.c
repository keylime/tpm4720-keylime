/********************************************************************************/
/*										*/
/*			     	TPM Flush a specific handle from the TPM	*/
/*			     Written by S. Berger				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*	      $Id: flushspecific.c 4702 2013-01-03 21:26:29Z kgoldman $		*/
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
	printf("Usage: flushspecific -ha <handle> -rt <resource type> [-v]\n"
	       "\n"
	       "-ha   : the handle to flush (give hex number)\n"
	       "-rt   : the resource type of the handle (as decimal)\n"
               "\t 1 - key\n"
               "\t 2 - auth\n"
               "\t 4 - transport\n"
               "\t 5 - context\n"
	       "-v    : turns on verbose mode\n"
	       "\n");
	exit(-1);
}

int main(int argc, char *argv[])
{
	int ret;
	int i = 1;
	uint32_t handle = -1;
	uint32_t type = -1;
	
	TPM_setlog(0);
	
	while (i < argc) {
		if (!strcmp("-ha",argv[i])) {
			i++;
			if (i < argc) {
				sscanf(argv[i],"%x",&handle);
			} else {
				printf("Missing parameter for -ha.\n");
				printUsage();
			}
		} else
		if (!strcmp("-rt",argv[i])) {
			i++;
			if (i < argc) {
				sscanf(argv[i],"%d",&type);
			} else {
				printf("Missing parameter for -rt.\n");
				printUsage();
			}
		} else
		if (!strcmp("-v",argv[i])) {
			TPM_setlog(1);
		} else
		if (!strcmp("-h",argv[i])) {
		    printUsage();
		} else {
		    printf("\n%s is not a valid option\n", argv[i]);
		    printUsage();
		}
		i++;
	}

	if (-1 == (int)handle || -1 == (int)type) {
		printf("Missing command line parameter.\n");
		printUsage();
	}

	ret = TPM_FlushSpecific(handle, type);
	if (ret != 0) {
		printf("FlushSpecific returned error %s.\n",
		        TPM_GetErrMsg(ret));
	} else {
		printf("Successfully flushed item of type %X with handle %08x.\n",
		       type,
		       handle);
	}

	exit(ret);
}
