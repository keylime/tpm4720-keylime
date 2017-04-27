/********************************************************************************/
/*										*/
/*			     	TPM CMK_SetRestrictions                         */
/*			     Written by S. Berger				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*	      $Id: cmk_setrestrictions.c 4702 2013-01-03 21:26:29Z kgoldman $	*/
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
	printf("Usage: cmk_setrestrictions -pwdo <owner password> -bm <bitmask> [-v]\n"
	       "\n"
	       " -pwdo pwd     : the TPM owner password\n"
	       " -bm <bitmask> : bit mask of the restrictions\n"
	       " -v            : to enable verbose output\n"
	       "\n"
	       "Examples:\n"
	       "cmk_setrestrictions -pwdo aaa -bm 80000000\n");
}


int main(int argc, char *argv[])
{
	unsigned char passhash1[20];
	char * ownerpass = NULL;
	int ret;
	int verbose = FALSE;
	uint32_t restrictions = 0;
	
	int i = 1;
	
	TPM_setlog(0);
	
	while (i < argc) {
		if (!strcmp("-pwdo",argv[i])) {
			i++;
			if (i < argc) {
				ownerpass = argv[i];
			} else {
				printf("Missing parameter for -pwdo.\n");
				usage();
				exit(-1);
			}
		} else
		if (!strcmp("-bm",argv[i])) {
			i++;
			if (i < argc) {
				ret = sscanf(argv[i],"%x",&restrictions);
				if (ret != 1) {
				    printf("Invalid argument '%s'\n",argv[i]);
				    exit(-1);
				}
			} else {
				printf("Missing parameter for -bm.\n");
				usage();
				exit(-1);
			}
		} else
		if (!strcmp("-v",argv[i])) {
			verbose = TRUE;
			TPM_setlog(1);
		} else
		if (!strcmp("-h",argv[i])) {
		        usage();
		        exit(-1);
		} else {
		        printf("\n%s is not a valid option\n",argv[i]);
			usage();
			exit(-1);
		}
		i++;
	}
	(void)verbose;

	if (NULL == ownerpass) {
		printf("Missing argument -pwdo.\n");
		usage();
		exit(-1);
	}
	
	if (NULL != ownerpass) {
		TSS_sha1(ownerpass,strlen(ownerpass),passhash1);
	}
	
   
	ret = TPM_CMK_SetRestrictions(restrictions,
	                              passhash1);


	if (0 != ret) {
		printf("CMK_SetRestrictions returned error '%s' (%d).\n",
		       TPM_GetErrMsg(ret),
		       ret);
	}
	

	exit(ret);
}
