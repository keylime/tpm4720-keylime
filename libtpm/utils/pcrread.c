/********************************************************************************/
/*										*/
/*			        Read value of a PCR   				*/
/*			     Written by Stefan Berger				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*	      $Id: pcrread.c 4702 2013-01-03 21:26:29Z kgoldman $		*/
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
#include <sys/types.h>
#include <sys/stat.h>

#ifdef TPM_POSIX
#include <netinet/in.h>
#endif
#ifdef TPM_WINDOWS
#include <winsock2.h>
#endif

#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/evp.h>

#include "tpm.h"
#include "tpmutil.h"
#include "tpmfunc.h"
#include "tpm_constants.h"
#include "tpm_structures.h"

/* local prototypes */

static void usage() {
	printf("Usage: pcrread -ix <pcr index> [-v]\n"
	       "-ix     : index of PCR to read\n"
	       "-v     : enable verbose output\n"
	       "\n"
	       "Read a PCR.\n"
	       "\n"
	       "Examples:\n"
	       "pcrread -ix 1\n");
}

int main(int argc, char * argv[]) {
	int i = 0;
	int ret = 0;
	int index = -1;
	unsigned char digest[TPM_HASH_SIZE];

	i = 1;
	
	TPM_setlog(0);
	
	while (i < argc) {
		if (!strcmp("-ix",argv[i])) {
			i++;
			if (i < argc) {
				if (1 != sscanf(argv[i],"%d",&index)) {
					printf("Could not parse the PCR index number.\n");
					exit(-1);
				}
			} else {
				printf("Missing parameter for -ix.\n");
				usage();
				exit(-1);
			}
		} else
		if (!strcmp("-v",argv[i])) {
			TPM_setlog(1);
		} else
		    if (!strcmp("-h",argv[i])) {
			usage();
			exit(-1);
		} else {
			printf("\n%s is not a valid option\n", argv[i]);
			usage();
			exit(-1);
		}
		i++;
	}


	if (-1 == index) {
		printf("Missing or wrong parameter.\n");
		usage();
		exit(-1);
	}

	ret = TPM_PcrRead(index, digest);

	if (0 == ret) {
		printf("Current value of PCR %d: ",index);
		i = 0;
		while (i < TPM_HASH_SIZE) {
			printf("%02x",digest[i]);\
			i++;
		}
		printf("\n");
	} else {
		printf("PCRRead returned error '%s'.\n",
		       TPM_GetErrMsg(ret));
	}
	exit(ret);
}
