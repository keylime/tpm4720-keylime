/********************************************************************************/
/*										*/
/*			     	TPM Get the audit digest			*/
/*			     Written by S. Berger				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*	      $Id: getauditdigest.c 4702 2013-01-03 21:26:29Z kgoldman $	*/
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
	printf("Usage: getauditdigest -s <start ordinal> [-v]\n"
	       "\n"
	       "-s    : option to pass the start ordinal for the audit\n"
	       "-v    : turns on verbose mode\n"
	       "\n");
}

int main(int argc, char *argv[])
{
	uint32_t startOrdinal = -1;
	int ret = 0;
	int verbose = FALSE;
	TPM_COUNTER_VALUE counter;
	uint32_t lowest = 0;
	TPM_BOOL more = TRUE;
	int i = 1;
	uint32_t ordSize;
	uint32_t * ord = NULL;
	unsigned char digest[TPM_DIGEST_SIZE];
	
	TPM_setlog(0);
	
	while (i < argc) {
	    if (!strcmp("-s",argv[i])) {
		i++;
		if (i < argc) {
		    sscanf(argv[i],"%d",&startOrdinal);
		} else {
		    printf("Missing parameter for -s.\n");
		    usage();
		    exit(-1);
		}
	    } else
		if (!strcmp("-v",argv[i])) {
		    verbose = TRUE;
		    TPM_setlog(1);
		} else {
		    printf("\n%s is not a valid option\n", argv[i]);
		    usage();
		    exit(-1);
		}
	    i++;
	}
	(void)verbose;

	if (-1 == (int)startOrdinal) {
		printf("Missing command line parameter.\n");
		usage();
		exit(1);
	}

	lowest = startOrdinal;
	
	while (TRUE == more) {
		unsigned char calcdigest[TPM_DIGEST_SIZE];
		int j = startOrdinal;
		ret = TPM_GetAuditDigest(lowest,
		                         &counter,
		                         digest,
		                         &more,
		                         &ord, &ordSize);
		if (ret != 0) {
			printf("GetAuditDigest returned error %s.\n",
			        TPM_GetErrMsg(ret));
			break;
		}
		
		ret = _TPM_GetCalculatedAuditDigest(&calcdigest);

		i = 0;
		printf("TPM Digest: ");
		while (i < (int)sizeof(digest) ) {
			printf("%02X",digest[i++]);
		}
		printf("\n");
		
		if (!memcmp(&calcdigest, digest, sizeof(calcdigest))) {
			printf("The stack calculated the same digest.\n");
		} else {
			printf("The stack calculated a different digest: ");
			i = 0;
			while (i < (int)sizeof(calcdigest)) {
				printf("%02X",calcdigest[i++]);
			}
			printf("\n");
		}

		i = 0;
		printf("counter value = %d\n",(uint32_t)counter.counter);
		while (i < (int)(ordSize/4)) {
			while (j < (int)htonl(ord[i])) {
				_TPM_SetAuditStatus(j,0);
				j++;
			}
			_TPM_SetAuditStatus(htonl(ord[i]),1);
			j=htonl(ord[i])+1;

			printf("%08lx=%03ld\n",
			       (long)htonl(ord[i]),
			       (long)htonl(ord[i]));
			if (ord[i] > lowest) {
				lowest = ord[i];
			}
			i++;
		}
		
		while (j < 256) {
			_TPM_SetAuditStatus(j,0);
			j++;
		}
		
		if (ord) 
			free(ord);
	}	

	exit(ret);
}
