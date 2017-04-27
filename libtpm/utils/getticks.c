/********************************************************************************/
/*										*/
/*		    TCPA Get the current tick count of the TPM			*/
/*			     Written by Stefan Berger				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*	      $Id: getticks.c 4702 2013-01-03 21:26:29Z kgoldman $		*/
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

void printUsage(void);

void printUsage(void)
{
    printf("getticks\n");
    printf("- Runs TPM_GetTicks\n");
    printf("\n");
    exit(-1);
}

int main(int argc, char *argv[])
{
	int ret = 0;
	unsigned char tickbuffer[36];
	TPM_CURRENT_TICKS ticks;
	int	i;		/* argc iterator */
	
	TPM_setlog(0);
	for (i=1 ; i<argc ; i++) {
	    if (!strcmp(argv[i], "-h")) {
		printUsage();
	    }
	    else if (!strcmp(argv[i], "-v")) {
		TPM_setlog(1);
	    }
	    else {
		printf("\n%s is not a valid option\n", argv[i]);
		printUsage();
	    }
	}

	ret = TPM_GetTicks(tickbuffer);
	if (0 != ret) {
		printf("Error %s from TPM_GetTicks\n",
		       TPM_GetErrMsg(ret));
	} else {
                STACK_TPM_BUFFER(buffer)
                TSS_SetTPMBuffer(&buffer, tickbuffer, sizeof(tickbuffer));
		/* this doesn't really get sec and usec, it gets an upper and lower uint32_t */
		TPM_GetCurrentTicks(&buffer, 0, &ticks);
#ifdef TPM_POSIX
		printf(" Sec:         %llu\n",
		       (long long int)
		       (((uint64_t)ticks.currentTicks.sec << 32) +
			(uint64_t)ticks.currentTicks.usec) / 1000000);
		printf("uSec:         %llu\n",
		       (long long int)
		       (((uint64_t)ticks.currentTicks.sec << 32) +
			(uint64_t)ticks.currentTicks.usec) % 1000000);
#endif
#ifdef TPM_WINDOWS
		printf(" Sec:         %I64u\n",
		       (long long int)
		       (((uint64_t)ticks.currentTicks.sec << 32) +
			(uint64_t)ticks.currentTicks.usec) / 1000000);
		printf("uSec:         %I64u\n",
		       (long long int)
		       (((uint64_t)ticks.currentTicks.sec << 32) +
			(uint64_t)ticks.currentTicks.usec) % 1000000);
#endif
		printf("tickRate:     %u\n",ticks.tickRate);
	}
 	exit(ret);
}
