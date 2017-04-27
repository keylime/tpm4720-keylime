/********************************************************************************/
/*										*/
/*	                      TCPA Self-test the TPM                            */
/*			     Written by Stefan Berger				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*	      $Id: selftest.c 4702 2013-01-03 21:26:29Z kgoldman $		*/
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


int main(int argc, char *argv[])
{
	int ret = 0;
	int	i;		/* argc iterator */
	TPM_setlog(0);      	/* turn off verbose output */
   
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

	ret = TPM_SelfTestFull();
	if (0 != ret) {
		char outData[2048];
		uint32_t outDataSize = sizeof(outData);
		printf("Error %s from TPM_SelfTestFull\n",
		    TPM_GetErrMsg(ret));
		ret = TPM_GetTestResult(outData, &outDataSize);
		if (0 != ret) {
			printf("Error %s from TPM_GetTestResult\n",
			        TPM_GetErrMsg(ret));
		} else {
			int i = 0;
			if (0 == outDataSize) {
				printf("The TPM returned no test result data.\n");
			} else {
				printf("Received the following test result:\n");
				while (i < (int)outDataSize) {
					printf("%02X ",outData[i]);
					i++;
					if (0 == (i & 0xf)) {
						printf("\n");
					}
				}
			}
		}
	} else {
	    printf("TPM_SelfTestFull returned success.\n");
	}
	return ret;
}

void printUsage(void)
{
    printf("\n");
    printf("selftest- Runs TPM_SelfTestFull and TPM_GetTestResult\n");
    printf("\n");
    exit(-1);
}
   
