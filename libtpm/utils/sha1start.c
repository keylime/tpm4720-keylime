/********************************************************************************/
/*										*/
/*			    TPM SHA1Start Function     				*/
/*			     Written by Ken Goldman  				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*	      $Id: sha1start.c 4702 2013-01-03 21:26:29Z kgoldman $		*/
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

/* This command creates a sha1context.  It is used for VTPM migration testing */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifdef TPM_POSIX
#include <netinet/in.h>
#endif
#ifdef TPM_WINDOWS
#include <winsock2.h>
#endif

#include "tpm.h"
#include "tpmutil.h"
#include "tpmfunc.h"
#include "tpm_constants.h"
#include "tpm_structures.h"

/* local functions */

static void usage() {
	printf("Usage: sha1start\n"
	       "\n");
	exit(-1);
}

int main(int argc, char * argv[])
{
    int i = 1;
    uint32_t ret = 0;
    TPM_BOOL verbose = FALSE;
    uint32_t maxNumBytes = 0;	/* return from TPM_SHA1Start */

    TPM_setlog(0);
	
    while (i < argc) {
	if (!strcmp("-v",argv[i])) {
	    TPM_setlog(1);
	    verbose = TRUE;
	} else
	    if (!strcmp("-h",argv[i])) {
		usage();
	    } else {
		printf("\n%s is not a valid option\n", argv[i]);
		usage();
	    }
	i++;
    }
    (void)verbose;

    /* Create the SHA1 context */
    ret = TPM_SHA1Start(&maxNumBytes);
    if (0 != ret) {
	printf("Error from TPM_SHA1Start(): %d (0x%x)\n",
	       ret,
	       ret);
	exit(-1);
    }
    if (maxNumBytes < 64) {
	printf("The size parameter returned from TPM_SHA1Start() is bad.\n");
	exit(-1);
    }
    return 0;
}
