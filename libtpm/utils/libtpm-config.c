/********************************************************************************/
/*										*/
/*			     	TPM Get TPM Configuration			*/
/*			     Written by S. Berger				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*	      $Id: libtpm-config.c 4702 2013-01-03 21:26:29Z kgoldman $		*/
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

/* NOTE: The regression test_console.sh uses this output.  Changes to print formats can change the
   test flow.
*/

int main(int argc, char *argv[])
{
	(void)argc;
	(void)argv;
	const char *env;
	
#if defined TPM_USE_CHARDEV
	printf("Device: /dev/tpm0 TPM_USE_CHARDEV\n");
#elif defined XCRYPTO_USE_CCA
	printf("Device: CCA XCRYPTO_USE_CCA\n");
#elif defined TPM_USE_UNIXIO
	printf("Device: UnixIO socket TPM_USE_UNIXIO\n");
#else
	printf("Device: TCP socket\n");
#endif

	printf("Virtual TPM communication disabled\n");
#ifdef TPM_MAXIMUM_KEY_SIZE
	printf("Maximum supported key size is %d.\n",TPM_MAXIMUM_KEY_SIZE);
#endif
	env = getenv("TPM_SERVER_PORT");
	if (env == NULL) {
	    printf("TPM_SERVER_PORT not set\n");
	}
	else {
	    printf("TPM_SERVER_PORT %s\n", env);
	}

	env = getenv("TPM_SERVER_NAME");
	if (env == NULL) {
	    printf("TPM_SERVER_NAME not set\n");
	}
	else {
	    printf("TPM_SERVER_NAME %s\n", env);
	}
	return 0;
}
