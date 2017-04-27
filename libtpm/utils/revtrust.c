/********************************************************************************/
/*										*/
/*			    TCPA Revoke Trust   				*/
/*			     Written by Stefan Berger				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*	      $Id: revtrust.c 4702 2013-01-03 21:26:29Z kgoldman $		*/
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


static void usage() {
	printf("Usage: revtrust -pwdk password [-v]\n"
	       "\n"
	       "-pwdk password : The password to be used with revoketrust\n"
	       "-v             : enables verbose mode\n"
	       "\n");
	exit(-1);
}

int main(int argc, char *argv[])
{
	int ret = 0;
	unsigned char *passptr1;
	char * password = NULL;
	unsigned char passhash1[20];    /* hash of password */
	int i = 1;

	TPM_setlog(0);
	while (i  < argc) {
		if (!strcmp(argv[i],"-pwdk")) {
			i++;
			if (i >= argc) {
				printf("Parameter missing!\n");
				usage();
			}
			password = argv[i];
		} else 
		if (!strcmp(argv[i],"-v")) {
			TPM_setlog(1);
		} else 
		    if (!strcmp(argv[i],"-h")) {
			usage();
		} else {
			printf("\n%s is not a valid option\n", argv[i]);
			usage();
		}
		i++;
	}

	if (password != NULL) {
		TSS_sha1(password,strlen(password),passhash1);
		passptr1 = passhash1;
	} else {
	    printf("Missing parameter -pwdk\n");
	    exit(-1);
	}

	ret = TPM_RevokeTrust(passptr1);
	if (0 != ret) {
		printf("Error %s from TPM_RevokeTrust\n",
		       TPM_GetErrMsg(ret));
	}
 	exit(ret);
}

