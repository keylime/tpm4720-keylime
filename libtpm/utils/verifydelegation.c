/********************************************************************************/
/*										*/
/*			     	TPM Verify Delegation				*/
/*			     Written by S. Berger				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*	      $Id: verifydelegation.c 4702 2013-01-03 21:26:29Z kgoldman $	*/
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

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
                     
#include "tpm.h"
#include "tpmutil.h"
#include <tpmfunc.h>

static void usage() {
    printf("Usage: verifydelegation -if filename [-v] \n"
	   "\n"
	   "-if  : delegation file name\n"
	   "-v   : to enable verbose output\n"
	   "\n");
    exit(-1);
}


int main(int argc, char *argv[])
{
	uint32_t ret = 0;
	char * filename = NULL;
	int i;
	struct stat _stat;

	TPM_setlog(0);

	for (i=1 ; i<argc ; i++) {
	    if (strcmp(argv[i],"-if") == 0) {
		i++;
		if (i < argc) {
		    filename = argv[i];
		}
		else {
		    printf("-if option needs a value\n");
		}
	    }
	    else if (!strcmp("-v",argv[i])) {
		TPM_setlog(1);
	    }
	    else if (!strcmp("-h",argv[i])) {
		usage();
	    }
	    else {
		printf("\n%s is not a valid option\n", argv[i]);
		usage();
	    }
	}
	if (filename == NULL) {
 	    printf("Missing the -if parameter!\n");
	    usage();
	}

	if (0 == stat(filename, &_stat)) {
		unsigned char *blob = malloc(_stat.st_size);
		uint32_t blobSize = _stat.st_size;
		FILE *f;
		if (NULL == blob) {
			printf("Could not allocate memory!\n");
			exit(-1);
		}
		
		f = fopen(filename, "rb");
		if (NULL == f) {
			printf("Could not open file for reading.\n");
			exit(-1);
		}
		
		if (blobSize != fread(blob, 1, blobSize, f)) {
			printf("Could not read the file.\n");
			fclose(f);
			exit(-1);
		}
		fclose(f);
		ret = TPM_Delegate_VerifyDelegation(blob, blobSize);

		if (ret  != 0) {
			printf("Error '%s' from Delegate_VerifyDelegation.\n",
			       TPM_GetErrMsg(ret));
			exit(-1);
		} else {
			printf("Successfully verified the blob.\n");
		}
	
	} else {
		printf("Error, file %s not accessible.\n",filename);
	}

	exit(ret);
}
