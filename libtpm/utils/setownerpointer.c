/********************************************************************************/
/*										*/
/*			     	TPM DisableForceClear                    	*/
/*			     Written by S. Berger				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*	      $Id: setownerpointer.c 4702 2013-01-03 21:26:29Z kgoldman $	*/
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

static void usage(void)
{
	printf("Usage: setownerpointer Argument\n"
	       "\n"
	       "The argument must be either one of the following\n"
	       "  -own       - to indicate owner type\n"
	       "  -row <row> - to indicate the row number; row number in hex (0x...) or dec.\n"
	       "\n"
	       "examples:\n"
	       "setownerpointer -row 2\n"
	       "setownerpointer -own\n");
	exit(-1);
}


int main(int argc, char *argv[])
{
	uint32_t ret;
	uint32_t value = -1;
	uint16_t type = -1;
	int i = 1;

	TPM_setlog(0);

	while (i < argc) {
	    if (!strcmp("-own",argv[i])) {
		type = TPM_ET_OWNER;
	    }
	    else if (!strcmp("-row",argv[i])) {
		type = TPM_ET_DEL_ROW;
		i++;
		if (i >= argc) {
		    printf("Missing argument after -row\n");
		    usage();
		}
		if (1 != sscanf(argv[i],"%x",&value)) {
		    printf("Could not parse the -row value.\n");
		    return -1;
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
	    i++;
	}
	if ((type == 0xffff) ||
	    ((type == TPM_ET_DEL_ROW) && (value == 0xffffffff))) {
	    printf("Missing parameter");
	    usage();
	}
	ret = TPM_SetOwnerPointer(type, value);

	if (0 != ret) {
		printf("SetOwnerPointer returned error '%s'.\n",
		       TPM_GetErrMsg(ret));
	}
	
	exit(ret);
}
