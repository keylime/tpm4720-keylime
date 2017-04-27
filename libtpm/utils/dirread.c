/********************************************************************************/
/*										*/
/*			     	TPM Write into a DIR (data integrity register)	*/
/*			     Written by S. Berger				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*	      $Id: dirread.c 4702 2013-01-03 21:26:29Z kgoldman $		*/
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
	printf("Usage: dirread -in <index>\n"
	       "\n"
	       "-in index    : The index of the DIR to read from - in hex\n"
	       "\n"
	       "Examples:\n"
	       "dirread -in 0\n");
	exit(-1);
}



int main(int argc, char *argv[])
{
	unsigned char data[TPM_HASH_SIZE];
	int ret;
	int index = -1;
	int j = 0;
	int i = 1;
	
	TPM_setlog(0);

	while (i < argc) {
	    if (!strcmp("-in",argv[i])) {
		i++;
		if (i < argc) {
		    if (1 != sscanf(argv[i],"%x",&index)) {
			printf("Could not parse the index number.\n");
			exit(-1);
		    }
		} else {
		    printf("Missing parameter for -in.\n");
		    usage();
		}
	    }
	    else if (!strcmp("-v",argv[i])) {
		TPM_setlog(1);
	    }
	    else if (!strcmp("-h",argv[i])) {
		usage();
	    }
	    else {
		printf("\n%s is not a valid option\n",argv[i]);
		usage();
	    }
	    i++;
	}
	if (index == -1) {
	    printf("Missing -in parameter\n");
	    usage();
	}

	ret = TPM_DirRead(index, data);


	if (0 != ret) {
		printf("DirRead returned error '%s'.\n",
		       TPM_GetErrMsg(ret));
	} else {
		printf("Content of DIR %d: ",index);
		while (j < (int)sizeof(data)) {
			printf("%02x",data[j]);
			j++;
		}
		printf("\n");
	}
	
	exit(ret);
}

