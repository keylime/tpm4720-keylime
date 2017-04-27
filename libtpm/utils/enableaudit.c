/********************************************************************************/
/*										*/
/*			     	TPM Enable audit				*/
/*			     Written by S. Berger				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*	      $Id: enableaudit.c 4704 2013-04-04 20:47:53Z stefanb $		*/
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

static void usage()
{
    printf("Usage: enableaudit -ord <ordinal>  [-d] [-v]\n"
	   "   [-pwdo <owner password> -pwdof <owner authorization file name>\n"
	   "\n"
	   "-ord  : option to pass the ordinal for the audit\n"
	   "-pwdo : the owner password\n"
	   "-d    : to disable the audit; default is enabling\n"
	   "-v    : turns on verbose mode\n"
	   "\n");
    exit(-1);
}

int main(int argc, char *argv[])
{
    uint32_t ordinal = 0xffffffff;
    int ret;
    int i = 1;
    unsigned char ownerAuth[TPM_DIGEST_SIZE];
    const char * ownerPassword = NULL;
    const char *ownerAuthFilename = NULL;
    TPM_BOOL auditState = TRUE;
	
    TPM_setlog(0);
	
    while (i < argc) {
	if (!strcmp("-ord",argv[i])) {
	    i++;
	    if (i < argc) {
		sscanf(argv[i],"%d",&ordinal);
	    }
	    else {
		printf("Missing parameter for -ord.\n");
		usage();
	    }
	}
	else if (!strcmp("-pwdo",argv[i])) {
	    i++;
	    if (i < argc) {
		ownerPassword = argv[i];
	    }
	    else {
		printf("Missing parameter for -pwdo.\n");
		usage();
	    }
	}
	else if (strcmp(argv[i],"-pwdof") == 0) {
	    i++;
	    if (i < argc) {
		ownerAuthFilename = argv[i];
	    }
	    else
		{
		printf("-pwdof option needs a value\n");
		usage();
	    }
	}
	else if (!strcmp("-d",argv[i])) {
	    auditState = FALSE;
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
    /* check command line parameters */
    if ((ownerPassword == NULL) && (ownerAuthFilename == NULL)) {
	printf("\nMissing -pwdo or -pwdof argument\n");
	usage();
    }
    if ((ownerPassword != NULL) && (ownerAuthFilename != NULL)) {
	printf("\nCannot have -pwdo and -pwdof arguments\n");
	usage();
    }
    if (ordinal == 0xffffffff) {
	printf("Missing mandatory parameter -ord.\n");
	usage();
    }
	
    /* use the SHA1 hash of the password string as the Owner Authorization Data */
    if (ownerPassword != NULL) {
	TSS_sha1((unsigned char *)ownerPassword,
		 strlen(ownerPassword),
		 ownerAuth);
    }
    /* get the ownerAuth from a file */
    else {
	unsigned char *buffer = NULL;
	uint32_t buffersize;
	ret = TPM_ReadFile(ownerAuthFilename, &buffer, &buffersize);
	if ((ret & ERR_MASK)) {
	    printf("Error reading %s.\n", ownerAuthFilename);
	    exit(-1);
	}
	if (buffersize != sizeof(ownerAuth)) {
	    printf("Error reading %s, size %u should be %lu.\n",
		   ownerAuthFilename, buffersize, (unsigned long)sizeof(ownerAuth));
	    exit(-1);
	}
	memcpy(ownerAuth, buffer, sizeof(ownerAuth));
	free(buffer);
    }

    ret = TPM_SetOrdinalAuditStatus(ordinal,
				    auditState,
				    ownerAuth);
    if (ret != 0) {
	printf("SetOrdinalAuditStatus returned error %s.\n",
	       TPM_GetErrMsg(ret));
    }

    exit(ret);
}
