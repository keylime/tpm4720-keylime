/********************************************************************************/
/*										*/
/*			    TCPA Write to NV Storage				*/
/*			     Written by Stefan Berger				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*	      $Id: nv_writevalue.c 4702 2013-01-03 21:26:29Z kgoldman $		*/
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
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>

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
	printf("Usage: nv_writevalue -in index -ic data -if file\n"
	       "\t[-pwdo <owner password> -pwdof <owner authorization file name>]"
	       "\t[-pwdd <area password>] [-off offset] [-cert]\n");
	printf("\n");
	printf(" -pwdo pwd       : The TPM owner password.\n");
	printf(" -pwdof file     : The TPM owner authorization file name.\n");
	printf(" -in index       : The index of the memory to use in hex.\n");
	printf(" -ic data string : The data to write into the memory (default data length 0.\n");
	printf(" -if data file   : The data to write into the memory (default data length 0.\n");
	printf(" -off offset     : The offset where to start writing (default 0).\n");
	printf(" -pwdd password  : The password for the memory area.\n");
	printf(" -cert           : With -if, writes the 7 byte TCG prefix: 10 01 00 length 10 02\n");
	printf(" -ee num         : Expected error\n");
	printf("\n");
        printf("With -pwdo, does TPM_WriteValue\n");
        printf("With -pwdd, does TPM_WriteValueAuth\n");
        printf("With neither, does TPM_WriteValue with no authorization\n");
        printf("\n");
	printf("Examples:\n");
	printf("nv_writevalue -pwdo ooo -in 1 -ic Hello\n");
	printf("nv_writevalue -pwdo ooo -in 1000f000 -if ekcert.cer -cert\n");
	printf("nv_writevalue -pwdd aaa -in 2 -ic Hello -off 5\n");
	exit(-1);
}


int main(int argc, char * argv[])
{
    const char * ownerPassword = NULL;
    const char *ownerAuthFilename = NULL;
    const char * areaPassword = NULL;
    unsigned char * ownerAuthPtr = NULL;
    unsigned char * areaAuthPtr = NULL;
    unsigned char ownerAuth[TPM_HASH_SIZE];
    unsigned char areaAuth[TPM_HASH_SIZE];	
    uint32_t ret = 0;
    uint32_t offset = 0;
    int i =	0;
    TPM_NV_INDEX index = 0xffffffff;
    unsigned char * data = NULL;
    char * datafilename = NULL;
    FILE *datafile = NULL;
    unsigned int datalen = 0;
    unsigned char datablob[4096];
    int cert = FALSE;
    uint32_t expectederror = 0;
    int verbose = FALSE;
	
    i = 1;
	
    TPM_setlog(0);
	
    while (i < argc) {
	if (!strcmp("-pwdo",argv[i])) {
	    i++;
	    if (i < argc) {
		ownerPassword = argv[i];
	    } else {
		printf("Missing mandatory parameter for -pwdo.\n");
		usage();
	    }
	}
	else if (strcmp(argv[i],"-pwdof") == 0) {
	    i++;
	    if (i < argc) {
		ownerAuthFilename = argv[i];
	    }
	    else {
		printf("-pwdof option needs a value\n");
		usage();
	    }
	}
	else if (!strcmp("-ic",argv[i])) {
	    i++;
	    if (i < argc) {
		data = (unsigned char*)argv[i];
	    } else {
		printf("Missing mandatory parameter for -ic.\n");
		usage();
	    }
	}
	else if (!strcmp("-if",argv[i])) {
	    i++;
	    if (i < argc) {
		datafilename = argv[i];
	    } else {
		printf("Missing mandatory parameter for -ic.\n");
		usage();
	    }
	}
	else if (!strcmp("-in",argv[i])) {
	    i++;
	    if (i < argc) {
		if (1 != sscanf(argv[i], "%x", &index)) {
		    printf("Could not parse index '%s'.\n", argv[i]);
		    exit(-1);
		}
	    }
	    else {
		printf("Missing mandatory parameter for -in (NV space index).\n");
		usage();
	    }
	}
	else if (!strcmp("-off",argv[i])) {
	    i++;
	    if (i < argc) {
		offset = atoi(argv[i]);
	    } else {
		printf("Missing optional parameter for -off.\n");
		usage();
	    }
	}
	else if (!strcmp("-pwdd",argv[i])) {
	    i++;
	    if (i < argc) {
		areaPassword = argv[i];
	    } else {
		printf("Missing parameter for -pwdd.\n");
		usage();
	    }
	}
	else if (!strcmp("-ee",argv[i])) {
	    i++;
	    if (i < argc) {
		expectederror = atoi(argv[i]);
	    } else {
		printf("Missing parameter for -ee.\n");
		usage();
	    }
	}
	else if (!strcmp("-cert",argv[i])) {
	    cert = TRUE;
	}
	else if (!strcmp("-v",argv[i])) {
	    verbose = TRUE;
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
    /* NV index must be specified */
    if (index == 0xffffffff) {
	printf("\nInput index parameter -in wrong or missing!\n");
	usage();
    }
    /* if both area and owner password specified */
    if (((ownerPassword != NULL) || (ownerAuthFilename != NULL)) &&
	(areaPassword != NULL)) {
	printf("Owner and area password cannot both be specified\n");
	usage();
    }

    /* default, write file size 0, useful for locks */
    if ((NULL == data) && (datafilename == NULL)) {
	datalen = 0;
    }
    else if ((NULL != data) && (datafilename != NULL)) {
	printf("\ndata string and data file cannot both be specified\n");
	usage();
    }
    /* data from command line string */
    else if (data != NULL) {
	datalen = strlen((char *)data);
    }
    /* data from command line file name */
    else {
	struct stat sbuf;

	datafile = fopen(datafilename ,"rb");
	if (datafile == NULL) {
	    printf("Unable to open data file %s\n", datafilename);
	    exit(-3);
	}
	stat(datafilename, &sbuf);
	datalen = sbuf.st_size;
	if (!cert) {
	    ret = fread(datablob, 1, datalen, datafile);
	}
	else {
	    ret = fread(datablob + 7, 1, datalen, datafile);
	}
	if (ret != datalen) {
	    printf("Unable to read data file %s\n", datafilename);
	    exit(-4);
	}
	fclose(datafile);
	/* prepend the certificate prefix and length */
	if (cert) {
	    datablob[0] = 0x00;		/* stored certificate, full certificate */
	    datablob[1] = 0x01;
	    datablob[2] = 0x00;
	    datablob[3] = ((datalen +2) & 0xff00) >> 8;	/* msb */
	    datablob[4] = ((datalen +2) & 0xff);	/* +2 for bytes 5 and 6 */
	    datablob[5] = 0x10;
	    datablob[6] = 0x02;		/* full certificate */
	    datalen += 7;
	}
	data = datablob;
    }
    if (verbose) {
	printf("Using ownerPassword : %s\n",ownerPassword);
	printf("Using ownerAuth : %s\n", ownerAuthFilename);
	printf("Using areaPassword: %s\n", areaPassword);
    }
    /* use the SHA1 hash of the password string as the Owner Authorization Data */
    if (ownerPassword != NULL) {
	TSS_sha1((unsigned char *)ownerPassword,
		 strlen(ownerPassword),
		 ownerAuth);
	ownerAuthPtr = ownerAuth;
    }
    /* get the ownerAuth from a file */
    else if (ownerAuthFilename != NULL) {
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
	ownerAuthPtr = ownerAuth;
	free(buffer);
    }
    else {
	ownerAuthPtr = NULL;
    }
    /* process area password if present */
    if (areaPassword != NULL) {
	TSS_sha1((unsigned char *)areaPassword, strlen(areaPassword), areaAuth);
	areaAuthPtr = areaAuth;
    }
    else {
	areaAuthPtr = NULL;
    }
    /* if no area password specified, do owner read (either auth-1 or no auth) */
    if (areaAuthPtr == NULL) {
	ret = TPM_NV_WriteValue(index,
				offset,
				data, datalen,
				ownerAuthPtr);
	if (0 != ret) {
	    if (ret != expectederror) {
		printf("Error %s from NV_WriteValue\n", TPM_GetErrMsg(ret));
	    }
	}
    }
    /* if area password specified */
    else  {
	ret = TPM_NV_WriteValueAuth(index,
				    offset,
				    data, datalen,
				    areaAuthPtr);
	if (0 != ret) {
	    if (ret != expectederror) {
		printf("Error %s from NV_WriteValueAuth\n", TPM_GetErrMsg(ret));
	    }
	}
    }
    exit(ret);
}
