/********************************************************************************/
/*										*/
/*			    TCPA Read Value from NV Storage			*/
/*			     Written by Stefan Berger				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*	      $Id: nv_readvalue.c 4702 2013-01-03 21:26:29Z kgoldman $		*/
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
#include <errno.h>
#include <unistd.h>
#include <ctype.h>

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
uint32_t readtpm(TPM_NV_INDEX index,
		 uint32_t size,
		 uint32_t offset,
		 unsigned char * ownerAuthPtr,
		 unsigned char * areaAuthPtr,
		 unsigned char **readbuffer,
		 uint32_t *readbufferlen,
		 uint32_t expectederror);
    
static void usage()
{
    printf("Usage: nv_readvalue -in index [-sz size -cert] [-off offset] \n"
	   "\t[-pwdo <owner password> -pwdof <owner authorization file name>]"
	   "\t[-pwdd <area password>] [-of <data file name>]\n"
	   "\n"
	   " -pwdo pwd      : The TPM owner password.\n"
	   " -pwdof file    : The TPM owner authorization file name.\n"
	   " -in index      : The index of the memory to use in hex.\n"
	   " -sz size       : The number of bytes to read.\n"
	   " -cert          : The number of bytes is embedded in the certificate prefix.\n"
	   " -off offset    : The offset in memory where to start reading from (default 0)\n"
	   " -pwdd password : The password for the memory area.\n"
	   " -of file       : File to store the read bytes.\n"
	   " -ee num        : Expected error number.\n"
	   "\n"
           "With -pwdo or -pwdof, does TPM_ReadValue\n"
           "With -pwdd, does TPM_ReadValueAuth\n"
           "With neither, does TPM_ReadValue with no authorization\n"
	   "\n"
	   "Examples:\n"
	   "nv_readvalue -pwdo ooo -in 2 -sz  2 -off 0\n"
	   "nv_readvalue -pwdd aaa -in 2 -sz 10 -off 5 \n");
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
    unsigned long lrc;
    int irc;
    uint32_t size = 0xffffffff;
    int cert = FALSE;
    uint32_t offset = 0;
    int i =	0;
    TPM_NV_INDEX index = 0xffffffff;
    unsigned char * readbuffer = NULL;
    uint32_t readbufferlen = -1;
    uint32_t expectederror = 0;
    const char *datafilename = NULL;
    FILE *datafile = NULL;
    int verbose = FALSE;
	
    i = 1;
	
    TPM_setlog(0);
	
    while (i < argc) {
	if (!strcmp("-pwdo",argv[i])) {
	    i++;
	    if (i < argc) {
		ownerPassword = argv[i];
	    } else {
		printf("Missing mandatory parameter for -pwdo (owner password).\n");
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
	else if (!strcmp("-sz",argv[i])) {
	    i++;
	    if (i < argc) {
		size = atoi(argv[i]);
		if ((int)size < 0) {
		    printf("Size must not be negative!\n");
		    exit(-1);
		}
	    } else {
		printf("Missing mandatory parameter for -sz (size).\n");
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
	    } else {
		printf("Missing mandatory parameter for -in (NV space index).\n");
		usage();
	    }
	}
	else if (!strcmp("-off",argv[i])) {
	    i++;
	    if (i < argc) {
		offset = atoi(argv[i]);
	    } else {
		printf("Missing mandatory parameter for -off (offset).\n");
		usage();
	    }
	}
	else if (!strcmp("-pwdd",argv[i])) {
	    i++;
	    if (i < argc) {
		areaPassword = argv[i];
	    } else {
		printf("Missing parameter for -pwdd (NV space password).\n");
		usage();
	    }
	}
	else if (!strcmp("-ee",argv[i])) {
	    i++;
	    if (i < argc) {
		expectederror = atoi(argv[i]);
	    } else {
		printf("Missing parameter for -ee (expected error).\n");
		usage();
	    }
	}
	else if (!strcmp("-of",argv[i])) {
	    i++;
	    if (i < argc) {
		datafilename = argv[i];
	    } else {
		printf("Missing mandatory parameter for -of (data file name).\n");
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

    if (index == 0xffffffff) {
	printf("Input parameter -ix wrong or missing!\n");
	usage();
    }
    if (((size == 0xffffffff) && !cert) ||
	((size != 0xffffffff) && cert)) {
	printf("One of -sz or -cert must be specified!\n");
	usage();
    }
    if (cert && (offset != 0)) {
	printf("-off must not be specified with -cert!\n");
	usage();
    }
  
    if ((ownerPassword != NULL) && (ownerAuthFilename != NULL)) {
	printf("\nCannot have -pwdo and -pwdof arguments\n");
	usage();
    }
    /* if both area and owner password specified */
    if (((ownerPassword != NULL) || (ownerAuthFilename != NULL)) &&
	(areaPassword != NULL)) {
	printf("Owner and area password cannot both be specified\n");
	usage();
    }

    if (verbose) {
	printf("Using ownerPassword : %s\n", ownerPassword);
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
    /* read raw data, not a certificate */
    if (!cert) {
	readbufferlen = size + 1;
	ret = readtpm(index,
		      size,
		      offset,
		      ownerAuthPtr,
		      areaAuthPtr,
		      &readbuffer,
		      &readbufferlen,
		      expectederror);
    }
    /* read a certificate */
    else {
	/* read the 7 byte prefix */
	if (ret == 0) {
	    readbufferlen = 7;
	    ret = readtpm(index,
			  readbufferlen,
			  offset,
			  ownerAuthPtr,
			  areaAuthPtr,
			  &readbuffer,
			  &readbufferlen,
			  expectederror);
	}
	/* validate the bytes and get the certificate length */
	if (ret == 0) {
	    if ((readbuffer[0] != 0x00) ||	/* stored certificate, full certificate */
		(readbuffer[1] != 0x01) ||
		(readbuffer[2] != 0x00) ||	/* full certificate */
		(readbuffer[5] != 0x10) ||
		(readbuffer[6] != 0x02)) {
		printf("Indexd dpoes not have certificate prefix\n");
		ret = -1;
	    }
	    readbufferlen = (readbuffer[3] << 8) +	/* msb */
			    readbuffer[4]
			    -2;		/* -2 for bytes 5 and 6 */
	}
	free(readbuffer);
	readbuffer = NULL;
	if (ret == 0) {
	    ret = readtpm(index,
			  readbufferlen,
			  7,		/* skip the prefix */
			  ownerAuthPtr,
			  areaAuthPtr,
			  &readbuffer,
			  &readbufferlen,
			  expectederror);
	}
    }
    /* optionally write the result to stdout */
    if ((0 == ret) && (datafilename == NULL)) {
	uint32_t i = 0;
	int is_ascii = TRUE;
	printf("Received %d bytes:\n", readbufferlen);
	while (i < readbufferlen) {
	    if ((i & 0xf) == 0)
		printf("%04x: ", i);
	    printf("%02x ",readbuffer[i]);
	    if (!isprint(readbuffer[i]) && !isspace(readbuffer[i])) {
		is_ascii = FALSE;
	    }
	    i++;
	    if ((i & 0xf) == 0 && i < readbufferlen)
		printf("\n");
	}
	printf("\n\n");
	if (TRUE == is_ascii) {
	    readbuffer[readbufferlen] = 0;
	    printf("Text: %s\n",readbuffer);
	}
    }
    /* optionally write the data to a file */
    if ((0 == ret) && (datafilename != NULL)) {
	datafile = fopen(datafilename, "wb");
	if (datafile == NULL) {
	    printf("Error, opening %s for write from NV_ReadValue, %s\n",
		   datafilename, strerror(errno));
	    ret = -1;
	}
    }
    if ((0 == ret) && (datafilename != NULL)) {
	lrc = fwrite(readbuffer, 1, readbufferlen, datafile);
	if (lrc != readbufferlen) {
	    printf("Error, could not write %u bytes from NV_ReadValue\n", readbufferlen);
	    ret = -1;
	}
    }
    if ((0 == ret) && (datafilename != NULL)) {
	if (datafile != NULL) {
	    irc = fclose(datafile);
	    if (irc != 0) {
		printf("Error closing output file %s from NV_ReadValue\n", datafilename);
		ret = -1;
	    }
	}
    }
    free(readbuffer);

    exit(ret);
}

uint32_t readtpm(TPM_NV_INDEX index,
		 uint32_t size,
		 uint32_t offset,
		 unsigned char * ownerAuthPtr,
		 unsigned char * areaAuthPtr,
		 unsigned char **readbuffer,
		 uint32_t *readbufferlen,
		 uint32_t expectederror)
{
    uint32_t ret = 0;

    *readbuffer = (unsigned char *)malloc(*readbufferlen);

    /* if no area password specified, do owner read (either auth-1 or no auth) */
    if (areaAuthPtr == NULL) {
       ret = TPM_NV_ReadValue(index,
			      offset,
			      size,
			      *readbuffer, readbufferlen,
			      ownerAuthPtr);
       if (0 != ret) {
	   if (ret != expectederror) {
	       printf("Error %s from NV_ReadValue\n",
		      TPM_GetErrMsg(ret));
	   }
       }
    }
    /* if area password specified */
    else  {
	ret = TPM_NV_ReadValueAuth(index,
				   offset,
				   size,
				   *readbuffer,readbufferlen,
				   areaAuthPtr);
	if (0 != ret) {	
	    if (ret != expectederror) {
		printf("Error %s from NV_ReadValueAuth\n",
		       TPM_GetErrMsg(ret));
	    }
	}
    }
    return ret;
}
