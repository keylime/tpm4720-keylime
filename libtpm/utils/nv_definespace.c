/********************************************************************************/
/*										*/
/*			    TCPA Define NV Storage Space			*/
/*			     Written by Stefan Berger				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*	      $Id: nv_definespace.c 4702 2013-01-03 21:26:29Z kgoldman $	*/
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


static void printUsage() {
    printf("usage: nv_definespace -in index -sz size\n"
	   "\t[-pwdo <owner password> -pwdof <owner authorization file name>\n"
	   "\t[-per permission] [-pwdd <area password>] [-v]\n"
	   "\t[-ixr <pcr num> <digest> require PCR authorization for read]\n"
	   "\t[-ixw <pcr num> <digest> require PCR authorization for write]\n"
	       "\n"
	       " -pwdo pwd    : The TPM owner password, if TPM has an owner\n"
	       " -in index    : Index of the memory to define in hex\n"
	       " -sz size      : Size of the memory in bytes\n"
	       " -per permission: A hex number that defines the permissions for the area of memory\n"
	       "       E.g. -per 40004 to set permissions to TPM_NV_PER_AUTHREAD|TPM_NV_PER_AUTHWRITE\n"
	       "       E.g. -per 20002 to set permissions to TPM_NV_PER_OWNERREAD|TPM_NV_PER_OWNERWRITE\n"
	       "                Default permissions 20000 allows reading only by the owner\n"
	       " -pwdd password  : The password for the memory area to protect.  If not specified, an\n"
               "                all zero value is used\n"
	       " -v           : Enable verbose output\n"
	       "\n"
	       "Examples:\n"
	       "nv_definespace -pwdo aaa -in 1 -sz 10\n"
	       "nv_definespace -pwdo aaa -in 2 -per 40004 -pwdd MyPWD\n"
	       "nv_definespace -in ffffffff -sz 0   (sets nvLocked)\n");
	exit(-1);
}

int main(int argc, char * argv[])
{
    const char *ownerPassword = NULL;
    const char *ownerAuthFilename = NULL;
    const char *areaPassword = NULL;
    unsigned char * ownerAuthPtr = NULL;
    unsigned char * areaAuthPtr = NULL;
    unsigned char ownerAuth[TPM_HASH_SIZE];
    unsigned char areaAuth[TPM_HASH_SIZE];	
    uint32_t ret;
    int i =	0;
    TPM_NV_INDEX index = 0;
    TPM_PCRINDEX pcrIndex;
    TPM_PCRINDEX pcrs;		/* maximum number of PCRs */
    int max_indexR = -1;
    int max_indexW = -1;
    unsigned char future_hash[TPM_HASH_SIZE];
    TPM_PCR_INFO_SHORT pcrInfoRead;
    TPM_PCR_INFO_SHORT pcrInfoWrite;
    TPM_PCR_COMPOSITE pcrCompRead;
    TPM_PCR_COMPOSITE pcrCompWrite;
    int index_ctrR = 0;
    int index_ctrW = 0;
    TPM_BOOL index_set = FALSE;
    uint32_t size = 0xffffffff;
    uint32_t permissions = TPM_NV_PER_OWNERREAD;
    int verbose = FALSE;
	
    TPM_setlog(0);
	
    memset(&pcrInfoRead, 0x0, sizeof(pcrInfoRead));
    pcrInfoRead.localityAtRelease = TPM_LOC_ZERO;

    memset(&pcrCompRead, 0x0, sizeof(pcrCompRead));

    memset(&pcrInfoWrite, 0x0, sizeof(pcrInfoWrite));
    pcrInfoWrite.localityAtRelease = TPM_LOC_ZERO;

    memset(&pcrCompWrite, 0x0, sizeof(pcrCompWrite));

    i = 1;
    while (i < argc) {
	if (!strcmp("-pwdo",argv[i])) {
	    i++;
	    if (i < argc) {
		ownerPassword = argv[i];
	    } else {
		printf("Missing mandatory parameter for -pwdo.\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-pwdof") == 0) {
	    i++;
	    if (i < argc) {
		ownerAuthFilename = argv[i];
	    }
	    else {
		printf("-pwdof option needs a value\n");
		printUsage();
	    }
	}
	else if (!strcmp("-in",argv[i])) {
	    i++;
	    if (i < argc) {
		if (1 == sscanf(argv[i], "%x", &index)) {
		    index_set = TRUE;
		}
		else {
		    printf("Could not read index.\n");
		    exit(-1);
		}
	    }
	    else {
		printf("Missing mandatory parameter for -in.\n");
		printUsage();
	    }
	}
	else if (!strcmp("-sz",argv[i])) {
	    i++;
	    if (i < argc) {
		size = atoi(argv[i]);
		if ((int)size < 0) {
		    printf("Negative size not allowed!\n");
		    exit(-1);
		}
	    }
	    else {
		printf("Missing mandatory parameter for -sz.\n");
		printUsage();
	    }
	}
	else if (!strcmp("-per",argv[i])) {
	    i++;
	    if (i < argc) {
		sscanf(argv[i],"%x",&permissions);
	    }
	    else {
		printf("Missing parameter for -per.\n");
		printUsage();
	    }
	}
	else if (!strcmp("-pwdd",argv[i])) {
	    i++;
	    if (i < argc) {
		areaPassword = argv[i];
	    }
	    else {
		printf("Missing parameter for -pwdd.\n");
		printUsage();
	    }
	}
	else if (!strcmp(argv[i],"-ixr")) {
	    int j = 0;
	    int shift = 4;
	    char * hash_str = NULL;
	    i++;
	    if (i >= argc) {
		printf("Missing index for option -ixr.\n");
		printUsage();
		exit(-1);
	    }
	    pcrIndex = atoi(argv[i]);

	    if ((int32_t)pcrIndex <= max_indexR) {
		printf("Indices must be given in ascending order.\n");
		exit(-1);
	    }
	    max_indexR = pcrIndex;
   	    
	    i++;
	    if (i >= argc) {
		printf("Missing digest for option -ixr.\n");
		exit(-1);
	    }
	    hash_str = argv[i];
	    if (40 != strlen(hash_str)) {
		printf("The digest must be exactly 40 characters long!\n");
		exit(-1);
	    }
	    memset(future_hash, 0x0, TPM_HASH_SIZE);
	    shift = 4;
	    j = 0;
	    while (j < (2 * TPM_HASH_SIZE)) {
		unsigned char c = hash_str[j];
   	        
		if (c >= '0' && c <= '9') {
		    future_hash[j>>1] |= ((c - '0') << shift);
		} else
		    if (c >= 'a' && c <= 'f') {
			future_hash[j>>1] |= ((c - 'a' + 10) << shift);
		    } else
			if (c >= 'A' && c <= 'F') {
			    future_hash[j>>1] |= ((c - 'A' + 10) << shift);
			} else {
			    printf("Digest contains non-hex character!\n");
			    exit(-1);
			}
		shift ^= 4;
		j++;
	    }
	    ret = TPM_GetNumPCRRegisters(&pcrs);
	    if (ret != 0) {
		printf("Error reading number of PCR registers.\n");
		exit(-1);
	    }
	    if (pcrs > TPM_NUM_PCR) {
		printf("Library does not support that many PCRs\n");
		exit(-1);
	    }
	    if (pcrIndex >= pcrs) {
		printf("Index out of range!\n");
		printUsage();
		exit(-1);
	    }
	    /*
	     * Now build the pcrInfoRead
	     */
	    pcrInfoRead.pcrSelection.sizeOfSelect = pcrs / 8;
	    pcrInfoRead.pcrSelection.pcrSelect[pcrIndex >> 3] |= (1 << (pcrIndex & 0x7));

	    index_ctrR += 1;

	    /*
	     * Update the PCR Composite structure.
	     */
	    pcrCompRead.select.sizeOfSelect = pcrs / 8;
	    pcrCompRead.select.pcrSelect[pcrIndex >> 3] |= (1 << (pcrIndex & 0x7));
	    pcrCompRead.pcrValue.size = index_ctrR * TPM_HASH_SIZE;
	    pcrCompRead.pcrValue.buffer = realloc(pcrCompRead.pcrValue.buffer,
						  pcrCompRead.pcrValue.size);

	    memcpy((char *)pcrCompRead.pcrValue.buffer + (index_ctrR-1)*TPM_HASH_SIZE,
		   future_hash,
		   TPM_HASH_SIZE);

	}
	else if (!strcmp(argv[i],"-ixw")) {
	    int j = 0;
	    int shift = 4;
	    char * hash_str = NULL;
	    i++;
	    if (i >= argc) {
		printf("Missing index for option -ixw.\n");
		printUsage();
		exit(-1);
	    }
	    pcrIndex = atoi(argv[i]);

	    if ((int32_t)pcrIndex <= max_indexW) {
		printf("Indices must be given in ascending order.\n");
		exit(-1);
	    }
	    max_indexW = pcrIndex;
   	    
	    i++;
	    if (i >= argc) {
		printf("Missing digest for option -ixw.\n");
		exit(-1);
	    }
	    hash_str = argv[i];
	    if (40 != strlen(hash_str)) {
		printf("The digest must be exactly 40 characters long!\n");
		exit(-1);
	    }
	    memset(future_hash, 0x0, TPM_HASH_SIZE);
	    shift = 4;
	    j = 0;
	    while (j < (2 * TPM_HASH_SIZE)) {
		unsigned char c = hash_str[j];
   	        
		if (c >= '0' && c <= '9') {
		    future_hash[j>>1] |= ((c - '0') << shift);
		} else
		    if (c >= 'a' && c <= 'f') {
			future_hash[j>>1] |= ((c - 'a' + 10) << shift);
		    } else
			if (c >= 'A' && c <= 'F') {
			    future_hash[j>>1] |= ((c - 'A' + 10) << shift);
			} else {
			    printf("Digest contains non-hex character!\n");
			    exit(-1);
			}
		shift ^= 4;
		j++;
	    }
	    ret = TPM_GetNumPCRRegisters(&pcrs);
	    if (ret != 0) {
		printf("Error reading number of PCR registers.\n");
		exit(-1);
	    }
	    if (pcrs > TPM_NUM_PCR) {
		printf("Library does not support that many PCRs\n");
		exit(-1);
	    }
	    if (pcrIndex >= pcrs) {
		printf("Index out of range!\n");
		printUsage();
		exit(-1);
	    }
	    /*
	     * Now build the pcrInfoWrite
	     */
	    pcrInfoWrite.pcrSelection.sizeOfSelect = pcrs / 8;
	    pcrInfoWrite.pcrSelection.pcrSelect[pcrIndex >> 3] |= (1 << (pcrIndex & 0x7));

	    index_ctrW += 1;

	    /*
	     * Update the PCR Composite structure.
	     */
	    pcrCompWrite.select.sizeOfSelect = pcrs / 8;
	    pcrCompWrite.select.pcrSelect[pcrIndex >> 3] |= (1 << (pcrIndex & 0x7));
	    pcrCompWrite.pcrValue.size = index_ctrW * TPM_HASH_SIZE;
	    pcrCompWrite.pcrValue.buffer  = realloc(pcrCompWrite.pcrValue.buffer,
						    pcrCompWrite.pcrValue.size);

	    memcpy((char *)pcrCompWrite.pcrValue.buffer + (index_ctrW-1)*TPM_HASH_SIZE,
		   future_hash,
		   TPM_HASH_SIZE);
	}
	else if (!strcmp("-v",argv[i])) {
	    verbose = TRUE;
	    TPM_setlog(1);
	}
	else if (!strcmp("-h",argv[i])) {
	    printUsage();
	}
	else {
	    printf("\n%s is not a valid option\n", argv[i]);
	    printUsage();
	}
	i++;
    }

    if (index_set == FALSE) {
	printf("Input parameter -in wrong or missing!\n");
	printUsage();
    }
    if (size == 0xffffffff) {
	printf("Input parameter -sz wrong or missing!\n");
	printUsage();
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

    if (NULL != areaPassword) {
	TSS_sha1((unsigned char *)areaPassword, strlen(areaPassword), areaAuth);
	areaAuthPtr = areaAuth;
    }
    else {
	areaAuthPtr = NULL;
    }

    if (TRUE == verbose) {
	printf("index = %d = 0x%x\n",(int)index,(int)index);
    }

    /*
     * If indices and hashes were given, calculate the hash over the
     * PCR Composite structure.
     */
    if (0 != index_ctrR) {
	TPM_HashPCRComposite(&pcrCompRead, pcrInfoRead.digestAtRelease);
    }
    if (0 != index_ctrW) {
	TPM_HashPCRComposite(&pcrCompWrite, pcrInfoWrite.digestAtRelease);
    }
    /*
     * Define a space in NV ram,
     */

    ret = TPM_NV_DefineSpace2(ownerAuthPtr,	/* Sha(HMAC key) */
			      index,
			      size,
			      permissions,
			      areaAuthPtr,	/* NV auth - used to create encAuth */
			      &pcrInfoRead,
			      &pcrInfoWrite);

    if (0 != ret) {
	printf("Got error '%s' from TPM_NV_DefineSpace2().\n",
	       TPM_GetErrMsg(ret));
    }

    exit(ret);
}
