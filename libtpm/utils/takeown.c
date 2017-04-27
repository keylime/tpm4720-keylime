/********************************************************************************/
/*										*/
/*			     	TPM Test of TPM Take Ownership			*/
/*			     Written by J. Kravitz, S. Berger			*/
/*		       IBM Thomas J. Watson Research Center			*/
/*	      $Id: takeown.c 4702 2013-01-03 21:26:29Z kgoldman $		*/
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
#include <string.h>
#include "tpmfunc.h"
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/evp.h>

static void printUsage(void)
{
    printf("Usage: takeown [-v12] [-sz keylen]\n"
	   "   [-pwdo <owner password> -pwdof <owner authorization file name>\n"
	   "   [-pwds <storage root key password>]\n"
	   "   [-ix <pcr num> <digest> PCR authorization for SRK]\n");
    printf("\tOmitting -pwds sets the SRK auth to all zeros\n");
}

int main(int argc, char *argv[])
{
	int ret;
	unsigned char ownerAuth[20];
	unsigned char pass2hash[20];
	keydata srk;
	RSA *rsa = NULL;       	/* OpenSSL format Public Key */
	FILE *keyfile;    	/* output file for public key */
	EVP_PKEY *pkey = NULL;  /* OpenSSL public key */
	int keylen = 2048;
	int i;

	TPM_setlog(0);		/* turn off verbose output */
	TPM_BOOL v12 = FALSE;
	const char *ownerPassword = NULL;
	const char *ownerAuthFilename = NULL;
 	const char *srkAuth = NULL;

	TPM_PCRINDEX pcrIndex;				/* command line argument */
	TPM_PCRINDEX pcrs;				/* maximum number of PCRs */
	int max_indexR = -1;
	unsigned char future_hash[TPM_HASH_SIZE];	/* hash argument in binary */
	TPM_PCR_INFO pcrInfo;
	TPM_PCR_COMPOSITE pcrComposite;
	int index_ctr = 0;
	STACK_TPM_BUFFER(serPcrInfo);

	memset(&pcrInfo, 0x0, sizeof(pcrInfo));
	memset(&pcrComposite, 0x0, sizeof(pcrComposite));

	for (i=1 ; (i<argc)  ; i++) {
	    if (!strcmp(argv[i], "-v12")) {
		v12 = TRUE;
	    }
	    else if (!strcmp(argv[i], "-sz")) {
		i++;
		if (i < argc) {
		    if (1 != sscanf(argv[i], "%d", &keylen)) {
			printf("Could not parse keylen.\n");
			exit(-1);
		    }
		}
		else {
		    printf("Missing parameter for '-sz'.\n");
		    printUsage();
		    exit(-1);
		}
		if (keylen < 512) {
		    printf("Unacceptable key length of %d\n",keylen);
		    exit(-1);
		}
	    }
	    else if (strcmp(argv[i],"-pwdo") == 0) {
		i++;
		if (i < argc) {
		    ownerPassword = argv[i];
		}
		else {
		    printf("-pwdo option needs a value\n");
		    printUsage();
		    exit(2);
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
		    exit(2);
		}
	    }
	    else if (strcmp(argv[i],"-pwds") == 0) {
		i++;
		if (i < argc) {
		    srkAuth = argv[i];
		}
		else {
		    printf("-pwds option needs a value\n");
		    printUsage();
		    exit(2);
		}

	    }
	    else if (!strcmp(argv[i],"-ix")) {
		int j = 0;
		int shift = 4;
		char *hash_str = NULL;
		i++;
		if (i >= argc) {
		    printf("Missing index for option -ix\n");
		    printUsage();
		    exit(2);
		}
		pcrIndex = atoi(argv[i]);

		if ((int32_t)pcrIndex <= max_indexR) {
		    printf("Indices must be given in ascending order.\n");
		    exit(2);
		}
		max_indexR = pcrIndex;
   	    
		i++;
		if (i >= argc) {
		    printf("Missing digest for option -ix\n");
		    exit(2);
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
		 * Now build the pcrInfo
		 */
		pcrInfo.pcrSelection.sizeOfSelect = pcrs / 8;
		pcrInfo.pcrSelection.pcrSelect[pcrIndex >> 3] |= (1 << (pcrIndex & 0x7));

		index_ctr += 1;

		/*
		 * Update the PCR Composite structure.
		 */
		pcrComposite.select.sizeOfSelect = pcrs / 8;
		pcrComposite.select.pcrSelect[pcrIndex >> 3] |= (1 << (pcrIndex & 0x7));
		pcrComposite.pcrValue.size = index_ctr * TPM_HASH_SIZE;
		pcrComposite.pcrValue.buffer = realloc(pcrComposite.pcrValue.buffer,
						       pcrComposite.pcrValue.size);

		memcpy((char *)pcrComposite.pcrValue.buffer + (index_ctr-1)*TPM_HASH_SIZE,
		       future_hash,
		       TPM_HASH_SIZE);

	    }
	    else if (strcmp(argv[i],"-v") == 0) {
		TPM_setlog(1);
	    }
	    else if (strcmp(argv[i],"-h") == 0) {
		printUsage();
		exit(2);
	    }
	    else {
		printf("\n%s is not a valid option\n",argv[i]);
		printUsage();
		exit(2);
	    }
	}
	if ((ownerPassword == NULL) && (ownerAuthFilename == NULL)) {
	    printf("\nMissing -pwdo or -pwdof argument\n");
	    printUsage();
	    exit(2);
	}
	if ((ownerPassword != NULL) && (ownerAuthFilename != NULL)) {
	    printf("\nCannot have -pwdo and -pwdof arguments\n");
	    printUsage();
	    exit(2);
	}
	    
	/*
	 * If indices and hashes were given, calculate the hash over the
	 * PCR Composite structure.
	 */
	if (0 != index_ctr) {
	    TPM_HashPCRComposite(&pcrComposite, pcrInfo.digestAtRelease);
	    ret = TPM_WritePCRInfo(&serPcrInfo, &pcrInfo);
            if ((ret & ERR_MASK)) {
                printf("Error while serializing PCRInfo.\n");
                exit(-1);
	    }
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
	/*
	** use the SHA1 hash of the password string as the SRK Authorization Data
	*/
	if (srkAuth != NULL) {
	    TSS_sha1((unsigned char *)srkAuth,
		     strlen(srkAuth),
		     pass2hash);
	    ret = TPM_TakeOwnership(ownerAuth,pass2hash,keylen,
				    serPcrInfo.buffer, serPcrInfo.used,	/* PCR */
				    &srk, v12);
	} else {
	    ret = TPM_TakeOwnership(ownerAuth,NULL,keylen,
				    serPcrInfo.buffer, serPcrInfo.used,	/* PCR */
				    &srk, v12);
	}
	if (ret != 0) {
		printf("Error %s from TPM_TakeOwnership\n",TPM_GetErrMsg(ret));
		exit(ret);
	}
	
	if (v12 == TRUE) {
	    if (srk.v.tag != TPM_TAG_KEY12) {
		printf("SRK should be a TPM_KEY12.\n");
		exit(-1);
	    }
	}
	/*
	** convert the returned public key to OpenSSL format and
	** export it to a file
	*/
	rsa = TSS_convpubkey(&(srk.pub));
	if (rsa == NULL) {
		printf("Error from TSS_convpubkey\n");
		exit(-3);
	}
	OpenSSL_add_all_algorithms();
	pkey = EVP_PKEY_new();
	if (pkey == NULL) {
	    printf("Unable to create EVP_PKEY\n");
	    exit(-4);
	}
	ret = EVP_PKEY_assign_RSA(pkey,rsa);
	if (ret == 0) {
	    printf("Unable to assign public key to EVP_PKEY\n");
	    exit(-5);
	}
	keyfile = fopen("srk.pem","wb");
	if (keyfile == NULL) {
		printf("Unable to create public key file\n");
		exit(-6);
	}
	ret = PEM_write_PUBKEY(keyfile,pkey);
	if (ret == 0) {
		printf("Unable to write public key file\n");
		exit(-7);
	}
	fclose(keyfile);
	EVP_PKEY_free(pkey);
	exit(0);
}
