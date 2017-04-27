/********************************************************************************/
/*										*/
/*			     	TPM CMK_ApproveMA				*/
/*			     Written by S. Berger				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*	      $Id: cmk_approvema.c 4702 2013-01-03 21:26:29Z kgoldman $		*/
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
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#ifdef TPM_POSIX
#include <netinet/in.h>
#endif
#ifdef TPM_WINDOWS
#include <winsock2.h>
#endif
#include "tpm.h"
#include "tpmutil.h"
#include <tpmfunc.h>

/* local prototypes */
static int addKeyToMSAList(TPM_MSA_COMPOSITE * msalist, char * filename);

static void usage() {
	printf("Usage: cmk_approvema [-msa <msa filename>] -pwdo <owner password> -ik <keyfile> -of <filename}\n"
	       "\n"
	       " -pwdo pwd    : the TPM owner password\n"
	       " -of filename : the name of the file where to write the HMAC and digest into\n"
	       " -ik          : a file containing a public key; option may be repeated multiple times\n"
	       " -msa         : name of file where to write the msa list into\n"
	       " -v           : to enable verbose output\n"
	       "\n"
	       "Examples:\n"
	       "cmk_approvema -pwdo aaa -ik stkey.key -ik lekey.pem \n");
}


int main(int argc, char *argv[])
{
	unsigned char passhash1[20];
	char * ownerpass = NULL;
	char * filename = NULL;
	int ret;
	int verbose = FALSE;
	TPM_MSA_COMPOSITE msaList = {0, NULL};
	unsigned char migAuthDigest[TPM_DIGEST_SIZE];
	unsigned char hmac[TPM_DIGEST_SIZE];
	char * msa_list_filename = NULL;
	
	int i = 1;
	
	TPM_setlog(0);
	
	while (i < argc) {
		if (!strcmp("-pwdo",argv[i])) {
			i++;
			if (i < argc) {
				ownerpass = argv[i];
			} else {
				printf("Missing parameter for -pwdo.\n");
				usage();
				exit(-1);
			}
		} else
		if (!strcmp("-of",argv[i])) {
			i++;
			if (i < argc) {
				filename = argv[i];
			} else {
				printf("Missing parameter for -of.\n");
				usage();
				exit(-1);
			}
		} else
		if (!strcmp("-msa",argv[i])) {
			i++;
			if (i < argc) {
				msa_list_filename = argv[i];
			} else {
				printf("Missing parameter for -msa.\n");
				usage();
				exit(-1);
			}
		} else
		if (!strcmp("-ik",argv[i])) {
			i++;
			if (i < argc) {
				if (0 != addKeyToMSAList(&msaList,argv[i])) {
					exit(-1);
				}
			} else {
				printf("Missing parameter for -ik.\n");
				usage();
				exit(-1);
			}
		} else
		if (!strcmp("-v",argv[i])) {
			verbose = TRUE;
			TPM_setlog(1);
		} else
		if (!strcmp("-h",argv[i])) {
		    usage();
		    exit(-1);
		} else {
		        printf("\n%s is not a valid option\n",argv[i]);
			usage();
			exit(-1);
		}
		i++;
	}
	(void)verbose;

	if (NULL == ownerpass ||
	    msaList.MSAlist == 0 ||
	    NULL == filename) {
		printf("Missing argument.\n");
		usage();
		exit(-1);
	}
	
	if (NULL != ownerpass) {
		TSS_sha1(ownerpass,strlen(ownerpass),passhash1);
	}
	
   
   
	TPM_HashMSAComposite(&msaList, migAuthDigest);
   	ret = TPM_CMK_ApproveMA(migAuthDigest,
	                        passhash1,
	                        hmac);


	if (0 != ret) {
		printf("CMK_ApproveMA returned error '%s' (%d).\n",
		       TPM_GetErrMsg(ret),
		       ret);
	} else {
		FILE * f = fopen(filename, "wb+");
		if (f != NULL) {
			if (TPM_DIGEST_SIZE == fwrite(hmac, 1, TPM_DIGEST_SIZE, f) &&
			    TPM_DIGEST_SIZE == fwrite(migAuthDigest, 1, TPM_DIGEST_SIZE, f) ) {
				printf("Successfully wrote HMAC and digest to %s.\n",
				       filename);
			}
			fclose(f);
			
		} else {
			printf("Could not open file %s for writing.\n",
			       filename);
		}
	}

	if (NULL != msa_list_filename) {
		struct tpm_buffer * buffer = TSS_AllocTPMBuffer(sizeof(msaList) + msaList.MSAlist * TPM_HASH_SIZE);
		if (NULL != buffer) {
			uint32_t len = TPM_WriteMSAComposite(buffer, &msaList);
			FILE * f = fopen(msa_list_filename, "wb");
			if (NULL != f) {
				fwrite(buffer->buffer,len,1, f);
				printf("Successfully wrote msa list to %s.\n",
				       msa_list_filename);
				fclose(f);
			} else {
				printf("Could not open file %s for writing.\n",
				       msa_list_filename);
			}
			TSS_FreeTPMBuffer(buffer);
		}
		
	}
	
	exit(ret);
}

static int addKeyToMSAList(TPM_MSA_COMPOSITE * msalist, char * filename)
{
	int ret  = 0;
	
	int len = strlen(filename);
	
	if (!strcmp(&filename[len-4],".pem")) {
		printf("Cannot deal with .pem files, yet.\n");
		ret = -1;
	} else
	if (!strcmp(&filename[len-4],".key") ||
	    !strcmp(&filename[len-4],".pub")) {
		struct keydata key;
		memset(&key, 0x0, sizeof(key));
		ret = TPM_ReadKeyfile(filename, &key);
		if ((ret & ERR_MASK)) {
			memset(&key, 0x0, sizeof(key));
			ret = TPM_ReadPubKeyfile(filename, &key.pub);
			if ((ret & ERR_MASK)) {
				printf("Error reading keyfile: %s\n", 
				       TPM_GetErrMsg(ret));
				return ret;
			}
		}
		if (ret == 0) {
			msalist->MSAlist++;
			msalist->migAuthDigest =
			          realloc(msalist->migAuthDigest,
			                  msalist->MSAlist * TPM_HASH_SIZE);
			TPM_HashPubKey(&key,
			               (unsigned char *)msalist->migAuthDigest + 
			               (msalist->MSAlist-1)* TPM_DIGEST_SIZE);
		}
	} else {
		printf("File '%s' in unknown format. Not .key or .pem.\n",
		       filename);
		ret = -1;
	}
	
	return ret;
}
