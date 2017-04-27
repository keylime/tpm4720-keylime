/********************************************************************************/
/*										*/
/*			    TCPA Load a migration blob into a TPM		*/
/*			     Written by Stefan Berger				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*	      $Id: cmk_loadmigrationblob.c 4702 2013-01-03 21:26:29Z kgoldman $	*/
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
	printf("Usage: cmk_loadmigrationblob -hp <mig. key handle> -im <mig. key filename> -if <mig. blob filename>\n"
	       "                             -pwdp <migration key password> -msa <msa list file>\n"
	       "                             -hs <handle of signing key> -pwds <password of signing key>\n"
	       "\n"
	       "-hp   : the handle of the key that was used for migration (in hex)\n"
	       "-im   : filename of migration key\n"
	       "-pwdp : the password of the key that was used for migration\n"
	       "-if   : the migration blob file (output from migrate -if option); this is the\n"
	       "         output of the cmk_migrate program\n"
	       "-msa  : filename with msa list\n"
	       "-hs   : handle of a key usable for signing\n"
	       "-pwds : password for the key used for signing\n"
	       "\n"
	       "\n"
	       "Examples:\n");
}


int main(int argc, char * argv[]) {
	uint32_t ret = 0;
	int i =	0;
	int verbose = FALSE;
	uint32_t migkeyhandle = 0;
	char * filename = NULL;
	unsigned char * buffer = NULL;
	uint32_t buffersize = 0;
	char * keypass = NULL;
	char * msa_list_filename = NULL;
	char * migrationkey_filename = NULL;
	TPM_MSA_COMPOSITE msaList = {0, NULL};
	TPM_CMK_AUTH restrictTicket;
	unsigned char sigTicketHash[TPM_HASH_SIZE];
	unsigned char resTicketHash[TPM_HASH_SIZE];
	keydata migrationkey;
	keydata signingkey;
	char * ownerpass = NULL;
	unsigned char migkeypasshash[TPM_HASH_SIZE];
	unsigned char * migkeypassptr = NULL;
	unsigned char ownerpasshash[TPM_HASH_SIZE];
	unsigned char * ownerpassptr = NULL;
	uint32_t sigkeyhandle = 0;
	
	unsigned char sigkeypasshash[TPM_HASH_SIZE];
	unsigned char * sigkeypassptr = NULL;
	char * sigkeypass = NULL;
	
	memset(&restrictTicket, 0x0, sizeof(restrictTicket));
	
	i = 1;
	
	TPM_setlog(0);
	
	while (i < argc) {
		if (!strcmp("-pwdo",argv[i])) {
			i++;
			if (i < argc) {
				ownerpass = argv[i];
			} else {
				printf("Missing mandatory parameter for -pwdo.\n");
				usage();
				exit(-1);
			}
		} else
		if (!strcmp("-if",argv[i])) {
			i++;
			if (i < argc) {
				filename = argv[i];
			} else {
				printf("Missing mandatory parameter for -if.\n");
				usage();
				exit(-1);
			}
		} else
		if (!strcmp("-hp",argv[i])) {
			i++;
			if (i < argc) {
				sscanf(argv[i],"%x",&migkeyhandle);
			} else {
				printf("Missing mandatory parameter for -hp.\n");
				usage();
				exit(-1);
			}
		} else
		    if (!strcmp("-im",argv[i])) {
			i++;
			if (i < argc) {
			    migrationkey_filename = argv[i];
			} else {
			    printf("Missing mandatory parameter for -im.\n");
			    usage();
			    exit(-1);
			}
		} else
		if (!strcmp("-hs",argv[i])) {
			i++;
			if (i < argc) {
				sscanf(argv[i],"%x",&sigkeyhandle);
			} else {
				printf("Missing mandatory parameter for -hs.\n");
				usage();
				exit(-1);
			}
		} else
		if (!strcmp("-pwds",argv[i])) {
			i++;
			if (i < argc) {
				sigkeypass = argv[i];
			} else {
				printf("Missing mandatory parameter for -pwds.\n");
				usage();
				exit(-1);
			}
		} else
		if (!strcmp("-pwdp",argv[i])) {
			i++;
			if (i < argc) {
				keypass = argv[i];
			} else {
				printf("Missing mandatory parameter for -pwdp.\n");
				usage();
				exit(-1);
			}
		} else
		if (!strcmp("-msa",argv[i])) {
			i++;
			if (i < argc) {
				msa_list_filename = argv[i];
			} else {
				printf("Missing mandatory parameter for -msa.\n");
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
	
	if (0 == migkeyhandle ||
	    NULL == filename  ||
	    NULL == keypass   ||
	    NULL == msa_list_filename ||
	    NULL == migrationkey_filename ||
	    NULL == ownerpass) {
		printf("Missing mandatory parameter.\n");
		usage();
		return -1;
	}


	if (NULL != keypass) {
		TSS_sha1(keypass, strlen(keypass), migkeypasshash);
		migkeypassptr = migkeypasshash;
	} else {
		migkeypassptr = NULL;
	}
	(void)migkeypassptr;

	if (NULL !=sigkeypass) {
		TSS_sha1(sigkeypass, strlen(sigkeypass), sigkeypasshash);
		sigkeypassptr = sigkeypasshash;
	} else {
		sigkeypassptr = NULL;
	}
	
	if (NULL != ownerpass) {
		TSS_sha1(ownerpass, strlen(ownerpass), ownerpasshash);
		ownerpassptr = ownerpasshash;
	} else {
		ownerpassptr = NULL;
	}
	/*
	 * read the msa list from the file.
	 */
	ret = TPM_ReadMSAFile(msa_list_filename, &msaList);
	if (0 != (ret & ERR_MASK)) {
		printf("Could not read msa file from %s.\n",msa_list_filename);
		exit(ret);
	}

	ret = TPM_ReadKeyfile(migrationkey_filename, &migrationkey);
	if (0 != (ret & ERR_MASK)) {
		printf("Could not read migration key from %s.\n",migrationkey_filename);
		exit(ret);
	}

	/*
	 * Get the public key part of the signing key.
	 */
	ret = TPM_GetPubKey(sigkeyhandle,
	                    sigkeypassptr,
	                    &signingkey.pub);
	if ( 0 != ret ) {
		printf("Error %s while retrieving public signing key.\n", 
		       TPM_GetErrMsg(ret));
		exit(-1);
	}
	
	ret = TPM_ReadFile(filename,
	                   &buffer,
	                   &buffersize);
	if (0 == (ret & ERR_MASK) ) {
		int offset = 0;
		unsigned char * encblob = NULL;
		uint32_t encsize = 0;
		unsigned char * rndblob = NULL;
		uint32_t rndsize = 0;
		uint32_t keysize = 0;
		unsigned char * keyblob = NULL;
		unsigned char outblob[1024];
		uint32_t outblen = sizeof(outblob);
		keydata newkey;
		unsigned char signatureValue[2048];
		uint32_t signatureValueSize = sizeof(signatureValue);
		STACK_TPM_BUFFER( tb )

		rndsize = LOAD32(buffer,offset);  offset += 4;
		rndblob = &buffer[offset];        offset += rndsize;
		encsize = LOAD32(buffer,offset);  offset += 4;
		encblob = &buffer[offset];        offset += encsize;
		keysize = LOAD32(buffer,offset);  offset += 4;
		keyblob = &buffer[offset];        offset += keysize;
		
		SET_TPM_BUFFER(&tb, keyblob, keysize);
		TSS_KeyExtract(&tb,0,&newkey);

		memcpy(newkey.encData.buffer,
		       encblob,
		       encsize);

		/*
		 * Build the restrictTicket!!!
		 */
		       
		ret = TPM_HashPubKey(&newkey,
		                     restrictTicket.sourceKeyDigest);

		if ( ( ret & ERR_MASK ) != 0) {
			printf("Could not calculate hash over the public key of the key to be migrated.\n");
			exit(ret);
		}
		
		ret = TPM_HashPubKey(&migrationkey,
		                     restrictTicket.destinationKeyDigest);

		if ( ( ret & ERR_MASK ) != 0) {
			printf("Could not calculate hash over the public key of the migration key.\n");
			exit(ret);
		}


		/*
		 * The sigticket must have been created by 
		 * HMAC(SHA1(verificationKey) || signedData)  (see 11.8)
		 * where the verification key's SHA1 MUST also be a part of the msaList
		 *    ( --> pass the verification key to cmk_approvema)
		 * and
		 * where the signed data must be a SHA1(restrictTicket)!!
		 * 
		 * The verification key MUST be in the MSA list.
		 * This key can only be a signing key or legacy key, since no
		 * other keys may be used for signing, and CMK_CreateTicket verifies a
		 * signature.
		 * restrictTicket contains two hashes: one of the parent key and one of the migrate key
		 */
#if 0
		ret = TPM_ReadFile(sigticket_file,
		                   &sigTicket,
		                   &sigTicketSize)
		if ( 0 != ret ) {
			printf("Error %s while reading file %s.\n",
			       TPM_GetErrMsg(ret),
			       sigticket_file);
		}
#else

		ret = TPM_HashCMKAuth(&restrictTicket, resTicketHash);

#if 0
		{
			int k = 0;
			printf("ResTicketHash: \n");
			while (k < TPM_HASH_SIZE) {
				printf("%02x",resTicketHash[k]);
				k++;
			}
			printf("\n");
		}
#endif

		ret = TPM_Sign(sigkeyhandle, sigkeypassptr,
		               resTicketHash, sizeof(resTicketHash),
		               signatureValue, &signatureValueSize);

		if ( 0 != ret) {
			printf("Error %s while signing.\n",
			       TPM_GetErrMsg(ret));
			exit(ret);
		}
		ret = TPM_CMK_CreateTicket(&signingkey,
		                           resTicketHash,
		                           signatureValue, signatureValueSize,
		                           ownerpassptr,
		                           sigTicketHash);
		if ( 0 != ret) {
			printf("Error %s while creating ticket.\n",
			       TPM_GetErrMsg(ret));
			exit(ret);
		}

#if 0
		{
			int k = 0;
			printf("SigTicketHash: \n");
			while (k < TPM_HASH_SIZE) {
				printf("%02x",sigTicketHash[k]);
				k++;
			}
			printf("\n");
		}
#endif

#endif

		ret = TPM_CMK_ConvertMigration(migkeyhandle,
		                               migkeypasshash,
		                               &restrictTicket,
		                               sigTicketHash,
		                               &newkey,
		                               &msaList,
		                               rndblob, rndsize,
		                               outblob, &outblen);
		if (0 == ret) {
			uint32_t newhandle;
			memcpy(newkey.encData.buffer,
			        outblob,
			        outblen);
			ret = TPM_LoadKey(migkeyhandle,
			                  migkeypasshash,
			                  &newkey,
			                  &newhandle);
			if (0 == ret) {
				printf("Successfully loaded key into TPM.\n"
				       "New Key Handle = %08X\n",
				       newhandle);
			} else {
				printf("LoadKey returned '%s' (0x%x).\n",
				       	TPM_GetErrMsg(ret),
				       	ret);
			}
		} else {
			printf("CMK_ConvertMigration returned error %s.\n",
			       	TPM_GetErrMsg(ret));
		}

	} else {
		printf("Error reading file %s.\n",filename);
	}
	exit (ret);
}

