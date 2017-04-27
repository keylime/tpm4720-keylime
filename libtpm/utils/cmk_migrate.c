/********************************************************************************/
/*										*/
/*			        TCPA Migration   				*/
/*			     Written by Stefan Berger				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*	      $Id: cmk_migrate.c 4702 2013-01-03 21:26:29Z kgoldman $		*/
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

#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/evp.h>

#include "tpm.h"
#include "tpmutil.h"
#include "tpmfunc.h"
#include "tpm_constants.h"
#include "tpm_structures.h"

static void usage() {
	printf("Usage: cmk_migrate -hp <parent key handle> -pwdp <parent key password>\n"
	       "       -pwdo <owner password> \n"
	       "       -im <file with the migration key> -pwdk <password for migration key>\n"
	       "       -msa <msa list filename>\n"
	       "       -pwdm <migration password> [-ok <filename for key>] [-v] -ik keyfile\n"
	       "       [-double]\n"
	       "-hp     : parent key handle; the key is used for encryption\n"
	       "-pwdp   : parent key password\n"
	       "-pwdo   : TPM owner password\n"
	       "-pwdm   : migration password\n"
	       "-im     : file containing the migration key (use createkey to create key)\n"
	       "-pwdk   : the password of the migration key\n"
	       "-ok     : filename to write the migrated key into. If not given, the key\n"
	       "          will be loaded back into the TPM.\n"
	       "-ik     : file with the key to be migrated\n"
	       "-double : if the migration scheme MS_RESTRICT_APPROVE is to be used\n"
	       "-hs     : signing key handle for MS_RESTRICT_APPROVE\n"
	       "-pwds   : signing key password\n"
	       "-v      : enable verbose output\n"
	       "\n"
	       "This program currently makes the TPM generate a key and then tries to migrate that key.\n");
	printf("\n");
	printf("\n");
	printf("Examples:\n");
}

int main(int argc, char * argv[]) {
	char * ownerpass = NULL;
	char * migpass = NULL;
	char * parpass = NULL;
	char * filename = NULL;
	char * migkeyfile = NULL;
	char * migkeypass = NULL;
	uint32_t parhandle = -1;             /* handle of parent key */
	unsigned char * passptr1 = NULL;
	unsigned char passhash1[20];
	unsigned char hashpass1[20];    /* hash of new key password */
	unsigned char hashpass3[20];    /* hash of parent key password */
	unsigned char hashpass4[20];    /* hash of migration key pwd */
	uint32_t ret = 0;
	int i =	0;
	keydata keyparms;
	keydata idkey;
	unsigned char *aptr1 = NULL;
	unsigned char *aptr3 = NULL;
	unsigned char *aptr4 = NULL;
	keydata migkey;
	uint16_t migscheme = TPM_MS_RESTRICT_MIGRATE;
	uint32_t sigTicketSize = 0;
	char * msa_list_filename = NULL;
	TPM_MSA_COMPOSITE msaList = {0, NULL};
	char * keyfile = NULL;
	keydata q;
	uint32_t sigkeyhandle = -1;
	char * sigkeypass = NULL;
	unsigned char sigkeypasshash[TPM_HASH_SIZE];
	unsigned char * sigkeypassptr = NULL;
	unsigned char sigTicket[TPM_HASH_SIZE];
	TPM_CMK_AUTH restrictTicket;
	TPM_CMK_AUTH *restrictTicketParameter;	/* parameter to command function call */
	unsigned char resTicketHash[TPM_HASH_SIZE];
	
	
	memset(&keyparms, 0x0, sizeof(keyparms));
	memset(&idkey   , 0x0, sizeof(idkey));
	memset(&restrictTicket, 0x0, sizeof(restrictTicket));
	
	i = 1;
	
	TPM_setlog(0);
	
	while (i < argc) {
		if (!strcmp("-hp",argv[i])) {
			i++;
			if (i < argc) {
				sscanf(argv[i],"%x",&parhandle);
			} else {
				printf("Missing parameter for -hp.\n");
				usage();
				exit(-1);
			}
		} else
		if (!strcmp("-pwdp",argv[i])) {
			i++;
			if (i < argc) {
				parpass = argv[i];
			} else {
				printf("Missing parameter for -pwdp.\n");
				usage();
				exit(-1);
			}
		} else
		if (!strcmp("-ok",argv[i])) {
			i++;
			if (i < argc) {
				filename = argv[i];
			} else {
				printf("Missing parameter for -ok.\n");
				usage();
				exit(-1);
			}
		} else
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
		if (!strcmp("-pwdm",argv[i])) {
			i++;
			if (i < argc) {
				migpass = argv[i];
			} else {
				printf("Missing parameter for -pwdm.\n");
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
				keyfile = argv[i];
			} else {
				printf("Missing parameter for -ik.\n");
				usage();
				exit(-1);
			}
		} else
		if (!strcmp("-im",argv[i])) {
			i++;
			if (i < argc) {
				migkeyfile = argv[i];
			} else {
				printf("Missing parameter for -im.\n");
				usage();
				exit(-1);
			}
		} else
		if (!strcmp("-pwdk",argv[i])) {
			i++;
			if (i < argc) {
				migkeypass = argv[i];
			} else {
				printf("Missing parameter for -pwdk.\n");
				usage();
				exit(-1);
			}
		} else
		if (!strcmp("-v",argv[i])) {
			TPM_setlog(1);
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
		if (!strcmp("-double",argv[i])) {
			migscheme = TPM_MS_RESTRICT_APPROVE;
		} else {
			printf("Unknown option '%s'.",argv[i]);
			usage();
			exit(-1);
		}
		i++;
	}


	if (NULL == keyfile ||
	    NULL == ownerpass || 
	    -1 == (int)parhandle   || 
	    NULL == migkeyfile ||
	    NULL == msa_list_filename) {
		printf("Missing or wrong parameter.\n");
		usage();
		exit(-1);
	}
	
	if (TPM_MS_RESTRICT_APPROVE == migscheme) {
		if (-1 == (int)sigkeyhandle) {
			printf("Must provide signing key data when '-double' has been selected.\n");
			exit(-1);
		}
	}

	if (NULL != ownerpass) {
		TSS_sha1(ownerpass,strlen(ownerpass),passhash1);
		passptr1 = passhash1;
	} else {
		passptr1 = NULL;
	}

	if (NULL !=sigkeypass) {
		TSS_sha1(sigkeypass, strlen(sigkeypass), sigkeypasshash);
		sigkeypassptr = sigkeypasshash;
	} else {
		sigkeypassptr = NULL;
	}
	

	/*
	** use the SHA1 hash of the password string as the Parent Key Authorization Data
	*/
	if (parpass != NULL) {
	        TSS_sha1(parpass,strlen(parpass),hashpass1);
	        aptr1 = hashpass1;
        }
	/*
	** use the SHA1 hash of the password string as the Key Migration Authorization Data
	*/
	if (migpass != NULL) { 
	        TSS_sha1(migpass,strlen(migpass),hashpass3);
	        aptr3 = hashpass3;
	        (void)aptr3;
        }
	/*
	** use the SHA1 hash of the password string as the Key Migration Authorization Data
	*/
	if (migkeypass != NULL) {
	        TSS_sha1(migkeypass,strlen(migkeypass),hashpass4);
	        aptr4 = hashpass4;
	        (void)aptr4;
        }
	
	/*
	 * 
	 * - Create an RSA key pair.
	 * - Call TPM_AuthorizeMigrationKey for the RSA public key authorization
	 * - Call TPM_CreateMigrationBlob   with the result from AuthorizeMigrationKey
	 *                                  and the encrypted TPM_STORE_ASYMKEY structure
	 * 
	 */

	/*
	 * read the msa list from the file.
	 */
	ret = TPM_ReadMSAFile(msa_list_filename, &msaList);
	if ( ( ret & ERR_MASK ) != 0) {
		printf("Error while reading msa list file.\n");
		exit(-1);
	}

	/*
	** create and wrap an asymmetric key and get back the
	** resulting keydata structure with the public and encrypted
	** private keys filled in by the TPM
	*/
	
	/*
	 * q is the key that we want to migrate. Create one such key.
	 * migkey is the (public) key part from another TPM that we want to use 
	 *   to migrate q. Since I am not loading a public key from another TPM,
	 *   I create a migration key here as well. I must never refer to this
	 *   key via any handle or load it into the TPM
	 */
	
	printf("Loading the (public) key to use for migration...\n");
	if (0 == ret) {
		printf("Migration key is: %s\n",migkeyfile);
		ret = TPM_ReadKeyfile(migkeyfile, &migkey);
		if ((ret & ERR_MASK)) {
			ret = TPM_ReadPubKeyfile(migkeyfile, &migkey.pub);
			if ((ret & ERR_MASK)) {
				printf("Could not read the keyfile %s as a "
				       "key or a pubkey.\n", migkeyfile);
				exit(-1);
			}
		}
		ret = TPM_ReadKeyfile(keyfile, &q);
		if ((ret & ERR_MASK)) {
			printf("Could not read the keyfile %s.\n",
			       keyfile);
		}
	}
	
	/*
	 * Create a ticket if needed.
	 */
	if (migscheme == TPM_MS_RESTRICT_APPROVE) {
		keydata signingkey;
		unsigned char signatureValue[2048];
		uint32_t signatureValueSize = sizeof(signatureValue);
		STACK_TPM_BUFFER(sigkey)
		
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

		/*
		 * Build the restrictTicket!!!
		 */
		restrictTicketParameter = &restrictTicket;	/* command needs restrictTicket */     
		ret = TPM_HashPubKey(&q,
		                     restrictTicket.sourceKeyDigest);

		if ( ( ret & ERR_MASK ) != 0) {
			printf("Could not calculate hash over the public key of the key to be migrated.\n");
			exit(ret);
		}
		
		ret = TPM_HashPubKey(&migkey,
		                     restrictTicket.destinationKeyDigest);

		if ( ( ret & ERR_MASK ) != 0) {
			printf("Could not calculate hash over the public key of the migration key.\n");
			exit(ret);
		}

		ret = TPM_HashCMKAuth(&restrictTicket, resTicketHash);

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
		                           passptr1,
		                           sigTicket);
		sigTicketSize = TPM_DIGEST_SIZE;
		
	}
	else {	/* TPM_MS_RESTRICT_MIGRATE */
	    restrictTicketParameter = NULL;	/* command does not need restrictTicket */     
	}
	if (0 == ret) {
		if (0 == ret) {

			STACK_TPM_BUFFER( keyblob)
			STACK_TPM_BUFFER( migblob);
			keydata keyd;

			memset(&keyd, 0x0, sizeof(keyd));

			ret = TPM_WriteKeyPub(&keyblob, &migkey);

			if ((ret & ERR_MASK) != 0) {
				printf("Could not serialize the keydata: %s\n",
				       TPM_GetErrMsg(ret));
				exit(-1);
			}

			ret = TPM_AuthorizeMigrationKey(passptr1,
			                                migscheme,         // migration scheme
			                                &keyblob,  // public key to be authorized
			                                &migblob);
			if (0 == ret) {
				unsigned char rndblob[1024];
				uint32_t rndblen = sizeof(rndblob);
				unsigned char outblob[1024];
				uint32_t outblen = sizeof(outblob);
				unsigned char sourceKeyDigest[TPM_DIGEST_SIZE];

				unsigned char encblob[1024];
				uint32_t encblen;
				
				memcpy(encblob,
				       q.encData.buffer,
				       q.encData.size);
				encblen = q.encData.size;

				if (0!= ret) {
					printf("Error occurred while creating encrypted blob.\n");
					exit (-1);
				}
				
				TPM_HashPubKey(&q,sourceKeyDigest);
				
				printf("parhandle = %x\n",parhandle);
				/*
				 * Now call the TPM_CreateMigrationBlob function.
				 */
				ret = TPM_CMK_CreateBlob(parhandle,         // handle of a key that can decrypt the encblob below
				                         aptr1,             // password for that parent key
				                         migscheme,
				                         &migblob,
				                         sourceKeyDigest,
				                         &msaList,
				                         restrictTicketParameter,	/* either NULL or restrictTicket */
				                         sigTicket, sigTicketSize,
				                         encblob, encblen,  // encrypted private key that will show up re-encrypted in outblob
				                         rndblob, &rndblen, // output: used for xor encryption
				                         outblob, &outblen);// output: re-encrypted private key
				if (0 == ret) {
					if (NULL != filename) {
						STACK_TPM_BUFFER(keybuf)
						// serialize the key in 'q'
						ret = TPM_WriteKey(&keybuf,&q);
						if (ret > 0) {
							unsigned int keybuflen = ret;
							FILE * f = fopen(filename,"wb");
							if (NULL != f) {
								struct tpm_buffer * filebuf = TSS_AllocTPMBuffer(10240);
								if (NULL != filebuf) {
									int l;
									l = TSS_buildbuff("@ @ @",filebuf,
									                   rndblen, rndblob,
									                     outblen, outblob,
									                       keybuflen, keybuf.buffer);
									fwrite(filebuf->buffer,
									       l,
									       1,
									       f);
									fclose(f);
									TSS_FreeTPMBuffer(filebuf);
									printf("Wrote migration blob and associated data to file.\n");
									ret = 0;
									
								} else {
									printf("Error. Could not allocate memory.\n");
									ret = -1;
								}
							} else {
								printf("Error. Could not write blob to file.\n");
								ret = -1;
							}
						} else {
							printf("Error while serializing key!\n");
						}
					} else {
					}
				} else {
					printf("CMK_CreateBlob returned '%s' (%d).\n",
					       TPM_GetErrMsg(ret),
					       ret);
				}

			} else {
				printf("AuthorizeMigrationKey returned '%s' (0x%x).\n",
				       TPM_GetErrMsg(ret),
				       ret);
			}

		} else {
		}
	} else {
	}
	return ret;
}
