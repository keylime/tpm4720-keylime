/********************************************************************************/
/*										*/
/*			        TCPA Key Migration   				*/
/*			     Written by Stefan Berger				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*	      $Id: migratekey.c 4702 2013-01-03 21:26:29Z kgoldman $		*/
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

/* local prototypes */
static int loadKey(char * filename, keydata * k);
static unsigned char * readFile(char * filename, uint32_t * bufferSize);

static void usage() {
	printf("Usage: migratekey -hm <handle of key to be used to migrate the blob>\n"
	       "                  [-pwdm <password of key to be used to migrate]\n"
	       "                  -ik <file of public key to migrate key to>\n"
	       "                  -if <filename with key blob> [-v]\n"
	       "\n"
	       "-hm    : key handle of previously used migration key (priv. part of key\n"
	       "         is encrypted with this key)\n"
	       "-pwdm  : password for migration key if it has one\n"
	       "-ik    : file containing the public key (output from createkey) that\n"
	       "         is used to re-encrypt the private key\n"
	       "-if    : filename of file containing the migration blob as obtained from\n"
	       "         the 'migrate' command\n"
	       "\n"
	       "Examples:\n"
	       "migratekey -hm <handle> -pwdm migrate -ik stkey.key -if migrationblob.bin\n");
}

int main(int argc, char * argv[]) {
	char * migrationkeyfile = NULL;
	char * filename = NULL;
	char * migrationKeyPassword = NULL;
	unsigned char migrationkeyUsageAuth[TPM_DIGEST_SIZE];
	unsigned char * passptr = NULL;
	uint32_t ret = 0;
	int i =	0;
	keydata migrationkey;
	int verbose = FALSE;
	uint32_t migrationkeyhandle = 0;
	unsigned char * buffer = NULL;
	uint32_t bufferSize = 0;
	
	i = 1;
	
	TPM_setlog(0);
	
	while (i < argc) {
	    if (!strcmp("-if",argv[i])) {
		i++;
		if (i < argc) {
		    filename = argv[i];
		} else {
		    printf("Missing parameter for -if.\n");
		    usage();
		    exit(-1);
		}
	    }
	    else if (!strcmp("-pwdm",argv[i])) {
		i++;
		if (i < argc) {
		    migrationKeyPassword = argv[i];
		} else {
		    printf("Missing parameter for -pwdm.\n");
		    usage();
		    exit(-1);
		}
	    }
	    else if (!strcmp("-hm",argv[i])) {
		i++;
		if (i < argc) {
		    sscanf(argv[i],"%x",&migrationkeyhandle);
		} else {
		    printf("Missing parameter for -hm.\n");
		    usage();
		    exit(-1);
		}
	    }
	    else if (!strcmp("-ik",argv[i])) {
		i++;
		if (i < argc) {
		    migrationkeyfile = argv[i];
		} else {
		    printf("Missing parameter for -ik.\n");
		    usage();
		    exit(-1);
		}
	    }
	    else if (!strcmp("-v",argv[i])) {
		verbose = TRUE;
		TPM_setlog(1);
	    }
	    else if (!strcmp("-h",argv[i])) {
		usage();
		exit(-1);
	    } else {
		printf("\n%s is not a valid option\n", argv[i]);
		usage();
		exit(-1);
	    }
	    i++;
	}
	(void)verbose;

	if (NULL == migrationkeyfile ||
	    NULL == filename   ||
	    -1 == (int)migrationkeyhandle) {
		printf("Missing or wrong parameter.\n");
		usage();
		exit(-1);
	}


	if (NULL != migrationKeyPassword) {
		TSS_sha1(migrationKeyPassword,
		         strlen(migrationKeyPassword),
		         migrationkeyUsageAuth);
		passptr = migrationkeyUsageAuth;
	}
	

	/*
	 * load the key to be migrated from a file.
	 */
	ret = 0;

	buffer = readFile(filename, &bufferSize);
	if (NULL != buffer) {

		unsigned int offset = 0;
		unsigned char * encblob = NULL;
		uint32_t encsize = 0;
		unsigned char * rndblob = NULL;
		uint32_t rndsize = 0;
		uint32_t keysize = 0;
		unsigned char * keyblob = NULL;
		keydata tobemigkey;
		STACK_TPM_BUFFER(tb)
		
		rndsize = LOAD32(buffer,offset);  offset += 4;
		if (offset > bufferSize) {
			printf("Bad input file. Exiting.\n");
			return -1;
		}
		rndblob = &buffer[offset];        offset += rndsize;
		if (offset > bufferSize) {
			printf("Bad input file. Exiting.\n");
			return -1;
		}
		encsize = LOAD32(buffer,offset);  offset += 4;
		if (offset > bufferSize) {
			printf("Bad input file. Exiting.\n");
			return -1;
		}
		encblob = &buffer[offset];        offset += encsize;
		if (offset > bufferSize) {
			printf("Bad input file. Exiting.\n");
			return -1;
		}
		keysize = LOAD32(buffer,offset);  offset += 4;
		if (offset > bufferSize) {
			printf("Bad input file. Exiting.\n");
			return -1;
		}
		keyblob = &buffer[offset];        offset += keysize;

		if (offset != bufferSize) {
			printf("Bad input file. Exiting");
			return -1;
		}
		
		SET_TPM_BUFFER(&tb, keyblob, keysize);
		TSS_KeyExtract(&tb,0,&tobemigkey);
		
		/*
		 * load the migration key from the destination
		 * TPM from a file. Need the public key part of
		 * that key.
		 */
		ret = loadKey(migrationkeyfile, &migrationkey);
		if (0 == ret) {
			STACK_TPM_BUFFER(keyblob)
			uint32_t keyblen = 0;
			unsigned char * reencData = malloc(encsize);
			uint32_t reencDataSize = encsize;

			if (NULL == encblob || NULL == reencData) {
				printf("Could not get memory for encrypted private key blob.\n");
				exit (-1);
			}

			ret = TPM_WriteKeyPub(&keyblob, &migrationkey);

			if (ret & ERR_MASK) {
				printf("Could not serialize the keydata!\n");
				free(reencData);
				exit(-1);
			}
			keyblen = ret;

			ret = TPM_MigrateKey(migrationkeyhandle,
			                     passptr,
			                     keyblob.buffer, keyblen,
			                     encblob, encsize,
			                     reencData, &reencDataSize);

			if (0 == ret) {
				STACK_TPM_BUFFER(keybuf)
				// serialize the key to be migrated
				ret = TPM_WriteKey(&keybuf,&tobemigkey);
				if (ret > 0) {
					unsigned int keybuflen = ret;
					FILE * f = fopen(filename,"wb");
					if (NULL != f) {
						struct tpm_buffer *filebuf = TSS_AllocTPMBuffer(10240);
						if (NULL != filebuf) {
							int l;
							l = TSS_buildbuff("@ @ @",filebuf,
							                   rndsize, rndblob,
							                     reencDataSize, reencData,
							                       keybuflen, keybuf.buffer);
							fwrite(filebuf->buffer,
							       l,
							       1,
							       f);
							fclose(f);
							printf("Wrote migration blob and associated data to file.\n");
							ret = 0;
							TSS_FreeTPMBuffer(filebuf);
						} else {
							printf("Error. Could not allocate memory.\n");
							ret = -1;
						}
					}
				}
			} else {
				printf("MigrateKey returned '%s' (0x%x).\n",
				       TPM_GetErrMsg(ret),
				       ret);
			}
			free(reencData);
		} else {
			printf("Error. Could not load the migration key.");
		}
	} else {
		printf("Error. Could not load the blob from file '%s'.\n",
		       filename);
	}
	return ret;
}


static int loadKey(char * filename, keydata * key)
{
	int ret = 0;
	FILE * kinfile;
	kinfile = fopen(filename,"rb");
	if (kinfile == NULL) {
		printf("Could not open key file.\n");
		ret = -1;
	} else {
		struct stat sbuf;
		if (0 ==stat(filename,&sbuf)) {
			unsigned int keyblen;
			unsigned char * keyblob = NULL;
			keyblen = (int)sbuf.st_size;
			keyblob = malloc(keyblen);
			if (NULL != keyblob) {
				ret = fread(keyblob,1,keyblen,kinfile);
				if (ret != (int)keyblen) {
					printf("Unable to read key file\n");
					ret = -1;
				} else {
					STACK_TPM_BUFFER(tb)
					SET_TPM_BUFFER(&tb, keyblob, keyblen);
					TSS_KeyExtract(&tb,0,key);
					ret = 0;
				}
				fclose(kinfile);
				free(keyblob);
			} else {
				printf("Could not allocate memory.\n");
				ret = -1;
			}
		} else {
			printf("Could not determine size of key file.\n");
			ret = -1;
		}
	}
	return ret;
}

static unsigned char * readFile(char * filename, uint32_t * bufferSize) {
	unsigned char * buffer = NULL;
	FILE * f;
	f = fopen(filename,"rb");
	if (NULL != f) {
		struct stat sbuff;
		if (0 == stat(filename,&sbuff)) {
			buffer = malloc(sbuff.st_size);
			if (NULL != buffer) {
				int n = fread(buffer, 1, sbuff.st_size,f);
				if (sbuff.st_size == n) {
					*bufferSize = n;
				} else {
					printf("Error. Could not read file.\n");
					free(buffer);
					buffer = NULL;
				}
			} else {
				printf("Error allocating memory.\n");
			}
		} else {
			printf("Error determining size of file.\n");
		}
		fclose(f);
	} else {
		printf("Error. Could not open migration file.\n");
	}
	return buffer;
}
