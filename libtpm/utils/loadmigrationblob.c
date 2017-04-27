/********************************************************************************/
/*										*/
/*			    TCPA Load a migration blob into a TPM		*/
/*			     Written by Stefan Berger				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*	      $Id: loadmigrationblob.c 4702 2013-01-03 21:26:29Z kgoldman $	*/
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
static unsigned char * readFile(char * filename);



static void usage() {
	printf("Usage: loadmigrationblob -hp <mig. key handle> -if <mig. blob filename>\n"
	       "                         -pwdp <migration key password> [-rewrap]\n"
	       "\n"
	       "-hp     : the handle of the key that was used for migration (in hex)\n"
	       "-if     : the migration blob file (output from migrate -if option)\n"
	       "-pwdp   : the migration key's password\n"
	       "-rewrap : if rewrap mode was used to migrate the key\n");
	printf("\n");
	printf("Examples:\n");
	exit(-1);
}


int main(int argc, char * argv[]) {
	uint32_t ret = 0;
	int i =	0;
	int verbose = FALSE;
	uint32_t migkeyhandle = 0;
	char * filename = NULL;
	unsigned char * buffer = NULL;
	unsigned char keypasshash[TPM_HASH_SIZE];
	char * keypass = NULL;
	uint16_t migscheme = TPM_MS_MIGRATE;
	unsigned char * keyhashptr = NULL;
	
	i = 1;
	
	TPM_setlog(0);
	
	while (i < argc) {
	    if (!strcmp("-if",argv[i])) {
		i++;
		if (i < argc) {
		    filename = argv[i];
		} else {
		    printf("Missing mandatory parameter for -if.\n");
		    usage();
		}
	    }
	    else if (!strcmp("-hp",argv[i])) {
		i++;
		if (i < argc) {
		    sscanf(argv[i],"%x",&migkeyhandle);
		} else {
		    printf("Missing mandatory parameter for -hp.\n");
		    usage();
		}
	    }
	    else if (!strcmp("-pwdp",argv[i])) {
		i++;
		if (i < argc) {
		    keypass = argv[i];
		} else {
		    printf("Missing mandatory parameter for -pwdp.\n");
		    usage();
		}
	    }
	    else if (!strcmp("-rewrap",argv[i])) {
		migscheme = TPM_MS_REWRAP;
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
	(void)verbose;
	
	if (0 == migkeyhandle ||
	    NULL == filename) {
		printf("Missing mandatory parameter.\n");
		usage();
	}

	if (NULL != keypass) {
		TSS_sha1(keypass,strlen(keypass),keypasshash);
		keyhashptr = keypasshash;
	} else {
		keyhashptr = NULL;
	}
	
	buffer = readFile(filename);
	if (NULL != buffer) {
		int offset = 0;
		unsigned char * encblob = NULL;
		uint32_t encsize = 0;
		unsigned char * rndblob = NULL;
		uint32_t rndsize = 0;
		uint32_t keysize = 0;
		unsigned char * keyblob = NULL;
		unsigned char * outblob = NULL;
		uint32_t outblen;
		keydata newkey;
		STACK_TPM_BUFFER( tb );
		
		rndsize = LOAD32(buffer,offset);  offset += 4;
		rndblob = &buffer[offset];        offset += rndsize;
		encsize = LOAD32(buffer,offset);  offset += 4;
		encblob = &buffer[offset];        offset += encsize;
		keysize = LOAD32(buffer,offset);  offset += 4;
		keyblob = &buffer[offset];        offset += keysize;
		
		SET_TPM_BUFFER(&tb, keyblob, keysize);
		TSS_KeyExtract(&tb, 0,&newkey);

		outblob = malloc(encsize);
		if (NULL == outblob) {
			printf("Error allocating memory for decrypted blob.\n");
			exit(-1);
		}
		outblen = encsize;

		if (TPM_MS_REWRAP == migscheme || 0 == rndsize) {
			memcpy(newkey.encData.buffer,
			       encblob,
			       encsize);
			newkey.encData.size = outblen;
			ret = 0;
		} else {
			ret = TPM_ConvertMigrationBlob(migkeyhandle,
			                               keyhashptr,
			                               rndblob, rndsize,
			                               encblob, encsize,
			                               outblob, &outblen);

			if (0 == ret) {
				memcpy(newkey.encData.buffer,
				       outblob,
				       outblen);
				newkey.encData.size = outblen;
			} else {
				printf("ConvertMigrationBlob returned '%s' (0x%x).\n",
				       	TPM_GetErrMsg(ret),
				       	ret);
			}
		}
		if (0 == ret) {
			uint32_t newhandle;
			ret = TPM_LoadKey(migkeyhandle,
			                  keyhashptr,
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
		}
	}
	return ret;
}

static unsigned char * readFile(char * filename) {
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
