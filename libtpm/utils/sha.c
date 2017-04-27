/********************************************************************************/
/*										*/
/*			    TCPA SHA1 functionality				*/
/*			     Written by Stefan Berger				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*	      $Id: sha.c 4702 2013-01-03 21:26:29Z kgoldman $			*/
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

/* local functions */

#define MIN(x,y)  (x) < (y) ? (x) : (y)

static void usage() {
	printf("Usage: sha1 [-ic data] [-if filename] [-ix index]\n"
	       "\n"
	       " -ic data     : The data to calculate a SHA1 digest over.\n"
	       " -if filename : The filename of a file to calculate the SHA1 digest for.\n"
	       " -ix index    : Index of the PCR to extend; optional parameter\n");
	exit(-1);
}

int main(int argc, char * argv[]) {
	char * data = NULL;
	char * filename = NULL;
	int i = 1;
	int offset = 0;
	uint32_t len;
	uint32_t ret = 0;
	unsigned char hashbuffer[TPM_HASH_SIZE];
	unsigned char pcrValue[TPM_HASH_SIZE];
	int index = -1;
	TPM_BOOL verbose = FALSE;
	uint32_t maxNumBytes = 0;	/* return from TPM_SHA1Start */

	TPM_setlog(0);
	
	while (i < argc) {
		if (!strcmp("-ic",argv[i])) {
			i++;
			if (i < argc) {
				data = argv[i];
			} else {
				printf("Missing mandatory parameter for -ic.\n");
				usage();
			}
		} else
		if (!strcmp("-if",argv[i])) {
			i++;
			if (i < argc) {
				filename = argv[i];
			} else {
				printf("Missing mandatory parameter for -if.\n");
				usage();
			}
		} else
		if (!strcmp("-ix",argv[i])) {
			i++;
			if (i < argc) {
				index = atoi(argv[i]);
			} else {
				printf("Missing mandatory parameter for -ix.\n");
				usage();
			}
		} else
		if (!strcmp("-v",argv[i])) {
			TPM_setlog(1);
			verbose = TRUE;
		} else
		    if (!strcmp("-h",argv[i])) {
			usage();
		} else {
			printf("\n%s is not a valid option\n", argv[i]);
			usage();
		}
		i++;
	}

	if (NULL == data && filename == NULL) {
		printf("Input parameters wrong or missing!\n");
		usage();
	}
	/* Common processing, for data or file */
	ret = TPM_SHA1Start(&maxNumBytes);
	if (0 != ret) {
	    printf("Error from TPM_SHA1Start(): %d (0x%x)\n",
		   ret,
		   ret);
	    exit(-1);
	}
	if (maxNumBytes < 64) {
	    printf("The size parameter returned from SHA1Start() is bad.\n");
	    exit(-1);
	}

	/* If the connection is to a hardware device, the driver limits the buffer size to
	   2048, even if the TPM can support a larger size.

	   The -20 is presumably for the TPM command packet tag, paramSize, ordinal,
	   numBytes, although this only adds up to 14 bytes.
	*/
#if defined TPM_USE_CHARDEV || defined XCRYPTO_USE_CCA
	maxNumBytes = MIN(maxNumBytes, (2 * 1024) - 20);
	maxNumBytes &= ~63;
#else
	/* Even if the connection is to a socket, it may be then through a proxy to a
	   hardware device.  Setting this env variable flag again limits the buffer to
	   2048. */
	if (getenv("TPM_HW_DRIVER") != NULL) {
	    maxNumBytes = MIN(maxNumBytes, (2 * 1024) - 20);
	    maxNumBytes &= ~63;
	}
#endif

	
	if (NULL != data) {
		len = strlen(data);
		printf("SHA1 hash for '%s': ",data);
		offset = 0;
		while (len > 64) {
			unsigned int chunksize;
			chunksize = MIN(maxNumBytes, len & ~63);

			if (verbose)
				printf("Chunksize to hash: %d\n",chunksize);

			ret = TPM_SHA1Update(&data[offset], chunksize);
			if (ret != 0) {
				printf("Error %s from SHA1Update.\n",
				       TPM_GetErrMsg(ret));
				exit(ret);
			}
			offset += chunksize;
			len -= chunksize;
		}

		if (index >= 0) {
			ret = TPM_SHA1CompleteExtend(&data[offset],len,
			                             index,
			                             hashbuffer,
			                             pcrValue);
		} else {
			ret = TPM_SHA1Complete(&data[offset],len,hashbuffer);
		}
		if (0 == ret) {
			printf("Hash: ");
			i = 0;
			while (i < (int)sizeof(hashbuffer)) {
				printf("%02x",hashbuffer[i]);
				i++;
			}
			printf("\n");
		
			if (index >= 0) {
				printf("New value of PCR: ");
				i = 0;
				while (i < (int)sizeof(pcrValue)) {
					printf("%02x",pcrValue[i]);
					i++;
				}
				printf("\n");
			}
		} else {
			printf("Error '%s' from SHA1Complete/SHA1CompleteExtend.\n",
			       TPM_GetErrMsg(ret));
		}
	}
	
	if (NULL != filename) {
		FILE * f = fopen(filename,"rb");
		if (NULL != f) {
			int n = 0;
			uint32_t chunksize;
			char *buf;
			uint32_t total = 0;
			printf("SHA1 hash for file '%s': \n",filename);

			buf = malloc(maxNumBytes);
			if (!buf) {
				printf("Could not allocated buffer.\n");
				exit(-1);
			}

			while ((n = fread(buf,1,maxNumBytes,f)) >= 64) {

				chunksize = MIN(maxNumBytes, 
				                (uint32_t)(n & ~63));
				
				if (verbose)
					printf("Chunksize to hash: %d\n",
					       chunksize);
				ret = TPM_SHA1Update(buf,chunksize);
				if (ret != 0) {
					printf("Error %s from SHA1Update.\n",
					       TPM_GetErrMsg(ret));
					exit(-1);
				}

				total += chunksize;
				if ((chunksize - n)) {
					offset = chunksize;
					n &= 63;
					break;
				}
			}
			total += n;
			
			if (index >= 0) {
				ret = TPM_SHA1CompleteExtend(&buf[offset],n,
				                             index,
				                             hashbuffer,
				                             pcrValue);
			} else {
				ret = TPM_SHA1Complete(&buf[offset],n,hashbuffer);
			}

			fclose(f);
			free(buf);

			if (0 == ret) {
				printf("Hash: ");
				i = 0;
				while (i < (int)sizeof(hashbuffer)) {
					printf("%02x",hashbuffer[i]);
					i++;
				}
				printf("\n");
			
				if (index >= 0) {
					printf("New value of PCR: ");
					i = 0;
					while (i < (int)sizeof(pcrValue)) {
						printf("%02x",pcrValue[i]);
						i++;
					}
					printf("\n");
				}
			} else {
				printf("Error '%s' from SHA1Complete/SHA1CompleteExtend.\n",
				       TPM_GetErrMsg(ret));
			}
		} else {
			printf("Could not find file '%s'.\n",filename);
		}
	}
	return 0;
}
