/********************************************************************************/
/*										*/
/*			    TCPA Check NV Storage				*/
/*			     Written by Stefan Berger				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*	      $Id: nv.c 4702 2013-01-03 21:26:29Z kgoldman $			*/
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

uint32_t TestNVStorage(uint32_t parhandle,
                       unsigned char * passptr1,
                       unsigned char * passptr2,
                       unsigned char * data,
                       uint32_t index);

uint32_t TestNVStorageAuth(uint32_t parhandle,
                           unsigned char * passptr1,
                           unsigned char * passptr2,
                           unsigned char * data,
                           uint32_t index);



static void usage() {
	printf("Usage: nv <owner password> -i index -d data [-p permission] [-a <area password>]\n");
	printf("\n");
	printf(" -i index     : The index of the memory to use.\n");
	printf(" -d data      : The data to write into the memory.\n");
	printf(" -p permission: A hex number that defines the permissions for the area\n"
	       "                of memory, i.e. -p 40004 to set permissions to \n"
	       "                TPM_NV_PER_AUTHREAD|TPM_NV_PER_AUTHWRITE. By default the\n"
	       "                permissions are set to allow reading / writing only be\n"
	       "                the owner.\n");
	printf(" -a password  : The password for the memory area to protect.\n");
	printf("\n");
	printf("Examples:\n");
	printf("nv aaa -i 1 -d Hello\n");
	printf("nv aaa -i 2 -d Hello -p 40004 -a MyPWD\n");
}


int main(int argc, char * argv[]) {
	char * keypass = NULL;
	char * areapass = NULL;
	uint32_t parhandle;             /* handle of parent key */
	unsigned char * passptr1 = NULL;
	unsigned char * passptr2 = NULL;
	unsigned char passhash1[20];
	unsigned char passhash2[20];	
	uint32_t ret;
	int i =	0;
	TPM_NV_INDEX index = 0xffffffff;
	unsigned char * data = NULL;
	uint32_t permissions = TPM_NV_PER_OWNERREAD;     	
	
	i = 1;
	
	if (i < argc) {
		keypass = argv[i];
	}
	
	TPM_setlog(0);
	
	i = 2;
	
	while (i < argc) {
		if (!strcmp("-d",argv[i])) {
			i++;
			if (i < argc) {
				data = (unsigned char*)argv[i];
			} else {
				printf("Missing mandatory parameter for -d.\n");
				usage();
				exit(-1);
			}
		} else
		if (!strcmp("-i",argv[i])) {
			i++;
			if (i < argc) {
				index = atoi(argv[i]);
			} else {
				printf("Missing mandatory parameter for -i.\n");
				usage();
				exit(-1);
			}
		} else
		if (!strcmp("-p",argv[i])) {
			i++;
			if (i < argc) {
				sscanf(argv[i],"%x",&permissions);
				printf("permissions: 0x%x\n",permissions);
			} else {
				printf("Missing parameter for -x.\n");
				usage();
				exit(-1);
			}
		} else
		if (!strcmp("-a",argv[i])) {
			i++;
			if (i < argc) {
				areapass = argv[i];
			} else {
				printf("Missing parameter for -a.\n");
				usage();
				exit(-1);
			}
		} else
		if (!strcmp("-v",argv[i])) {
			TPM_setlog(1);
		} else
		if (!strcmp("-h",argv[i])) {
		        usage();
		        exit(-1);
		} else {
		        printf("\n%s is not a valid option\n", argv[i]);
			usage();
			exit(-1);
		}
		i++;
	}

	if (NULL == data || index == 0xffffffff) {
		printf("Input parameters wrong or missing!\n");
		usage();
		exit(-1);
	}
	
	
	printf("Using keypass : %s\n",keypass);
	printf("Using areapass: %s\n",areapass);
	
	/*
	 * convert parent key handle from hex
	 */
//	ret = sscanf(argv[nxtarg+0],"%x",&parhandle);
	parhandle = 0x00000000;
	

	if (NULL != keypass) {
		TSS_sha1(keypass,strlen(keypass),passhash1);
		passptr1 = passhash1;
	} else {
		passptr1 = NULL;
	}

	if (NULL != areapass) {
		TSS_sha1(areapass,strlen(areapass),passhash2);
		passptr2 = passhash2;
	} else {
		passptr2 = NULL;
	}

#if 0
	i = 0;
	printf("SHA(HMAC key = %s): ",keypass);
	while (i < 20) {
		printf("%02x ",passhash1[i]);
		i++;
	}
	printf("\n");

	i = 0;
	printf("SHA(HMAC area key = %s): ",areapass);
	while (i < 20) {
		printf("%02x ",passhash2[i]);
		i++;
	}
	printf("\n");
#endif

	/*
	 * Define a space in NV ram, write something into it and
	 * read it out again and compare.
	 */


	if (NULL == areapass) {
		ret = TestNVStorage(parhandle,passptr1,passptr2,data,index);
	} else {
		ret = TestNVStorageAuth(parhandle,passptr1,passptr2,data,index);
	}

	return ret;
}

uint32_t TestNVStorage(uint32_t parhandle,
                       unsigned char * passptr1,
                       unsigned char * passptr2,
                       unsigned char * data,
                       uint32_t index) {
	uint32_t ret;
	(void)parhandle;
	/*
	 * Define a space in NV ram, write something into it and
	 * read it out again and compare.
	 */
	ret = TPM_NV_DefineSpace2(passptr1,                // Sha(HMAC key)
	                          index,
	                          strlen((char *)data)*2,
	                          TPM_NV_PER_OWNERREAD,
	                          passptr2,                 // keyauth   - used to create  encAuth
				  NULL,
				  NULL);


	if (0 != ret){
		printf("Got error '%s' from NV_DefineSpace.\n",TPM_GetErrMsg(ret));
	} else {
		ret = TPM_NV_WriteValue(index,
		                        0,
		                        data,strlen((char *)data),
		                        passptr1 );
	}
	
	if (0 != ret) {
		printf("Got error '%s' from NV_WriteValue.\n",TPM_GetErrMsg(ret));
	} else {
		unsigned char * buffer = malloc(strlen((char *)data)+1);
		uint32_t bufferlen = strlen((char *)data);
		ret = TPM_NV_ReadValue(index,
		                       0,
		                       strlen((char *)data),
		                       buffer,&bufferlen,
		                       passptr1);
		if (0 == ret) {
			uint32_t i = 0;
			printf("Received %d bytes: ",bufferlen);
			while (i < bufferlen) {
				printf("%02x ",buffer[i]);
				i++;
			}
			printf("\n");
			buffer[bufferlen] = 0;
			printf("%s\n",buffer);
			
			if (0 == memcmp(buffer,data,bufferlen)) {
				printf("Test was successful. Could read what was written.\n");
			} else {
				printf("Test was Unsuccessful. Read different data than what was written.\n");
			}
			
		} else {
			printf("Got error '%s' from NV_ReadValue.\n",TPM_GetErrMsg(ret));
		}
	}
	return ret;
}

uint32_t TestNVStorageAuth(uint32_t parhandle,
                           unsigned char *passptr1,
                           unsigned char *passptr2,
                           unsigned char *data,
                           uint32_t index) {
	uint32_t ret;
	(void)parhandle;
	/*
	 * Define a space in NV ram, write something into it and
	 * read it out again and compare.
	 */
	ret = TPM_NV_DefineSpace2(passptr1,
	                          index,
	                          strlen((char *)data)*2,
	                          TPM_NV_PER_AUTHREAD|TPM_NV_PER_AUTHWRITE,
	                          passptr2,
				  NULL,
				  NULL);

	if (0 != ret){
		printf("Got error code from NV_DefineSpace2: %d (0x%x)\n",ret,ret);
	} else {
		ret = TPM_NV_WriteValueAuth(index,
		                            0,
		                            data,strlen((const char*)data),
		                            passptr2 );
	}
	
	if (0 != ret) {
		printf("Got error code from NV_WriteValueAuth: %d (0x%x)\n",ret,ret);
	} else {
		unsigned char * buffer = malloc(strlen((char *)data)+1);
		uint32_t bufferlen = strlen((char *)data);
		ret = TPM_NV_ReadValueAuth(index,
		                           0,
		                           strlen((char *)data),
		                           buffer,&bufferlen,
		                           passptr2);
		if (0 == ret) {
			uint32_t i = 0;
			printf("Received %d bytes: ",bufferlen);
			while (i < bufferlen) {
				printf("%02x ",buffer[i]);
				i++;
			}
			printf("\n");
			buffer[bufferlen] = 0;
			printf("%s\n",buffer);
			
			if (0 == memcmp(buffer,data,bufferlen)) {
				printf("Test was successful. Could read what was written.\n");
			} else {
				printf("Test was Unsuccessful. Read different data than what was written.\n");
			}
			
		} else {
			printf("Got error code from NV_ReadValueAuth: %d (0x%x)\n",ret,ret);
		}
	}
	
	return ret;
}
