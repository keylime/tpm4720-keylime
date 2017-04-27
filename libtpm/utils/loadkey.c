/********************************************************************************/
/*										*/
/*			     	TPM Load a Key					*/
/*			     Written by J. Kravitz, S. Berger			*/
/*		       IBM Thomas J. Watson Research Center			*/
/*	      $Id: loadkey.c 4702 2013-01-03 21:26:29Z kgoldman $		*/
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
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include "tpmfunc.h"

void printUsage(void);

int main(int argc, char *argv[])
{
    int ret;
    struct stat sbuf;
    unsigned char  	pass1hash[20];
    unsigned char  	keyblob[4096];
    unsigned int   	keyblen;
    unsigned int   	parhandle = 0;
    char 		*parpass = NULL;
    uint32_t   		newhandle;
    unsigned char  	*pptr = NULL;
    FILE          	*kinfile;
    keydata       	k;
    int			i;
    int          	oldversion = FALSE;
    int 		zeroAuth = FALSE;
    char		*kfilename = NULL;
   
    STACK_TPM_BUFFER( buffer );
    TPM_setlog(0);
   
    for (i=1 ; i<argc ; i++) {
	if (!strcmp(argv[i], "-v1")) {
	    oldversion = TRUE;
	}
	else if (!strcmp(argv[i], "-pwdz")) {
	    zeroAuth = TRUE;
	}
	else if (strcmp(argv[i],"-hp") == 0) {
	    i++;
	    if (i < argc) {
		/* convert parent key handle from hex */
		if (1 != sscanf(argv[i], "%x", &parhandle)) {
		    printf("Invalid -hp argument '%s'\n",argv[i]);
		    exit(2);
		}
		if (parhandle == 0) {
		    printf("Invalid -hp argument '%s'\n",argv[i]);
		    exit(2);
		}		 
	    }
	    else {
		printf("-hp option needs a value\n");
		printUsage();
	    }
	}
	else if (!strcmp(argv[i], "-pwdp")) {
	    i++;
	    if (i < argc) {
		parpass = argv[i];
	    }
	    else {
		printf("Missing parameter for -pwdp\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-ik") == 0) {
	    i++;
	    if (i < argc) {
		kfilename = argv[i];
	    }
	    else {
		printf("-ik option needs a value\n");
		printUsage();
	    }
	}
	else if (!strcmp(argv[i], "-h")) {
	    printUsage();
	}
	else if (!strcmp(argv[i], "-v")) {
	    TPM_setlog(1);
	}
	else {
	    printf("\n%s is not a valid option\n", argv[i]);
	    printUsage();
	}
    }
    if ((parhandle == 0) ||
	(kfilename == NULL)) {
	printf("Missing parameter\n");
	printUsage();
    }
    /*
    ** use the SHA1 hash of the parent key password string as the Key Authorization Data
    */
    if (parpass != NULL) {
	TSS_sha1(parpass, strlen(parpass), pass1hash);
	pptr = pass1hash;
	}
    else if (zeroAuth) {
	memset(pass1hash, 0, 20);	/* all zero password */
	pptr = pass1hash;
    }
    /*
    ** read the Key File
    */
    kinfile = fopen(kfilename,"rb");
    if (kinfile == NULL)
	{
	    printf("Unable to open key file\n");
	    exit(-3);
	}
    stat(kfilename,&sbuf);
    keyblen = (int)sbuf.st_size;
    ret = fread(keyblob,1,keyblen,kinfile);
    if (ret != (int)keyblen)
	{
	    printf("Unable to read key file\n");
	    exit(-4);
	}
    fclose(kinfile);
    SET_TPM_BUFFER(&buffer, keyblob, keyblen);
    TSS_KeyExtract(&buffer, 0, &k);
    if (TRUE == oldversion) {
	ret = TPM_LoadKey(parhandle,pptr,&k,&newhandle);
	if (ret != 0)
	    {
		printf("%s from TPM_LoadKey\n",TPM_GetErrMsg(ret));
		exit(-6);
	    }
    } else {
	ret = TPM_LoadKey2(parhandle,pptr,&k,&newhandle);
	if (ret != 0)
	    {
		printf("%s from TPM_LoadKey2\n",TPM_GetErrMsg(ret));
		exit(-6);
	    }
    }
    printf("New Key Handle = %08X\n",newhandle);
    exit(0);
}


void printUsage()
{
    printf("Usage: loadkey "
	   "\t[-v1]\n"
	   "\t-hp <parent key handle>\n"
	   "\t-ik <key file name (.key)>\n"
	   "\t[-pwdp <parent key password>]\n"
	   "\t[-pwdz Use zeros as parent key authorization key]\n"
	   "\n"
	   "Set environment variable TPM_NO_KEY_SWAP to 1 to prevent swapping\n");
    
    exit(-1);
}
