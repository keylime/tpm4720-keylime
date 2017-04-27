/********************************************************************************/
/*										*/
/*			     	TPM Evict Key					*/
/*			     Written by J. Kravitz, S. Berger			*/
/*		       IBM Thomas J. Watson Research Center			*/
/*	      $Id: evictkey.c 4702 2013-01-03 21:26:29Z kgoldman $		*/
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
#ifdef TPM_POSIX
#include <netinet/in.h>
#endif
#ifdef TPM_WINDOWS
#include <winsock2.h>
#endif
#include "tpmfunc.h"

/* local prototypes */
void printUsage(void);

int main(int argc, char *argv[])
{
   int ret;
   uint32_t keyhandle = 0;
   STACK_TPM_BUFFER(response);
   int i;
   int listsize;
   int offset;
   int all = FALSE;
   
   TPM_setlog(0);

   for (i=1 ; i<argc ; i++) {
       if (strcmp(argv[i],"-hk") == 0) {
	   i++;
	   if (i < argc) {
	       /* convert key handle from hex */
	       if (1 != sscanf(argv[i], "%x", &keyhandle)) {
		   printf("Invalid -hk argument '%s'\n",argv[i]);
		   exit(2);
	       }
	       if (keyhandle == 0) {
		   printf("Invalid -hk argument '%s'\n",argv[i]);
		   exit(2);
	       }		 
	   }
	   else {
	       printf("-hk option needs a value\n");
	       printUsage();
	   }
       }
       else if (!strcmp(argv[i], "-all")) {
	   all = TRUE;
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
   if (all) {
       /* must evict all keys */
       ret = TPM_GetCapability(0x0000007,NULL,&response);
       if (ret != 0)
	   {
	       printf("Error %x from TPM_GetCapability\n",ret);
	       exit(-1);
	   }
       listsize = LOAD16(response.buffer,0);
       offset = 2;
       for (i = 0; i < listsize; ++i)
	   {
	       keyhandle = LOAD32(response.buffer,offset);
	       ret = TPM_EvictKey(keyhandle);
	       if (ret == 0) printf("Evicted key handle %08X\n",keyhandle);
	       else          printf("Error %s attempting to Evict key handle %08X\n",TPM_GetErrMsg(ret),keyhandle);
	       offset += 4;
	   }
       exit(0);
   }
   else if (keyhandle == 0) {
       printf("Missing argument\n");
       printUsage();
   }
   else {
       ret = TPM_EvictKey(keyhandle);
       if (ret != 0)
	   {
	       printf("Error %s from TPM_EvictKey\n",TPM_GetErrMsg(ret));
	       exit(-1);
	   }
   }
   exit(0);
}

void printUsage(void)
{
    printf("\n");
    printf("evictkey - Runs TPM_EvictKey\n");
    printf("\n");
    printf("Usage: evictkey -hk <key handle in hex> | -all\n");
    printf("\n");
    exit(-2);
    return;
}
