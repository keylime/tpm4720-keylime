/********************************************************************************/
/*										*/
/*			     	TPM Dump a Key					*/
/*			     Written by J. Kravitz, S. Berger			*/
/*		       IBM Thomas J. Watson Research Center			*/
/*	      $Id: dumpkey.c 4702 2013-01-03 21:26:29Z kgoldman $		*/
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
#ifdef TPM_POSIX
#include <netinet/in.h>
#endif
#ifdef TPM_WINDOWS
#include <winsock2.h>
#endif
#include "tpmfunc.h"

static void printUsage(void);

int main(int argc, char *argv[])
   {
   int ret;
   int i;
   struct stat sbuf;
   unsigned char  keyblob[4096];
   unsigned int   keyblen;
   FILE          *kinfile;
   keydata       k;
   const char *keyfilename = NULL;
   STACK_TPM_BUFFER(buffer);
   
    
   TPM_setlog(0);
   for (i=1 ; i<argc ; i++) {
       if (strcmp(argv[i],"-ik") == 0) {
	   i++;
	   if (i < argc) {
	       keyfilename = argv[i];
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
   /*
   ** read the Key File
   */
   if (keyfilename == NULL) {
       printf("Missing -ik argument\n");
       printUsage();
   }
       
   kinfile = fopen(keyfilename ,"rb");
   if (kinfile == NULL)
      {
      printf("Unable to open key file\n");
      exit(3);
      }
   stat(keyfilename ,&sbuf);
   keyblen = (int)sbuf.st_size;
   ret = fread(keyblob,1,keyblen,kinfile);
   if (ret != (int)keyblen)
      {
      printf("Unable to read key file\n");
      exit(4);
      }
   fclose(kinfile);
   SET_TPM_BUFFER(&buffer, keyblob, keyblen);
   TSS_KeyExtract(&buffer,0,&k);
   printf("Version:        %02x%02x%02x%02x\n",k.v.ver.major,k.v.ver.minor,k.v.ver.revMajor,k.v.ver.revMinor);
   printf("KeyUsage:       %02x\n",k.keyUsage);
   printf("KeyFlags:       %04x\n",k.keyFlags);
   printf("AuthDataUsage:  %02x\n",k.authDataUsage);
   printf("Pub Algorithm:  %04x\n",k.pub.algorithmParms.algorithmID);
   printf("Pub EncScheme:  %02x\n",k.pub.algorithmParms.encScheme);
   printf("Pub SigScheme:  %02x\n",k.pub.algorithmParms.sigScheme);
   printf("Pub KeyBitLen:  %04x\n",k.pub.algorithmParms.u.rsaKeyParms.keyLength);
   printf("Pub KeyLength:  %04x\n",k.pub.pubKey.keyLength);
   printf("Pub Exp Size:   %02X\n",k.pub.algorithmParms.u.rsaKeyParms.exponentSize);
   exit(0);
   }


static void printUsage()
{
    printf("Prints public data from a key file\n\n");
    printf("Usage: dumpkey -ik filename\n");
    printf("\n");
    printf("   Where the arguments are...\n");
    printf("    -ik <filename> is the key binary file\n");
    printf("\n");
    exit(1);
}
