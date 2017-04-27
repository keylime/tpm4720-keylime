/********************************************************************************/
/*										*/
/*			     	TPM Change TPM Auth				*/
/*			     Written by J. Kravitz 				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*	      $Id: chgtpmauth.c 4702 2013-01-03 21:26:29Z kgoldman $		*/
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
#include <sys/types.h>
#include <string.h>
#include <unistd.h>
#include "tpmfunc.h"

static void printUsage(void);

static int ownflag  = 0;


int main(int argc, char *argv[])
   {
   int ret;
   const char *ownerPassword = NULL;
   const char *newPassword = NULL;
   const char *ownerAuthFilename = NULL;
   const char *newAuthFilename = NULL;
   unsigned char  ownerAuth[TPM_HASH_SIZE];
   unsigned char  newAuth[TPM_HASH_SIZE];
   int 	i;
   
   TPM_setlog(0);

   for (i=1 ; i<argc ; i++) {
       if (!strcmp(argv[i], "-pwdo")) {
	   i++;
	   if (i < argc) {
	       ownerPassword = argv[i];
	   }
	   else {
	       printf("Missing parameter to -pwdo\n");
	       printUsage();
	   }
       }
       else if (strcmp(argv[i],"-pwdof") == 0) {
	   i++;
	   if (i < argc) {
	       ownerAuthFilename = argv[i];
	   }
	   else {
	       printf("-pwdof option needs a value\n");
	       printUsage();
	   }
       }
       else if (!strcmp(argv[i], "-pwdn")) {
	   i++;
	   if (i < argc) {
	       newPassword = argv[i];
	   }
	   else {
	       printf("Missing parameter to -pwdn\n");
	       printUsage();
	   }
       }
       else if (!strcmp(argv[i], "-pwdnf")) {
	   i++;
	   if (i < argc) {
	       newAuthFilename = argv[i];
	   }
	   else {
	       printf("Missing parameter to -pwdnf\n");
	       printUsage();
	   }
       }
       else if (strcmp(argv[i],"-own") == 0) {
	   ownflag = 1;
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
   if ((ownerPassword == NULL) && (ownerAuthFilename == NULL)) {
       printf("\nMissing -pwdo or -pwdof argument\n");
       printUsage();
   }
   if ((ownerPassword != NULL) && (ownerAuthFilename != NULL)) {
       printf("\nCannot have -pwdo and -pwdof arguments\n");
       printUsage();
   }
   if ((newPassword == NULL) && (newAuthFilename == NULL)) {
       printf("\nMissing -pwdo or -pwdof argument\n");
       printUsage();
   }
   if ((newPassword != NULL) && (newAuthFilename != NULL)) {
       printf("\nCannot have -pwdn and -pwdnf arguments\n");
       printUsage();
   }


   /* use the SHA1 hash of the password string as the Owner Authorization Data */
   if (ownerPassword != NULL) {
       TSS_sha1((unsigned char *)ownerPassword,
		strlen(ownerPassword),
		ownerAuth);
   }
   /* get the ownerAuth from a file */
   else {
       unsigned char *buffer = NULL;
       uint32_t buffersize;
       ret = TPM_ReadFile(ownerAuthFilename, &buffer, &buffersize);
       if ((ret & ERR_MASK)) {
	   printf("Error reading %s.\n", ownerAuthFilename);
	   exit(-1);
       }
       if (buffersize != sizeof(ownerAuth)) {
	   printf("Error reading %s, size %u should be %lu.\n",
		  ownerAuthFilename, buffersize, (unsigned long)sizeof(ownerAuth));
	   exit(-1);
       }
       memcpy(ownerAuth, buffer, sizeof(ownerAuth));
       free(buffer);
   }
   /* use the SHA1 hash of the password string as the Owner new Authorization Data */
   if (newPassword != NULL) {
       TSS_sha1((unsigned char *)newPassword,
		strlen(newPassword),
		newAuth);
   }
   /* get the ownerAuth from a file */
   else {
       unsigned char *buffer = NULL;
       uint32_t buffersize;
       ret = TPM_ReadFile(newAuthFilename, &buffer, &buffersize);
       if ((ret & ERR_MASK)) {
	   printf("Error reading %s.\n", newAuthFilename);
	   exit(-1);
       }
       if (buffersize != sizeof(newAuth)) {
	   printf("Error reading %s, size %u should be %lu.\n",
		  newAuthFilename, buffersize, (unsigned long)sizeof(newAuth));
	   exit(-1);
       }
       memcpy(newAuth, buffer, sizeof(newAuth));
       free(buffer);
   }
   if (ownflag)
      {
      ret = TPM_ChangeOwnAuth(ownerAuth, newAuth);
      if (ret != 0)
         {
         printf("Error %s from TPM_ChangeOwnAuth\n",TPM_GetErrMsg(ret));
         exit(1);
         }
      }
   else
      {
      ret = TPM_ChangeSRKAuth(ownerAuth, newAuth);
      if (ret != 0)
         {
         printf("Error %s from TPM_ChangeSRKAuth\n",TPM_GetErrMsg(ret));
         exit(1);
         }
      }
   exit(0);
   }
   
static void printUsage()
   {
   printf("Usage: chgtpmauth [-own]> -pwdn <new SRK or Owner password>\n"
	  "   [-pwdo <owner password> -pwdof <owner authorization file name>\n"
	  "   [-pwdn <new password>   -pwdnf <new authorization file name>\n");
   printf("Runs TPM_ChangeAuthOwner\n");
   printf("\n");
   printf("    -own to specify the TPM Owner password is to be changed\n");
   printf("    -h print usage information (this message)\n");
   exit(1);
   }
