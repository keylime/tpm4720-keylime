/********************************************************************************/
/*										*/
/*			     	TPM Change Key/Data Auth 			*/
/*			     Written by J. Kravitz & S. Berger			*/
/*		       IBM Thomas J. Watson Research Center			*/
/*	      $Id: chgauth.c 4702 2013-01-03 21:26:29Z kgoldman $		*/
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
#include <sys/stat.h>
#include <string.h>
#ifdef TPM_POSIX
#include <netinet/in.h>
#endif
#ifdef TPM_WINDOWS
#include <winsock2.h>
#endif
#include <unistd.h>
#include "tpmfunc.h"

static void printUsage(void);

int main(int argc, char *argv[])
   {
   int ret;
   struct stat sbuf;
   unsigned char  keyblob[4096];
   unsigned int   keyblen;
   STACK_TPM_BUFFER(outblob)
   unsigned int   outblen;
   unsigned int   handle = 0;
   char  filename[256];
   char  filename2[256];
   unsigned char  parphash[TPM_HASH_SIZE];
   unsigned char  newphash[TPM_HASH_SIZE];
   unsigned char  keyphash[TPM_HASH_SIZE];
   unsigned char  *passptr1;
   FILE          *outfile;
   FILE          *ainfile;
   keydata        key;
   char  *keypass = NULL;
   char  *newpass = NULL;
   char  *parpass = NULL;
   char  *keyname = NULL;
   STACK_TPM_BUFFER( buffer );
   int 	i;
   
   TPM_setlog(0);

   for (i=1 ; i<argc ; i++) {
       if (!strcmp(argv[i], "-pwd")) {
	   i++;
	   if (i < argc) {
	       keypass = argv[i];
	   }
	   else {
	       printf("Missing parameter to -pwd\n");
	       printUsage();
	   }
       }
       else if (!strcmp(argv[i], "-pwdn")) {
	   i++;
	   if (i < argc) {
	       newpass = argv[i];
	   }
	   else {
	       printf("Missing parameter to -pwdn\n");
	       printUsage();
	   }
       }
       else if (!strcmp(argv[i], "-pwdp")) {
	   i++;
	   if (i < argc) {
	       parpass = argv[i];
	   }
	   else {
	       printf("Missing parameter to -pwdp\n");
	       printUsage();
	   }
       }
       else if (strcmp(argv[i],"-hp") == 0) {
	   i++;
	   if (i < argc) {
	       /* convert key handle from hex */
	       if (1 != sscanf(argv[i], "%x", &handle)) {
		   printf("Invalid -hp argument '%s'\n",argv[i]);
		   exit(2);
	       }
	       if (handle == 0) {
		   printf("Invalid -hp argument '%s'\n",argv[i]);
		   exit(2);
	       }		 
	   }
	   else {
	       printf("-hp option needs a value\n");
	       printUsage();
	   }
       }
       else if (strcmp(argv[i],"-if") == 0) {
	   i++;
	   if (i < argc) {
	       keyname = argv[i];
	   }
	   else {
	       printf("-if option needs a value\n");
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
   if ((keypass == NULL) ||
       (newpass == NULL) ||
       (handle == 0) ||
       (keyname == NULL)) {
	   printf("Missing argument\n");
	   exit(2);
   }
   /*
   ** use the SHA1 hash of the password string as the Parent Key Authorization Data
   */
   if (parpass != NULL)
      {
      TSS_sha1((unsigned char*)parpass,strlen(parpass),parphash);
      passptr1 = parphash;
      }
   else passptr1 = NULL;
   /*
   ** use the SHA1 hash of the password string as the Key Authorization Data
   */
   TSS_sha1((unsigned char *)keypass,strlen(keypass),keyphash);
   /*
   ** use the SHA1 hash of the password string as the New Authorization Data
   */
   TSS_sha1((unsigned char *)newpass,strlen(newpass),newphash);
   /*
   ** read the key blob
   */
   ainfile = fopen(keyname,"rb");
   if (ainfile == NULL)
      {
      printf("Unable to open key/sealed file\n");
      exit(3);
      }
   stat(keyname,&sbuf);
   keyblen = (int)sbuf.st_size;
   ret = fread(keyblob,1,keyblen,ainfile);
   if (ret != (int)keyblen)
      {
      printf("Unable to read key/sealed data file\n");
      exit(4);
      }
   fclose(ainfile);
   SET_TPM_BUFFER(&buffer, keyblob, keyblen);
   ret = TSS_KeyExtract(&buffer, 0,&key);
   if (ret > 0) {
           /* It's a key */
           ret = TPM_ChangeAuth(handle,passptr1,keyphash,newphash,
                                TPM_ET_KEY,
                                key.encData.buffer, key.encData.size);
           if (ret != 0) {
                printf("Error %s from TPM_ChangeAuth\n",TPM_GetErrMsg(ret));
                exit(5);
           }
           ret = TPM_WriteKey(&outblob,&key);
           if ((ret & ERR_MASK) != 0) return ret;
           outblen = ret;
   } else {
           TPM_STORED_DATA tsd;
           ret = TPM_ReadStoredData(&buffer, 0, &tsd);
           if ((ret & ERR_MASK)) {
                   printf("Could not read sealed data data structure.\n");
                   exit(6);
           }
           /* sealed data */
           ret = TPM_ChangeAuth(handle,passptr1,keyphash,newphash,
                                TPM_ET_DATA,
                                tsd.encData.buffer, tsd.encData.size);
           if (ret != 0) {
                printf("Error %s from TPM_ChangeAuth\n",TPM_GetErrMsg(ret));
                exit(7);
           }
           ret = TPM_WriteStoredData(&outblob, &tsd);
           if ((ret & ERR_MASK) != 0) return ret;
           outblen = ret;
   }
   sprintf(filename2,"%s.save",keyname);
   sprintf(filename,"%s",keyname);
   ret = rename(filename,filename2);
   if (ret != 0)
      {
      printf("Unable to rename old key file\n");
      exit(6);
      }
   outfile = fopen(filename,"wb");
   if (outfile == NULL)
      {
      printf("Unable to create new key file\n");
      exit(7);
      }
   ret = fwrite(outblob.buffer,1,outblen,outfile);
   if (ret != (int)outblen)
      {
      printf("Unable to write new key file\n");
      exit(8);
      }
   fclose(outfile);
   exit(0);
   }
   
static void printUsage()
{
	printf("Usage: chgauth [options] -hp <parent key handle> -if <key/data file name>\n"
	       "-pwd <old key/data password> -pwdn <new key/data password>\n"
               "   Where the arguments are...\n"
               "    -hp <parent key handle>   is the parent key handle in hex\n"
               "    -if <key/data file name>  is the name of the key or sealed data file\n"
               "    -pwd <old key password>   is the current key or sealed data password\n"
               "    -pwdn <new key password>  is the new key or sealed data password\n"
               "\n"
               "   Where the <options> are...\n"
               "    -pwdp <parpass>   to specify the parent key use password\n"
               "    -h                print usage information (this message)\n");
        exit(1);
}
