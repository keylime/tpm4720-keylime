/********************************************************************************/
/*										*/
/*			     	TPM Verify a Signature				*/
/*			     Written by J. Kravitz 				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*	      $Id: verifyfile.c 4702 2013-01-03 21:26:29Z kgoldman $		*/
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
#include <openssl/sha.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <tpmutil.h>
#include <tpmfunc.h>

void printUsage(void);

int main(int argc, char *argv[])
   {
   int ret;
   struct stat sbuf;
   unsigned char databuff[65535];  /* data read work buffer */
   unsigned char datahash[20];     /* hash of data file */
   unsigned char digest[20];
   SHA_CTX sha;
   FILE *datafile;
   const char *datafilename = NULL;
   FILE *sigfile;
   const char *sigfilename = NULL;
   FILE *keyfile;
   const char *kfilename = NULL;
   EVP_PKEY *pkey;
   RSA  *rsa;
   uint16_t sigscheme = TPM_SS_RSASSAPKCS1v15_SHA1;
   int plain;
   unsigned char padded[4096];
   unsigned char plainarray[4096];
   TPM_SIGN_INFO tsi;
   STACK_TPM_BUFFER(tsi_ser);
   STACK_TPM_BUFFER(signature);
   int i;
   
   for (i=1 ; i<argc ; i++) {
       if (!strcmp(argv[i], "-ss")) {
	   i++;
	   if (i < argc) {
	       if (!strcmp(argv[i], "info")) {
		   sigscheme = TPM_SS_RSASSAPKCS1v15_INFO;
	       }
	       else if (!strcmp(argv[i], "der")) {
		   sigscheme = TPM_SS_RSASSAPKCS1v15_DER;
	       }
	       else {
		   printf("Bad parameter for -ss\n");
		   printUsage();
	       }
	   }
	   else {
	       printf("Missing parameter for -ss\n");
	       printUsage();
	   }
       }
       else if (strcmp(argv[i],"-if") == 0) {
	   i++;
	   if (i < argc) {
	       datafilename = argv[i];
	   }
	   else {
	       printf("-if option needs a value\n");
	       printUsage();
	       exit(2);
	   }
       }
       else if (strcmp(argv[i],"-is") == 0) {
	   i++;
	   if (i < argc) {
	       sigfilename = argv[i];
	   }
	   else {
	       printf("-is option needs a value\n");
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
	       exit(2);
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
   if ((datafilename == NULL) ||
       (sigfilename == NULL) ||
       (kfilename == NULL)) {
       printf("Missing parameter\n");
       printUsage();
   }
   /*
   ** read and hash the data file
   */
   datafile = fopen(datafilename,"rb");
   if (datafile == NULL)
      {
	  printf("Unable to open data file '%s'\n",datafilename);
	  exit(2);
      }
   SHA1_Init(&sha);
   for (;;)
      {
      ret = fread(databuff,1,sizeof databuff,datafile);
      if (ret < 0)
         {
	     printf("I/O Error while reading data file '%s'\n",datafilename);
	     exit(3);
         }
      SHA1_Update(&sha,databuff,ret);
      if (ret < (int)sizeof(databuff)) break;
      }
   fclose(datafile);
   SHA1_Final(datahash,&sha);
   /*
   ** get size of signature file
   */
   stat(sigfilename,&sbuf);
   signature.used = (int)sbuf.st_size;
   sigfile = fopen(sigfilename,"rb");
   if (sigfile == NULL)
      {
	  printf("Unable to open signature file '%s'\n",sigfilename);
	  exit(4);
      }
   /*
   ** read the signature file
   */
   ret = fread(signature.buffer,1,signature.used,sigfile);
   if (ret != (int)signature.used)
      {
	  printf("I/O Error while reading signature file '%s'\n",sigfilename);
	  exit(5);
      }
   fclose(sigfile);
   /*
   ** read the key file
   */
   keyfile = fopen(kfilename,"rb");
   if (keyfile == NULL)
      {
	  printf("Unable to open public key file '%s'\n",kfilename);
	  exit(6);
      }
   pkey = PEM_read_PUBKEY(keyfile,NULL,NULL,NULL);
   if (pkey == NULL)
      {
	  printf("I/O Error while reading public key file '%s'\n",kfilename);
	  exit(7);
      }
   rsa = EVP_PKEY_get1_RSA(pkey);
   if (rsa == NULL)
      {
      printf("Error while converting public key \n");
      exit(8);
      }

   switch (sigscheme) {
   default:
   case TPM_SS_RSASSAPKCS1v15_SHA1:
       ret = RSA_verify(NID_sha1,datahash,20,
                        signature.buffer,signature.used,
                        rsa);
       if (ret != 1) {
          printf("Verification Failed\n");
          exit(100);
       }
       break;
   case TPM_SS_RSASSAPKCS1v15_DER:
       plain = RSA_public_decrypt(signature.used, signature.buffer,
                                  plainarray, rsa, RSA_NO_PADDING);
       if (plain == -1) {
          printf("Verification (DER) had an error\n");
          exit(100);
       }
       ret = RSA_padding_add_PKCS1_type_1(padded,plain,datahash,sizeof(datahash));
       if (ret != 1) {
          printf("Could not add the padding.\n");
          exit(100);
       }
       if (memcmp(padded, plainarray, plain) != 0) {
          printf("Verification (DER) failed.\n");
          exit(100);
       }
       break;
   case TPM_SS_RSASSAPKCS1v15_INFO:
       // the nonce is the digest of the hashed data!!
       TSS_sha1(datahash, 20, digest);
       tsi.tag = TPM_TAG_SIGNINFO;
       memcpy(tsi.fixed,"SIGN",4);
       tsi.data.size = TPM_HASH_SIZE;
       tsi.data.buffer = datahash;
       memcpy(tsi.replay, digest, TPM_HASH_SIZE);
       
       /* need to calculate the digest of the TPM_SIGN_INFO structure */
       ret = TPM_WriteSignInfo(&tsi_ser, &tsi);
       if ((ret & ERR_MASK)) {
           printf("Could not serialize TPM_SIGN_INFO structure.\n");
           exit(100);
       }
       ret = TPM_ValidateSignature(sigscheme,
                                   &tsi_ser,
                                   &signature,
                                   rsa);
       if (ret != 0) {
           printf("Verification (INFO) failed.\n");
           exit(-1);
       }
       break;
   }
   RSA_free(rsa);
   EVP_PKEY_free(pkey);
   exit(0);
   }

void printUsage()
{
    printf("Usage: verifyfile [-ss info|der] -is <sig file> -if <data file> -ik <pubkey file (.pem)>\n");
    exit(1);
}
