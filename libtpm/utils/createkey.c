/********************************************************************************/
/*										*/
/*			     	TPM Create a TPM Key 				*/
/*			     Written by J. Kravitz, S. Berger			*/
/*		       IBM Thomas J. Watson Research Center			*/
/*	      $Id: createkey.c 4702 2013-01-03 21:26:29Z kgoldman $		*/
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
#include "tpmfunc.h"
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/evp.h>

static void printUsage(void);

enum {
    NONE,
    PCR_INFO,
    PCR_INFO_LONG
};


/**************************************************************************/
/*                                                                        */
/*  Main Program                                                          */
/*                                                                        */
/**************************************************************************/
int main(int argc, char *argv[])
   {
   uint32_t ret;

   unsigned char hashpass1[20];    /* hash of new key password */
   unsigned char hashpass2[20];    /* hash of migration password */
   unsigned char hashpass3[20];    /* hash of parent key password */
   keydata k;                      /* keydata structure for input key parameters */
   keydata q;                      /* keydata structure for resulting key */
   RSA *rsa;                       /* OpenSSL format Public Key */
   FILE *keyfile;                  /* output file for public key */
   FILE *blbfile;                  /* output file for encrypted blob */
   EVP_PKEY *pkey = NULL;          /* OpenSSL public key */
   char filename[256];             /* file name string of key file */
   unsigned char blob[4096];       /* area to hold key blob */
   unsigned int  bloblen;          /* key blob length */
   char *keyname = NULL;           /* pointer to key name argument */
   unsigned char *aptr1 = NULL;
   unsigned char *aptr2 = NULL;
   unsigned char *aptr3 = NULL;
   int i;
   int index;
   int index_ctr = 0;
   int max_index = -1;
   unsigned char future_hash[TPM_HASH_SIZE];
   uint32_t pcrs;
   TPM_PCR_INFO_LONG pcrInfoLong;
   TPM_PCR_INFO pcrInfo;
   TPM_PCR_COMPOSITE pcrComp;
   STACK_TPM_BUFFER(serPcrInfo)

   /* command line argument defaults */
   TPM_BOOL pkcsv15 = FALSE;
   TPM_BOOL use_oldversion = FALSE;
   char keytype = 's';
   char *migpass = NULL;
   char *parpass = NULL;
   char *keypass = NULL;
   int use_struct = NONE;
   unsigned int keysize = 2048;		/* key size default */
   uint32_t exponent = 0;		/* public exponent default */
   int verbose = 0;
   uint32_t parhandle = 0;         /* handle of parent key */
   TPM_setlog(0);                   /* turn off verbose output */

   memset(&pcrInfoLong, 0x0, sizeof(pcrInfoLong));
   memset(&pcrInfo    , 0x0, sizeof(pcrInfo));
   memset(&pcrComp    , 0x0, sizeof(pcrComp));
   memset(&k          , 0x0, sizeof(k));

   for (i=1 ; i<argc ; i++) {
       if (!strcmp(argv[i], "-v1")) {
           use_oldversion = TRUE;
       }
       else if (!strcmp(argv[i], "-es")) {
	   i++;
	   if (i < argc) {
	       if (!strcmp(argv[i], "pkcsv15")) {
		   pkcsv15 = TRUE;
	       }
	       else {
		   printf("Bad parameter for -es\n");
		   printUsage();
	       }
	   }
	   else {
	       printf("Missing parameter for -es\n");
	       printUsage();
	   }
       }
       else if (!strcmp(argv[i], "-kt")) {
	   i++;
	   if (i < argc) {
	       if (argv[i][0] != 's' && argv[i][0] != 'e' &&
		   argv[i][0] != 'b' && argv[i][0] != 'l' &&
		   argv[i][0] != 'm' && argv[i][0] != 'd' &&
		   argv[i][0] != 'i') {
		   printUsage();
	       }
	       keytype = argv[i][0];
	   }
	   else {
	       printf("Missing parameter for -kt\n");
	       printUsage();
	   }
       }
       else if (!strcmp(argv[i], "-pwdm")) {
	   i++;
	   if (i < argc) {
	       migpass = argv[i];
	   }
	   else {
	       printf("Missing parameter for -pwdm\n");
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
       else if (!strcmp(argv[i], "-pwdk")) {
	   i++;
	   if (i < argc) {
	       keypass = argv[i];
	   }
	   else {
	       printf("Missing parameter to -pwdk\n");
	       printUsage();
	   }
       }
       else if (!strcmp(argv[i], "-sz")) {
	   i++;
	   if (i < argc) {
	       if (1 != sscanf(argv[i], "%u", &keysize)) {
		   printf("Could not parse the keysize\n");
		   exit(-1);
	       }
	   }
	   else {
	       printf("Missing parameter to -sz\n");
	       printUsage();
	   }
       }
       else if (!strcmp(argv[i], "-exp")) {
	   i++;
	   if (i < argc) {
	       if (1 != sscanf(argv[i], "%u", &exponent)) {
		   printf("Could not parse the exponent\n");
		   exit(-1);
	       }
	   }
	   else {
	       printf("Missing parameter to -exp\n");
	       printUsage();
	   }
       }
       else if (!strcmp(argv[i], "-h")) {
	   printUsage();
       }
       else if (!strcmp(argv[i], "-v")) {
	   TPM_setlog(1);
	   verbose = 1;
       }
       else if (!strcmp(argv[i],"-ix")) {
	   int j = 0;
	   int shift = 4;
	   char *hash_str = NULL;
	   i++;
	   if (i >= argc) {
	       printf("Missing parameter for option -ix\n");
	       printUsage();
	       exit(-1);
	   }
	   index = atoi(argv[i]);
   	    
	   if (index <= max_index) {
	       printf("Indices must be given in ascending order\n");
	       exit(-1);
	   }
	   max_index = index;
   	    
	   i++;
	   if (i >= argc) {
	       printf("Missing parameter for option -ix\n");
	       printUsage();
	       exit(-1);
	   }
	   hash_str = argv[i];
	   if (40 != strlen(hash_str)) {
	       printf("The hash must be exactly 40 characters long!\n");
	       exit(-1);
	   }
	   memset(future_hash, 0x0, TPM_HASH_SIZE);
	   shift = 4;
	   j = 0;
	   while (j < (2 * TPM_HASH_SIZE)) {
	       unsigned char c = hash_str[j];
   	        
	       if (c >= '0' && c <= '9') {
		   future_hash[j>>1] |= ((c - '0') << shift);
	       } else
		   if (c >= 'a' && c <= 'f') {
		       future_hash[j>>1] |= ((c - 'a' + 10) << shift);
		   } else
		       if (c >= 'A' && c <= 'F') {
			   future_hash[j>>1] |= ((c - 'A' + 10) << shift);
		       } else {
			   printf("Hash contains non-hex character!\n");
			   exit(-1);
		       }
	       shift ^= 4;
	       j++;
	   }

	   ret = TPM_GetNumPCRRegisters(&pcrs);
	   if (ret != 0) {
	       printf("Error reading number of PCR register.\n");
	       exit(-1);
	   }
	   if (pcrs > TPM_NUM_PCR) {
	       printf("Library does not support that many PCRs\n");
	       exit(-1);
	   }

	   if ((index < 0) || ((uint32_t)index >= pcrs)) {
	       printf("Index out of range!\n");
	       printUsage();
	       exit(-1);
	   }
	   /*
	    * Now build the pcrInfo
	    */
	   pcrInfoLong.tag = TPM_TAG_PCR_INFO_LONG;
	   pcrInfoLong.localityAtCreation = TPM_LOC_ZERO;
	   pcrInfoLong.localityAtRelease = TPM_LOC_ZERO;
	   pcrInfoLong.releasePCRSelection.sizeOfSelect = pcrs / 8;
	   pcrInfoLong.releasePCRSelection.pcrSelect[index >> 3] |= (1 << (index & 0x7));

	   index_ctr += 1;

	   /*
	    * Update the PCR Composite structure.
	    */
	   pcrComp.select.sizeOfSelect = pcrs / 8;
	   pcrComp.select.pcrSelect[index >> 3] |= (1 << (index & 0x7));
	   pcrComp.pcrValue.size = index_ctr * TPM_HASH_SIZE;
	   pcrComp.pcrValue.buffer  = realloc(pcrComp.pcrValue.buffer,
					      pcrComp.pcrValue.size);
	   if (index >= 16) {
	       /* force usage of pcrInfoLong */
	       use_struct = PCR_INFO_LONG;
	   }

	   memcpy((char *)pcrComp.pcrValue.buffer + (index_ctr-1)*TPM_HASH_SIZE,
		  future_hash,
		  TPM_HASH_SIZE);
       }
       else if (!strcmp(argv[i], "-vlong")) {
	   use_struct = PCR_INFO_LONG;
       }
       else if (!strcmp(argv[i], "-vinfo")) {
	   use_struct = PCR_INFO;
       }
       else if (strcmp(argv[i],"-ok") == 0) {
	   i++;
	   if (i < argc) {
	       keyname = argv[i];
	   }
	   else {
	       printf("-ok option needs a value\n");
	       printUsage();
	   }
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
       else {
	   printf("\n%s is not a valid option\n", argv[i]);
	   printUsage();
       }
   }
   if (keyname == NULL) {
       printf("-ok missing\n");
       printUsage();
   }
   if (parhandle == 0) {
       printf("-hp missing\n");
       printUsage();
   }
   if (exponent > 0x00ffffff) {
       printf("-exp must be 0x00ffffff maximum\n");
   }
   /*
    * If indices and hashes were given, calculate the hash over the
    * PCR Composite structure.
    */
   if (0 != index_ctr) {
        pcrInfoLong.creationPCRSelection.sizeOfSelect = pcrs / 8;
        if ((use_oldversion && use_struct != PCR_INFO_LONG) || use_struct == PCR_INFO) {
            pcrComp.select.sizeOfSelect = 2;
            TPM_HashPCRComposite(&pcrComp, pcrInfoLong.digestAtRelease);
            /* must copy from the TPM_PCR_INFO_LONG structure into the
               TPM_PCR_INFO structure */
            pcrInfo.pcrSelection = pcrInfoLong.releasePCRSelection;
            pcrInfo.pcrSelection.sizeOfSelect = 2;
            memcpy(pcrInfo.digestAtRelease,
                   pcrInfoLong.digestAtRelease,
                   sizeof(pcrInfo.digestAtRelease));
            memcpy(pcrInfo.digestAtCreation,
                   pcrInfoLong.digestAtCreation,
                   sizeof(pcrInfo.digestAtCreation));
            ret = TPM_WritePCRInfo(&serPcrInfo, &pcrInfo);
            if ((ret & ERR_MASK)) {
                printf("Error while serializing PCRInfo.\n");
                exit(-1);
            }
            use_struct = PCR_INFO;
            if (verbose) {
                printf("Using TPM_PCR_INFO structure.\n");
            }
        } else {
            TPM_HashPCRComposite(&pcrComp, pcrInfoLong.digestAtRelease);
            ret = TPM_WritePCRInfoLong(&serPcrInfo, &pcrInfoLong);
            if ((ret & ERR_MASK)) {
                printf("Error while serializing PCRInfoLong.\n");
                exit(-1);
            }
            use_struct = PCR_INFO_LONG;
            if (verbose) {
                printf("Using TPM_PCR_INFO_LONG structure.\n");
            }
        }
        k.pub.pcrInfo.size = ret;
        memcpy(k.pub.pcrInfo.buffer, serPcrInfo.buffer, serPcrInfo.used);
   }
   /*
   ** use the SHA1 hash of the password string as the Parent Key Authorization Data
   */
   if (parpass != NULL) { 
      TSS_sha1((unsigned char *)parpass,
               strlen(parpass),hashpass1); 
               aptr1 = hashpass1; 
   }
               
   /*
   ** use the SHA1 hash of the password string as the Key Authorization Data
   */
   if (keypass != NULL) { TSS_sha1((unsigned char *)keypass,strlen(keypass),hashpass2); aptr2 = hashpass2; }
   /*
   ** use the SHA1 hash of the password string as the Key Migration Authorization Data
   */
   if (migpass != NULL) { TSS_sha1((unsigned char *)migpass,strlen(migpass),hashpass3); aptr3 = hashpass3; }
   /*
   ** initialize new key parameters
   */
   k.keyFlags = 0;
   if (migpass != NULL)
      k.keyFlags |= TPM_MIGRATABLE;    /* key flags - migratable */
   if (keypass != NULL)
      k.authDataUsage = 1;         /* key requires authorization (password) */
   else
      k.authDataUsage = 0;         /* key requires no authorization (password) */
   k.encData.size = 0;               /* no private key specified here */
   k.pub.algorithmParms.algorithmID = 0x00000001;   /* key algorithm 1 = RSA */
   if (keytype == 's')
      {
      k.keyUsage = TPM_KEY_SIGNING;                    /* key Usage - 0x0010 = signing */
      k.pub.algorithmParms.encScheme = TPM_ES_NONE;    /* encryption scheme 1 = NONE - signing key */
      k.pub.algorithmParms.sigScheme = TPM_SS_RSASSAPKCS1v15_SHA1;    /* signature scheme RSA/SHA1  */
      }
   else if (keytype == 'd')
      {
      k.keyUsage = TPM_KEY_SIGNING;                    /* key Usage - 0x0010 = signing */
      k.pub.algorithmParms.encScheme = TPM_ES_NONE;    /* encryption scheme 1 = NONE - signing key */
      k.pub.algorithmParms.sigScheme = TPM_SS_RSASSAPKCS1v15_DER;     /* signature scheme RSA/DER  */
      }
   else if (keytype == 'i')
      {
      k.keyUsage = TPM_KEY_SIGNING;                    /* key Usage - 0x0010 = signing */
      k.pub.algorithmParms.encScheme = TPM_ES_NONE;    /* encryption scheme 1 = NONE - signing key */
      k.pub.algorithmParms.sigScheme = TPM_SS_RSASSAPKCS1v15_INFO;    /* signature scheme RSA/INFO  */
      }
   else if (keytype == 'e')
      {
      k.keyUsage = TPM_KEY_STORAGE;                    /* key Usage - 0x0011 = encryption */
      k.pub.algorithmParms.encScheme = TPM_ES_RSAESOAEP_SHA1_MGF1;    /* encryption scheme 3 RSA */
      k.pub.algorithmParms.sigScheme = TPM_SS_NONE;    /* signature scheme NONE  */
      }
   else if (keytype == 'b')
      {
      k.keyUsage = TPM_KEY_BIND;                       /* key Usage - 0x0014 = bind */
      if (pkcsv15)
          k.pub.algorithmParms.encScheme = TPM_ES_RSAESPKCSv15;
      else
          k.pub.algorithmParms.encScheme = TPM_ES_RSAESOAEP_SHA1_MGF1;    /* encryption scheme 3 RSA */
      k.pub.algorithmParms.sigScheme = TPM_SS_NONE;                   /* signature scheme none */
      }
   else if (keytype == 'l')
      {
      k.keyUsage = TPM_KEY_LEGACY;                     /* key Usage - 0x0015 = legacy */
      if (pkcsv15)
          k.pub.algorithmParms.encScheme = TPM_ES_RSAESPKCSv15;
      else
          k.pub.algorithmParms.encScheme = TPM_ES_RSAESOAEP_SHA1_MGF1;    /* encryption scheme 3 RSA */
      k.pub.algorithmParms.sigScheme = TPM_SS_RSASSAPKCS1v15_SHA1;    /* signature scheme RSA/SHA1  */
      }
   else if (keytype == 'm')
      {
      k.keyUsage = TPM_KEY_MIGRATE;                    /* key Usage - 0x0016 = migration */
      k.pub.algorithmParms.encScheme = TPM_ES_RSAESOAEP_SHA1_MGF1;    /* encryption scheme 3 RSA */
      k.pub.algorithmParms.sigScheme = TPM_SS_NONE;                   /* signature scheme RSA/SHA1  */
      }
   else printUsage();
   k.pub.algorithmParms.u.rsaKeyParms.keyLength = keysize;      /* RSA modulus size 2048 bits */
   k.pub.algorithmParms.u.rsaKeyParms.numPrimes = 2;            /* required */
   if (exponent == 0) {
       k.pub.algorithmParms.u.rsaKeyParms.exponentSize = 0;       /* RSA exponent - default 0x010001 */
   }
   else {
       k.pub.algorithmParms.u.rsaKeyParms.exponentSize = 3;
       k.pub.algorithmParms.u.rsaKeyParms.exponent[2] = (exponent >> 16) & 0xff;
       k.pub.algorithmParms.u.rsaKeyParms.exponent[1] = (exponent >>  8) & 0xff;;
       k.pub.algorithmParms.u.rsaKeyParms.exponent[0] = (exponent >>  0) & 0xff;;
   }
   k.pub.pubKey.keyLength = 0;            /* key not specified here */

   if (use_oldversion == FALSE) {
       k.v.tag = TPM_TAG_KEY12;
   }

   /*
   ** create and wrap an asymmetric key and get back the
   ** resulting keydata structure with the public and encrypted
   ** private keys filled in by the TPM
   */
   ret =  TPM_CreateWrapKey(parhandle,aptr1,aptr2,aptr3,&k,&q,blob,&bloblen);
   if (ret != 0)
      {
      printf("Error %s from TPM_CreateWrapKey\n",TPM_GetErrMsg(ret));
      exit(ret);
      }
   
   /* verify the returned data structure 'q' */
   if (!use_oldversion) {
       if (q.v.tag != TPM_TAG_KEY12) {
           printf("Wrong key structure was returned.\n");
           exit(-1);
       }
       if (0 != index_ctr) {
           STACK_TPM_BUFFER(tmp);
           SET_TPM_BUFFER(&tmp, q.pub.pcrInfo.buffer, q.pub.pcrInfo.size);
           ret = TPM_ReadPCRInfoLong(&tmp, 0, &pcrInfoLong);
           if ((ret & ERR_MASK)) {
               printf("Error parsing the TPM_PCR_INFO_LONG struct.\n");
               exit(-1);
           }
           if (ret != tmp.used) {
               printf("Did not parse all the data in the serialized TPM_PCR_INFO_LONG.\n");
               exit(-1);
           }
       }
   } else {
       if (0 != index_ctr) {
           STACK_TPM_BUFFER(tmp);
           SET_TPM_BUFFER(&tmp, q.pub.pcrInfo.buffer, q.pub.pcrInfo.size);
           ret = TPM_ReadPCRInfo(&tmp, 0, &pcrInfo);
           if ((ret & ERR_MASK)) {
               printf("Error parsing the TPM_PCR_INFO struct.\n");
               exit(-1);
           }
           if (ret != tmp.used) {
               printf("Did not parse all the data in the serialized TPM_PCR_INFO.\n");
               exit(-1);
           }
       }
   }
  
   sprintf(filename,"%s.key",keyname);
   blbfile = fopen(filename,"wb");
   if (blbfile == NULL)
      {
      printf("Unable to create key file %s.\n",filename);
      exit(-1);
      }
   ret = fwrite(blob,1,bloblen,blbfile);
   if (ret != bloblen)
      {
      printf("I/O Error writing key file\n");
      exit(-1);
      }
   fclose(blbfile);
   /*
   ** convert the returned public key to OpenSSL format and
   ** export it to a file
   */
   rsa = TSS_convpubkey(&(q.pub));
   if (rsa == NULL)
      {
      printf("Error from TSS_convpubkey\n");
      exit(-1);
      }
   OpenSSL_add_all_algorithms();
   pkey = EVP_PKEY_new();
   if (pkey == NULL) {
       printf("Unable to create EVP_PKEY\n");
       exit(-4);
   }
   ret = EVP_PKEY_assign_RSA(pkey,rsa);
   if (ret == 0) {
       printf("Unable to assign public key to EVP_PKEY\n");
       exit(-5);
   }
   sprintf(filename,"%s.pem",keyname);
   keyfile = fopen(filename,"wb");
   if (keyfile == NULL)
      {
      printf("Unable to create public key file\n");
      exit(-6);
      }
   ret = PEM_write_PUBKEY(keyfile,pkey);
   if (ret == 0)
      {
      printf("I/O Error writing public key file\n");
      exit(-7);
      }
   fclose(keyfile);
   EVP_PKEY_free(pkey);
   exit(0);
   }

   

static void printUsage(void)
{
   printf(
              "Usage: createkey [<options>] -ok <keyname> -hp <pkeyhandle>\n"
              "\n"
              "   Where the arguments are...\n"
              "    <keyname>    is the new key file name (.key and .pem appended)\n"
              "    <pkeyhandle> is the parent key handle in hex\n"
              "\n"
              "The SRK handle is 40000000\n"
              "\n"
              "   Where the <options> are...\n"
              "    -kt s/d/i| e | b | l | m  keytype is s for signing (default)\n"
	      "                                        d for signing using DER\n"
              "                                        i for signing using INFO sig. scheme\n"
              "                                        e for encryption(storage)\n"
              "                                        b for binding, l for legacy\n"
              "                                        m for migration\n"
              "    -pwdp <parpass>   to specify parent key use password\n"
              "    -pwdk <keypass>   to specify new key use password\n"
              "    -pwdm <migpass>   to specify new key is migratable, and specify migration password\n"
              "    -sz <keysize>     to specify the size of key to create; default is 2048\n"
	      "    -exp <exponent>   to specify the public exponent, default is 65537\n"
              "    -v                to specify verbose output\n"
              "    -v1               use TPM_KEY instead of TPM_KEY12\n"
              "    -es pkcsv15       create a key that uses PKCSv15 encryption scheme\n"
              "    -ix <pcr num> <digest>    used to wrap a key to values of PCRs\n"
              "    -vlong, -vinfo    force usage of PCR_INFO_LONG or PCR_INFO structure\n"
              "    -h                print usage information (this message)\n");
   exit(1);
}
