/********************************************************************************/
/*										*/
/*			     	TPM Test of TPM DeepQuote			*/
/*			     Written by J. Kravitz, S. Berger			*/
/*		       IBM Thomas J. Watson Research Center			*/
/*	      $Id: quote.c 4702 2013-01-03 21:26:29Z kgoldman $			*/
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
#include <unistd.h>
#include <string.h>
#ifdef TPM_POSIX
#include <netinet/in.h>
#endif
#ifdef TPM_WINDOWS
#include <winsock2.h>
#endif
#include "tpmfunc.h"
#include "deepquote.h"
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

static int printUsage()
{
    printf("Usage: checkdeepquote\n"
	   "-aik <keyfile provided by vTPM manager (pem)>\n"
	   "-vaik <keyfile of the associated vTPM quote>\n"
	   "-deepquote <deepquote.bin>\n"
	   "-nonce <random value>\n"
	   "[-repeat <number of iterations>]\n");
    exit(-1);
    return -1;
}

int main(int argc, char *argv[])
{
    int i;
    int ret;	
    unsigned char vq_nonce[TPM_NONCE_SIZE]; 
    unsigned char dq_nonce[TPM_NONCE_SIZE]; 
    const char *keyname = NULL;
    const char *vkeyname = NULL;
    const char *binpath = NULL;
    char *nonceval = NULL;      
    EVP_PKEY *pkey = NULL;          /* OpenSSL public key */  
    RSA *rsa = NULL;
    EVP_PKEY *vpkey = NULL;          /* OpenSSL public key */  
    RSA *vrsa = NULL;
	FILE *keyfile = NULL; 
	FILE *fp;   
	struct DeepQuoteBin dqb;
   	unsigned int numhPCRs=0;
   	unsigned int numvPCRs=0;
    STACK_TPM_BUFFER(signature);
    TPM_PCR_COMPOSITE tpc;
	SHA_CTX sha;
	int verified = 0;
	unsigned int repeat = 1;
    
    TPM_setlog(0);		/* turn off verbose output from TPM driver */
    for (i=1 ; i<argc ; i++) {
	if (!strcmp(argv[i], "-aik")) {
	    i++;
	    if (i < argc) {
		keyname = argv[i];
	    }
	    else {
		printf("Missing parameter to -aik\n");
		printUsage();
	    }
	}
	else if (!strcmp(argv[i], "-vaik")) {
	    i++;
	    if (i < argc) {
		vkeyname = argv[i];
	    }
	    else {
		printf("Missing parameter to -vaik\n");
		printUsage();
	    }
	}
	else if (!strcmp(argv[i], "-deepquote")) {
	    i++;
	    if (i < argc) {
		binpath = argv[i];
	    }
	    else {
		printf("Missing parameter to -quote\n");
		printUsage();
	    }
	}
	else if (!strcmp(argv[i],"-nonce")) {
	    i++;
	    if (i < argc) {
		nonceval = argv[i];
	    }
	    else {
		printf("Missing parameter to -nonce\n");
		printUsage();
	    }
	}
    else if (!strcmp(argv[i],"-repeat")) {
        i++;
        if (i < argc) {
        repeat = atoi(argv[i]);
        }
        else {
        printf("Missing parameter to -repeat\n");
        return printUsage();
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

    CHECK_ARG(keyname,  "-aik");
    CHECK_ARG(vkeyname, "-vaik");
    CHECK_ARG(nonceval, "-nonce");
    CHECK_ARG(binpath,  "-deepquote");


    /*  hash nonceval to create nonce data */
    TSS_sha1((unsigned char *)nonceval,strlen(nonceval),vq_nonce);

	/*
	** read the public AIK
	*/
	keyfile = fopen(keyname,"rb");
	if (keyfile == NULL)
	  {
	  printf("Unable to open public aik file '%s'\n",keyname);
	  exit(6);
	  }
	pkey = PEM_read_PUBKEY(keyfile,NULL,NULL,NULL);
	fclose(keyfile);
	if (pkey == NULL)
	  {
	  printf("I/O Error while reading public aik file '%s'\n",keyname);
	  exit(7);
	  }

	if (binpath == NULL) {
		fprintf(stderr, "Path to DeepQuoteBin cannot be NULL\n");
		return 1;
	}
	if ((fp = fopen(binpath, "rb")) == 0) {
		fprintf(stderr, "Failed to open '%s'\n", binpath);
		return 1;
	}

	if (fread(&dqb, sizeof(dqb), 1, fp) != 1) {
		fprintf(stderr, "Failed to read in DeepQuoteBin");
		return 1;
	}
    if(fread(&signature,sizeof(uint32_t),3,fp)<3) {
    printf("Error reading signature header.\n");
    exit(-1);
    }
    if(signature.used>sizeof(signature.buffer)) {
    printf("Error invalid signature: bytes used %u is larger than the buffer %lu.\n",signature.used,sizeof(signature.buffer));
    exit(-1);
    }
    if(fread(&signature.buffer,sizeof(char),signature.used,fp)<signature.used) {
    printf("Error read signature data.\n");
    exit(-1);
    }
    if(fread(&tpc,sizeof(TPM_PCR_COMPOSITE),1,fp)<1) {
    printf("Error reading PCR composite.\n");
    exit(-1);
    }
    if((tpc.pcrValue.buffer=(BYTE*)malloc(sizeof(BYTE)*tpc.pcrValue.size))==NULL) {
    printf("unable to allocate memory for PCR buffer.\n");
    exit(-1);
    }
	if(fread(tpc.pcrValue.buffer,sizeof(BYTE),tpc.pcrValue.size,fp)<tpc.pcrValue.size) {
    printf("Error reading PCR value.\n");
    exit(-1);
    }
    fclose(fp);

   /*
   ** read the virtual public AIK file
   */
   keyfile = fopen(vkeyname,"rb");
   if (keyfile == NULL)
      {
	  printf("Unable to open virtual public key file '%s'\n",vkeyname);
	  exit(6);
      }
   vpkey = PEM_read_PUBKEY(keyfile,NULL,NULL,NULL);
   if (pkey == NULL)
      {
	  printf("I/O Error while reading virtual public key file '%s'\n",vkeyname);
	  exit(7);
      }
    fclose(keyfile);
    
    
    unsigned int j =0;
    for(j=0;j<repeat;j++) {
    
	rsa = EVP_PKEY_get1_RSA(pkey);
	if (rsa == NULL)
	  {
	  printf("Error while converting public key \n");
	  exit(8);
	  }
    
       vrsa = EVP_PKEY_get1_RSA(vpkey);
   if (vrsa == NULL)
      {
      printf("Error while converting virtual public key \n");
      exit(8);
      }

    /* now verify the vTPM quote */

    ret = TPM_ValidatePCRCompositeSignatureNoCap(&tpc,
					    vq_nonce,
					    vrsa,
					    &signature,
					    TPM_SS_RSASSAPKCS1v15_SHA1);
    if (ret) {
	fprintf(stderr, "Error %s from validating the signature over the vPCR composite.\n",
	       TPM_GetErrMsg(ret));
    } 
    else {
    	verified++;
    }

    /* at this point the vTPM quote is valid */
    /* take the quote sig and TPC and hash them into the nonce for the deepquote */
	SHA1_Init(&sha);
	SHA1_Update(&sha, vq_nonce,     TPM_NONCE_SIZE);
	SHA1_Update(&sha, &signature,  sizeof(signature));
	SHA1_Update(&sha, &tpc.select,  sizeof(TPM_PCR_SELECTION));
	SHA1_Update(&sha, tpc.pcrValue.buffer, tpc.pcrValue.size);
	SHA1_Final(dq_nonce, &sha);


	TPM_PCR_SELECTION htps;
			
	htps.sizeOfSelect = ntohs(dqb.ppcrSel.sizeOfSelect);
	memcpy(htps.pcrSelect, dqb.ppcrSel.pcrSelect, htps.sizeOfSelect);

    if ((ret = TPM_ValidateDeepQuoteInfo(rsa,
					 &htps,
					 dq_nonce,
					 &dqb.dqi)) != 0) {
	fprintf(stderr, "Error %s from validating the signature over the PCR composite.\n",
	       TPM_GetErrMsg(ret));
    }
    else {
    	verified++;
    }
    
    }
    
    if (verified >= 2) {
    fprintf(stdout, "Verification against AIK succeeded\n");
	}	

    fprintf(stdout, "PCR contents from quote:\n");
    for(i=0;i<ntohs(dqb.ppcrSel.sizeOfSelect*CHAR_BIT);i++) {
	    if((dqb.ppcrSel.pcrSelect[i/8] & (1<<(i&0x7)))>0) {
		    unsigned int j=0;
		    if(TPM_HASH_SIZE*(numhPCRs+1)>sizeof(dqb.dqi.values.PCRVals)) {
			    fprintf(stdout, "Error: malformed PCR structure\n");
			    exit(-1);
		    }
		    fprintf(stdout, "PCR %.2d ",i);
		    for(j=0;j<TPM_HASH_SIZE;j++) {
			    fprintf(stdout, "%.2x",dqb.dqi.values.PCRVals[TPM_HASH_SIZE*numhPCRs+j]);
		    }
		    fprintf(stdout, "\n");
		    numhPCRs++;
	    }
    }
    
    fprintf(stdout, "PCR contents from vTPM quote:\n");
    for(i=0;i<tpc.select.sizeOfSelect*CHAR_BIT;i++) {
	    if((tpc.select.pcrSelect[i/8] & (1<<(i&0x7)))>0) {
		    unsigned int j=0;
		    /* check tpc.pcrValue.size */
		    if(TPM_HASH_SIZE*(numvPCRs+1)>tpc.pcrValue.size) {
			    fprintf(stdout, "Error: malformed vPCR structure\n");
			    exit(-1);
		    }
		    fprintf(stdout, "vPCR %.2d ",i);
		    for(j=0;j<TPM_HASH_SIZE;j++) {
			    fprintf(stdout, "%.2x",tpc.pcrValue.buffer[TPM_HASH_SIZE*numvPCRs+j]);
		    }
		    fprintf(stdout, "\n");
		    numvPCRs++;
	    }
    }


    free(tpc.pcrValue.buffer);
    if(verified < 2)
    	return -1;
    else
    	return 0;
}
