/********************************************************************************/
/*										*/
/*			    TCPA Identity    					*/
/*			     Written by Stefan Berger				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*	      $Id: identity.c 4702 2013-01-03 21:26:29Z kgoldman $		*/
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

#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include "tpm.h"
#include "tpmutil.h"
#include "tpmfunc.h"
#include "tpm_constants.h"
#include "tpm_structures.h"
#include "tpm_error.h"
#include "tpmkeys.h"
#include "newserialize.h"


static void usage() {
	printf("Usage: encaik -ik <keyblob> -ek <pubek> -ok <outputblob> [-oak <keyname>]\n");
	printf("\n");
	printf(" -ik <keydata>  : The public key(.pem) from identity\n");
	printf(" -ek <pubek>    : The public EK of the TPM\n");
	printf(" -ok <keyname>  : Output blob file name\n");
	printf(" -oak <keyname> : Output AES key file name\n");
	printf(" -ekb           : Use a TPM_EK_BLOB for activation instead of TPM_ASYM_CA_CONTENTS.\n");
	printf(" -v             : verbose\n");
	printf("\n");
	exit(-1);
}

static uint32_t encryptBlob(unsigned char *blobbuf,
							 uint32_t blobbuflen,
							 RSA *rsa, int verbose, char *outputkeyname);
							 
uint32_t TPM_WriteKeyPubOnly(struct tpm_buffer *buffer, pubkeydata * k);

void printhash(void *ptr, unsigned int len, char *name);							 
void printhash(void *ptr, unsigned int len, char *name) {
	unsigned char hash[20];
		TSS_sha1((unsigned char *)ptr,
		 len,
		 hash);	
			printf("hash of %s (len %d): ",name,len);
		unsigned int i =0;
		for(i=0;i<20;i++) {
			printf("%X ",0xFF & hash[i]);
		}
		printf("\n");
}

void printbuf(void *ptr, unsigned int len, char *name);
void printbuf(void *ptr, unsigned int len, char *name) {
			printf("%s (len %d): ",name,len);
		unsigned int i =0;
		for(i=0;i<len;i++) {
			printf("%X ",0xFF & ((unsigned char*)ptr)[i]);
		}
		printf("\n");
}

int main(int argc, char * argv[])
{
    uint32_t ret = 0;
    int i =	0;
    pubkeydata pubidkey;
    FILE *keyfile;                  /* output file for key token */
    RSA *ek_rsa;                    /* OpenSSL format Public EK */
    RSA *aik_rsa;                   /* OpenSSL format Public EK */
    EVP_PKEY *pkey = NULL;          /* OpenSSL public key */
    char *keyname = NULL;           /* pointer to key name argument */
    char *outputkeyname = NULL;     /* pointer to output blob name */
    char *outputaeskeyname = NULL;  /* pointer to the output AES key name */
    char *pubekname = NULL;         /* pointer to the name of the ek file */
	int verbose = FALSE;
    int use_ca = TRUE;
    unsigned char *blobbuf = NULL;
    uint32_t blobbuflen=0;
	
	/*
	 * An random symmetric key
	 */
	unsigned char symkey[32];
	
    i = 1;
	
    TPM_setlog(0);
	
    for (i=1 ; i<argc ; i++) {
	if (!strcmp("-ok",argv[i])) {
	    i++;
	    if (i < argc) {
		outputkeyname = argv[i];
	    }
	    else {
		printf("Missing parameter for -ok\n");
		usage();
	    }
	}
	else if (!strcmp("-ik",argv[i])) {
	    i++;
	    if (i < argc) {
		keyname = argv[i];
	    }
	    else {
		printf("Missing parameter for -ik\n");
		usage();
	    }
	}
	else if (!strcmp("-ek",argv[i])) {
	    i++;
	    if (i < argc) {
		pubekname = argv[i];
	    }
	    else {
		printf("Missing parameter for -ik\n");
		usage();
	    }
	}
	else if (!strcmp("-oak",argv[i])) {
	    i++;
	    if (i < argc) {
		outputaeskeyname = argv[i];
	    }
	    else {
		printf("Missing parameter for -oak\n");
		usage();
	    }
	}
	else if (!strcmp("-v",argv[i])) {
	    TPM_setlog(1);
	    verbose = TRUE;
	}
	else if (!strcmp("-ekb",argv[i])) {
	    use_ca = FALSE;
	}
	else if (!strcmp("-h",argv[i])) {
	    usage();
	}
	else {
	    printf("\n%s is not a valid option\n", argv[i]);
	    usage();
	}
    }

    if ((keyname == NULL) || (outputkeyname == NULL)) {
	printf("\nMissing keyname\n");
	usage();
    }
    if (pubekname == NULL) {
	printf("\nMissing public EK\n");
	usage();
    }
    
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
	aik_rsa = EVP_PKEY_get1_RSA(pkey);
	if (aik_rsa == NULL)
	  {
	  printf("Error while converting public key \n");
	  exit(8);
	  }
	  
	// now convert the rsa key to a TPM pubkeydata  
	TSS_convrsakey(aik_rsa,&pubidkey);
    
    /* generate the symmetric key */
    if (!RAND_bytes(symkey,sizeof(symkey))) {
		printf("Error creating random symmetric key\n");
		exit(6);
	}
	if (outputaeskeyname != NULL) {
		/* now write out the AES key that we used */
		keyfile = fopen(outputaeskeyname, "wb");
		if (keyfile == NULL) {
			printf("Unable to create key file %s.\n", outputaeskeyname);
			exit(-1);
		}
		ret = fwrite(symkey, 1, sizeof(symkey), keyfile);
		if (ret != sizeof(symkey)) {
			printf("I/O Error writing key file %s\n", outputaeskeyname);
			exit(-1);
		}
		fclose(keyfile);
	}
    
    if (use_ca) {
	STACK_TPM_BUFFER(buffer)
	uint32_t serkeylen;
	uint32_t sercacontlen;
	TPM_ASYM_CA_CONTENTS data;
	TPM_SYMMETRIC_KEY tpm_symkey;
	STACK_TPM_BUFFER(ser_symkey_buf)
	uint32_t ser_symkey_len;
	uint32_t ret = 0;
	/*
	 * Need to build the symmetric key structure,
	 * serialize it and attach it to data.buffer of 'data'.
	 */
	tpm_symkey.algId       = TPM_ALG_AES256;
	tpm_symkey.encScheme   = TPM_ES_SYM_CTR;
	tpm_symkey.size        = sizeof(symkey);
	tpm_symkey.data        = symkey;
	
	ser_symkey_len = TPM_WriteSymmetricKey(&ser_symkey_buf, &tpm_symkey);	
	if (ser_symkey_len & ERR_MASK) {
		return ret;
	}

	memset(&data,0x0,sizeof(data));
	// symmetric key
	data.sessionKey =  tpm_symkey;
	/*
	 * Need to calculate the digest of the public key part in 
	 * idKey as returned by MakeIdentity
	 * First serialize the key, then sha it
	 */
	ret = TPM_WriteKeyPubOnly(&buffer,&pubidkey);
	if (ret & ERR_MASK) {
		printf("Error while serializing key!\n");
		return ret;
	}
	
	serkeylen = ret;
	
	TSS_sha1(buffer.buffer,serkeylen,data.idDigest);
	
	/*
	 * Need to serialize the 'data' structure
	 * and encrypt it using the public EK.
	 */
	RESET_TPM_BUFFER(&buffer);
	ret = TPM_WriteCAContents(&buffer, &data);
	if (ret & ERR_MASK) {
		printf("Error while serializing CA Contents.\n");
		return ret;
	}
	sercacontlen = ret;
	
	blobbuf = buffer.buffer;
	blobbuflen = sercacontlen;
	
	}
	else {
	TPM_EK_BLOB ekblob;
	TPM_EK_BLOB_ACTIVATE activate;
	TPM_SYMMETRIC_KEY tpm_symkey;
	STACK_TPM_BUFFER( ser_symkey_buf )
	uint32_t ser_symkey_len;
	uint32_t serkeylen;
	STACK_TPM_BUFFER( buffer )
	STACK_TPM_BUFFER( ek_actblob )
	uint32_t ek_actblobsize = 0;
	STACK_TPM_BUFFER(ek_blobbuf)
	uint32_t ek_blobbufsize = 0;

	uint32_t ret = 0;
	uint32_t pcrs = TPM_NUM_PCR;

	memset(&activate, 0x0, sizeof(activate));
	
	/*
	 * Need to build the symmetric key structure,
	 * serialize it and attach it to data.buffer of 'data'.
	 */
	tpm_symkey.algId       = TPM_ALG_AES256;
	tpm_symkey.encScheme   = TPM_ES_SYM_CTR;
	tpm_symkey.size        = sizeof(symkey);
	tpm_symkey.data        = symkey;

	ser_symkey_len = TPM_WriteSymmetricKey(&ser_symkey_buf, &tpm_symkey);
	if (ser_symkey_len & ERR_MASK) {
		return ret;
	}


	activate.tag  = TPM_TAG_EK_BLOB_ACTIVATE;
	activate.sessionKey = tpm_symkey;

	ret = TPM_WriteKeyPubOnly(&buffer,&pubidkey);
	if (ret & ERR_MASK) {
		return ret;
	}
	serkeylen = ret;
	TSS_sha1(buffer.buffer,serkeylen,activate.idDigest);

	activate.pcrInfo.pcrSelection.sizeOfSelect = pcrs / 8;
	activate.pcrInfo.localityAtRelease = TPM_LOC_ZERO;

	ret = TPM_WriteEkBlobActivate(&ek_actblob,&activate);

	if (ret & ERR_MASK) {
		return ret;
	}
  
	ek_actblobsize = ret;

	ekblob.tag    = TPM_TAG_EK_BLOB;
	ekblob.ekType = TPM_EK_TYPE_ACTIVATE;
	ekblob.blob.size   = ek_actblobsize;
	ekblob.blob.buffer = ek_actblob.buffer;

	ret = TPM_WriteEkBlob(&ek_blobbuf, &ekblob);
	if (ret & ERR_MASK) {
		return ret;
	}
  
	ek_blobbufsize = ret;
	
	blobbuf = ek_blobbuf.buffer;
	blobbuflen = ek_blobbufsize;
	}
	
	//==========================
	
	/*
	** read the public EK
	*/
	keyfile = fopen(pubekname,"rb");
	if (keyfile == NULL)
	  {
	  printf("Unable to open public EK file '%s'\n",pubekname);
	  exit(6);
	  }
	pkey = PEM_read_PUBKEY(keyfile,NULL,NULL,NULL);
	fclose(keyfile);
	if (pkey == NULL)
	  {
	  printf("I/O Error while reading public EK file '%s'\n",pubekname);
	  exit(7);
	  }
	ek_rsa = EVP_PKEY_get1_RSA(pkey);
	if (ek_rsa == NULL)
	  {
	  printf("Error while converting public key \n");
	  exit(8);
	  }
    

	return encryptBlob(blobbuf,blobbuflen,ek_rsa,verbose,outputkeyname);
	
}



static uint32_t encryptBlob(unsigned char *blobbuf,
							 uint32_t blobbuflen,
							 RSA *rsa, int verbose, char *outputkeyname) {
	unsigned char out_blob[2048];
	uint32_t blobsize;
	unsigned char * blob;
	STACK_TPM_BUFFER(returnbuffer)
	unsigned char tpm_oaep_pad_str[] = { 'T' , 'C' , 'P' , 'A' };
	uint32_t ret = 0;
    unsigned int i =	0;
    FILE *keyfile;                  /* output file for key token */

	blobsize = RSA_size(rsa);
	blob = malloc(blobsize);
	
	if(verbose) {
		printhash(blobbuf,blobbuflen,"pre-pad-blob");
		printhash(tpm_oaep_pad_str,sizeof(tpm_oaep_pad_str),"tpm oaep");
	}

	/*
	 * Add some padding to the data that need to
	 * be encrypted.
	 */
	ret = RSA_padding_add_PKCS1_OAEP(blob,
									 blobsize,
									 blobbuf,
									 blobbuflen,
									 tpm_oaep_pad_str,
									 sizeof(tpm_oaep_pad_str));

	if (0 == ret) {
		printf("Error while adding padding.\n");
		exit(-1);
	}

	if(verbose) {
	printhash(blob,blobsize,"pre-enc-blob");
	//RSA_print_fp(stdout,rsa,0);
	printf("padded blob PRE-ENC: ");
	for(i=0;i<blobbuflen;i++) {
		printf("%X ",0xFF & ((unsigned char*)blobbuf)[i]);
	}
	printf("\n");
	}
	
	ret = RSA_public_encrypt(blobsize, 
							 blob,
							 out_blob, 
							 rsa,
							 RSA_NO_PADDING);

	if (ret != blobsize) {
		printf("Something went wrong while encoding with public key!!! ret(%d)!=blobsize(%d)\n",
			   ret,
			   blobsize);
		exit(-1);
	}
	
	// now write out the final blob for passing into activeidentity
	keyfile = fopen(outputkeyname, "wb");
	if (keyfile == NULL) {
	    printf("Unable to create key file %s.\n", outputkeyname);
	    exit(-1);
	}
	ret = fwrite(out_blob, 1, blobsize, keyfile);
	if (ret != blobsize) {
	    printf("I/O Error writing key file %s\n", outputkeyname);
	    exit(-1);
	}
	fclose(keyfile);
	return 0;
}

uint32_t TPM_WriteKeyPubOnly(struct tpm_buffer *buffer, pubkeydata * k)
{
	uint32_t ret = -1;
	switch (k->algorithmParms.algorithmID) {
		case TPM_ALG_RSA:
			ret = TSS_buildbuff(FORMAT_TPM_PUBKEY_EMB_RSA, buffer,
			                    PARAMS_TPM_PUBKEY_EMB_RSA_W(k));
		break;
		
		case TPM_ALG_AES128:
		case TPM_ALG_AES192:
		case TPM_ALG_AES256:
			ret = TSS_buildbuff(FORMAT_TPM_PUBKEY_EMB_SYM, buffer,
			                    PARAMS_TPM_PUBKEY_EMB_SYM_W(k));
		break;
		
		default:
			ret = ERR_BAD_ARG;
		break;
	}
	return ret;
}






