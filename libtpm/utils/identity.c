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

#include "tpm.h"
#include "tpmutil.h"
#include "tpmfunc.h"
#include "tpm_constants.h"
#include "tpm_structures.h"
#include "tpm_error.h"

/* local prototypes */
static RSA * getpubek(unsigned char * passhash) ;
static uint32_t do_ca_contents(unsigned char * ownerAuth,
                               keydata * idkey,
                               uint32_t  newhandle,
                               unsigned char * usageptr);
uint32_t do_ek_blob(unsigned char * ownerAuth,
                    keydata * idkey,
                    uint32_t newhandle,
                    unsigned char * usageptr);
static uint32_t do_activateIdentity(unsigned char * ownerAuth,
                               unsigned char * usageptr,
                               unsigned char * blobbuf, uint32_t blobbufsize,
                               uint32_t newhandle);

static void usage() {
	printf("Usage: identity -la <label> [options]\n"
	       "   [-pwdo <owner password> -pwdof <owner authorization file name>\n");
	printf("\n");
	printf(" -la label    : Some label for the identity.\n");
	printf(" -pwdk idpwd  : A password for the identity.\n");
	printf(" -pwds srkpwd : The password for the storage root key.\n");
	printf(" -sz <keysize>     to specify the size of key to create; default is 2048, others illegal\n");
	printf(" -exp <exponent>   to specify the public exponent, default is 65537 others illegal\n");
	printf(" -ac          : To activate the identity after generating it.\n");
	printf(" -ekb         : Use a TPM_EK_BLOB for activation instead of TPM_ASYM_CA_CONTENTS.\n");
	printf(" -v12         : Use version 1.2 key structure\n");
	printf(" -ok <keyname>: Key file name (.key and .pem appended)\n");
	printf("\n");
	printf("Examples:\n");
	exit(-1);
}

int main(int argc, char * argv[])
{
    char * ownerPassword = NULL;
    const char *ownerAuthFilename = NULL;
    char * usagepass = NULL;
    char * label = NULL;
    char * srkpass = NULL;  
    unsigned char * usageptr = NULL;
    unsigned char * srkhashptr = NULL;
    unsigned char ownerAuth[20];
    unsigned char srkhash[20];
    unsigned char labelhash[20];	
    unsigned char usagehash[20];	
    uint32_t ret;
    int i =	0;
    uint32_t idbindingbuffersize = 1024;
    unsigned char idbindingbuffer[idbindingbuffersize];    	
    keydata keyparms;
    keydata idkey;
    char filename[256];             /* file name string of key file */
    FILE *keyfile;                  /* output file for key token */
    FILE *pubkeyfile;               /* output file for public key token */
    RSA *rsa;                       /* OpenSSL format Public Key */
    EVP_PKEY *pkey = NULL;          /* OpenSSL public key */
    unsigned char idkeyblob[4096];  /* area to hold key blob */
    unsigned int  idkeybloblen;     /* key blob length */
    char *keyname = NULL;           /* pointer to key name argument */
    int activate = FALSE;
    int use_ca = TRUE;
    TPM_BOOL v12 = FALSE;
    unsigned int keysize = 2048;	/* key size default */
    uint32_t exponent = 0;		/* public exponent default */

    memset(&keyparms, 0x0, sizeof(keyparms));
    memset(&idkey   , 0x0, sizeof(idkey));
	
    i = 1;
	
    TPM_setlog(0);
	
    for (i=1 ; i<argc ; i++) {
	if (!strcmp("-pwdo",argv[i])) {
	    i++;
	    if (i < argc) {
		ownerPassword = argv[i];
	    } else {
		printf("Missing parameter for -pwdo.\n");
		usage();
	    }
	}
	else if (strcmp(argv[i],"-pwdof") == 0) {
	    i++;
	    if (i < argc) {
		ownerAuthFilename = argv[i];
	    }
	    else {
		printf("-pwdof option needs a value\n");
		usage();
	    }
	}
	else if (!strcmp("-pwdk",argv[i])) {
	    i++;
	    if (i < argc) {
		usagepass = argv[i];
	    } else {
		printf("Missing parameter for -pwdk.\n");
		usage();
	    }
	}
	else if (!strcmp("-pwds",argv[i])) {
	    i++;
	    if (i < argc) {
		srkpass = argv[i];
	    } else {
		printf("Missing parameter for -pwds.\n");
		usage();
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
		usage();
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
		usage();
	    }
	}
	else if (!strcmp("-la",argv[i])) {
	    i++;
	    if (i < argc) {
		label = argv[i];
	    } else {
		printf("Missing parameter for -la.\n");
		usage();
	    }
	}
	else if (!strcmp("-ac",argv[i])) {
	    activate = TRUE;
	}
	else if (!strcmp("-ekb",argv[i])) {
	    use_ca = FALSE;
	}
	else if (!strcmp("-v12",argv[i])) {
	    v12 = TRUE;
	}
	else if (!strcmp("-ok",argv[i])) {
	    i++;
	    if (i < argc) {
		keyname = argv[i];
	    }
	    else {
		printf("Missing parameter for -ok\n");
		usage();
	    }
	}
	else if (!strcmp("-v",argv[i])) {
	    TPM_setlog(1);
	}
	else if (!strcmp("-h",argv[i])) {
	    usage();
	}
	else {
	    printf("\n%s is not a valid option\n", argv[i]);
	    usage();
	}
    }

    if ((ownerPassword == NULL) && (ownerAuthFilename == NULL)) {
	printf("\nMissing -pwdo or -pwdof argument\n");
	usage();
    }
    if ((ownerPassword != NULL) && (ownerAuthFilename != NULL)) {
	printf("\nCannot have -pwdo and -pwdof arguments\n");
	usage();
    }
    if (NULL == label) {
	printf("Missing label.\n");
	usage();
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

    if (NULL != srkpass) {
	TSS_sha1(srkpass,strlen(srkpass),srkhash);
	srkhashptr = srkhash;
    } else {
	srkhashptr = NULL;
    }

    if (NULL != usagepass) {
	TSS_sha1(usagepass,strlen(usagepass),usagehash);
	usageptr = usagehash;
    } else {
	usageptr = NULL;
    }

    if (exponent > 0x00ffffff) {
	printf("-exp must be 0x00ffffff maximum\n");
    }
	
    if (NULL != label) {
	TSS_sha1(label,strlen(label),labelhash);
    }

    if (FALSE == v12) {
	keyparms.v.ver.major = 1;
	keyparms.v.ver.minor = 1;
    } else {
	keyparms.v.tag = TPM_TAG_KEY12;
    }
    keyparms.keyUsage      = TPM_KEY_IDENTITY;
    keyparms.pub.algorithmParms.algorithmID = TPM_ALG_RSA;
    keyparms.pub.algorithmParms.u.rsaKeyParms.keyLength = keysize;
    keyparms.pub.algorithmParms.u.rsaKeyParms.numPrimes = 2;
    if (exponent == 0) {
	keyparms.pub.algorithmParms.u.rsaKeyParms.exponentSize = 0;       /* RSA exponent - default 0x010001 */
    }
    else {
	keyparms.pub.algorithmParms.u.rsaKeyParms.exponentSize = 3;
	keyparms.pub.algorithmParms.u.rsaKeyParms.exponent[2] = (exponent >> 16) & 0xff;
	keyparms.pub.algorithmParms.u.rsaKeyParms.exponent[1] = (exponent >>  8) & 0xff;;
	keyparms.pub.algorithmParms.u.rsaKeyParms.exponent[0] = (exponent >>  0) & 0xff;;
    }
    keyparms.pub.algorithmParms.encScheme = TPM_ES_NONE;
    keyparms.pub.algorithmParms.sigScheme = TPM_SS_RSASSAPKCS1v15_SHA1;
    if (usagepass) {
	keyparms.authDataUsage = TPM_AUTH_ALWAYS;
    } else {
	keyparms.authDataUsage = TPM_AUTH_NEVER;
    }
	
    ret = TPM_MakeIdentity(usageptr,
			   labelhash,
			   &keyparms,
			   &idkey,
			   idkeyblob,
			   &idkeybloblen,
			   srkhashptr,
			   ownerAuth,
			   idbindingbuffer,
			   &idbindingbuffersize);

    if (0 != ret) {
	printf("MakeIdentity returned error '%s' (%d).\n",
	       TPM_GetErrMsg(ret),
	       ret);
	exit(ret);
    }

    if (TRUE == v12) {
	if (idkey.v.tag != TPM_TAG_KEY12) {
	    printf("MakeIdentity returned a wrong key structure! Expected TPM_KEY12\n");
	    exit(-1);
	}
    }
    /* optionally save the key token and public key */
    if (keyname != NULL) {
	/* key token */
	sprintf(filename, "%s.key", keyname);
	keyfile = fopen(filename, "wb");
	if (keyfile == NULL) {
	    printf("Unable to create key file %s.\n", filename);
	    exit(-1);
	}
	ret = fwrite(idkeyblob, 1, idkeybloblen, keyfile);
	if (ret != idkeybloblen) {
	    printf("I/O Error writing key file %s\n", filename);
	    exit(-1);
	}
	fclose(keyfile);
	/*
	** convert the returned public key to OpenSSL format and
	** export it to a file
	*/
	rsa = TSS_convpubkey(&(idkey.pub));
	if (rsa == NULL) {
	    printf("Error from TSS_convpubkey\n");
	    exit(-1);
	}
	OpenSSL_add_all_algorithms();
	pkey = EVP_PKEY_new();
	if (pkey == NULL) {
	    printf("Unable to create EVP_PKEY\n");
	    exit(-4);
	}
	ret = EVP_PKEY_assign_RSA(pkey, rsa);
	if (ret == 0) {
	    printf("Unable to assign public key to EVP_PKEY\n");
	    exit(-5);
	}
	sprintf(filename, "%s.pem", keyname);
	pubkeyfile = fopen(filename,"wb");
	if (pubkeyfile == NULL) {
	    printf("Unable to create public key file\n");
	    exit(-6);
	}
	ret = PEM_write_PUBKEY(pubkeyfile, pkey);
	if (ret == 0) {
	    printf("I/O Error writing public key file\n");
	    exit(-7);
	}
	fclose(pubkeyfile);
	EVP_PKEY_free(pkey);
	ret = 0;
    }
    if (TRUE == activate) {
	uint32_t newhandle = 0;
	char *version = getenv("TPM_VERSION");
	/*
	 * Activate the identity.
	 */
	if (version == NULL || !strcmp("11",version)) {
	    ret = TPM_LoadKey(0x40000000, // must be SRK in this case!
			      srkhashptr,
			      &idkey,
			      &newhandle);
	    if (ret == TPM_BAD_ORDINAL) {
		ret = TPM_LoadKey2(0x40000000, // must be SRK in this case!
				   srkhashptr,
				   &idkey,
				   &newhandle);
	    }
	} else {
	    ret = TPM_LoadKey2(0x40000000, // must be SRK in this case!
			       srkhashptr,
			       &idkey,
			       &newhandle);
	}
	if (0 != ret) {
	    printf("LoadKey returned error '%s' (%d).\n",
		   TPM_GetErrMsg(ret),
		   ret);
	} else {
	    printf("Identity key handle %08X\n",newhandle);
	    if (TRUE == use_ca) {
		ret = do_ca_contents(ownerAuth,
				     &idkey,
				     newhandle,
				     usageptr);
	    } else {
		ret = do_ek_blob(ownerAuth,
				 &idkey,
				 newhandle,
				 usageptr);
	    }
	}
    }

    return ret;
}


uint32_t do_ek_blob(unsigned char * ownerAuth,
                    keydata * idkey,
                    uint32_t newhandle,
                    unsigned char * usageptr) {
	TPM_EK_BLOB ekblob;
	TPM_EK_BLOB_ACTIVATE activate;
	TPM_SYMMETRIC_KEY tpm_symkey;
	unsigned char symkey[] = {0x12,0x34,0x56,0x78,0x9a,0xbc,0xde,0xf0,
	                          0x12,0x34,0x56,0x78,0x9a,0xbc,0xde,0xf0};
	STACK_TPM_BUFFER( ser_symkey_buf )
	uint32_t ser_symkey_len;
	uint32_t serkeylen;
	STACK_TPM_BUFFER( buffer )
	STACK_TPM_BUFFER( ek_actblob )
	uint32_t ek_actblobsize = 0;
	STACK_TPM_BUFFER(ek_blobbuf)
	uint32_t ek_blobbufsize = 0;

	uint32_t ret = 0;
	uint32_t pcrs;

	memset(&activate, 0x0, sizeof(activate));

	/*
	 * Need to build the symmetric key structure,
	 * serialize it and attach it to data.buffer of 'data'.
	 */
	tpm_symkey.algId       = TPM_ALG_AES128;
	tpm_symkey.encScheme   = TPM_ES_SYM_CTR;
	tpm_symkey.size        = sizeof(symkey);
	tpm_symkey.data        = symkey;

	ser_symkey_len = TPM_WriteSymmetricKey(&ser_symkey_buf, &tpm_symkey);
	if (ser_symkey_len & ERR_MASK) {
		return ret;
	}


	activate.tag  = TPM_TAG_EK_BLOB_ACTIVATE;
	activate.sessionKey = tpm_symkey;

	ret = TPM_WriteKeyPub(&buffer,idkey);
	if (ret & ERR_MASK) {
		return ret;
	}
	serkeylen = ret;
	TSS_sha1(buffer.buffer,serkeylen,activate.idDigest);

	
	ret = TPM_GetNumPCRRegisters(&pcrs);
	if (ret != 0) {
		printf("Error reading number of PCR registers.\n");
		exit(-1);
	}
	if (pcrs > TPM_NUM_PCR) {
		printf("Library does not support that many PCRs.\n");
		exit(-1);
	}

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

	return do_activateIdentity(ownerAuth,
	                           usageptr,
	                           ek_blobbuf.buffer, ek_blobbufsize,
	                           newhandle);
}

static 
uint32_t   do_activateIdentity(unsigned char * ownerAuth,
                               unsigned char * usageptr,
                               unsigned char * blobbuf, uint32_t blobbufsize,
                               uint32_t newhandle) {
	uint32_t ret = 0;
	RSA * rsa;
	rsa = getpubek(ownerAuth);
	if (NULL != rsa) {
		unsigned char out_blob[2048];
		uint32_t blobsize;
		unsigned char * blob;
		STACK_TPM_BUFFER(returnbuffer)
		unsigned char tpm_oaep_pad_str[] = { 'T' , 'C' , 'P' , 'A' };

		blobsize = RSA_size(rsa);
		blob = malloc(blobsize);

		/*
		 * Add some padding to the data that need to
		 * be encrypted.
		 */
		ret = RSA_padding_add_PKCS1_OAEP(blob,
		                                 blobsize,
		                                 blobbuf,
		                                 blobbufsize,
		                                 tpm_oaep_pad_str,
		                                 sizeof(tpm_oaep_pad_str));

		if (0 == ret) {
			printf("Error while adding padding.\n");
			exit(-1);
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


		ret = TPM_ActivateIdentity(newhandle,
		                           out_blob, blobsize,
		                           usageptr,
		                           ownerAuth,
		                           &returnbuffer);

		if (0 != ret) {
			printf("ActivateIdentity returned error '%s' (0x%x).\n",
			       TPM_GetErrMsg(ret),
			       ret);
			exit(-1);
		} else {
			TPM_SYMMETRIC_KEY retkey;
			printf("Successfully activated the identity.\n");
			ret = TPM_ReadSymmetricKey(&returnbuffer,
			                           0,
			                           &retkey);
			if (ret > 0) {
				uint32_t j = 0;
				printf("Received the following symmetric key:\n");
				printf("algId     : 0x%x\n",(uint32_t)retkey.algId);
				printf("encScheme : 0x%x\n",(uint32_t)retkey.encScheme);
				printf("data      : ");
				while (j < retkey.size) {
					printf("%02X ",retkey.data[j]);
					j++;
				}
				printf("\n");
				ret = 0;
			}
		}
	} else {
		exit(-1);
	}

	return ret;
}


/*
 * Call the ActivateIdentity function with a TPM_ASYM_CA_CONTENTS
 * structure.
 */
uint32_t do_ca_contents(unsigned char * ownerAuth,
                        keydata * idkey,
                        uint32_t  newhandle,
                        unsigned char * usageptr) {
	/*
	 * An arbitrary symmetric key
	 */
	unsigned char symkey[] = {0x12,0x34,0x56,0x78,0x9a,0xbc,0xde,0xf0,
	                          0x12,0x34,0x56,0x78,0x9a,0xbc,0xde,0xf0,
	                          0x12,0x34,0x56,0x78,0x9a,0xbc,0xde,0xf0,
	                          0x12,0x34,0x56,0x78,0x9a,0xbc,0xde,0xf0};
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
	ret = TPM_WriteKeyPub(&buffer,idkey);
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

	return do_activateIdentity(ownerAuth,
	                           usageptr,
	                           buffer.buffer, sercacontlen,
	                           newhandle);

}

/*
 * Get the public endorsement key needed for encryption
 */
static RSA * getpubek(unsigned char * passhash) 
{
	RSA *rsa;                       /* OpenSSL format Public Key */
	pubkeydata pubek;
	uint32_t ret;
	memset(&pubek,0x0,sizeof(pubek));

	/*
	 * Get the public endorsement key from the TPM.
	 */
	ret = TPM_OwnerReadPubek(passhash,&pubek);
	if (ret == TPM_BAD_ORDINAL) {
		ret = TPM_OwnerReadInternalPub(TPM_KH_EK,
		                               passhash,
		                               &pubek);
		if (ret != 0) {
			printf("Error '%s' from OwnerReadInternalPub.\n",
			        TPM_GetErrMsg(ret));
			return NULL;
		}
	}
	if (ret != 0) {
		printf("Error %s from TPM_OwnerReadPubek\n",TPM_GetErrMsg(ret));
		return NULL;
	}
	/*
	 ** convert the returned public key to OpenSSL format 
	 */
	rsa = TSS_convpubkey(&pubek);

	return rsa;
}
