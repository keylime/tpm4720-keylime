/********************************************************************************/
/*										*/
/*			     Activate Identity  				*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*	      $Id: activateidentity.c 4702 2013-01-03 21:26:29Z kgoldman $	*/
/*										*/
/* (c) Copyright IBM Corporation 2012.						*/
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

/* AES requires data lengths that are a multiple of the block size */
#define AES_BITS 128

int Ossl_AES_Decrypt(unsigned char **decrypt_data,
		     uint32_t *decrypt_length,
		     const unsigned char *encrypt_data,
		     uint32_t encrypt_length,
		     const unsigned char *initialization_vector,
		     const unsigned char *aes_key);

/* local prototypes */

static void PrintUsage() {
    printf("activateidentity activates the identity blob agains the loaded AIK\n"
	   "It optionally outputs the symmetric key.  If the AIK certificate is supplied, "
	   "it is decrypted with the symmetric key");
    printf("\n");
    printf("\n");
    printf("Usage: activateidentity-hk keyhandle -pwdo <owner password>\n"
	   "\t-if identity blob[options]\n");
    printf("\n");
    printf("Inputs\n");
    printf(" -hk <keyhandle>   AIK key handle in hex\n");
    printf(" -pwdo pwd     : The TPM owner password\n");
    printf(" [-pwdk idpwd  : A password for the identity]\n");
    printf(" -if filename  : the filename of the identity blob\n");
    printf(" [-aikcertenc  : Encrypted AIK certificate]\n");
    printf("Outputs\n");
    printf(" [-ok filename : Symmetric key file name]\n");
    printf(" [-aikcert     : AIK certificate (DER)\n]");
    printf(" [-v           : to enable verbose output]\n");
    printf(" [-h           : usage help]\n");
    printf("\n");
    printf("Examples:\n");
    exit(-1);
}

int main(int argc, char * argv[])
{
    uint32_t ret = 0;

    /* command line parameters */
    const char *blobFilename = NULL;		/* input EK blob */
    const char *aikPassword = NULL;		/* AIK password */
    const char *ownerPassword = NULL;		/* owner password */
    const char *keyFilename = NULL;           /* output symmetric key */
    const char *aikCertificateFileName = NULL;
    const char *aikCertificateEncFileName = NULL;
    int verbose = FALSE;

    
    unsigned char usagehash[20];	/* hash of aikPassword if supplied */	
    unsigned char * usageAuth = NULL;	/* AIK usageAuth */
    unsigned char ownerHash[20];
    unsigned char * ownerAuth = NULL;
    uint32_t aikHandle = 0;		/* IAK key handle */
    unsigned char *blobData = NULL;	/* blob to be activated, free @1 */
    uint32_t blobSize;

    
    STACK_TPM_BUFFER(returnbuffer);	/* decrypted symmetric key */	
    TPM_SYMMETRIC_KEY retkey;		/* decrypted symmetric key */	
    

    int i = 0;

    i = 1;
	
    TPM_setlog(0);
	
    for (i=1 ; i<argc ; i++) {
       if (strcmp(argv[i],"-hk") == 0) {
	   i++;
	   if (i < argc) {
	       /* convert key handle from hex */
	       if (1 != sscanf(argv[i], "%x", &aikHandle )) {
		   printf("Invalid -hk argument '%s'\n",argv[i]);
		   exit(2);
	       }
	       if (aikHandle == 0) {
		   printf("Invalid -hk argument '%s'\n",argv[i]);
		   exit(2);
	       }		 
	   }
	   else {
	       printf("-hk option needs a value\n");
	       PrintUsage();
	   }
       }
       else if (!strcmp("-pwdo",argv[i])) {
	    i++;
	    if (i < argc) {
		ownerPassword = argv[i];
	    } else {
		printf("Missing parameter for -pwdo.\n");
		PrintUsage();
	    }
	}
	else if (!strcmp("-pwdk",argv[i])) {
	    i++;
	    if (i < argc) {
		aikPassword = argv[i];
	    } else {
		printf("Missing parameter for -pwdk.\n");
		PrintUsage();
	    }
	}
	else if (!strcmp("-if",argv[i])) {
	    i++;
	    if (i < argc) {
		blobFilename = argv[i];
	    } else {
		printf("Missing parameter for -if.\n");
		PrintUsage();
	    }
	}
	else if (!strcmp("-ok",argv[i])) {
	    i++;
	    if (i < argc) {
		keyFilename = argv[i];
	    }
	    else {
		printf("Missing parameter for -ok\n");
		PrintUsage();
	    }
	}
	else if (strcmp(argv[i],"-aikcert") == 0) {
	    i++;
	    if (i < argc) {
		aikCertificateFileName = argv[i];
	    }
	    else {
		printf("ERROR1007: -aikcert option needs a value\n");
		PrintUsage();
	    }
	}
	else if (strcmp(argv[i],"-aikcertenc") == 0) {
	    i++;
	    if (i < argc) {
		aikCertificateEncFileName = argv[i];
	    }
	    else {
		printf("ERROR1007: -aikcertenc option needs a value\n");
		PrintUsage();
	    }
	}
	else if (!strcmp("-ok",argv[i])) {
	    i++;
	    if (i < argc) {
		keyFilename = argv[i];
	    }
	    else {
		printf("Missing parameter for -ok\n");
		PrintUsage();
	    }
	}
	else if (!strcmp("-v",argv[i])) {
	    TPM_setlog(1);
	    verbose = TRUE;
	}
	else if (!strcmp("-h",argv[i])) {
	    PrintUsage();
	}
	else {
	    printf("\n%s is not a valid option\n", argv[i]);
	    PrintUsage();
	}
    }
    /* validate command line arguments */
    if (aikHandle == 0) {
	printf("Missing AIK handle\n");
	PrintUsage();
    }
    if (ownerPassword == NULL) {
	printf("Missing owner password.\n");
	PrintUsage();
    }
    if (blobFilename == NULL) {
	printf("Missing input file name\n");
    }
    if ((aikCertificateEncFileName == NULL) && (aikCertificateFileName != NULL)) {
	printf("AIK certificate output requires encrypted AIK certificate input\n");
    }
    
    /* calculate ownerAuth */
    if (ownerPassword != NULL) {
	TSS_sha1((char *)ownerPassword, strlen(ownerPassword), ownerHash);
	ownerAuth = ownerHash;
    } else {
	ownerAuth = NULL;
    }
    /* calculate usageAuth */
    if (aikPassword != NULL) {
	TSS_sha1((char *)aikPassword, strlen(aikPassword), usagehash);
	usageAuth = usagehash;
    } else {
	usageAuth = NULL;
    }
    /* read the blob */
    if (ret == 0) {
	ret = TPM_ReadFile(blobFilename,
			   &blobData, &blobSize);	/* freed @1 */
	if ( (ret & ERR_MASK) != 0) {
	    printf("Error while reading blob file.\n");
	    ret = -1;
	}
    }
    /*
     * Activate the identity.
     */
    if (ret == 0) {
	ret = TPM_ActivateIdentity(aikHandle,
				   blobData, blobSize,
				   usageAuth,
				   ownerAuth,
				   &returnbuffer);
	if (ret != 0) {
	    printf("ActivateIdentity returned error '%s' (0x%x).\n",
		   TPM_GetErrMsg(ret),
		   ret);
	}
    }
    if (ret == 0) {
	if (verbose) printf("Successfully activated the identity.\n");
	ret = TPM_ReadSymmetricKey(&returnbuffer,
				   0,
				   &retkey);
	if (ret & ERR_MASK) {
	    printf("TPM_ReadSymmetricKey returned error '%s' (0x%x).\n",
		   TPM_GetErrMsg(ret),
		   ret);
	}
	else {
	    ret = 0;
	}
    }
    if ((ret == 0) && verbose) {
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
    }
    /* optionally write the symmetric key to a file */
    if ((ret == 0) && (keyFilename != NULL)) {
	ret = TPM_WriteFile(keyFilename , retkey.data, retkey.size);
    }

    unsigned char *aikCertificate = NULL;	/* freed @6 */
    uint32_t aikCertificateLength;
    unsigned char *aikCertificateEnc = NULL;	/* freed @7 */
    uint32_t aikCertificateEncLength;
    unsigned char initializationVector[16];


    /* optionally decrypt the AIK certificate */
    if ((ret == 0) && (aikCertificateEncFileName != NULL)) {
	ret = TPM_ReadFile(aikCertificateEncFileName,
			   &aikCertificateEnc,	/* freed @6 */
			   &aikCertificateEncLength);
    }
    if ((ret == 0) && (aikCertificateEncFileName != NULL)) {
	memset(initializationVector, 0, sizeof(initializationVector));
	ret = Ossl_AES_Decrypt(&aikCertificate, &aikCertificateLength,	/* freed @7 */
			       aikCertificateEnc, aikCertificateEncLength,
			       initializationVector,
			       retkey.data);
    }
    /* optionally write the AIK certificate */
    if ((ret == 0) && (aikCertificateFileName != NULL)) {
	ret = TPM_WriteFile(aikCertificateFileName,
			    aikCertificate ,
			    aikCertificateLength);
    }
    free(blobData); 			/* @1 */
    free(aikCertificate);		/* @6 */ 
    free(aikCertificateEnc);		/* @7 */ 
    return ret;
}

/* FIXME move to library */

/* Ossl_AES_Decrypt() is AES non-portable code to decrypt 'encrypt_data' to
   'decrypt_data'

   The stream must be padded as per PKCS#7 / RFC2630

   decrypt_data must be free by the caller
*/

int Ossl_AES_Decrypt(unsigned char **decrypt_data,   		/* output, caller frees */
		     uint32_t *decrypt_length,				/* output */
		     const unsigned char *encrypt_data,			/* input */
		     uint32_t encrypt_length,				/* input */
		     const unsigned char *initialization_vector,	/* input */
		     const unsigned char *aes_key) 			/* input */
{
    int          	rc = 0;
    size_t		pad_length;
    unsigned int	i;
    unsigned char       *pad_data;
    AES_KEY 		aes_dec_key;
    unsigned char       ivec[AES_BLOCK_SIZE];       /* initial chaining vector */
   
    if (rc == 0) {
	rc = AES_set_decrypt_key(aes_key,
				 AES_BITS,
				 &aes_dec_key);
	if (rc != 0) {
	    rc = -1;
	}
    }
    /* sanity check encrypted length */
    if (rc == 0) {
        if (encrypt_length < AES_BLOCK_SIZE) {
            printf("Ossl_AES_Decrypt: Error, bad length\n");
            rc = -1;
        }
    }
    /* allocate memory for the padded decrypted data */
    if (rc == 0) {
	*decrypt_data = malloc(encrypt_length);
	if (*decrypt_data == NULL) {
	    rc = -1;
	}
    }
    /* decrypt the input to the padded output */
    if (rc == 0) {
	/* make a copy of the initialization vector */
	memcpy(ivec, initialization_vector, sizeof(ivec));
	/* decrypt the padded input to the output */
        AES_cbc_encrypt(encrypt_data,
                        *decrypt_data,
                        encrypt_length,
                        &(aes_dec_key),
			ivec,
                        AES_DECRYPT);
    }
    /* get the pad length */
    if (rc == 0) {
        /* get the pad length from the last byte */
        pad_length = (size_t)*(*decrypt_data + encrypt_length - 1);
        /* sanity check the pad length */
        if ((pad_length == 0) ||
            (pad_length > AES_BLOCK_SIZE)) {
            printf("Ossl_AES_Decrypt: Error, illegal pad length\n");
            rc = -1;
        }
    }
    if (rc == 0) {
        /* get the unpadded length */
        *decrypt_length = encrypt_length - pad_length;
        /* pad starting point */
        pad_data = *decrypt_data + *decrypt_length;
        /* sanity check the pad */
        for (i = 0 ; i < pad_length ; i++, pad_data++) {
            if (*pad_data != pad_length) {
                printf("Ossl_AES_Decrypt: Error, bad pad %02x at index %u\n", *pad_data, i);
                rc = -1;
            }
        }
    }
    return rc;
}



