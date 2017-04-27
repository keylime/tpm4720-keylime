/********************************************************************************/
/*										*/
/*			     	TPM Test of TPM Quote				*/
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
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

int GetRSAKey(RSA **rsa,
	      X509 *x509Certificate);
uint32_t TPM_ValidatePCRCompositeSignatureRSA(TPM_PCR_COMPOSITE *tpc,
					      unsigned char *antiReplay,
					      RSA *rsaKey,
					      struct tpm_buffer *signature,
					      uint16_t sigscheme);

static int printUsage()
{
    printf("Usage: quote\n"
	   "-hk <key handle in hex>\n"
	   "-bm <pcr mask in hex>\n"
	   "[-noverify]\n"
	   "[-pwdk <key password>]\n"
       "[-oq   <destination file for quote>]\n"
	   "[-nonce <random value>]\n"
	   "[-cert <key certificate to verify the quote signature]\n");
    return -1;
}

#ifndef SHARED_LIB
#define outStream stdout
int main(int argc, char *argv[])
#else
#define exit(rc) return rc;	
int quote_main(FILE *outStream, int argc, char *argv[])
#endif	
{
    int ret;			/* general return value */
    uint32_t keyhandle = 0;	/* handle of quote key */
    int setkh = 0;
    unsigned int pcrmask = 0;	/* pcr register mask */
    unsigned char passhash1[TPM_HASH_SIZE];	/* hash of key password */
    unsigned char nonce[TPM_NONCE_SIZE];	/* nonce data */
    static char *nonceval = NULL; /* nonce value passed in by user */
    static char *outputname = NULL;         /* file to write out the quote to */
    STACK_TPM_BUFFER(signature);
    pubkeydata pubkey;	/* public key structure */
    unsigned char *passptr;
    TPM_PCR_COMPOSITE tpc;
    STACK_TPM_BUFFER (ser_tpc);
    STACK_TPM_BUFFER (ser_tqi);
    uint32_t pcrs;
    int i;
    uint16_t sigscheme = TPM_SS_RSASSAPKCS1v15_SHA1;
    TPM_PCR_SELECTION tps;
    static char *keypass = NULL;
    const char *certFilename = NULL;
    int verbose = FALSE;
    FILE *fp = NULL;
    int noverify = FALSE;
    
    TPM_setlog(0);		/* turn off verbose output from TPM driver */
    for (i=1 ; i<argc ; i++) {
	if (strcmp(argv[i],"-hk") == 0) {
	    i++;
	    if (i < argc) {
		/* convert key handle from hex */
		if (1 != sscanf(argv[i], "%x", &keyhandle)) {
		    printf("Invalid -hk argument '%s'\n",argv[i]);
		    exit(2);
		}
		setkh=1;	 
	    }
	    else {
		printf("-hk option needs a value\n");
		return printUsage();
	    }
	}
	else if (!strcmp(argv[i], "-pwdk")) {
	    i++;
	    if (i < argc) {
		keypass = argv[i];
	    }
	    else {
		printf("Missing parameter to -pwdk\n");
		return printUsage();
	    }
	}
	else if (!strcmp(argv[i], "-noverify")) {
		noverify= TRUE;
	}
	else if (strcmp(argv[i],"-bm") == 0) {
	    i++;
	    if (i < argc) {
		/* convert key handle from hex */
		if (1 != sscanf(argv[i], "%x", &pcrmask)) {
		    printf("Invalid -bm argument '%s'\n",argv[i]);
		    exit(2);
		}
	    }
	    else {
		printf("-bm option needs a value\n");
		return printUsage();
	    }
	}
	else if (!strcmp(argv[i], "-cert")) {
	    i++;
	    if (i < argc) {
		certFilename = argv[i];
	    }
	    else {
		printf("Missing parameter to -cert\n");
		return printUsage();
	    }
	}
	else if (!strcmp(argv[i], "-oq")) {
	    i++;
	    if (i < argc) {
		outputname = argv[i];
	    }
	    else {
		printf("Missing parameter to -oq\n");
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
        return printUsage();
        }
    }
	else if (!strcmp(argv[i], "-h")) {
	    return printUsage();
	}
	else if (!strcmp(argv[i], "-v")) {
	    verbose = TRUE;
	    TPM_setlog(1);
	}
	else {
	    printf("\n%s is not a valid option\n", argv[i]);
	    return printUsage();
	}
    }
    if ((setkh== 0) ||
	(pcrmask == 0)) {
	printf("Missing argument\n");
	return printUsage();
    }
    if(outputname==NULL)
    	outputname = "quote.bin";


    /* get the SHA1 hash of the password string for use as the Key Authorization Data */
    if (keypass != NULL) {
	TSS_sha1((unsigned char *)keypass, strlen(keypass), passhash1);
	passptr = passhash1;
    }
    else {
	passptr = NULL;
    }
    
    if (nonceval != NULL) {
    /* if specified, hash nonceval to create nonce data */
    TSS_sha1((unsigned char *)nonceval,strlen(nonceval),nonce);
    }
    else {
    /* for testing, use the password hash as the test nonce */
    memcpy(nonce, passhash1, TPM_HASH_SIZE);
    }
	
    ret = TPM_GetNumPCRRegisters(&pcrs);
    if (ret != 0) {
	printf("Error reading number of PCR registers.\n");
	exit(-1);
    }
    if (pcrs > TPM_NUM_PCR) {
	printf("Library does not support that many PCRs.\n");
	exit(-1);
    }
	
    tps.sizeOfSelect = pcrs / 8;
    for (i = 0; i < tps.sizeOfSelect; i++) {
	tps.pcrSelect[i] = (pcrmask & 0xff);
	pcrmask >>= 8;
    }
    /*
    ** perform the TPM Quote function
    */
    ret = TPM_Quote(keyhandle,	/* KEY handle */
		    passptr,	/* Key Password (hashed), or null */
		    nonce,	        /* nonce data */
		    &tps,	        /* specify PCR registers */
		    &tpc,		/* pointer to pcr composite */
		    &signature);/* buffer to receive result, int to receive result length */
    if (ret != 0) {
	printf("Error '%s' from TPM_Quote\n", TPM_GetErrMsg(ret));
	exit(ret);
    }
    
    /*
    ** Get the public key and convert to an OpenSSL RSA public key
    */
    ret = TPM_GetPubKey(keyhandle, passptr, &pubkey);
    if (ret != 0) {
	printf("quote: Error '%s' from TPM_GetPubKey\n", TPM_GetErrMsg(ret));
	exit(-6);
    }
        
    /* write out quote to file */
    if((fp = fopen(outputname,"w"))==0) {
    printf("Error opening file %s\n",outputname);
    exit(-1);
    }
    if(fwrite(&signature,sizeof(uint32_t),3,fp)<3) {
    printf("Error writing signature header.\n");
    exit(-1);
    }
    if(fwrite(&signature.buffer,sizeof(char),signature.used,fp)<signature.used) {
    printf("Error writing signature data.\n");
    exit(-1);
    }
    if(fwrite(&tpc,sizeof(TPM_PCR_COMPOSITE),1,fp)<1) {
    printf("Error writing PCR composite.\n");
    exit(-1);
    }
    if(fwrite(tpc.pcrValue.buffer,sizeof(BYTE),tpc.pcrValue.size,fp)<tpc.pcrValue.size) {
    printf("Error writing PCR buffer.\n");
    exit(-1);
    }
    fclose(fp);
    
    if(noverify) {
    	exit(0);
    }
    
    ret = TPM_ValidatePCRCompositeSignature(&tpc,
					    nonce,
					    &pubkey,
					    &signature,
					    sigscheme);
    if (ret) {
	printf("Error %s from validating the signature over the PCR composite.\n",
	       TPM_GetErrMsg(ret));
	exit(ret);
    }
    fprintf(outStream, "Verification against AIK succeeded\n");
    
    /* optionally verify the quote signature against the key certificate */
    if (certFilename != NULL) {
	unsigned char *certStream = NULL;	/* freed @1 */
	uint32_t certStreamLength;
	X509 *x509Certificate = NULL;		/* freed @2 */
	unsigned char 	*tmpPtr;		/* because d2i_X509 moves the ptr */
	
	/* AIK public key parts */
	RSA *rsaKey = NULL; 			/* freed @3 */

	if (verbose) printf("quote: verifying the signature against the certificate\n");
	/* load the key certificate */
	if (ret == 0) {
	    ret = TPM_ReadFile(certFilename,
			       &certStream,	/* freed @1 */
			       &certStreamLength);
	}
	/* convert to openssl X509 */
	if (ret == 0) {
	    if (verbose) fprintf(outStream, "quote: parsing the certificate stream\n");
	    tmpPtr = certStream;
	    x509Certificate = d2i_X509(NULL,
				       (const unsigned char **)&tmpPtr, certStreamLength);
	    if (x509Certificate == NULL) {
		fprintf(outStream, "Error in certificate deserialization d2i_X509()\n");
		ret = -1;
	    }
	}
	if (ret == 0) {
	    if (verbose) fprintf(outStream, "quote: get the certificate public key\n");
	    ret = GetRSAKey(&rsaKey,	/* freed @3 */
			    x509Certificate);
	}
	if (ret == 0) {
	    if (verbose) fprintf(outStream, "quote: quote validate signature\n");
	    ret = TPM_ValidatePCRCompositeSignatureRSA(&tpc,
						       nonce,
						       rsaKey,
						       &signature,
						       sigscheme);
	    if (ret != 0) {
		fprintf(outStream, "Verification against certificate failed\n");
	    }
	}
	if (ret == 0) {
	    fprintf(outStream, "Verification against certificate succeeded\n");
	}
	free(certStream);		/* @1 */
	X509_free(x509Certificate); 	/* @2 */
	RSA_free(rsaKey);		/* @3 */
    }
    exit(ret);
}

/* FIXME move to library pcrs.c  */
/* 
 * Validate the signature over a PCR composite structure.
 * Returns '0' on success, an error code otherwise.
 */

uint32_t TPM_ValidatePCRCompositeSignatureRSA(TPM_PCR_COMPOSITE *tpc,
					      unsigned char *antiReplay,
					      RSA *rsaKey,
					      struct tpm_buffer *signature,
					      uint16_t sigscheme)
{
    uint32_t ret;
    TPM_QUOTE_INFO tqi;
    STACK_TPM_BUFFER (ser_tqi);
    STACK_TPM_BUFFER(response);
    STACK_TPM_BUFFER (ser_tpc);

    ret = TPM_GetCapability(TPM_CAP_VERSION, NULL,
			    &response);
    if (ret != 0) {
	return ret;
    }

    memcpy(&(tqi.version), response.buffer, response.used);
    memcpy(&(tqi.fixed), "QUOT", 4);
    memcpy(&(tqi.externalData), antiReplay, TPM_NONCE_SIZE);
    ret = TPM_WritePCRComposite(&ser_tpc, tpc);
    if ((ret & ERR_MASK)) {
	return ret;
    }
    /* create the hash of the PCR_composite data for the quoteinfo structure */
    TSS_sha1(ser_tpc.buffer, ser_tpc.used, tqi.digestValue);

    ret = TPM_WriteQuoteInfo(&ser_tqi, &tqi);
    if ((ret & ERR_MASK)) {
	return ret;
    }
	
    ret = TPM_ValidateSignature(sigscheme,
				&ser_tqi,
				signature,
				rsaKey);
    return ret;
}
/* FIXME move to library */

int GetRSAKey(RSA **rsa,		/* freed by caller */	
	      X509 *x509Certificate)
{
    int 		rc = 0;
    EVP_PKEY 		*pkey = NULL;
    
    if (rc == 0) {
	pkey = X509_get_pubkey(x509Certificate);
	if (pkey == NULL) {
	    printf("Error: Cannot get certificate public key\n");
	    rc = -1;
	}
    }
    if (rc == 0) {
	*rsa = EVP_PKEY_get1_RSA(pkey);
	if (*rsa == NULL) {
	    printf("Error: Cannot extract certificate RSA public key\n");
	    rc = -1;
	}
    }
    return rc;
}
