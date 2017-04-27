/* -*- Mode: C; c-basic-offset: 8; -*- */
/********************************************************************************/
/*										*/
/*			     	TPM PCR Processing Functions			*/
/*			     Written by J. Kravitz, S. Berger			*/
/*		       IBM Thomas J. Watson Research Center			*/
/*	      $Id: pcrs.c 4702 2013-01-03 21:26:29Z kgoldman $			*/
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
#ifdef TPM_POSIX
#include <netinet/in.h>
#endif
#ifdef TPM_WINDOWS
#include <winsock2.h>
#endif
#include <tpm.h>
#include <tpmutil.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <openssl/rsa.h>
#include <oiaposap.h>
#include <hmac.h>
#include <pcrs.h>
#include <tpm_constants.h>
#include <tpm_structures.h>
#include "tpmfunc.h"
#include "deepquote.h"


uint32_t TPM_ValidateSignature(uint16_t sigscheme,
                               struct tpm_buffer *data,
                               struct tpm_buffer *signature,
                               RSA *rsa)
{
	STACK_TPM_BUFFER(tsi_ser);
	unsigned char sighash[TPM_HASH_SIZE];	/* hash of quote info structure */
	uint32_t ret = 0;
	unsigned char padded[4096];
	unsigned char plainarray[4096];
	int plain, irc;

	switch (sigscheme) {
		case TPM_SS_RSASSAPKCS1v15_INFO:
		case TPM_SS_RSASSAPKCS1v15_SHA1:
			/* create the hash of the quoteinfo structure for signature verification */
			TSS_sha1(data->buffer, data->used, sighash);
			/*
			 ** perform an RSA verification on the signature returned by Quote
			 */
			ret = RSA_verify(NID_sha1, sighash, sizeof(sighash),
			                 signature->buffer, signature->used,
			                 rsa);
			if (ret != 1) {
				ret =  ERR_SIGNATURE;
			} else {
				ret = 0;
			}
		break;
		case TPM_SS_RSASSAPKCS1v15_DER:
			/* create the hash of the quoteinfo structure for signature verification */
			TSS_sha1(data->buffer, data->used, sighash);

			plain = RSA_public_decrypt(signature->used,
			                           signature->buffer,
			                           plainarray,
			                           rsa, RSA_NO_PADDING);
			if (plain == -1) {
				ret = ERR_SIGNATURE;
			}
			if (ret == 0) {
				irc = RSA_padding_add_PKCS1_type_1(padded,plain,sighash,sizeof(sighash));
				if (irc != 1) {
					ret = ERR_SIGNATURE;
				}
			}
			if (ret == 0) {
				if (memcmp(padded, plainarray, plain) != 0) {
					ret = ERR_SIGNATURE;
				}
			}
		break;
		default:
			ret = ERR_SIGNATURE;
	}
	return ret;
}

/* 
 * Validate the signature over a PCR composite structure.
 * Returns '0' on success, an error code otherwise.
 */
uint32_t TPM_ValidatePCRCompositeSignature(TPM_PCR_COMPOSITE *tpc,
                                           unsigned char *antiReplay,
                                           pubkeydata *pk,
                                           struct tpm_buffer *signature,
                                           uint16_t sigscheme)
{
	uint32_t ret;
	RSA *rsa;			/* openssl RSA public key */
	TPM_QUOTE_INFO tqi;
	STACK_TPM_BUFFER (ser_tqi);
	STACK_TPM_BUFFER(response);
	STACK_TPM_BUFFER (ser_tpc);
	/*
	** Convert to an OpenSSL RSA public key
	*/
	rsa = TSS_convpubkey(pk);

	ret = TPM_GetCapability(TPM_CAP_VERSION, NULL,
	                        &response);
	if (ret != 0) {
		RSA_free(rsa);
		return ret;
	}

	memcpy(&(tqi.version), response.buffer, response.used);
	memcpy(&(tqi.fixed), "QUOT", 4);
	memcpy(&(tqi.externalData), antiReplay, TPM_NONCE_SIZE);
	ret = TPM_WritePCRComposite(&ser_tpc, tpc);
	if ((ret & ERR_MASK)) {
		RSA_free(rsa);
		return ret;
	}
	/* create the hash of the PCR_composite data for the quoteinfo structure */
	TSS_sha1(ser_tpc.buffer, ser_tpc.used, tqi.digestValue);

	ret = TPM_WriteQuoteInfo(&ser_tqi, &tqi);
	if ((ret & ERR_MASK)) {
		RSA_free(rsa);
		return ret;
	}
	
	ret = TPM_ValidateSignature(sigscheme,
	                            &ser_tqi,
	                            signature,
	                            rsa);
	RSA_free(rsa);
	return ret;
}

/* 
 * Validate the signature over a PCR composite structure. take in vinfo rather than query
 * Returns '0' on success, an error code otherwise.
 */
uint32_t TPM_ValidatePCRCompositeSignatureNoCap(TPM_PCR_COMPOSITE *tpc,
                                           unsigned char *antiReplay,
                                           RSA *rsa,
                                           struct tpm_buffer *signature,
                                           uint16_t sigscheme)
{
	uint32_t ret;
	TPM_QUOTE_INFO tqi;
	STACK_TPM_BUFFER (ser_tqi);
	STACK_TPM_BUFFER (ser_tpc);

	/* hard code version to 1.1 no revs */
	tqi.version.major = 0x01;
	tqi.version.minor = 0x01;
	tqi.version.revMajor = 0x00;
	tqi.version.revMinor = 0x00;
	
	memcpy(&(tqi.fixed), "QUOT", 4);
	memcpy(&(tqi.externalData), antiReplay, TPM_NONCE_SIZE);
	ret = TPM_WritePCRComposite(&ser_tpc, tpc);
	if ((ret & ERR_MASK)) {
		RSA_free(rsa);
		return ret;
	}
	/* create the hash of the PCR_composite data for the quoteinfo structure */
	TSS_sha1(ser_tpc.buffer, ser_tpc.used, tqi.digestValue);

	ret = TPM_WriteQuoteInfo(&ser_tqi, &tqi);
	if ((ret & ERR_MASK)) {
		RSA_free(rsa);
		return ret;
	}
	
	ret = TPM_ValidateSignature(sigscheme,
	                            &ser_tqi,
	                            signature,
	                            rsa);
	RSA_free(rsa);
	return ret;
}


/****************************************************************************/
/*                                                                          */
/* Extend a specified PCR register by adding a new measure                  */
/*                                                                          */
/* The arguments are...                                                     */
/*                                                                          */
/* pcrIndex  is the index of the PCR register to extend                     */
/* event     is pointing to a buffer the size of TPM_HASH_SIZE (=20) that   */
/*           contains the (encrypted) information to extend the PCR with    */
/* outDigest is pointing to a buffer the size of TPM_HASH_SIZE (-20) that   */
/*           will contain the new value of the PCR register upon return     */
/*           (may be NULL)                                                  */
/****************************************************************************/
uint32_t TPM_Extend(uint32_t pcrIndex,
                    unsigned char * event,
                    unsigned char * outDigest) {
	uint32_t ret;
	uint32_t ordinal_no = htonl(TPM_ORD_Extend);
	uint32_t pcrIndex_no = htonl(pcrIndex);
	STACK_TPM_BUFFER(tpmdata)
	
	ret = TSS_buildbuff("00 c1 T l l %",&tpmdata,
	                             ordinal_no,
	                               pcrIndex_no,
	                                 TPM_HASH_SIZE, event);
	if ((ret & ERR_MASK)) {
		return ret;
	}
	
	ret = TPM_Transmit(&tpmdata,"Extend");
	
	if (0 != ret) {
		return ret;
	}
	
	if (NULL != outDigest) {
		memcpy(outDigest, 
		       &tpmdata.buffer[TPM_DATA_OFFSET], 
		       TPM_HASH_SIZE);
	}
	
	return ret;
}



/****************************************************************************/
/*                                                                          */
/* Quote the specified PCR registers                                        */
/*                                                                          */
/* The arguments are...                                                     */
/*                                                                          */
/* keyhandle is the handle of the key used to sign the results              */
/* tps       selection of the PCRs to quote                                 */
/* keyauth   is the authorization data (password) for the key               */
/*           if NULL, it will be assumed that no password is required       */
/* data      is a pointer to a nonce                                        */
/* tpc       is a pointer to an area to receive a pcrcomposite structure    */
/* signature is a pointer to an area to receive the signature               */
/*                                                                          */
/****************************************************************************/
uint32_t TPM_Quote(uint32_t keyhandle,
                   unsigned char *keyauth,
                   unsigned char *externalData,
                   TPM_PCR_SELECTION *tps,
                   TPM_PCR_COMPOSITE *tpc,
                   struct tpm_buffer *signature)
{
	uint32_t ret;
	STACK_TPM_BUFFER( tpmdata )
	session sess;
	unsigned char pubauth[TPM_HASH_SIZE];
	unsigned char nonceodd[TPM_NONCE_SIZE];
	unsigned char c;
	uint32_t ordinal = htonl(TPM_ORD_Quote);
	uint32_t keyhndl = htonl(keyhandle);
	uint16_t pcrselsize;
	uint32_t valuesize;
	uint32_t sigsize;
	uint32_t offset;
	STACK_TPM_BUFFER( serPcrSel );

	/* check input arguments */
	if (tpc == NULL || externalData == NULL || signature == NULL) return ERR_NULL_ARG;

	ret = needKeysRoom(keyhandle, 0, 0, 0);
	if (ret != 0) {
		return ret;
	}

	ret = TPM_WritePCRSelection(&serPcrSel, tps);

	if ((ret & ERR_MASK))
		return ret;

	if (keyauth != NULL)  /* authdata required */ {
		/* Open OSAP Session */
		ret = TSS_SessionOpen(SESSION_OSAP|SESSION_DSAP,&sess,
		                      keyauth,TPM_ET_KEYHANDLE,keyhandle);
		if (ret != 0) return ret;
		/* generate odd nonce */
		TSS_gennonce(nonceodd);
		/* move Network byte order data to variables for hmac calculation */
		c = 0;
		/* calculate authorization HMAC value */
		ret = TSS_authhmac(pubauth,TSS_Session_GetAuth(&sess),
				   TPM_HASH_SIZE,
				   TSS_Session_GetENonce(&sess),
				   nonceodd,c,
		                   TPM_U32_SIZE,
				   &ordinal,
		                   TPM_HASH_SIZE,
				   externalData,
		                   serPcrSel.used,
				   serPcrSel.buffer,
		                   0,0);
		if (ret != 0) {
			TSS_SessionClose(&sess);
			return ret;
		}
		/* build the request buffer */
		ret = TSS_buildbuff("00 C2 T l l % % L % o %",&tpmdata,
				    ordinal,
				    keyhndl,
				    TPM_HASH_SIZE,externalData,
				    serPcrSel.used, serPcrSel.buffer,
				    
				    TSS_Session_GetHandle(&sess),
				    TPM_NONCE_SIZE,nonceodd,
				    c,
				    TPM_HASH_SIZE,pubauth);
		if ((ret & ERR_MASK) != 0) {
			TSS_SessionClose(&sess);
			return ret;
		}
		/* transmit the request buffer to the TPM device and read the reply */
		ret = TPM_Transmit(&tpmdata,"Quote");
		TSS_SessionClose(&sess);
		if (ret != 0) {
			return ret;
		}
		
		offset = TPM_DATA_OFFSET;
		/* calculate the size of the returned Blob */
		ret  =  tpm_buffer_load16(&tpmdata,offset,&pcrselsize);
		if ((ret & ERR_MASK)) {
			return ret;
		}
		offset += TPM_U16_SIZE + pcrselsize;
		
		ret =  tpm_buffer_load32(&tpmdata,offset,&valuesize);
		if ((ret & ERR_MASK)) {
			return ret;
		}
		offset += TPM_U32_SIZE + valuesize;
		ret =  tpm_buffer_load32(&tpmdata,offset, &sigsize);
		if ((ret & ERR_MASK)) {
			return ret;
		}
		offset += TPM_U32_SIZE;

		/* check the HMAC in the response */
		ret = TSS_checkhmac1(&tpmdata,ordinal,nonceodd,TSS_Session_GetAuth(&sess),TPM_HASH_SIZE,
		                     offset-TPM_DATA_OFFSET+sigsize,TPM_DATA_OFFSET,
		                     0,0);
		if (ret != 0) {
			return ret;
		}
		ret = TPM_ReadPCRComposite(&tpmdata,
		                           TPM_DATA_OFFSET,
		                           tpc);
		if ((ret & ERR_MASK)) {
			return ret;
		}
		/* copy the returned blob to caller */
		SET_TPM_BUFFER(signature,
		               &tpmdata.buffer[offset],
		               sigsize);
	} else  /* no authdata required */ {
		/* build the request buffer */
		ret = TSS_buildbuff("00 C1 T l l % %",&tpmdata,
				    ordinal,
				    keyhndl,
		                                 TPM_HASH_SIZE,externalData,
		                                   serPcrSel.used,serPcrSel.buffer);
		if ((ret & ERR_MASK) != 0) return ret;
		/* transmit the request buffer to the TPM device and read the reply */
		ret = TPM_Transmit(&tpmdata,"Quote");
		if (ret != 0) return ret;
		/* calculate the size of the returned Blob */
		offset = TPM_DATA_OFFSET;
		ret =  tpm_buffer_load16(&tpmdata,offset, &pcrselsize);
		if ((ret & ERR_MASK)) {
			return ret;
		}
		offset += TPM_U16_SIZE + pcrselsize;
		ret  =  tpm_buffer_load32(&tpmdata,offset, &valuesize);
		if ((ret & ERR_MASK)) {
			return ret;
		}
		offset += TPM_U32_SIZE + valuesize;

		ret =  tpm_buffer_load32(&tpmdata,offset, &sigsize);
		if ((ret & ERR_MASK)) {
			return ret;
		}
		offset += TPM_U32_SIZE;
		
		/* copy the returned PCR composite to caller */
		ret = TPM_ReadPCRComposite(&tpmdata,
		                           TPM_DATA_OFFSET,
		                           tpc);
		if ((ret & ERR_MASK)) {
			return ret;
		}
		/* copy the returned blob to caller */
		SET_TPM_BUFFER(signature,
		               &tpmdata.buffer[offset],
		               sigsize);
	}
	return 0;
}
	
int TPM_WriteDeepQuoteBin(const char *path,
			  const TPM_PCR_SELECTION *htps,
			  const DeepQuoteInfo *dqi,
        	struct tpm_buffer *vq_signature,
        	TPM_PCR_COMPOSITE *vq_tpc)
{
	FILE *fp;
	struct DeepQuoteBin dqb = {
		.ppcrSel = {
			.sizeOfSelect = htons(3),
			.pcrSelect = {
				[0] = htps->pcrSelect[0],
				[1] = htps->pcrSelect[1],
				[2] = htps->pcrSelect[2]
			}
		},
		.dqi = *dqi
	};
	
	if (path == NULL) {
		fprintf(stderr, "Path to DeepQuoteBin cannot be NULL\n");
		return 1;
	}
	
	if ((fp = fopen(path, "wb")) == 0) {
		fprintf(stderr, "Failed to open '%s'\n", path);
		return 1;
	}

	if (fwrite(&dqb, sizeof(dqb), 1, fp) != 1) {
		perror("Failed to write out DeepQuoteBin");
		return 1;
	}

	/* write out the vTPM quote too */
    if(fwrite(vq_signature,sizeof(uint32_t),3,fp)<3) {
    perror("Error writing signature header.\n");
    exit(-1);
    }
    if(fwrite(vq_signature->buffer,sizeof(char),vq_signature->used,fp)<vq_signature->used) {
    perror("Error writing signature data.\n");
    return 1;
    }
    if(fwrite(vq_tpc,sizeof(TPM_PCR_COMPOSITE),1,fp)<1) {
    perror("Error writing PCR composite.\n");
    return 1;
    }
    if(fwrite(vq_tpc->pcrValue.buffer,sizeof(BYTE),vq_tpc->pcrValue.size,fp)<vq_tpc->pcrValue.size) {
    perror("Error writing PCR buffer.\n");
    return 1;
    }

	return fclose(fp);
}

/****************************************************************************/
/*                                                                          */
/* Validate a DeepQuoteInfo's signature                                     */
/*                                                                          */
/* The arguments are...                                                     */
/*                                                                          */
/* pubkey    is a pointer to a buffer containing a raw public AIK           */
/*           (as a TPM would return it)                                     */
/* htps      is a pointer to a selection of physical PCRs                   */
/* nonce     is a pointer to the nonce passed to TPM_DeepQuote()            */
/* dqi       is a pointer to a DeepQuoteInfo struct as returned from        */
/*           TPM_DeepQuote()                                                */
/*                                                                          */
/****************************************************************************/
uint32_t TPM_ValidateDeepQuoteInfo(RSA *pubKeyRSA,
				   TPM_PCR_SELECTION *htps,
				   unsigned char *nonce,
				   DeepQuoteInfo *dqi)
{
	SHA_CTX sha;
	/* ExternalData used by vTPM's GetParentQuote */
	unsigned char extData1[TPM_HASH_SIZE];
	/* ExternalData used by pTPM's Quote */
	unsigned char extData2[TPM_HASH_SIZE];
	/* Composite hash of the pPCRs */
	unsigned char compDigest[TPM_DIGEST_SIZE];
	unsigned char quoteBlob[sizeof(quot_hdr) + sizeof(compDigest) + sizeof(extData2)];
	uint32_t valueSize;
	size_t offset=0;
	pubkeydata pubKeyData;
	STACK_TPM_BUFFER (signatureBuf);
	STACK_TPM_BUFFER (blobBuf);
	int ret;
    
	/* Make the physical PCR Selection */
	struct PCR_SELECTION ppcrSel = {
		.sizeOfSelect = htons(3),
		.pcrSelect = {
			[0] = htps->pcrSelect[0],
			[1] = htps->pcrSelect[1],
			[2] = htps->pcrSelect[2]	    
		}
	};
    
	/* For now we're going to ignore vpcr mask */
	struct PCR_INFO_SHORT vpcrData = {
		.pcrSelection = {
			.sizeOfSelect = htons(3),
			.pcrSelect = {0,},
		},
		.localityAtRelease = 1,
		.digestAtRelease   = {0,}
	};
	uint16_t sigscheme = TPM_SS_RSASSAPKCS1v15_SHA1;    

	dump_bytes(dqi->signature, "Signature", 256);
    
	dump_hash(nonce, "extData");
	dump_bytes(dquot_hdr, "dquot", sizeof(dquot_hdr));
	dump_bytes(&vpcrData, "vPCR_INFO_SHORT", sizeof(vpcrData));

	/* GetParentQuote's extData is just the composite hash of the vPCRs */
	SHA1_Init(&sha);
	SHA1_Update(&sha, dquot_hdr, sizeof(dquot_hdr));
	SHA1_Update(&sha, nonce,     TPM_NONCE_SIZE);
	SHA1_Update(&sha, &vpcrData,  sizeof(vpcrData));
	SHA1_Final(extData1, &sha);
	dump_hash(extData1, "ParentQuote.extData");

	/* Dump out information we use to calculate Quote's extData */
	logfprintf(stderr, "\n\n  NumPCR: %u, NumHashes: %u, ExtraFlags: %x\n", dqi->values.numPCRVals, dqi->values.numInfoHashes, *(uint32_t *)dqi->extraInfoFlags);
	dump_bytes(&dqi->extraInfoFlags, "ExtraInfoFlags", 4);
	dump_bytes(dqi->values.PCRVals, "PCRVals", 20 * dqi->values.numPCRVals);
	dump_bytes(dqi->values.infoHashes, "InfoHashes", 20 * dqi->values.numInfoHashes);

	/* Calculate the extData to Quote */
	SHA1_Init(&sha);
	SHA1_Update(&sha, &dqi->extraInfoFlags, 4);
	SHA1_Update(&sha, extData1, TPM_NONCE_SIZE);
	SHA1_Update(&sha, dqi->values.infoHashes, TPM_HASH_SIZE * dqi->values.numInfoHashes);
	SHA1_Final(extData2, &sha);
	dump_bytes(extData2, "Quote.externData", TPM_DIGEST_SIZE);

	/* Create the valueSize parameters in network order */
	valueSize = htonl(dqi->values.numPCRVals * 20);
    
	/* Calculate composite hash of the serialized versions of these */
	SHA1_Init(&sha);
	SHA1_Update(&sha, &ppcrSel, sizeof(ppcrSel));
	SHA1_Update(&sha, &valueSize , sizeof(valueSize));
	SHA1_Update(&sha, dqi->values.PCRVals, dqi->values.numPCRVals * 20);
	SHA1_Final(compDigest, &sha);

	/* Dump the hash and selection out; we'll be using them to recreate the blob Quote signed */
	dump_bytes(&ppcrSel,   "Quote.ppcrSel",    sizeof(ppcrSel));
	dump_bytes(compDigest, "Quote.compDigest", TPM_DIGEST_SIZE);

    
	/* Recreate the blob Quote signed */
	memcpy(&quoteBlob[offset], quot_hdr,   sizeof(quot_hdr));
	offset+= sizeof(quot_hdr);
	memcpy(&quoteBlob[offset], compDigest, sizeof(compDigest));
	offset+= sizeof(compDigest);
	memcpy(&quoteBlob[offset], extData2,   sizeof(extData2));
	offset+= sizeof(extData2);

	/* Set up buffers of the blob and signature */
	logfprintf(stderr, "Total size of blob is %zu\n", offset);
	SET_TPM_BUFFER(&blobBuf, quoteBlob, sizeof(quoteBlob));
	SET_TPM_BUFFER(&signatureBuf, dqi->signature, sizeof(dqi->signature)); 

	dump_bytes(pubKeyData.pubKey.modulus, "Public Key", 256);

	ret = TPM_ValidateSignature(sigscheme, 
				    &blobBuf,
				    &signatureBuf, 
				    pubKeyRSA); 
	if (ret != 0) {
		return ret;
	}

	return 0;

}




/****************************************************************************/
/*                                                                          */
/* DEEPLY Quote the specified PCR registers                                 */
/*                                                                          */
/* The arguments are...                                                     */
/*                                                                          */
/* keyhandle is the handle of the key used to sign the results              */
/* tps       selection of the PCRs to quote                                 */
/* keyauth   is the authorization data (password) for the key               */
/*           if NULL, it will be assumed that no password is required       */
/* data      is a pointer to a nonce                                        */
/* tpc       is a pointer to an area to receive a pcrcomposite structure    */
/* signature is a pointer to an area to receive the signature               */
/*                                                                          */
/****************************************************************************/
uint32_t TPM_DeepQuote(unsigned char *keyauth,
		       unsigned char *externalData,
                       TPM_PCR_SELECTION *vtps,
                       TPM_PCR_SELECTION *ptps,
		       DeepQuoteInfo *dqi)
{
	
	uint32_t ret;
	int i, j;
	uint32_t sessHandle;
	unsigned char c;
	uint32_t keyhandle;
	uint32_t extraInfo= htonl(VTPM_QUOTE_FLAGS_HASH_UUID);
	STACK_TPM_BUFFER( tpmdata );
	session sess;
	unsigned char nonceodd[TPM_NONCE_SIZE];
	unsigned char pubauth[TPM_HASH_SIZE];
	uint32_t ordinal = htonl(TPM_ORD_DeepQuote);
	uint32_t offset;
	uint32_t pcrOffset;	
	uint32_t infoHashOffset;
	STACK_TPM_BUFFER( ptSel );
	STACK_TPM_BUFFER( vtSel );
	uint32_t numPCR = 0;
	uint32_t numInfoHashes = 0;
	uint32_t paramSize = 0;

	/* Auth is done against TPM_KH_OWNER */
	keyhandle = TPM_KH_OWNER;	

	/* check input arguments */
	if (externalData == NULL || keyauth == NULL || dqi == NULL)  
		return ERR_NULL_ARG;

	/* Validate key */
	ret = needKeysRoom(keyhandle, 0, 0, 0);
	if (ret != 0) 
		return ret;

	/* Create selection for physical PCRs */
	ret = TPM_WritePCRSelection(&ptSel, ptps);
	if ((ret & ERR_MASK)) {
		fprintf(stderr, "Failed to create phys. PCR selection [%s]\n", TPM_GetErrMsg(ret));
		return ret;
	}

	/* Create selection for virtual PCRs */
	ret = TPM_WritePCRSelection(&vtSel, vtps);
	if ((ret & ERR_MASK)) {
		fprintf(stderr, "Failed to create virt. PCR selection [%s]\n", TPM_GetErrMsg(ret));		
		return ret;
	}

	/* Requested PCRs */
	for (i=0; i < ptps->sizeOfSelect; i++) {
		BYTE selectByte = ptps->pcrSelect[i];
		for(j = 0; j < 8; j++) {
			numPCR += selectByte & 1;
			selectByte = selectByte >> 1;
		}
	}
	logfprintf(stderr, "Num PCRs selected: %d\n", numPCR);
	

	/* Open an __OIAP__ session. This bit me good as TPM_Quote can be used via 
	 * plain ORD commands, OSAP, or DSAP, while DeepQuote as currently implemented
	 * only supports OIAP*/
	ret = TSS_SessionOpen(SESSION_OIAP, &sess, keyauth,TPM_ET_KEYHANDLE,keyhandle);
	if (ret != 0)  {
		fprintf(stderr, "Failed to auth [%s]\n", TPM_GetErrMsg(ret));
		return ret;
	}
	
	/* Get session handle */
	sessHandle = TSS_Session_GetHandle(&sess);
	/* Don't continue session */
	c = 0;
	/* Generate odd nonce */
	TSS_gennonce(nonceodd);

	/* calculate authorization HMAC value */
	ret = TSS_authhmac(pubauth,TSS_Session_GetAuth(&sess),
			   TPM_HASH_SIZE,TSS_Session_GetENonce(&sess),nonceodd,c,
			   TPM_U32_SIZE,&ordinal,
			   TPM_HASH_SIZE,externalData,
			   vtSel.used, vtSel.buffer,
			   ptSel.used, ptSel.buffer,
			   TPM_U32_SIZE, &extraInfo,
			   0,0);
	if (ret != 0) {
		fprintf(stderr, "Failed to generate HMAC [%s]\n", TPM_GetErrMsg(ret));;
		TSS_SessionClose(&sess);
		return ret;
	}
	

	// <header> 0:ord 1:ext 2:vtps 3:ptps 4:extraInfo 5:sessHandle 6:oddNonce 7:continue 8:hmac
	// 00 C2 T  l     %     %      %      l           L            %          o          %
	ret = TSS_buildbuff("00 C2 T l % % % l L % o %", 
			    &tpmdata,         /* dest buffer             */
			    ordinal,          /* [0] T:     <ord>        */
			    TPM_HASH_SIZE,    /* [1] %.len: <ext>        */
			    externalData,     /* [1] %.buf: <ext>        */
			    vtSel.used,       /* [2] %.len: <vtSel       */
			    vtSel.buffer,     /* [2] %.buf: <vtSel       */
			    ptSel.used,       /* [3] %.len: <ptSel>      */
			    ptSel.buffer,     /* [3] %.buf: <ptSel>      */
			    extraInfo,        /* [4] l:     <extraInfo>  */			    
			    sessHandle,       /* [5] L:     <sessHandle> */
			    TPM_NONCE_SIZE,   /* [6] %.len: <oddNonce>   */
			    nonceodd,         /* [6] %.buf: <oddNonce>   */
			    c,                /* [7] o:     <continue>   */
			    TPM_HASH_SIZE,    /* [8] %.len  <pubauth>    */
			    pubauth           /* [8] %.buf  <pubauth>    */
			    );

	if ((ret & ERR_MASK) != 0) {
		fprintf(stderr, "Failed to build buffer [%s]\n", TPM_GetErrMsg(ret));
		TSS_SessionClose(&sess);
		return ret;
	}

	/* transmit the request buffer to the TPM device and read the reply */
	ret = TPM_Transmit(&tpmdata,"Deep Quote");
	TSS_SessionClose(&sess);
	if (ret != 0) {
		fprintf(stderr, "Unable to transmit to TPM [%s]\n", TPM_GetErrMsg(ret));
		return ret;
	}

	ret =  tpm_buffer_load32(&tpmdata,TPM_PARAMSIZE_OFFSET, &paramSize);
	if (ret != 0) {
		fprintf(stderr, "Unable to read paramSize [%s]\n", TPM_GetErrMsg(ret));
		return ret;
	}
	logfprintf(stderr, "Size is %du\n", paramSize);
	
	/* Header and signature blob */
	offset  = 10 + 256;
		
	infoHashOffset = offset;
	/* extraInfo hashes */
	if (extraInfo & htonl(VTPM_QUOTE_FLAGS_HASH_UUID)) {
		offset += 20;
		numInfoHashes++;
	}
	if (extraInfo & htonl(VTPM_QUOTE_FLAGS_VTPM_MEASUREMENTS)) {
		offset += 20;
		numInfoHashes++;
	}
	if (extraInfo & htonl(VTPM_QUOTE_FLAGS_GROUP_INFO)) {
		offset += 20;
		numInfoHashes++;
	}
	if (extraInfo & htonl(VTPM_QUOTE_FLAGS_GROUP_PUBKEY)) {
		offset += 20;
		numInfoHashes++;
	}
	
	pcrOffset = offset;
	offset += numPCR * sizeof(TPM_PCRVALUE);
	logfprintf(stderr, "Size of return data %d\n", offset);

	/* check the HMAC in the response */
	ret = TSS_checkhmac1(&tpmdata,ordinal,nonceodd,
			     TSS_Session_GetAuth(&sess),TPM_HASH_SIZE,
			     offset-TPM_DATA_OFFSET, TPM_DATA_OFFSET,
			     0,0);

	if ((ret & ERR_MASK)) {
		fprintf(stderr, "Failed to validate hmac [%s]\n", TPM_GetErrMsg(ret));
		return ret;
	}

	if (pcrOffset != (infoHashOffset + (numInfoHashes * 20))) {
		fprintf(stderr, "Inconsistent offsets. pcrOff: %x, infoHashOff: %x, numInfo: %u, numPCR %u\n",
			pcrOffset, infoHashOffset, numInfoHashes, numPCR);
		return -1;
	}

	dqi->extraInfoFlags[0] = extraInfo >> 24;
	dqi->extraInfoFlags[1] = extraInfo >> 16;
	dqi->extraInfoFlags[2] = extraInfo >>  8;
	dqi->extraInfoFlags[3] = extraInfo >>  0;

	dqi->values.numInfoHashes = numInfoHashes;
	memcpy(dqi->values.infoHashes, &tpmdata.buffer[infoHashOffset], numInfoHashes * TPM_HASH_SIZE);

	dqi->values.numPCRVals = numPCR;	
	memcpy(dqi->values.PCRVals, &tpmdata.buffer[pcrOffset], numPCR * TPM_HASH_SIZE);

	memcpy(dqi->signature, &tpmdata.buffer[TPM_DATA_OFFSET], 256);
	return 0;
}




/****************************************************************************/
/*                                                                          */
/* Quote the specified PCR registers  (2nd function)                        */
/*                                                                          */
/* The arguments are...                                                     */
/*                                                                          */
/* keyhandle is the handle of the key used to sign the results              */
/* pcrmap    is a 32 bit integer containing a bit map of the PCR register   */
/*           numbers to be used when sealing. e.g 0x0000001 specifies       */
/*           PCR 0. 0x00000003 specifies PCR's 0 and 1, etc.                */
/* keyauth   is the authorization data (password) for the key               */
/*           if NULL, it will be assumed that no password is required       */
/* data      is a pointer to the data to be sealed  (20 bytes)              */
/* pcrcompos is a pointer to an area to receive a pcrcomposite structure    */
/* blob      is a pointer to an area to receive the signed data             */
/* bloblen   is a pointer to an integer which will receive the length       */
/*           of the signed data                                             */
/*                                                                          */
/****************************************************************************/
uint32_t TPM_Quote2(uint32_t keyhandle,
                    TPM_PCR_SELECTION * selection,
                    TPM_BOOL addVersion,
                    unsigned char *keyauth,
                    unsigned char *antiReplay,
                    TPM_PCR_INFO_SHORT * pcrinfo,
                    struct tpm_buffer *versionblob,
                    struct tpm_buffer *signature)
{
	uint32_t ret;
	uint32_t rc;
	STACK_TPM_BUFFER( tpmdata )
	session sess;
	unsigned char pubauth[TPM_HASH_SIZE];
	unsigned char nonceodd[TPM_NONCE_SIZE];
	unsigned char c = 0;
	uint32_t ordinal_no = htonl(TPM_ORD_Quote2);
	uint16_t pcrselsize;
	uint32_t verinfosize;
	uint32_t sigsize;
	uint32_t storedsize;
	uint32_t keyhndl = htonl(keyhandle);
	uint16_t keytype;
	struct tpm_buffer * serPCRSelection;
	uint32_t serPCRSelectionSize;

	/* check input arguments */
	if (pcrinfo   == NULL ||
	    selection == NULL ||
	    antiReplay == NULL) return ERR_NULL_ARG;
	keytype = 0x0001;

	ret = needKeysRoom(keyhandle, 0, 0, 0);
	if (ret != 0) {
		return ret;
	}

	TSS_gennonce(antiReplay);

	serPCRSelection = TSS_AllocTPMBuffer(TPM_U16_SIZE +
	                                     selection->sizeOfSelect);
	if (NULL == serPCRSelection) {
		return ERR_MEM_ERR;
	}

	ret = TPM_WritePCRSelection(serPCRSelection, selection);
	if (( ret & ERR_MASK) != 0) {
		TSS_FreeTPMBuffer(serPCRSelection);
		return ret;
	}
	serPCRSelectionSize = ret;

	if (keyauth != NULL) {
		/* Open OSAP Session */
		ret = TSS_SessionOpen(SESSION_OSAP|SESSION_DSAP,&sess,keyauth,keytype,keyhandle);
		if (ret != 0)  {
			TSS_FreeTPMBuffer(serPCRSelection);
			return ret;
		}
		/* generate odd nonce */
		TSS_gennonce(nonceodd);
		/* move Network byte order data to variables for hmac calculation */

		/* calculate authorization HMAC value */
		ret = TSS_authhmac(pubauth,TSS_Session_GetAuth(&sess),TPM_HASH_SIZE,TSS_Session_GetENonce(&sess),nonceodd,c,
		                   TPM_U32_SIZE,&ordinal_no,
		                   TPM_HASH_SIZE,antiReplay,
		                   serPCRSelectionSize, serPCRSelection->buffer,
		                   sizeof(TPM_BOOL), &addVersion,
		                   0,0);
		if (ret != 0) {
			TSS_FreeTPMBuffer(serPCRSelection);
			TSS_SessionClose(&sess);
			return ret;
		}
		/* build the request buffer */
		ret = TSS_buildbuff("00 C2 T l l % % o L % o %",&tpmdata,
				    ordinal_no,
				    keyhndl,
				    TPM_HASH_SIZE,antiReplay,
				    serPCRSelectionSize,serPCRSelection->buffer,
				    addVersion,
				    TSS_Session_GetHandle(&sess),
				    TPM_NONCE_SIZE,nonceodd,
				    c,
		                                             TPM_HASH_SIZE,pubauth);
		TSS_FreeTPMBuffer(serPCRSelection);
		if ((ret & ERR_MASK) != 0) {
			TSS_SessionClose(&sess);
			return ret;
		}
		/* transmit the request buffer to the TPM device and read the reply */
		ret = TPM_Transmit(&tpmdata,"Quote2 - AUTH1");
		TSS_SessionClose(&sess);
		if (ret != 0) {
			return ret;
		}
	} else {
		/* build the request buffer */
		ret = TSS_buildbuff("00 C1 T l l % % o",&tpmdata,
		                             ordinal_no,
		                               keyhndl,
		                                 TPM_HASH_SIZE,antiReplay,
		                                   serPCRSelectionSize,serPCRSelection->buffer,
		                                     addVersion);
		TSS_FreeTPMBuffer(serPCRSelection);
		if ((ret & ERR_MASK) != 0) {
			TSS_SessionClose(&sess);
			return ret;
		}

		/* transmit the request buffer to the TPM device and read the reply */
		ret = TPM_Transmit(&tpmdata,"Quote2");
		TSS_SessionClose(&sess);
		if (ret != 0) {
			return ret;
		}
	}
	/* calculate the size of the returned Blob */
        ret =  tpm_buffer_load16(&tpmdata,TPM_DATA_OFFSET, &pcrselsize);
        if ((ret & ERR_MASK)) {
        	return ret;
        }
        pcrselsize += TPM_U16_SIZE + 1 + TPM_HASH_SIZE;
	ret =  tpm_buffer_load32(&tpmdata, TPM_DATA_OFFSET + pcrselsize, &verinfosize);
	if ((ret & ERR_MASK)) {
		return ret;
	}
	ret  =  tpm_buffer_load32(&tpmdata, TPM_DATA_OFFSET + pcrselsize + TPM_U32_SIZE + verinfosize, &sigsize);
	if ((ret & ERR_MASK)) {
		return ret;
	}
	
	storedsize   = pcrselsize + TPM_U32_SIZE + verinfosize +
	                            TPM_U32_SIZE + sigsize;

	if (keyauth != NULL) {
		/* check the HMAC in the response */
		ret = TSS_checkhmac1(&tpmdata,ordinal_no,nonceodd,TSS_Session_GetAuth(&sess),TPM_HASH_SIZE,
		                     storedsize,TPM_DATA_OFFSET,
		                     0,0);
		if (ret != 0) {
			return ret;
		}
	}
	/* copy the returned PCR composite to caller */
	
	if (pcrselsize != (rc = 
	     TPM_ReadPCRInfoShort(&tpmdata, TPM_DATA_OFFSET,
	                          pcrinfo))) {
		if ((rc & ERR_MASK)) 
			return rc;
		return ERR_BUFFER;
	}
	
	if (NULL != versionblob) {
		SET_TPM_BUFFER(
		       versionblob,
		       &tpmdata.buffer[TPM_DATA_OFFSET+pcrselsize+TPM_U32_SIZE],
		       verinfosize);
	}
	
	if (NULL != signature) {
		SET_TPM_BUFFER(signature,
		       &tpmdata.buffer[TPM_DATA_OFFSET+pcrselsize+TPM_U32_SIZE+verinfosize+TPM_U32_SIZE],
		       sigsize);
	}

	return ret;
}
             

/****************************************************************************/
/*                                                                          */
/*  Read PCR value                                                          */
/*                                                                          */
/****************************************************************************/
uint32_t TPM_PcrRead(uint32_t pcrindex, unsigned char *pcrvalue)
   {
   uint32_t ret;
   STACK_TPM_BUFFER(tpmdata)
   
   if (pcrvalue == NULL) return ERR_NULL_ARG;
   ret = TSS_buildbuff("00 c1 T 00 00 00 15 L",&tpmdata,pcrindex);
   if ((ret & ERR_MASK) != 0 ) return ret;
   ret = TPM_Transmit(&tpmdata,"PCRRead");
   if (ret != 0) return ret;
   memcpy(pcrvalue,
          &tpmdata.buffer[TPM_DATA_OFFSET],
          TPM_HASH_SIZE);
   return 0;
   }

/****************************************************************************/
/*                                                                          */
/*  Create PCR_INFO structure using current PCR values                      */
/*                                                                          */
/****************************************************************************/
uint32_t TSS_GenPCRInfo(uint32_t pcrmap, unsigned char *pcrinfo, uint32_t *len)
   {
   struct pcrinfo
      {
      uint16_t selsize;
      unsigned char select[TPM_PCR_MASK_SIZE];
      unsigned char relhash[TPM_HASH_SIZE];
      unsigned char crthash[TPM_HASH_SIZE];
      } myinfo;
   uint32_t i;
   int j;
   uint32_t work;
   unsigned char *valarray;
   uint32_t numregs;
   uint32_t ret;
   uint32_t valsize;
   SHA_CTX sha;
   
   
   /* check arguments */
   if (pcrinfo == NULL || len == NULL) return ERR_NULL_ARG;
   /* build pcr selection array */
   work = pcrmap;
   memset(myinfo.select,0,TPM_PCR_MASK_SIZE);
   for (i = 0; i < TPM_PCR_MASK_SIZE; ++i)
      {
      myinfo.select[i] = work & 0x000000FF;
      work = work >> 8;
      }
   /* calculate number of PCR registers requested */
   numregs = 0;
   work = pcrmap;
   for (i = 0; i < (TPM_PCR_MASK_SIZE * 8); ++i)
      {
      if (work & 1) ++numregs;
      work = work >> 1;
      }
   if (numregs == 0)
      {
      *len = 0;
      return 0;
      }
   /* create the array of PCR values */
   valarray = (unsigned char *)malloc(TPM_HASH_SIZE * numregs);
   /* read the PCR values into the value array */
   work = pcrmap;
   j = 0;
   for (i = 0; i < (TPM_PCR_MASK_SIZE * 8); ++i, work = work >> 1)
      {
      if ((work & 1) == 0) continue;
      ret = TPM_PcrRead(i,&(valarray[(j*TPM_HASH_SIZE)]));
      if (ret) return ret;
      ++j;
      }
   myinfo.selsize = ntohs(TPM_PCR_MASK_SIZE);
   valsize = ntohl(numregs * TPM_HASH_SIZE);
   /* calculate composite hash */
   SHA1_Init(&sha);
   SHA1_Update(&sha,&myinfo.selsize,TPM_U16_SIZE);
   SHA1_Update(&sha,&myinfo.select,TPM_PCR_MASK_SIZE);
   SHA1_Update(&sha,&valsize,TPM_U32_SIZE);
   for (i = 0;i < numregs;++i)
      {
      SHA1_Update(&sha,&(valarray[(i*TPM_HASH_SIZE)]),TPM_HASH_SIZE);
      }
   SHA1_Final(myinfo.relhash,&sha);
   memcpy(myinfo.crthash,myinfo.relhash,TPM_HASH_SIZE);
   memcpy(pcrinfo,&myinfo,sizeof (struct pcrinfo));
   *len = sizeof (struct pcrinfo);
   return 0;
   }


/****************************************************************************/
/*                                                                          */
/* Reset the indicated PCRs                                                 */
/*                                                                          */
/* The arguments are...                                                     */
/*                                                                          */
/* pcrmap : The selection of PCRs to reset as 32 bit bitmap                 */
/*                                                                          */
/****************************************************************************/
uint32_t TPM_PCRReset(TPM_PCR_SELECTION * selection)
{
	uint32_t ret;
	uint32_t ordinal_no = htonl(TPM_ORD_PCR_Reset);
	STACK_TPM_BUFFER(tpmdata)
	struct tpm_buffer *serPCRMap = TSS_AllocTPMBuffer(TPM_U16_SIZE + selection->sizeOfSelect + 10);
	uint32_t serPCRMapSize;

	if (NULL == serPCRMap) {
		return ERR_MEM_ERR;
	}

	ret = TPM_WritePCRSelection(serPCRMap, selection);
	if ((ret & ERR_MASK) != 0) {
		TSS_FreeTPMBuffer(serPCRMap);
		return ret;
	}
	serPCRMapSize = ret;

	ret = TSS_buildbuff("00 c1 T l %",&tpmdata,
                                     ordinal_no,
                                       serPCRMapSize, serPCRMap->buffer);

	TSS_FreeTPMBuffer(serPCRMap);
	if ((ret & ERR_MASK)) {
		return ret;
	}
	ret = TPM_Transmit(&tpmdata,"PCR Reset");

	return ret;
}

