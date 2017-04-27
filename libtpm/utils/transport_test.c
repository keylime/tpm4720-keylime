/********************************************************************************/
/*										*/
/*			        Transport Test   				*/
/*			     Written by Stefan Berger				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*	      $Id: transport_test.c 4702 2013-01-03 21:26:29Z kgoldman $	*/
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
#include <sys/types.h>
#include <sys/stat.h>

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

/* local prototypes */

static void usage() {
	printf("Usage: transport_test -ek <handle> [-ekp <pwd>]\n"
	       "                      -sk <handle> [-skp <pwd>]\n"
	       "                      [-tp <pwd>]\n"
	       "\n"
	       " -ek <handle>  : encryption key handle\n"
	       " -ekp <pwd>    : encryption key password\n"
	       " -sk <handle>  : signing key handle\n"
	       " -skp <pwd>    : signing key password\n"
	       " -tp <pwd>     : password for the transport\n");
}

int main(int argc, char * argv[]) {
	int i = 0;
	uint32_t ret = 0;
	TPM_TRANSPORT_PUBLIC ttp;
	uint32_t keyhandle = 0;
	char *keypass = NULL;
	unsigned char keypassHash[TPM_HASH_SIZE];
	unsigned char *keyPassHashPtr = NULL;
	uint32_t sigkeyhandle = 0;
	char *sigkeypass = NULL;
	unsigned char sigkeypassHash[TPM_HASH_SIZE];
	unsigned char *sigkeyPassHashPtr = NULL;
	char *transpass = "test";
	unsigned char transpassHash[TPM_HASH_SIZE];
	unsigned char *transPassHashPtr = NULL;
	STACK_TPM_BUFFER( secret );
	STACK_TPM_BUFFER( buffer );
	TPM_CURRENT_TICKS currentTicks;
	session transSession;
	RSA *rsa;
	pubkeydata pubkey;
	TPM_TRANSPORT_AUTH tta;
	
	i = 1;
	
	TPM_setlog(0);
	
	while (i < argc) {
		if (!strcmp("-ek",argv[i])) {
			i++;
			if (i >= argc) {
				printf("Missing parameter for -ek.\n");
				exit(-1);
			}
			if (1 != sscanf(argv[i],"%x",&keyhandle)) {
				printf("Could not parse the encryption key keyhandle.\n");
				exit(-1);
			}
		} else
		if (!strcmp("-ekp",argv[i])) {
			i++;
			if (i >= argc) {
				printf("Missing parameter for -ekp.\n");
				exit(-1);
			}
			keypass = argv[i];
		} else
		if (!strcmp("-sk",argv[i])) {
			i++;
			if (i >= argc) {
				printf("Missing parameter for -sk.\n");
				exit(-1);
			}
			if (1 != sscanf(argv[i],"%x",&sigkeyhandle)) {
				printf("Could not parse the signing key keyhandle.\n");
				exit(-1);
			}
		} else
		if (!strcmp("-skp",argv[i])) {
			i++;
			if (i >= argc) {
				printf("Missing parameter for -skp.\n");
				exit(-1);
			}
			sigkeypass = argv[i];
		} else
		if (!strcmp("-tp",argv[i])) {
			i++;
			if (i >= argc) {
				printf("Missing parameter for -tp.\n");
				exit(-1);
			}
			transpass = argv[i];
		} else
		if (!strcmp("-v",argv[i])) {
			TPM_setlog(1);
		} else
		if (!strcmp("-h",argv[i])) {
		        usage();
		        exit(-1);

		} else {
		        printf("\n%s is not a valid option\n", argv[i]);
			usage();
			exit(-1);
		}
		i++;
	}
	
	if (keyhandle == 0) {
		printf("You must provide a keyhandle for the encryption key.\n");
		usage();
		exit(-1);
	}
	if (sigkeyhandle == 0) {
		printf("You must provide a keyhandle for the signing key.\n");
		usage();
		exit(-1);
	}

	if (NULL != keypass) {
		TSS_sha1(keypass, strlen(keypass), keypassHash);
		keyPassHashPtr = keypassHash;
	}
	if (NULL != sigkeypass) {
		TSS_sha1(sigkeypass, strlen(sigkeypass), sigkeypassHash);
		sigkeyPassHashPtr = sigkeypassHash;
	}
	
	if (NULL != transpass) {
		TSS_sha1(transpass, strlen(transpass), transpassHash);
		transPassHashPtr = transpassHash;
	}


	/*
	 * Get the public key associate with the given handle
	 * Will use that key to encrypt the transport authorization
	 */
	ret = TPM_GetPubKey(keyhandle, 
	                    keyPassHashPtr,
	                    &pubkey);

	if (ret != 0) {
		printf("transport_test: Error '%s' from TPM_GetPubKey(0x%08x)\n",
		       TPM_GetErrMsg(ret),
		       keyhandle);
		exit(-1);
	}
	rsa = TSS_convpubkey(&pubkey);

	if (NULL == rsa) {
		printf("Could not convert the key into an RSA structure.\n");
		exit(-1);
	}
	/*
	 * Create the structure with the transport 
	 * authorization
	 */	
	tta.tag = TPM_TAG_TRANSPORT_AUTH;
	for (i = 0; i < TPM_AUTHDATA_SIZE; i++) {
		tta.authData[i] = transpassHash[i];
	}
	/*
	 * Serialize the transport authorization
	 */
	TPM_WriteTransportAuth(&buffer, &tta);

	/*
	 * Encrypt the transport authorization
	 * with the public key belonging to the given handle
	 */
	TSS_Bind(rsa, &buffer, &secret);

	ttp.tag = TPM_TAG_TRANSPORT_PUBLIC;
	ttp.transAttributes = TPM_TRANSPORT_ENCRYPT|TPM_TRANSPORT_LOG;
	_TPM_getTransportAlgIdEncScheme(&ttp.algId, &ttp.encScheme);

	/* env. variable not set? -- we choose */
	if (!ttp.algId)
		ttp.algId = TPM_ALG_MGF1;

	ret = TPM_EstablishTransport(keyhandle,
	                             keyPassHashPtr,
	                             &ttp,
	                             transPassHashPtr,
	                             &secret,
	                             &currentTicks,
	                             &transSession);

	if (ret != 0) {
		printf("Error %s from TPM_EstablishTransport.\n",
		       TPM_GetErrMsg(ret));
	}

	if (ret == 0) {
		uint32_t idx = 1;
		unsigned char antiReplay[TPM_HASH_SIZE];
		unsigned char digest[TPM_HASH_SIZE];
		unsigned char h1[TPM_DIGEST_SIZE];
		STACK_TPM_BUFFER(signature);
		STACK_TPM_BUFFER(tsi_ser);
		TPM_SIGN_INFO tsi;
		pubkeydata pubkey;
		RSA *rsa;
		memset(&tsi, 0x0, sizeof(tsi));
		uint32_t _ret;
		unsigned char transDigest[TPM_DIGEST_SIZE];

		TSS_PushTransportFunction(TPM_ExecuteTransport,
		                          &idx);

		TSS_SetTransportParameters(&transSession, idx);

		_ret = TPM_PcrRead(10, digest);

		TSS_PopTransportFunction(&idx);
		
		if (_ret != 0) {
			printf("Error '%s' from TPM_PcrRead()\n",
			       TPM_GetErrMsg(_ret));
			if (ret == 0) {
				ret = _ret;
			}
		} else {
			printf("PCR Value of Index 10: ");
			for (i = 0 ; i < (int)sizeof(digest); i++) {
				printf("%02x",digest[i]);
			}			
			printf("\n");
		}

		_ret = TPM_ReleaseTransportSigned(sigkeyhandle,
		                                  sigkeyPassHashPtr,
		                                  &transSession,
		                                  antiReplay,
		                                  &signature,
		                                  transDigest);
		if (_ret != 0) {
			printf("Error '%s' from TPM_ReleaseTransportSigned()\n",
			       TPM_GetErrMsg(ret));
			if (ret == 0)
				ret = _ret;
		}
		/* verify the signature */
		tsi.tag = TPM_TAG_SIGNINFO;
		memcpy(tsi.fixed, "TRAN", 4);
		memcpy(tsi.replay, antiReplay, sizeof(antiReplay));
		tsi.data.size = sizeof(transDigest);
		tsi.data.buffer = transDigest;
		_ret = TPM_WriteSignInfo(&tsi_ser,&tsi);
		if (( _ret & ERR_MASK)) {
			printf("Error '%s' while serializing the SIGN_INFO structure.\n",
			       TPM_GetErrMsg(_ret));
			if (ret == 0)
				ret = _ret;
			exit(ret);
		}
		TSS_sha1(tsi_ser.buffer, tsi_ser.used, h1);
		
		_ret = TPM_GetPubKey(sigkeyhandle,
		                    sigkeyPassHashPtr,
		                    &pubkey);
		if (_ret != 0) {
			printf("transport_test: Error %s from TPM_GetPubKey(0x%08x).\n",
			       TPM_GetErrMsg(_ret),
			       sigkeyhandle);
			if (ret == 0) {
				ret = _ret;
			}
			exit(ret);
		}

		rsa = TSS_convpubkey(&pubkey);
		if (NULL == rsa) {
			printf("Could not convert key into RSA format.\n");
			exit(-1);
		}

		ret = TPM_ValidateSignature(TPM_SS_RSASSAPKCS1v15_SHA1,
		                            &tsi_ser,
		                            &signature,
		                            rsa);
		if (ret != 0) {
			printf("Signature verification failed.\n");
		}
	}

	RSA_free(rsa);

	exit(ret);
}
