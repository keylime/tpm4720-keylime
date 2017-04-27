/********************************************************************************/
/*										*/
/*			         Session handling : opening,closing 		*/
/*			     Written by Stefan Berger				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*	      $Id: session.c 4702 2013-01-03 21:26:29Z kgoldman $		*/
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

#include <tpm.h>
#include <tpmutil.h>
#include <tpmfunc.h>
#include <tpm_constants.h>
#include <tpm_structures.h>
#include <oiaposap.h>
#include <tpm_types.h>
#include <tpm_constants.h>
#include <tpm_error.h>
#include <hmac.h>

enum {
	ACTION_OPEN = 0,
	ACTION_CLOSE,
	ACTION_TEST
};

/*  local function prototypes */
static uint32_t TestOSAPOwner(session *sess);
static uint32_t TestDSAPOwner(session *sess);
static uint32_t TestOSAPKey(session *sess, uint32_t keyhandle);

static void usage(void) {
	printf("Usage: session oiap|osap|dsap|transport|daa [close <id>] [Options]\n"
	       "\n"
	       "Options are:\n"
	       "owner <owner password>    : to use owner password\n"
	       "key <keyhandle>           : to use a key handle\n"
	       "keypass <password>        : password for the key given with 'key'\n"
	       "srkpass <password>        : shortcut for specifying the SRK's password\n"
	       "                            it's not necessary to provide 'key'\n"
	       "row <row, delg. owner pwd>: in connection with DSAP session type this\n"
	       "                            allows to specify a row in the delegation\n"
	       "                            table; also need delegate owner pwd.\n"
	       "test <id> <owner|...>     : to test a session with a given id\n"
	       "     <enonce> <ssecret>     that uses an owner or ... password\n"
	       "-ek                       : handle of encryption key; mandatory when using 'transport'.\n"
	       "-ekp                      : password for encryption key\n"
	       "\n");
}

static uint32_t 
createTransport(uint32_t ekhandle,
                unsigned char *keyPassHashPtr,
                unsigned char *transPassHashPtr,
                session *transSession)
{
	uint32_t ret;
	TPM_TRANSPORT_PUBLIC ttp;
	TPM_TRANSPORT_AUTH tta;
	TPM_CURRENT_TICKS currentTicks;
	int i;
	STACK_TPM_BUFFER(buffer);
	STACK_TPM_BUFFER(secret);
	RSA *rsa;
	pubkeydata pubkey;
	
	ttp.tag = TPM_TAG_TRANSPORT_PUBLIC;
	ttp.transAttributes = TPM_TRANSPORT_ENCRYPT|TPM_TRANSPORT_LOG;
	_TPM_getTransportAlgIdEncScheme(&ttp.algId, &ttp.encScheme);

	/* env. variable not set? -- we choose */
	if (!ttp.algId)
		ttp.algId = TPM_ALG_MGF1;

	ret = TPM_GetPubKey(ekhandle,
			     keyPassHashPtr,
			     &pubkey);

	if (ret != 0) {
		return ret;
	}
	rsa = TSS_convpubkey(&pubkey);
	
	tta.tag = TPM_TAG_TRANSPORT_AUTH;
	for (i = 0; i < TPM_AUTHDATA_SIZE; i++ ) {
		tta.authData[i] = transPassHashPtr[i];
	}
	TPM_WriteTransportAuth(&buffer, &tta);

	TSS_Bind(rsa, &buffer, &secret);

	ret = TPM_EstablishTransport(ekhandle,
				     keyPassHashPtr,
				     &ttp,
				     transPassHashPtr,
				     &secret,
				     &currentTicks,
				     transSession);
	return ret;
}

int main(int argc, char * argv[]) {
	int i = 1;
	unsigned int type = 0;
	char *password = NULL;
	char *pwdtype = NULL;
	unsigned char passHash[TPM_HASH_SIZE];
	unsigned int passwd_type = 0;
	unsigned int id;
	int ret = 0;
	int action = ACTION_OPEN;
	session sess;
	unsigned char *tmp;
	unsigned char enonce[TPM_HASH_SIZE];
	unsigned char ssecret[TPM_HASH_SIZE];
	uint32_t ekhandle = 0;
	char *keyPass = NULL;
	uint32_t keyhandle = 0;

	TPM_setlog(0);

	while (i < argc) {
		if (!strcmp("owner",argv[i])) {
			i++;
			if (i >= argc) {
				printf("Missing owner password!\n");
				usage();
				exit(-1);
			}
			password = argv[i];
			TSS_sha1(password, strlen(password), passHash);
			passwd_type = TPM_ET_OWNER;
		} else
		if (!strcmp("key",argv[i])) {
			i++;
			if (i >= argc) {
				printf("Missing key handle!\n");
				usage();
				exit(-1);
			}
			if (1 != sscanf(argv[i], "%x", &keyhandle)) {
				printf("Could not scan the keyhandle.\n");
				exit(-1);
			}
		} else
		if (!strcmp("row",argv[i])) {
			i++;
			if (i >= argc) {
				printf("Missing row index!\n");
				usage();
				exit(-1);
			}
			/*
			   use the keyhandle for DSAP session establishment
			   since it is not used in the TPM_DSAP command
			   when using TPM_ET_DEL_ROW.
			 */
			if (1 != sscanf(argv[i], "%x", &keyhandle)) {
				printf("Could not scan the keyhandle.\n");
				exit(-1);
			}
			i++;
			if (i >= argc) {
				printf("Missing owner password!\n");
				usage();
				exit(-1);
			}
			password = argv[i];
			TSS_sha1(password, strlen(password), passHash);
			passwd_type = TPM_ET_DEL_ROW;
		} else
		if (!strcmp("keypass",argv[i])) {
			i++;
			if (i >= argc) {
				printf("Missing key password!\n");
				usage();
				exit(-1);
			}
			password = argv[i];
			TSS_sha1(password, strlen(password), passHash);
			passwd_type = TPM_ET_KEYHANDLE;
		} else
		if (!strcmp("srkpass",argv[i])) {
			i++;
			if (i >= argc) {
				printf("Missing SRK key password!\n");
				usage();
				exit(-1);
			}
			password = argv[i];
			TSS_sha1(password, strlen(password), passHash);
			passwd_type = TPM_ET_SRK;
		} else
		if (!strcmp("test",argv[i])) {
			i++;
			if (i >= argc) {
				printf("Missing id!\n");
				usage();
				exit(-1);
			}
			if (1 != sscanf(argv[i],"%x",&id)) {
				printf("Could not read session id "
				       "from parameter '%s'.\n",
				       argv[i]);
				exit(-1);
			}
			i++;
			if (i >= argc) {
				printf("Missing password type!\n");
				usage();
				exit(-1);
			}
			pwdtype = argv[i];
			i++;
			if (i >= argc) {
				printf("Missing even nonce!\n");
				usage();
				exit(-1);
			}
			if (0 != parseHash(argv[i], enonce)) {
				printf("Error parsing nonce.\n");
				exit(-1);
			}
			
			i++;
			if (i >= argc) {
				printf("Missing session secret!\n");
				usage();
				exit(-1);
			}
			if (0 != parseHash(argv[i], ssecret)) {
				printf("Error parsing session secret.\n");
				exit(-1);
			}
			action = ACTION_TEST;
		} else
		if (!strcmp("osap",argv[i])) {
			type = SESSION_OSAP;
		} else
		if (!strcmp("oiap",argv[i])) {
			type = SESSION_OIAP;
		} else
		if (!strcmp("dsap",argv[i])) {
			type = SESSION_DSAP;
		} else
		if (!strcmp("transport",argv[i])) {
			type = SESSION_TRAN;
		} else
		if (!strcmp("daa",argv[i])) {
			type = SESSION_DAA;
		} else
		if (!strcmp("close",argv[i])) {
			i++;
			if (i >= argc) {
				printf("Missing session number!\n");
				usage();
				exit(-1);
			}
			if (1 != sscanf(argv[i],"%x",&id)) {
				printf("Could not read session id "
				       "from parameter '%s'.\n",
				       argv[i]);
				exit(-1);
			}
			action = ACTION_CLOSE;
		} else
		if (!strcmp("-ek",argv[i])) {
			i++;
			if (i >= argc) {
				printf("Missing argument for '-ek'.\n");
				exit(-1);
			}
			if (1 != sscanf(argv[i],"%x",&ekhandle)) {
				printf("Could not read encryption key handle.\n");
				exit(-1);
			}
		} else
		if (!strcmp("-ekp",argv[i])) {
			i++;
			if (i >= argc) {
				printf("Missing argument for '-ekp'.\n");
				exit(-1);
			}
			keyPass = argv[i];
		} else
		if (!strcmp("-v",argv[i])) {
			TPM_setlog(1);
		} else {
			printf("\n%s is not a valid option\n", argv[i]);
			usage();
			exit(-1);
		}
		i++;
	}
	
	if (type == 0) {
		printf("Missing parameter oiap|osap|dsap|transport.\n");
		usage();
		exit(-1);
	}
	
	switch (action) {
		case ACTION_OPEN: 
			if (type != SESSION_TRAN &&
			    type != SESSION_DAA) {
				ret = TSS_SessionOpen(type, &sess,
						      passHash,
						      passwd_type,
						      keyhandle);
				if (ret == 0) {
					switch (type) {
						case SESSION_OIAP:
							id = sess.type.oiap.handle;
						break;
						case SESSION_OSAP:
							id = sess.type.osap.handle;
						break;
						case SESSION_DSAP:
							id = sess.type.dsap.handle;
						break;
					}
					printf("Successfully opened session: 0x%08X\n",
					       id);
					printf("Even Nonce: ");
					i = 0;
					tmp = TSS_Session_GetENonce(&sess);
					while (i < TPM_HASH_SIZE) {
						printf("%02X",tmp[i]);
						i++;
					}
					printf("\n");
					printf("Session Secret: ");
					i = 0;
					tmp = TSS_Session_GetAuth(&sess);
					while (i < TPM_HASH_SIZE) {
						printf("%02X",tmp[i]);
						i++;
					}
					printf("\n");
				} else {
					printf("Error %s while opening session.\n",
					       TPM_GetErrMsg(ret));
				}
			} else if (type == SESSION_TRAN) {
				unsigned char keyPassHash[TPM_HASH_SIZE];
				unsigned char transPassHash[TPM_HASH_SIZE];
				char *transPass = "test";
				if (ekhandle == 0 ||
				    keyPass == NULL) {
				    	printf("You must provide '-ek' and '-ekp'.\n");
				    	exit(-1);
				}
				
				TSS_sha1(keyPass, 
					 strlen(keyPass),
					 keyPassHash);
					 
				TSS_sha1(transPass,
					 strlen(transPass),
					 transPassHash);
				
				ret = createTransport(ekhandle,
						      keyPassHash,
						      transPassHash,
						      &sess);
				if (ret == 0) {
					id = sess.type.tran.handle;
					printf("Successfully opened session: 0x%08X\n",
					       id);
					printf("Even Nonce: ");
					i = 0;
					tmp = TSS_Session_GetENonce(&sess);
					while (i < TPM_HASH_SIZE) {
						printf("%02X",tmp[i]);
						i++;
					}
					printf("\n");
					ret = TPM_WriteFile(".enonce",
							    TSS_Session_GetENonce(&sess),
							    TPM_NONCE_SIZE);
					printf("Session Secret: ");
					i = 0;
					tmp = TSS_Session_GetAuth(&sess);
					while (i < TPM_HASH_SIZE) {
						printf("%02X",tmp[i]);
						i++;
					}
					printf("\n");
				} else {
					printf("Error while creating "
					       "transport: '%s'\n",
					       TPM_GetErrMsg(ret));
				}
			} else {
				/* daa session */
				uint32_t inputData0 = 1;
				uint32_t inputData0Size = sizeof(inputData0);
				uint32_t outputData, dummy;
				uint32_t outputDataSize = sizeof(outputData);
				uint32_t dummySize = 0;
				if (passwd_type != TPM_ET_OWNER) {
				       printf("Need owner password for DAA session.\n");
				       break;
				}
				ret = TPM_DAA_Join(0,
						   passHash,
						   0,
						   (unsigned char *)&inputData0, inputData0Size,
						   (unsigned char *)&dummy, dummySize,
						   (unsigned char *)&outputData, &outputDataSize);
				if (ret == 0) {
					uint32_t handle = htonl(outputData);
					printf("Successfully created DAA session: 0x%08X\n",
					       handle);
				} else {
					printf("Error while creating "
					       "DAA session: '%s'\n",
					       TPM_GetErrMsg(ret));
				}
			}
		break;
		
		case ACTION_CLOSE:
			sess.sess_type = type;
			switch (type) {
				case SESSION_OIAP:
					sess.type.oiap.handle = id;
				break;
				case SESSION_OSAP:
					sess.type.osap.handle = id;
				break;
				case SESSION_DSAP:
					sess.type.dsap.handle = id;
				break;
			}
			ret = TSS_SessionClose(&sess);
			if (ret == 0) {
				printf("Successfully closed session.\n");
			} else {
				printf("Error %s while closing session.\n",
				       TPM_GetErrMsg(ret));
			}
		break;
		
		case ACTION_TEST: {
			session sess;
			sess.sess_type = type;
			switch (type) {
				case SESSION_OIAP:
					if (NULL == password) {
						printf("Need a password, i.e., owner password\n");
						exit(-1);
					}
					sess.type.oiap.handle = id;
					memcpy(sess.type.oiap.enonce,
					       enonce,
					       TPM_HASH_SIZE);
					memcpy(sess.authdata,
					       passHash,
					       TPM_AUTHDATA_SIZE);
					if (!strcmp(pwdtype,"owner")) {
						ret = TestOSAPOwner(&sess);
						if (ret == 0) {
							printf("Successfully tested OIAP session.\n");
							printf("Even Nonce: ");
							i = 0;
							tmp = TSS_Session_GetENonce(&sess);
							while (i < TPM_HASH_SIZE) {
								printf("%02X",tmp[i]);
								i++;
							}
							printf("\n");
							printf("Session Secret: ");
							i = 0;
							tmp = TSS_Session_GetAuth(&sess);
							while (i < TPM_HASH_SIZE) {
								printf("%02X",tmp[i]);
								i++;
							}
							printf("\n"); 
						} else {
							printf("Error '%s' from test of OIAP owner session\n",
							       TPM_GetErrMsg(ret));
						}
						
					} else if (!strcmp(pwdtype,"key")) {
						if (0 == keyhandle) {
							printf("Need a keyhandle for this test.");
							
							break;
						}
						ret = TestOSAPKey(&sess,
								  keyhandle);
						if (ret == 0) {
							printf("Successfully tested OIAP session.\n");
							printf("Even Nonce: ");
							i = 0;
							tmp = TSS_Session_GetENonce(&sess);
							while (i < TPM_HASH_SIZE) {
								printf("%02X",tmp[i]);
								i++;
							}
							printf("\n");
							printf("Session Secret: ");
							i = 0;
							tmp = TSS_Session_GetAuth(&sess);
							while (i < TPM_HASH_SIZE) {
								printf("%02X",tmp[i]);
								i++;
							}
							printf("\n"); 
						} else {
							printf("Error '%s' from test of OIAP key session\n",
							       TPM_GetErrMsg(ret));
						}
					}
				break;
				
				case SESSION_OSAP: {
					sess.type.osap.handle = id;
					memcpy(sess.type.osap.ssecret,
					       ssecret,
					       TPM_HASH_SIZE);
					memcpy(sess.type.osap.enonce,
					       enonce,
					       TPM_HASH_SIZE);
					if (!strcmp(pwdtype,"owner")) {
						ret = TestOSAPOwner(&sess);
						if (ret == 0) {
							printf("Successfully tested OSAP session.\n");
							printf("Even Nonce: ");
							i = 0;
							tmp = TSS_Session_GetENonce(&sess);
							while (i < TPM_HASH_SIZE) {
								printf("%02X",tmp[i]);
								i++;
							}
							printf("\n");
							printf("Session Secret: ");
							i = 0;
							tmp = TSS_Session_GetAuth(&sess);
							while (i < TPM_HASH_SIZE) {
								printf("%02X",tmp[i]);
								i++;
							}
							printf("\n"); 
						} else {
							printf("Error '%s' from test of OSAP owner session\n",
							       TPM_GetErrMsg(ret));
						}
					} else if (!strcmp(pwdtype,"key")) {
						if (0 == keyhandle) {
							printf("Need a keyhandle for this test.");
							exit(-1);
						}
						ret = TestOSAPKey(&sess,
								  keyhandle);
						if (ret == 0) {
							printf("Successfully tested OSAP session.\n");
							printf("Even Nonce: ");
							i = 0;
							tmp = TSS_Session_GetENonce(&sess);
							while (i < TPM_HASH_SIZE) {
								printf("%02X",tmp[i]);
								i++;
							}
							printf("\n");
							printf("Session Secret: ");
							i = 0;
							tmp = TSS_Session_GetAuth(&sess);
							while (i < TPM_HASH_SIZE) {
								printf("%02X",tmp[i]);
								i++;
							}
							printf("\n"); 
						} else {
							printf("Error '%s' from test of OSAP key session\n",
							       TPM_GetErrMsg(ret));
						}
					} else {
						printf("Error. Unknown password type.\n");
						usage();
						exit(-1);
					}
				}
				break;
				
				case SESSION_DSAP: {
					sess.type.dsap.handle = id;
					memcpy(sess.type.dsap.ssecret,
					       ssecret,
					       TPM_HASH_SIZE);
					memcpy(sess.type.dsap.enonce,
					       enonce,
					       TPM_HASH_SIZE);
					if (!strcmp(pwdtype,"owner") ||
					    !strcmp(pwdtype,"row")) {
						ret = TestDSAPOwner(&sess);
						if (ret == 0) {
							printf("Successfully tested DSAP session.\n");
							printf("Even Nonce: ");
							i = 0;
							tmp = TSS_Session_GetENonce(&sess);
							while (i < TPM_HASH_SIZE) {
								printf("%02X",tmp[i]);
								i++;
							}
							printf("\n");
							printf("Session Secret: ");
							i = 0;
							tmp = TSS_Session_GetAuth(&sess);
							while (i < TPM_HASH_SIZE) {
								printf("%02X",tmp[i]);
								i++;
							}
							printf("\n"); 
						} else {
							printf("Error '%s' from test of DSAP owner session\n",
							       TPM_GetErrMsg(ret));
						}
					} else if (!strcmp(pwdtype,"key")) {
						if (0 == keyhandle) {
							printf("Need a keyhandle for this test.");
							break;
						}
						ret = TestOSAPKey(&sess,
								  keyhandle);
						if (ret == 0) {
							printf("Successfully tested DSAP session.\n");
							printf("Even Nonce: ");
							i = 0;
							tmp = TSS_Session_GetENonce(&sess);
							while (i < TPM_HASH_SIZE) {
								printf("%02X",tmp[i]);
								i++;
							}
							printf("\n");
							printf("Session Secret: ");
							i = 0;
							tmp = TSS_Session_GetAuth(&sess);
							while (i < TPM_HASH_SIZE) {
								printf("%02X",tmp[i]);
								i++;
							}
							printf("\n"); 
						} else {
							printf("Error '%s' from test of DSAP key session\n",
							       TPM_GetErrMsg(ret));
						}
					} else {
						printf("Error. Unknown password type.\n");
						usage();
						exit(-1);
					}
				}
				break;
				default:
				        printf("Error. No test implemented for this session type.\n");
				        exit(-1);
				break;
			}
		}
		break;
	}
	exit(ret);
}

/*
 * to test an owner OSAP session do the ResetLockValue command
 */
static uint32_t TestOSAPOwner(session *sess)
{
	STACK_TPM_BUFFER(tpmdata)
	uint32_t ordinal_no = htonl(TPM_ORD_ResetLockValue);
	uint32_t ret;
	
	/* check input arguments */

	unsigned char nonceodd[TPM_NONCE_SIZE];
	unsigned char authdata[TPM_NONCE_SIZE];
	TPM_BOOL c = 1;

	/* generate odd nonce */
	ret  = TSS_gennonce(nonceodd);
	if (0 == ret) 
		return ERR_CRYPT_ERR;

	/* move Network byte order data to variable for HMAC calculation */
	ret = TSS_authhmac(authdata,TSS_Session_GetAuth(sess),TPM_HASH_SIZE,TSS_Session_GetENonce(sess),nonceodd,c,
			   TPM_U32_SIZE,&ordinal_no,
			   0,0);

	if (0 != ret) {
		return ret;
	}
	/* build the request buffer */
	ret = TSS_buildbuff("00 c2 T l L % o %", &tpmdata,
				     ordinal_no,
				       TSS_Session_GetHandle(sess),
					 TPM_HASH_SIZE, nonceodd,
					   c,
					     TPM_HASH_SIZE, authdata);
		
	if ((ret & ERR_MASK) != 0) {
		return ret;
	}

	/* transmit the request buffer to the TPM device and read the reply */
	ret = TPM_Transmit(&tpmdata,"ResetLockValue");

	if (ret != 0) {
		return ret;
	}

	/* check the HMAC in the response */
	ret = TSS_checkhmac1New(&tpmdata,ordinal_no,sess,nonceodd,TSS_Session_GetAuth(sess),TPM_HASH_SIZE,
			     0,0);

	return ret;
}


/*
 * to test a key OSAP session do the GetPubKey() command
 */
static uint32_t TestOSAPKey(session *sess, uint32_t keyhandle)
{
	STACK_TPM_BUFFER(tpmdata)
	uint32_t ordinal_no = htonl(TPM_ORD_GetPubKey);
	uint32_t keyhandle_no = htonl(keyhandle);
	uint32_t ret;
	uint32_t size;
	pubkeydata pk;
	
	/* check input arguments */

	unsigned char nonceodd[TPM_NONCE_SIZE];
	unsigned char authdata[TPM_NONCE_SIZE];
	TPM_BOOL c = 1;

	/* generate odd nonce */
	ret  = TSS_gennonce(nonceodd);
	if (0 == ret) 
		return ERR_CRYPT_ERR;

	/* move Network byte order data to variable for HMAC calculation */
	ret = TSS_authhmac(authdata,TSS_Session_GetAuth(sess),
			   TPM_HASH_SIZE,TSS_Session_GetENonce(sess),
			   nonceodd,c,
			   TPM_U32_SIZE,&ordinal_no,
			   0,0);

	if (0 != ret) {
		return ret;
	}
	/* build the request buffer */
	ret = TSS_buildbuff("00 c2 T l l L % o %", &tpmdata,
				     ordinal_no,
				       keyhandle_no,
					 TSS_Session_GetHandle(sess),
					   TPM_HASH_SIZE, nonceodd,
					     c,
					       TPM_HASH_SIZE, authdata);
		
	if ((ret & ERR_MASK) != 0) {
		return ret;
	}

	/* transmit the request buffer to the TPM device and read the reply */
	ret = TPM_Transmit(&tpmdata,"GetPubKey");

	/* if it was the SRK and INVALID_KEYHANDLE is returned, then it's ok */
	if (keyhandle == 0x40000000 && ret == TPM_INVALID_KEYHANDLE) {
		return 0;
	}

	if (ret != 0) {
		return ret;
	}

	/* check the HMAC in the response */
	ret = TSS_PubKeyExtract(&tpmdata, TPM_DATA_OFFSET, &pk);
	if ((ret & ERR_MASK)) 
		return ret;
	size = ret;

	/* check the HMAC in the response */
	ret = TSS_checkhmac1New(&tpmdata,ordinal_no,sess,nonceodd,TSS_Session_GetAuth(sess),TPM_HASH_SIZE,
				size,TPM_DATA_OFFSET,
				0,0);
	return ret;
}

/*
 * to test and owner DSAP session do the ResetLockValue command
 */
static uint32_t TestDSAPOwner(session *sess)
{
	STACK_TPM_BUFFER(tpmdata)
	uint32_t ordinal_no = htonl(TPM_ORD_ResetLockValue);
	uint32_t ret;
	
	/* check input arguments */

	unsigned char nonceodd[TPM_NONCE_SIZE];
	unsigned char authdata[TPM_NONCE_SIZE];
	TPM_BOOL c = 1;

	/* generate odd nonce */
	ret  = TSS_gennonce(nonceodd);
	if (0 == ret) 
		return ERR_CRYPT_ERR;

	/* move Network byte order data to variable for HMAC calculation */
	ret = TSS_authhmac(authdata,TSS_Session_GetAuth(sess),TPM_HASH_SIZE,TSS_Session_GetENonce(sess),nonceodd,c,
			   TPM_U32_SIZE,&ordinal_no,
			   0,0);

	if (0 != ret) {
		return ret;
	}
	/* build the request buffer */
	ret = TSS_buildbuff("00 c2 T l L % o %", &tpmdata,
				     ordinal_no,
				       TSS_Session_GetHandle(sess),
					 TPM_HASH_SIZE, nonceodd,
					   c,
					     TPM_HASH_SIZE, authdata);
		
	if ((ret & ERR_MASK) != 0) {
		return ret;
	}

	/* transmit the request buffer to the TPM device and read the reply */
	ret = TPM_Transmit(&tpmdata,"ResetLockValue");

	if (ret != 0) {
		return ret;
	}

	/* check the HMAC in the response */
	ret = TSS_checkhmac1New(&tpmdata,ordinal_no,sess,nonceodd,TSS_Session_GetAuth(sess),TPM_HASH_SIZE,
				0,0);

	return ret;
}
