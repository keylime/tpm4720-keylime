/********************************************************************************/
/*										*/
/*			     	TPM CMK_CreateKey 				*/
/*			     Written by S. Berger				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*	      $Id: cmk_createkey.c 4702 2013-01-03 21:26:29Z kgoldman $		*/
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
#include <sys/stat.h>
#include <sys/types.h>
#include "tpmfunc.h"
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <fcntl.h>

   
static int ParseArgs(int argc, char *argv[]);
static void printUsage(void);

static char keytype = 's';

static char *parpass = NULL;
static char *keypass = NULL;
static char *keyname = NULL;         /* pointer to key name argument */
static char *digestfilename = NULL;
static unsigned char migAuthApproval[TPM_HASH_SIZE];
static unsigned char migAuthDigest[TPM_HASH_SIZE];
static unsigned int keysize = 2048;
static uint32_t parhandle = 0;           /* handle of parent key */

/* local prototypes */
static int readHMACandDigest(char * filename, unsigned char *, unsigned char *);

/**************************************************************************/
/*                                                                        */
/*  Main Program                                                          */
/*                                                                        */
/**************************************************************************/
int main(int argc, char *argv[])
{
	int ret;

	unsigned char hashpass1[TPM_HASH_SIZE];    /* hash of new key password */
	unsigned char hashpass2[TPM_HASH_SIZE];    /* hash of migration password */
	keydata k;                      /* keydata structure for input key parameters */
	keydata q;                      /* keydata structure for resulting key */
	RSA *rsa;                       /* OpenSSL format Public Key */
	FILE *keyfile;                  /* output file for public key */
	FILE *blbfile;                  /* output file for encrypted blob */
	EVP_PKEY *pkey = NULL;          /* OpenSSL public key */
	char filename[256];    /* file name string of public key file */
	unsigned char blob[4096];       /* area to hold key blob */
	uint32_t  bloblen;          /* key blob length */
	unsigned char *aptr1 = NULL;
	unsigned char *aptr2 = NULL;

	int nxtarg;

	TPM_setlog(0);                   /* turn off verbose output */
	/*
	**  parse command line
	*/
	nxtarg = ParseArgs(argc, argv);
	(void)nxtarg;

	if ((digestfilename == NULL) ||
	    (keyname == NULL) ||
	    (parhandle == 0)) {
	    printf("Missing parameter\n");
	    printUsage();
	}

	if (-1 == readHMACandDigest(digestfilename, migAuthApproval, migAuthDigest)) {
	    printf("Error reading from file %s.\n", digestfilename);
	    exit(-1);
	}
	/*
	** convert parent key handle from hex
	*/
	/*
	** use the SHA1 hash of the password string as the Parent Key Authorization Data
	*/
	if (parpass != NULL) { TSS_sha1(parpass,strlen(parpass),hashpass1); aptr1 = hashpass1; }
	/*
	** use the SHA1 hash of the password string as the Key Authorization Data
	*/
	if (keypass != NULL) { TSS_sha1(keypass,strlen(keypass),hashpass2); aptr2 = hashpass2; }
	/*
	** initialize new key parameters
	*/
	k.v.tag = TPM_TAG_KEY12;
	k.keyFlags = TPM_MIGRATABLE | TPM_MIGRATEAUTHORITY;
	if (keypass != NULL)
		k.authDataUsage = 1;         /* key requires authorization (password) */
	else
		k.authDataUsage = 0;         /* key requires no authorization (password) */
	k.encData.size = 0;                    /* no private key specified here */
	k.pub.algorithmParms.algorithmID = TPM_ALG_RSA;       /* key algorithm 1 = RSA */
	if (keytype == 's') {
		k.keyUsage = TPM_KEY_SIGNING;                    /* key Usage - 0x0010 = signing */
		k.pub.algorithmParms.encScheme = TPM_ES_NONE;    /* encryption scheme 1 = NONE - signing key */
		k.pub.algorithmParms.sigScheme = TPM_SS_RSASSAPKCS1v15_SHA1;    /* signature scheme RSA/SHA1  */
	}
	else if (keytype == 'd') {
		k.keyUsage = TPM_KEY_SIGNING;                    /* key Usage - 0x0010 = signing */
		k.pub.algorithmParms.encScheme = TPM_ES_NONE;    /* encryption scheme 1 = NONE - signing key */
		k.pub.algorithmParms.sigScheme = TPM_SS_RSASSAPKCS1v15_DER;     /* signature scheme RSA/DER  */
	}
	else if (keytype == 'i') {
		k.keyUsage = TPM_KEY_SIGNING;                    /* key Usage - 0x0010 = signing */
		k.pub.algorithmParms.encScheme = TPM_ES_NONE;    /* encryption scheme 1 = NONE - signing key */
		k.pub.algorithmParms.sigScheme = TPM_SS_RSASSAPKCS1v15_INFO;    /* signature scheme RSA/INFO  */
	}
	else if (keytype == 'e') {
		k.keyUsage = TPM_KEY_STORAGE;                    /* key Usage - 0x0011 = encryption */
		k.pub.algorithmParms.encScheme = TPM_ES_RSAESOAEP_SHA1_MGF1;    /* encryption scheme 3 RSA */
		k.pub.algorithmParms.sigScheme = TPM_SS_NONE;                   /* signature scheme NONE  */
	}
	else if (keytype == 'b') {
		k.keyUsage = TPM_KEY_BIND;                       /* key Usage - 0x0014 = bind */
		k.pub.algorithmParms.encScheme = TPM_ES_RSAESOAEP_SHA1_MGF1;    /* encryption scheme 3 RSA */
		k.pub.algorithmParms.sigScheme = TPM_SS_NONE;                   /* signature scheme none */
	}
	else if (keytype == 'l') {
		k.keyUsage = TPM_KEY_LEGACY;                     /* key Usage - 0x0015 = legacy */
		k.pub.algorithmParms.encScheme = TPM_ES_RSAESOAEP_SHA1_MGF1;    /* encryption scheme 3 RSA */
		k.pub.algorithmParms.sigScheme = TPM_SS_RSASSAPKCS1v15_SHA1;    /* signature scheme RSA/SHA1  */
	}
	else if (keytype == 'm') {
		k.keyUsage = TPM_KEY_MIGRATE;                    /* key Usage - 0x0016 = migration */
		k.pub.algorithmParms.encScheme = TPM_ES_RSAESOAEP_SHA1_MGF1;    /* encryption scheme 3 RSA */
		k.pub.algorithmParms.sigScheme = TPM_SS_NONE;                   /* signature scheme RSA/SHA1  */
	}
	else {
	    printUsage();
	}
	k.pub.algorithmParms.u.rsaKeyParms.keyLength = keysize;      /* RSA modulus size 2048 bits */
	k.pub.algorithmParms.u.rsaKeyParms.numPrimes = 2;            /* required */
	k.pub.algorithmParms.u.rsaKeyParms.exponentSize = 0;            /* RSA exponent - default 0x010001 */
	k.pub.pubKey.keyLength = 0;            /* key not specified here */
	k.pub.pcrInfo.size = 0;           /* no PCR's used at this time */

	/*
	** create and wrap an asymmetric key and get back the
	** resulting keydata structure with the public and encrypted
	** private keys filled in by the TPM
	*/
	bloblen = sizeof(blob);
	ret =  TPM_CMK_CreateKey(parhandle,
	                         aptr1,
	                         aptr2,
	                         &k,
	                         migAuthApproval,
	                         migAuthDigest,
	                         &q,
	                         blob,
	                         &bloblen);
	if (ret != 0) {
		printf("Error %s from TPM_CMK_CreateKey\n",
		       TPM_GetErrMsg(ret));
		exit(-2);
	}
	sprintf(filename,"%s.key",keyname);
	blbfile = fopen(filename,"wb+");
	if (blbfile == NULL) {
		printf("Unable to create key file\n");
		exit(-3);
	}
	ret = fwrite(blob,1,bloblen,blbfile);
	if (ret != (int)bloblen) {
		printf("I/O Error writing key file\n");
		exit(-4);
	}
	fclose(blbfile);
	/*
	** convert the returned public key to OpenSSL format and
	** export it to a file
	*/
	rsa = TSS_convpubkey(&(q.pub));
	if (rsa == NULL) {
		printf("Error from TSS_convpubkey\n");
		exit(-5);
	}
	OpenSSL_add_all_algorithms();
	pkey = EVP_PKEY_new();
	if (pkey == NULL) {
	    printf("Unable to create EVP_PKEY\n");
	    exit(-6);
	}
	ret = EVP_PKEY_assign_RSA(pkey,rsa);
	if (ret == 0) {
	    printf("Unable to assign public key to EVP_PKEY\n");
	    exit(-7);
	}
	sprintf(filename,"%s.pem",keyname);
	keyfile = fopen(filename,"wb");
	if (keyfile == NULL) {
		printf("Unable to create public key file\n");
		exit(-8);
	}
	ret = PEM_write_PUBKEY(keyfile,pkey);
	if (ret == 0) {
		printf("I/O Error writing public key file\n");
		exit(-9);
	}
	fclose(keyfile);
	EVP_PKEY_free(pkey);
	exit(0);
}

	
/**************************************************************************/
/*                                                                        */
/*  Parse Arguments                                                       */
/*                                                                        */
/**************************************************************************/
static int ParseArgs(int argc, char *argv[])
{
    int i;
    /*
     * Loop over the command line looking for arguments.
     */
    for (i=1 ; i<argc ; i++) {
	if (!strcmp(argv[i], "-kt")) {
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
		if (1 != sscanf(argv[i], "%d", &keysize)) {
		    printf("Could not parse the keysize\n");
		    exit(-1);
		}
	    }
	    else {
		printf("Missing parameter to -sz\n");
		printUsage();
	    }
	}
	else if (!strcmp(argv[i], "-h")) {
	    printUsage();
	}
	else if (!strcmp(argv[i], "-v")) {
	    TPM_setlog(1);
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
	else if (strcmp(argv[i],"-if") == 0) {
	    i++;
	    if (i < argc) {
		digestfilename = argv[i];
	    }
	    else {
		printf("-ok option needs a value\n");
		printUsage();
	    }
	}
	else {
	    printf("\n%s is not a valid option\n", argv[i]);
	    printUsage();
	}
    }
    return 0;
}

static void printUsage()
{
	printf("Usage: cmk_createkey [<options>] -if <HMAC and digest file> -ok <keyname> -hp <pkeyhandle>\n");
	printf("\n");
	printf("   Where the arguments are...\n");
	printf("    <keyname>    is the new key name\n");
	printf("    <pkeyhandle> is the parent key handle in hex\n");
	printf("\n");
	printf("The SRK handle is 40000000\n");
	printf("\n");
	printf("   Where the <options> are...\n");
	printf("    -kt s/d/i | e | b | l | m  keytype is s for signing, e for encryption(storage)\n");
	printf("                                         b for binding, l for legacy\n");
	printf("                                         m for migration\n");
	printf("    -pwdp <parpass>   to specify parent key use password\n");
	printf("    -pwdk <keypass>      to specify new key use password\n");
	printf("    -sz <keysize>      to specify the size of the key; default is 2048\n");
	printf("    -h                print usage information (this message)\n");
	exit(-1);
}


static int readHMACandDigest(char * filename, unsigned char * hmac, unsigned char * digest)
{
	struct stat _stat;
	int ret  = 0;
	if (0 == stat(filename, &_stat)) {
		if (_stat.st_size == TPM_HASH_SIZE + TPM_DIGEST_SIZE) {
			int fd = open(filename, O_RDONLY);
			if (fd > 0) {	
				if (TPM_HASH_SIZE   != read(fd, hmac, TPM_HASH_SIZE) ||
				    TPM_DIGEST_SIZE != read(fd, digest, TPM_DIGEST_SIZE)) {
					ret = -1;
				}
			} else {
				ret = -1;
			}
		} else {
			ret = -1;
		}
	} else {
		ret = -1;
	}
	return ret;
}

