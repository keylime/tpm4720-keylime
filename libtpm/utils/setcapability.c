/********************************************************************************/
/*										*/
/*			     	TPM Set a TPM capability			*/
/*			     Written by S. Berger				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*	      $Id: setcapability.c 4702 2013-01-03 21:26:29Z kgoldman $		*/
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
#include <string.h>
#include <unistd.h>
#include "tpmfunc.h"
#include "tpm.h"
#include "tpm_constants.h"
#include "tpm_structures.h"

#include <openssl/pem.h>
#include <openssl/rsa.h>

struct set_matrix
{
	char       *name;
	uint32_t   subcap32;
	uint32_t   type;
};

struct choice
{
	uint32_t                capArea;
	char                    *name;
	const struct set_matrix *smatrix;
};

#define TYPE_BOOL          1
#define TYPE_STRUCTURE     2
#define TYPE_UINT32        4
#define TYPE_UINT32_ARRAY  8
#define TYPE_VARIOUS       16
#define TYPE_PCR_SELECTION 32


static const struct set_matrix matrix_permflags[] = 
{
	{"TPM_PF_DISABLE"          , TPM_PF_DISABLE          , TYPE_BOOL},
	{"TPM_PF_OWNERSHIP"        , TPM_PF_OWNERSHIP        , TYPE_BOOL},
	{"TPM_PF_DEACTIVATED"      , TPM_PF_DEACTIVATED      , TYPE_BOOL},
	{"TPM_PF_READPUBEK"        , TPM_PF_READPUBEK        , TYPE_BOOL},
	{"TPM_PF_DISABLEOWNERCLEAR", TPM_PF_DISABLEOWNERCLEAR, TYPE_BOOL},
	{"TPM_PF_ALLOWMAINTENANCE" , TPM_PF_ALLOWMAINTENANCE , TYPE_BOOL},
	{"TPM_PF_PHYSICALPRESENCELIFETIMELOCK",
	                            TPM_PF_PHYSICALPRESENCELIFETIMELOCK,
	                                                      TYPE_BOOL},
	{"TPM_PF_PHYSICALPRESENCEHWENABLE",
	                            TPM_PF_PHYSICALPRESENCEHWENABLE,
	                                                      TYPE_BOOL},
	{"TPM_PF_PHYSICALPRESENCECMDENABLE",
	                            TPM_PF_PHYSICALPRESENCECMDENABLE,
	                                                      TYPE_BOOL},
//	{"TPM_PF_CEKPUSED"         , TPM_PF_CEKPUSED         , TYPE_BOOL},
//	{"TPM_PF_TPMPOST"          , TPM_PF_TPMPOST          , TYPE_BOOL},
//	{"TPM_PF_TPMPOSTLOCK"      , TPM_PF_TPMPOSTLOCK      , TYPE_BOOL},
//	{"TPM_PF_FIPS"             , TPM_PF_FIPS             , TYPE_BOOL},
//	{"TPM_PF_OPERATOR"         , TPM_PF_OPERATOR         , TYPE_BOOL},
//	{"TPM_PF_ENABLEREVOKEEK"   , TPM_PF_ENABLEREVOKEEK   , TYPE_BOOL},
	{"TPM_PF_NV_LOCKED"        , TPM_PF_NV_LOCKED        , TYPE_BOOL},
	{"TPM_PF_READSRKPUB"       , TPM_PF_READSRKPUB       , TYPE_BOOL},
	{"TPM_PF_TPMESTABLISHED"   , TPM_PF_TPMESTABLISHED   , TYPE_BOOL},
	{"TPM_PF_DISABLEFULLDALOGICINFO",
	                             TPM_PF_DISABLEFULLDALOGICINFO,
	                                                       TYPE_BOOL},
	{NULL                      , -1                      , 0}
};


static const struct set_matrix matrix_permdata[] = 
{
	{"TPM_PD_RESTRICTDELEGATE" , TPM_PD_RESTRICTDELEGATE , TYPE_UINT32},
	{NULL                      , -1                      , 0}
};

static const struct set_matrix matrix_stcflags[] = 
{
	{"TPM_SF_DISABLEFORCECLEAR", TPM_SF_DISABLEFORCECLEAR, TYPE_BOOL},
	{"TPM_SF_PHYSICALPRESENCE" , TPM_SF_PHYSICALPRESENCE , TYPE_BOOL},
	{"TPM_SF_PHYSICALPRESENCELOCK",
	                             TPM_SF_PHYSICALPRESENCELOCK,
	                                                       TYPE_BOOL},
	{NULL                      , -1                      , 0}
};

static const struct set_matrix matrix_stcdata[] = 
{
	{"TPM_SD_CONTEXTNONCEKEY"  , TPM_SD_CONTEXTNONCEKEY  , TYPE_BOOL},
	{"TPM_SD_COUNTID"          , TPM_SD_COUNTID          , TYPE_BOOL},
	{"TPM_SD_OWNERREFERENCE"   , TPM_SD_OWNERREFERENCE   , TYPE_BOOL},
	{"TPM_SD_DISABLERESETLOCK" , TPM_SD_DISABLERESETLOCK , TYPE_BOOL},
	{"TPM_SD_PCR"              , TPM_SD_PCR              , TYPE_BOOL},
	{"TPM_SD_DEFERREDPHYSICALPRESENCE"
	                           , TPM_SD_DEFERREDPHYSICALPRESENCE
	                                                     , TYPE_UINT32},
	{NULL                      , -1                      , 0}
};

static const struct set_matrix matrix_stanyflags[] =
{
	{"TPM_AF_TOSPRESENT"       , TPM_AF_TOSPRESENT       , TYPE_BOOL},
	{NULL                      , -1                      , 0}
};

static const struct set_matrix matrix_stanydata[] =
{
	{NULL                      , -1                      , 0}
};

static const struct set_matrix matrix_vendor[] =
{
	{NULL                      , -1                      , 0}
};

static const struct choice choice[] =
{
	{TPM_SET_PERM_FLAGS   , "TPM_PERMANENT_FLAGS", matrix_permflags},
	{TPM_SET_PERM_DATA    , "TPM_PERMANENT_DATA" , matrix_permdata},
	{TPM_SET_STCLEAR_FLAGS, "TPM_STCLEAR_FLAGS"  , matrix_stcflags},
	{TPM_SET_STCLEAR_DATA , "TPM_STCLEAR_DATA"   , matrix_stcdata},
	{TPM_SET_STANY_FLAGS  , "TPM_STANY_FLAGS"    , matrix_stanyflags},
	{TPM_SET_STANY_DATA   , "TPM_STANY_DATA"     , matrix_stanydata},
	{TPM_SET_VENDOR       , "TPM_SET_VENDOR"     , matrix_vendor},
	{-1                   , NULL                 , NULL}
};



static void ParseArgs(int argc, char *argv[]);

static const char *ownerPassword = NULL;
static const char *ownerAuthFilename = NULL;
static uint32_t cap = 0xffffffff;
static uint32_t scap = 0xffffffff;
static uint32_t val = 0xffffffff;

static void printUsage() {
	printf("Usage: setcapability [options] -cap <capability (hex)> -scap <sub cap (hex)>\n"
	       "-val <value (decimal> or -valx <value (hex)>\n"
	       "\n"
	       "Possible options are:\n"
	       "  [-pwdo <owner password> -pwdof <owner authorization file name>\n"
	       "  -v    : verbose trace\n"
	       "  -h    : help\n"
	       "\n");
	exit(2);
}

int main(int argc, char *argv[])
{
	int ret;
	unsigned char * ownerAuthPtr = NULL;
	unsigned char ownerAuth[TPM_HASH_SIZE];
	uint32_t capArea = 0;
	uint32_t subCap32 = -1;
	unsigned char serSubCap[4];
	uint32_t serSubCapLen = sizeof(serSubCap);
	STACK_TPM_BUFFER(serSetValue);
	uint32_t cap_index = 0;
	uint32_t scap_index = 0;
	const struct set_matrix *smatrix = NULL;
	TPM_PCR_SELECTION pcrsel;
	int idx;

	TPM_setlog(0);		/* turn off verbose output */

	ParseArgs(argc, argv);
	if ((cap == 0xffffffff) ||
	    (scap == 0xffffffff) ||
	    (val == 0xffffffff)) {
	    printf("Missing argument\n");
	    printUsage();
	}
	/*
	 * Find the capability
	 */
	while (NULL != choice[cap_index].name) {
	    if (cap == choice[cap_index].capArea) {
		smatrix = choice[cap_index].smatrix;
		capArea = choice[cap_index].capArea;
		break;
	    }
	    cap_index++;
	}
	if (NULL == smatrix) {
	    printf("Invalid capability.\n");
	    exit(-1);
	}
	/*
	 * Find the sub capability
	 */
	while (NULL != smatrix[scap_index].name) {
	    if (scap == smatrix[scap_index].subcap32) {
		subCap32 = smatrix[scap_index].subcap32;
		break;
	    }
	    scap_index++;
	}
	
	if (-1 == (int)subCap32) {
	    printf("Invalid sub-capability.\n");
	    exit(-1);
	}
	STORE32(serSubCap,
	        0,
	        subCap32);
	serSubCapLen = 4;

	switch(smatrix[scap_index].type) {
		case TYPE_BOOL:
			serSetValue.buffer[0] = val;
			serSetValue.used = 1;
		break;
		
		case TYPE_UINT32:
			STORE32(serSetValue.buffer,
			        0,
			        val);
			serSetValue.used = 4;
		break;
		
		case TYPE_PCR_SELECTION:
			/* user provided the selection */
			memset(&pcrsel, 0x0, sizeof(pcrsel));
			idx = 0;
			while (val > 0) {
				pcrsel.sizeOfSelect++;
				pcrsel.pcrSelect[idx] = (uint8_t)val;
				val >>= 8;
				idx++;
			}
			ret = TPM_WritePCRSelection(&serSetValue, &pcrsel);
			if ((ret & ERR_MASK)) {
				printf("Error '%s' while serializing "
				       "TPM_PCR_SELECTION.\n",TPM_GetErrMsg(ret));
				exit(-1);
			}
		break;
		
		default:
			printf("Unknown type of value to set.\n");
			exit(-1);
	}

	/* use the SHA1 hash of the password string as the Owner Authorization Data */
	if (ownerPassword != NULL) {
	    TSS_sha1((unsigned char *)ownerPassword,
		     strlen(ownerPassword),
		     ownerAuth);
	    ownerAuthPtr = ownerAuth;
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
	    ownerAuthPtr = ownerAuth;
	    free(buffer);
	}


	ret = TPM_SetCapability(capArea,
	                        serSubCap, serSubCapLen,
	                        &serSetValue,
	                        ownerAuthPtr);

	if ( 0 != ret ) {
		printf("Error %s from SetCapability.\n",
		       TPM_GetErrMsg(ret));
	} else {
		printf("Capability was set successfully.\n");
	}

	exit(ret);
}


/**************************************************************************/
/*                                                                        */
/*  Parse Arguments                                                       */
/*                                                                        */
/**************************************************************************/
static void ParseArgs(int argc, char *argv[])
{
    int i;
    
    for (i=1 ; i<argc ; i++) {
	if (!strcmp(argv[i], "-pwdo")) {
	    i++;
	    if (i < argc) {
		ownerPassword = argv[i];
	    }
	    else {
		printf("Missing parameter to -pwdo\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-pwdof") == 0) {
	    i++;
	    if (i < argc) {
		ownerAuthFilename = argv[i];
	    }
	    else {
		printf("-pwdof option needs a value\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-cap") == 0) {
	    i++;
	    if (i < argc) {
		/* convert key handle from hex */
		if (1 != sscanf(argv[i], "%x", &cap)) {
		    printf("Invalid -cap argument '%s'\n",argv[i]);
		    exit(2);
		}
	    }
	    else {
		printf("-cap option needs a value\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-scap") == 0) {
	    i++;
	    if (i < argc) {
		/* convert key handle from hex */
		if (1 != sscanf(argv[i], "%x", &scap)) {
		    printf("Invalid -scap argument '%s'\n",argv[i]);
		    exit(2);
		}
	    }
	    else {
		printf("-scap option needs a value\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-val") == 0) {
	    i++;
	    if (i < argc) {
		if (1 != sscanf(argv[i], "%d", &val)) {
		    printf("Invalid -val argument '%s'\n",argv[i]);
		    exit(2);
		}
	    }
	    else {
		printf("-val option needs a value\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-valx") == 0) {
	    i++;
	    if (i < argc) {
		if (1 != sscanf(argv[i], "%x", &val)) {
		    printf("Invalid -valx argument '%s'\n",argv[i]);
		    exit(2);
		}
	    }
	    else {
		printf("-valx option needs a value\n");
		printUsage();
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
    return;
}
