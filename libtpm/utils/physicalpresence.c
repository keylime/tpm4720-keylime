/********************************************************************************/
/*										*/
/*		  Set or clear software physical presence			*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*	      $Id: physicalpresence.c 4702 2013-01-03 21:26:29Z kgoldman $	*/
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

#include "tpmutil.h"
#include "tpmfunc.h"
#include "tpm_constants.h"

/* local prototypes */

static void print_usage(void);

int main(int argc, char *argv[])
{
    int 	ret = 0;
    int		i;			/* argc iterator */
    int		state = -1;		/* 0 raw ordinal parameter
					   1 clear pp
					   2 set pp
					   3 set deferred pp for field upgrade
					   -1 illegal value */
    short	physicalPresence = -1;	/* raw ordinal parameter */
    
    TPM_setlog(0);      /* turn off verbose output */

    /* parse command line parameters */
    for (i=1 ; (i<argc) && (ret == 0) ; i++) {
	if (strcmp(argv[i],"-c") == 0) {
	    if (state == -1) {
		state = 1;
	    }
	    else {
		printf("\nOnly one command line argument may be specified\n");
		print_usage();
		ret = ERR_BAD_ARG;
	    }
	}
	else if (strcmp(argv[i],"-h") == 0) {
	    print_usage();
	    ret = ERR_BAD_ARG;
	}
	else if (strcmp(argv[i],"-v") == 0) {
	    TPM_setlog(1);
	}
	else if (strcmp(argv[i],"-s") == 0) {
	    if (state == -1) {
		state = 2;
	    }
	    else {
		printf("\nOnly one command line argument may be specified\n");
		print_usage();
		ret = ERR_BAD_ARG;
	    }
	}
	else if (strcmp(argv[i],"-x") == 0) {
	    if (state == -1) {
		state = 0;
		i++;
		if (i < argc) {
		    sscanf(argv[i], "%hx", &physicalPresence);
		} else {
		    printf("Missing parameter for -x\n");
		    print_usage();
		    ret = ERR_BAD_ARG;
		}
	    }
	    else {
		printf("\nOnly one command line argument may be specified\n");
		print_usage();
		ret = ERR_BAD_ARG;
	    }
	}
	else if (strcmp(argv[i],"-dfu") == 0) {
	    if (state == -1) {
		state = 3;
	    }
	    else {
		printf("\nOnly one command line argument may be specified\n");
		print_usage();
		ret = ERR_BAD_ARG;
	    }
	}
	else {
	    printf("\n%s is not a valid option\n", argv[i]);
	    print_usage();
	    ret = ERR_BAD_ARG;
	}
    }
    /* validate command line parameters */
    if ((ret == 0) && (state == -1)) {
	printf("\nA command line argument must be specified\n");
	print_usage();
	ret = ERR_BAD_ARG;
    }
    /* For all but the raw parameter, start by sending the TSC_PhysicalPresence command to turn on
       physicalPresenceCMDEnable */
    if ((ret == 0) && (state != 0)) {
	TSC_PhysicalPresence(TPM_PHYSICAL_PRESENCE_CMD_ENABLE);
	/* This will fail even if it's set if the lifetime lock is set.  So ignore the error and try
	   to continue. */
    }
    /* Send the TSC_PhysicalPresence command to turn on physicalPresence */
    if ((ret == 0) && (state == 2)) {
	ret = TSC_PhysicalPresence(TPM_PHYSICAL_PRESENCE_PRESENT);
	if (ret != 0) {
	    printf("Error %s from TSC_PhysicalPresence\n",
		   TPM_GetErrMsg(ret));
	}	
    }
    /* Send the TSC_PhysicalPresence command to turn off physicalPresence */
    if ((ret == 0) && (state == 1)) {
	ret = TSC_PhysicalPresence(TPM_PHYSICAL_PRESENCE_NOTPRESENT);
	if (ret != 0) {
	    printf("Error %s from TSC_PhysicalPresence\n",
		   TPM_GetErrMsg(ret));
	}	
    }
    /* Send the TSC_PhysicalPresence command, etc., to set deferredPhysicalPresence */
    if ((ret == 0) && (state == 3)) {
	if (ret == 0) {
	    ret = TSC_PhysicalPresence(TPM_PHYSICAL_PRESENCE_PRESENT);
	    if (ret != 0) {
		printf("Error %s from TSC_PhysicalPresence\n",
		       TPM_GetErrMsg(ret));
	    }	
	}
	if (ret == 0) {
	    unsigned char serSubCap[4];
	    STACK_TPM_BUFFER(serSetValue);
	    STORE32(serSubCap,
		    0,
		    TPM_SD_DEFERREDPHYSICALPRESENCE);
	    STORE32(serSetValue.buffer,
		    0,
		    TPM_DPP_UNOWNED_FIELD_UPGRADE);
	    serSetValue.used = 4;
	    ret = TPM_SetCapability(TPM_SET_STCLEAR_DATA,		/* capArea */
				    serSubCap,
				    sizeof(serSubCap),			/* subcap and length */
				    &serSetValue,
				    NULL);				/* ownerAuth */
	    if (ret != 0) {
		printf("Error %s from TPM_SetCapability\n",
		       TPM_GetErrMsg(ret));
	    }	
	}
	if (ret == 0) {
	    ret = TSC_PhysicalPresence(TPM_PHYSICAL_PRESENCE_NOTPRESENT);
	    if (ret != 0) {
		printf("Error %s from TSC_PhysicalPresence\n",
		       TPM_GetErrMsg(ret));
	    }	
	}
    }
    if ((ret == 0) && (state == 0)) {
	ret = TSC_PhysicalPresence(physicalPresence);
	if (ret != 0) {
	    printf("Error %s from TSC_PhysicalPresence\n",
		   TPM_GetErrMsg(ret));
	}	
    }
    return ret;
}

static void print_usage(void)
{
    printf("\n");
    printf("physicalpresence\n");
    printf("\n");
    printf("\t-c clear physical presence\n");
    printf("\t-s set physical presence\n");
    printf("\t-x send this hex parameter to TCS_PhysicalPresence\n");
    printf("\t-dfu set deferred physical presence for field upgrade\n");
    printf("\t-h help\n");
    return;
}

