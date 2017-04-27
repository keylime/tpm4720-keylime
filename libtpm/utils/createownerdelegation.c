/********************************************************************************/
/*										*/
/*			     	TPM Create owner delegation			*/
/*			     Written by S. Berger				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*	      $Id: createownerdelegation.c 4702 2013-01-03 21:26:29Z kgoldman $	*/
/*										*/
/*			       IBM Confidential					*/
/*			     OCO Source Materials				*/
/*			 (c) Copyright IBM Corp. 2010				*/
/*			      All Rights Reserved			        */
/*										*/
/*	   The source code for this program is not published or otherwise	*/
/*	   divested of its trade secrets, irrespective of what has been		*/
/*	   deposited with the U.S. Copyright Office.				*/
/*										*/
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
#include "tpm.h"
#include "tpmutil.h"
#include <tpmfunc.h>

static void usage()
{
    printf("Usage: createownerdelegation  pwdd <delegate password> -of <filename>\n"
	   "   [-pwdo <owner password> -pwdof <owner authorization file name>\n"
	   "\n"
	   "Valid parameters are:\n"
	   "-inc                : to increment the verificationCount\n"
	   "-la <label>         : the label for the public parameters\n"
	   "-id <familyID>      : to set the familyID\n"
	   "-per1 <permissions> : to set the permission1 parameter\n"
	   "-per2 <permissions> : to set the permission2 parameter\n"
	   "-v                  : turns on verbose mode\n"
	   "-pwdo <owner password> : TPM owner password\n"
	   "-pwdof <owner auth> : TPM owner authorization file name\n"
	   "-pwdd <password>    : Delegate password\n"
	   "\n"
	   "Example:\n"
	   "createownerdelegation \n"
	   "\t-inc -la 1 -id 1 -per1 0x2 -pwdo ooo -pwdd newpass -of ownerblob.bin\n"
	   "\n");
    exit(-1);
}

int main(int argc, char *argv[])
{
    int ret = 0;
    int i;
    TPM_BOOL inc = FALSE;
    STACK_TPM_BUFFER(buffer);

    const char *ownerPassword = NULL;
    const char *ownerAuthFilename = NULL;
    unsigned char ownerAuth[TPM_HASH_SIZE];
	
    const char *delegationPassword = NULL;
    unsigned char delegationAuth[TPM_HASH_SIZE];

    TPM_FAMILY_ID familyID;
    uint32_t pcrs;

    unsigned char retbuffer[10240];
    uint32_t retbufferlen = sizeof(retbuffer);

    TPM_DELEGATE_PUBLIC tdp;
    unsigned char label;
    unsigned int per1 = 0, per2 = 0;
    char *filename = NULL;
    unsigned int verificationCount = 0;

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
		printf("Missing parameter for -pwdof.\n");
		usage();
	    }
	}
	else if (!strcmp("-inc", argv[i])) {
	    inc = TRUE;
	}
	else if (!strcmp("-la", argv[i])) {
	    i++;
	    if (i < argc) {
		if (1 != sscanf(argv[i], "%c", &label)) {
		    printf("Error while reading option parameter.\n");
		    usage();
		}
	    } else {
		printf("Missing parameter for '-la'.\n");
		usage();
	    }
	}
	else if (!strcmp(argv[i], "-pwdd")) {
	    i++;
	    if (i < argc) {
		delegationPassword = argv[i];
	    }
	    else {
		printf("Missing parameter to -pwdd\n");
		usage();
	    }
	}
	else if (!strcmp("-id", argv[i])) {
	    i++;
	    if (i < argc) {
		if (1 != sscanf(argv[i], "%d", &familyID)) {
		    printf("Error while reading option parameter.\n");
		    usage();
		}
	    } else {
		printf("Missing parameter for '-id'.\n");
		usage();
	    }
	}
	else if (!strcmp("-per1", argv[i])) {
	    i++;
	    if (i < argc) {
		if (1 != sscanf(argv[i], "%x", &per1)) {
		    printf("Error while reading option parameter.\n");
		    usage();
		}
	    } else {
		printf("Missing parameter for '-per1'.\n");
		usage();
	    }
	}
	else if (!strcmp("-per2", argv[i])) {
	    i++;
	    if (i < argc) {
		if (1 != sscanf(argv[i], "%x", &per2)) {
		    printf("Error while reading option parameter.\n");
		    usage();
		}
	    } else {
		printf("Missing parameter for '-per2'.\n");
		usage();
	    }
	}
	else if (strcmp(argv[i],"-of") == 0) {
	    i++;
	    if (i < argc) {
		filename = argv[i];
	    }
	    else {
		printf("-of option needs a value\n");
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

    if (delegationPassword == NULL) {
	printf("Missing mandatory parameter -pwdd: delegate password\n");
	exit(-1);
    }
    if (filename == NULL) {
	printf("Missing mandatory parameter -of: filename\n");
	exit(-1);
    }
    if ((ownerPassword == NULL) && (ownerAuthFilename == NULL)) {
	printf("\nMissing -pwdo or -pwdof argument\n");
	usage();
    }
    if ((ownerPassword != NULL) && (ownerAuthFilename != NULL)) {
	printf("\nCannot have -pwdo and -pwdof arguments\n");
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

    TSS_sha1((unsigned char *)delegationPassword,
	     strlen(delegationPassword),
	     delegationAuth);

    ret = TPM_GetNumPCRRegisters(&pcrs);
    if (ret != 0) {
	printf("Error reading number of PCR registers.\n");
	exit(-1);
    }
    if (pcrs > TPM_NUM_PCR) {
	printf("Library does not support that many PCRs.\n");
	exit(-1);
    }
	
    tdp.tag = TPM_TAG_DELEGATE_PUBLIC;
    tdp.rowLabel = label;
    tdp.pcrInfo.pcrSelection.sizeOfSelect = pcrs / 8;
    memset(&tdp.pcrInfo.pcrSelection.pcrSelect,
	   0x0,
	   sizeof(tdp.pcrInfo.pcrSelection.pcrSelect));
    tdp.pcrInfo.localityAtRelease = TPM_LOC_ZERO;
    tdp.permissions.tag = TPM_TAG_DELEGATIONS;
    tdp.permissions.delegateType = TPM_DEL_OWNER_BITS;
    tdp.permissions.per1 = per1;
    tdp.permissions.per2 = per2;
    tdp.familyID = familyID;
    tdp.verificationCount = verificationCount;

    ret = TPM_Delegate_CreateOwnerDelegation(inc,
					     &tdp,
					     delegationAuth,
					     ownerAuth,
					     retbuffer, &retbufferlen);

    if (ret != 0) {
	printf("Error %s from TPM_Delegate_CreateOwnerDelegation.\n",
	       TPM_GetErrMsg(ret));
    }
    else {
	FILE *f = fopen(filename,"wb");
	if (NULL != f) {
	    fwrite(retbuffer, retbufferlen, 1, f);
	    fclose(f);
	    printf("Ok.\n");
	} else {
	    printf("Could not write data to file!\n");
	}
    }
    exit(ret);
}
