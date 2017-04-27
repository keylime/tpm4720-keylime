/********************************************************************************/
/*										*/
/*			     	TPM Create key delegation			*/
/*			     Written by S. Berger				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*	      $Id: createkeydelegation.c 4702 2013-01-03 21:26:29Z kgoldman $	*/
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

static void usage() {
    printf("Usage: createkeydelegation  Parameters \n"
	   "-hk <key handle> -pwdd <delegate password> -of <filename>\n"
	   "\n"
	   "Valid parameters are:\n"
	   "-hk <keyhandle>       : the key handle in hex\n"
	   "-la <label>           : the label for the public parameters\n"
	   "-id <familyID>        : to set the familyID\n"
	   "-per1 <permissions>   : to set the permission1 parameter (hex)\n"
	   "-per2 <permissions>   : to set the permission2 parameter (hex)\n"
	   "-v                    : turns on verbose mode\n"
	   "[-pwdk <key password> : Key password]\n"
	   "-pwdd <password>      : Delegate password\n"
	   "-of <filename>	  : output file for delegate blob\n"
	   "\n"
	   "Example:\n"
	   "createkeydelegation \n"
	   "\t-la 1 -id 1 -per1 0x2 -pwdk key -hk 05abcde -pwdd key2 -of keydel.bin\n"
	   "\n");
    exit(1);
}

int main(int argc, char *argv[])
{
	int ret = 0;
	STACK_TPM_BUFFER(buffer)

	char *delpass = NULL;
	char *keyPass = NULL;
	unsigned char keyPassHash[TPM_HASH_SIZE];
	unsigned char *keyHashPtr = NULL;
	uint32_t keyhandle = 0;
	
	unsigned char delhash[TPM_HASH_SIZE];
	unsigned char *delAuthHashPtr = NULL;
	int i;
	TPM_FAMILY_ID familyID;
	uint32_t pcrs;

	unsigned char retbuffer[1024];
	uint32_t retbufferlen = sizeof(retbuffer);

	TPM_DELEGATE_PUBLIC tdp;
	unsigned char label;
	unsigned int per1 = 0, per2 = 0;
	char *filename = NULL;
#if 0
	BOOL bool;
#endif
	unsigned int verificationCount = 0;

	TPM_setlog(0);
	
	for (i=1 ; i<argc ; i++) {
	    if (!strcmp("-la", argv[i])) {
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
	    else if (strcmp(argv[i],"-hk") == 0) {
		i++;
		if (i < argc) {
		    /* convert key handle from hex */
		    if (1 != sscanf(argv[i], "%x", &keyhandle)) {
			printf("Invalid -hk argument '%s'\n",argv[i]);
			exit(2);
		    }
		    if (keyhandle == 0) {
			printf("Invalid -hk argument '%s'\n",argv[i]);
			exit(2);
		    }		 
		}
		else {
		    printf("-hk option needs a value\n");
		    usage();
		}
	    }
	    else if (!strcmp(argv[i], "-pwdd")) {
		i++;
		if (i < argc) {
		    delpass = argv[i];
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
		    exit(-1);
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
#if 0
	    if (!strcmp("-admin",argv[i])) {
		i++;
		if (i < argc) {
		    unsigned int x;
		    mode = TPM_FAMILY_ADMIN;
		    if (1 != sscanf(argv[i], "%x", &x)) {
			printf("Error while reading option parameter.\n");
			usage();
		    }
		    if (x == 0) {
			bool = 0;
		    } else 
			bool = 1;
		} else {
		    printf("Missing parameter for -admin.\n");
		    usage();
		}
			
	    } else
#endif
	    else if (!strcmp("-pwdk",argv[i])) {
		i++;
		if (i < argc) {
		    keyPass = argv[i];
		} else {
		    printf("Missing parameter for -pwdk.\n");
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

#if 0
	if (-1 == mode) {
		printf("Missing mandatory option.\n");
		usage();
		exit(-1);
	}
#endif
	if (filename == NULL) {
	    printf("Missing mandatory parameter: filename\n");
	    exit(-1);
	}
	if (delpass == NULL) {
	    printf("Missing mandatory parameter: password\n");
	    exit(-1);
	}
	if (keyhandle == 0) {
	    printf("Missing mandatory parameter: keyhandle\n");
	    exit(-1);
	}
	
	TSS_sha1(delpass, strlen(delpass), delhash);
	delAuthHashPtr = delhash;

	if (NULL != keyPass) {
		TSS_sha1(keyPass, strlen(keyPass), keyPassHash);
		keyHashPtr = keyPassHash;
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

	tdp.tag = TPM_TAG_DELEGATE_PUBLIC;
	tdp.rowLabel = label;
	tdp.pcrInfo.pcrSelection.sizeOfSelect = pcrs / 8;
	memset(&tdp.pcrInfo.pcrSelection.pcrSelect,
	       0x0,
	       sizeof(tdp.pcrInfo.pcrSelection.pcrSelect));
	tdp.pcrInfo.localityAtRelease = TPM_LOC_ZERO;
	tdp.permissions.tag = TPM_TAG_DELEGATIONS;
	tdp.permissions.delegateType = TPM_DEL_KEY_BITS;
	tdp.permissions.per1 = per1;
	tdp.permissions.per2 = per2;
	tdp.familyID = familyID;
	tdp.verificationCount = verificationCount;

	ret = TPM_Delegate_CreateKeyDelegation(keyhandle,
	                                       &tdp,
	                                       delAuthHashPtr,
	                                       keyHashPtr,
	                                       retbuffer, &retbufferlen);

	if (0 != ret) {
		printf("Error %s from TPM_Delegate_CreateKeyDelegation.\n",
		       TPM_GetErrMsg(ret));
	} else {
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
