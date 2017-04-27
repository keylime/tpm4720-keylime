/********************************************************************************/
/*										*/
/*			SHA1 test that can send in 4 parts			*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*	$Id: sha1parts.c 4702 2013-01-03 21:26:29Z kgoldman $		*/
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
#include <string.h>
#include <stdlib.h>

#include "tpm_structures.h"
#include "tpmfunc.h"

int getArgs(int *start,
	    int *update,
	    int *complete,
	    int *verbose,
	    int argc,
	    char **argv);
void printUsage(void);

int main(int argc, char** argv)
{
    int 	rc = 0;
    int start;
    int update;
    int complete;
    int verbose;

    unsigned char buffer1[] = "1234567890123456789012345678901234567890123456789012345678901234";	
    unsigned char buffer2[] = "12345678901234567890123456789012";
    unsigned char expect[] = {0xbf, 0x63, 0xee, 0xe7, 0x1c, 0x21, 0x1f, 0x83,
			      0xc9, 0x63, 0xf1, 0x41, 0xd2, 0xff, 0xd4, 0x0a,
			      0x01, 0x9f, 0xb0, 0x90};
    TPM_DIGEST	actual;
    int		not_equal;
    uint32_t 	maxNumBytes = 0;	/* return from TPM_SHA1Start */

    /* get caller's command line arguments */
    if (rc == 0) {
	rc = getArgs(&start,
		     &update,
		     &complete,
		     &verbose,
		     argc, argv);
    }
    if ((rc == 0) && start) {
	rc = TPM_SHA1Start(&maxNumBytes);	/* ignore, buffer is small */
	if (rc != 0) {
	    printf("sha1parts: Error in TPM_SHA1Start\n");
	}
    }    
    if ((rc == 0) && update) {
	rc = TPM_SHA1Update(buffer1, 64);
 	if (rc != 0) {
	    printf("sha1parts: Error in TPM_SHA1Update\n");
	}
    }    
    if ((rc == 0) && complete) {
	rc = TPM_SHA1Complete(buffer2, 32, actual);
	if (rc != 0) {
	    printf("sha1parts: Error in TPM_SHA1Complete\n");
	}
    }    
    if ((rc == 0) && complete) {
	not_equal = memcmp(expect, actual, TPM_DIGEST_SIZE);
	if (not_equal) {
	    printf("sha1parts: Error in digest\n");
	    rc = -1;
	}
    }
    if (rc != 0) {
	printf("sha1parts: Error\n");
    }
    return rc;
}

/* getArgs() gets the command line arguments from the framework.
 */
 
int getArgs(int *start,
	    int *update,
	    int *complete,
	    int *verbose,
	    int argc,
	    char **argv)
{
    long	rc = 0;
    int	i;

    /* command line argument defaults */
    *start = FALSE;
    *update = FALSE;
    *complete = FALSE;
    TPM_setlog(0);

    /* get the command line arguments */
    for (i = 1 ; (i < argc) && (rc == 0) ; i++) {
	if (strcmp(argv[i],"-s") == 0) {
	    *start = TRUE;
	}
	else if (strcmp(argv[i],"-u") == 0) {
	    *update = TRUE;
	}
	else if (strcmp(argv[i],"-c") == 0) {
	    *complete = TRUE;
	}
	else if (strcmp(argv[i],"-h") == 0) {
	    printUsage();
	}
	else if (strcmp(argv[i],"-v") == 0) {
	    TPM_setlog(1);
	    *verbose = TRUE;
	}
	else {
	    printf("\n%s is not a valid option\n", argv[i]);
	    printUsage();
	}
    }
    return rc;
}

void printUsage()
{
    printf("sha1parts usage:\n"
	    "\n"
	    "\t-s          - Issue SHA1 Start\n"
	    "\t-u          - Issue SHA1 Update\n"
	    "\t-c          - Issue SHA1 Complete\n"
	    "\n"
	   );
    exit(1);
}
