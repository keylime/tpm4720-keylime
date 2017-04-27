/********************************************************************************/
/*										*/
/*			    TCPA Bios Emulation 				*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*	      $Id: tpmbios.c 4702 2013-01-03 21:26:29Z kgoldman $		*/
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

/* 1 - Sends one of three commands:

   -c startup_clear:	all back to non-volatile state
   -s startup_save:	back to saved state
   -d startup_deactivated:	requires another init (reboot)

   Then after _save or _clear:
   
   2 - Sends the TSC_PhysicalPresence command to turn on physicalPresenceCMDEnable
   3 - Sends the TPM_PhysicalEnable command to enable
   4 - Sends the TPM_PhysicalSetDeactivated command to activate

*/

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
#include "tpmfunc.h"

/* local prototypes */

void print_usage(void);
static long getPhysicalCMDEnable(TPM_BOOL *physicalPresenceCMDEnable);


int main(int argc, char *argv[])
{
   int 			ret = 0;
   int			i;			/* argc iterator */
   int			do_more = 1;
   int                  contselftest = 0;
   unsigned char        startupparm = 0x1;      /* parameter for TPM_Startup(); */
   TPM_BOOL 		physicalPresenceCMDEnable = FALSE;
   
   TPM_setlog(0);      /* turn off verbose output */
   /* command line argument defaults */
   
   for (i=1 ; (i<argc) && (ret == 0) ; i++) {
       if (strcmp(argv[i],"-c") == 0) {
           startupparm = 0x01;
	   do_more = 1;
       }
       else if (strcmp(argv[i],"-d") == 0) {
	   do_more = 0;
           startupparm = 0x03;
       }
       else if (strcmp(argv[i],"-h") == 0) {
	   ret = ERR_BAD_ARG;
	   print_usage();
       }
       else if (strcmp(argv[i],"-v") == 0) {
	   TPM_setlog(1);
       }
       else if (strcmp(argv[i],"-n") == 0) {
	   startupparm = 0xff; 
	   do_more = 1;
       }
       else if (strcmp(argv[i],"-s") == 0) {
           startupparm = 0x2;
	   do_more = 1;
       }
       else if (strcmp(argv[i],"-o") == 0) {
	   do_more = 0;
       }
       else if (strcmp(argv[i],"-cs") == 0) {
           contselftest = 1;
       }
       else {
	   printf("\n%s is not a valid option\n", argv[i]);
	   ret = ERR_BAD_ARG;
	   print_usage();
       }
   }
   if (ret == 0) {
       if (0xff != startupparm) {
	   ret = TPM_Startup(startupparm);
	   if (ret != 0) {
	       printf("Error %s from TPM_Startup\n", 
		      TPM_GetErrMsg(ret));
	   }
       }
   }
   /* check to see if physicalPresenceCMDEnable is already set.  If it is, don't try to send it
      again as the command will fail if the lifetime lock is set. */
   if ((ret == 0) && do_more) {
       ret = getPhysicalCMDEnable(&physicalPresenceCMDEnable);
   }
   /* Sends the TSC_PhysicalPresence command to turn on physicalPresenceCMDEnable */
   if ((ret == 0) && do_more && !physicalPresenceCMDEnable) {
       ret = TSC_PhysicalPresence(0x20);
       if (ret != 0) {
	   printf("Error %s from TSC_PhysicalPresence\n",
		  TPM_GetErrMsg(ret));
       }
   }
   /* Sends the TSC_PhysicalPresence command to turn on physicalPresence */
   if ((ret == 0) && do_more) {
       ret = TSC_PhysicalPresence(0x08);
       if (ret != 0) {
	   printf("Error %s from TSC_PhysicalPresence\n",
		  TPM_GetErrMsg(ret));
       }
   }
   /* Sends the TPM_Process_PhysicalEnable command to clear disabled */
   if ((ret == 0) && do_more) {
       ret = TPM_PhysicalEnable();
       if (ret != 0) {
	   printf("Error %s from TPM_PhysicalEnable\n",
		  TPM_GetErrMsg(ret));
       }
   }
   /* Sends the TPM_Process_PhysicalSetDeactivated command to clear deactivated */
   if ((ret == 0) && do_more) {
       ret = TPM_PhysicalSetDeactivated(FALSE);
       if (ret != 0) {
	   printf("Error %s from TPM_PhysicalSetDeactivated\n",
		  TPM_GetErrMsg(ret));
       }
   }

   if ((ret == 0) && contselftest) {
       ret = TPM_ContinueSelfTest();
       if (ret != 0) {
           printf("Error %s from TPM_ContinueSelfTest\n",
                  TPM_GetErrMsg(ret));
       }
   }

   return ret;
}

void print_usage(void)
{
    printf("\n");
    printf("tpmbios\n");
    printf("\n");
    printf("Runs TPM_Startup (unless -n), then (unless -o) sets PP, enable, activate \n");
    printf("\n");
    printf("\t-c  startup clear (default)\n");
    printf("\t-s  startup state\n");
    printf("\t-d  startup deactivate\n");
    printf("\t-n  no startup\n");
    printf("\t-o  startup only\n");
    printf("\t-cs run TPM_ContinueSelfTest\n");
    return;
}

static long getPhysicalCMDEnable(TPM_BOOL *physicalPresenceCMDEnable)
{
    uint32_t ret = 0;
    STACK_TPM_BUFFER( subcap );
    STACK_TPM_BUFFER( resp );
    STACK_TPM_BUFFER( tb );
    TPM_PERMANENT_FLAGS permanentFlags;
    
    if (ret == 0) {
	STORE32(subcap.buffer, 0, TPM_CAP_FLAG_PERMANENT  );
	subcap.used = 4;
	ret = TPM_GetCapability(TPM_CAP_FLAG,
				&subcap,
				&resp);
	if (ret != 0) {
	    printf("Error %s from TPM_GetCapability\n",
		   TPM_GetErrMsg(ret));
	}
    }
    if (ret == 0) {
	TSS_SetTPMBuffer(&tb, resp.buffer, resp.used);
	ret = TPM_ReadPermanentFlags(&tb, 0, &permanentFlags, resp.used);
	if ( ( ret & ERR_MASK ) != 0 || ret > resp.used) {
	    printf("TPM_ReadPermanentFlags: ret %08x, responselen %d\n", ret, resp.used);
	    printf("TPM_ReadPermanentFlags: Error parsing response!\n");
	}
	else {
	    ret = 0;
	}
    }
    if (ret == 0) {
	*physicalPresenceCMDEnable = permanentFlags.physicalPresenceCMDEnable;
    }
    return ret;
}
