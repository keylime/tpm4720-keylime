/********************************************************************************/
/*                                                                              */
/*                           TPM Main Program                                   */
/*                           Written by Ken Goldman                             */
/*                     IBM Thomas J. Watson Research Center                     */
/*            $Id: tpm_server.c 4716 2013-12-24 20:47:44Z kgoldman $            */
/*                                                                              */
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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

/* Commented out.  This is not a standard header.  If needed for a particular platform, replace but
   also add comments and ifdef. */
/* #include <stdint.h> */

#include "tpm_debug.h"
#include "tpm_global.h"
#include "tpm_io.h"
#include "tpm_init.h"
#include "tpm_nvram.h"
#include "tpm_process.h"
#include "tpm_startup.h"
#include "tpm_svnrevision.h"

/* local function prototypes */

#ifdef TPM_POSIX
static void *mainLoop(void *mainLoopArgs);
#endif
#ifdef TPM_WINDOWS
static void mainLoop(void *mainLoopArgs);
#endif

/* if it's threaded and TPM_NUM_THREADS was not specified as a compile time argument, use a default
   value */


int main(int argc, char **argv)
{
    TPM_RESULT          rc = 0;
    time_t              start_time;

#ifdef TPM_ALLOW_DAEMONIZE
    if (argc > 1 && (!strcmp("-d",argv[1]) || !strcmp("--daemon",argv[1]))) {
       if (0 != daemon(0,0)) {
           return EXIT_FAILURE;
       }
    }
#else	/* TPM_ALLOW_DAEMONIZE */
    /* to silence compiler */
    (void)argc;
    (void)argv;
#endif	/* TPM_ALLOW_DAEMONIZE */

    setvbuf(stdout, 0, _IONBF, 0);      /* output may be going through pipe */
    /* initialization */
    start_time = time(NULL);
    printf("main: Initializing TPM at %s", ctime(&start_time));
    if (TPM_REVISION == TPM_REVISION_MAX) {
        printf("main: Compiled for latest revision specLevel %04x errataRev %02x\n",
	TPM_SPEC_LEVEL, TPM_ERRATA_REV);
    }
    else {
        printf("main: Compiled for revision %u specLevel %04x errataRev %02x\n",
               TPM_REVISION, TPM_SPEC_LEVEL, TPM_ERRATA_REV);
    }
    printf("main: Compiled svn version %hu revMajor %02x revMinor %02x\n",
           tpm_svn_revision, (tpm_svn_revision >> 8) & 0xff, tpm_svn_revision & 0xff);
    printf("main: Compiled as standard TPM\n");
    
    printf("main: Compiled for single instance\n");
#ifdef TPM_PCCLIENT
    printf("main: Compiled for PC Client\n");
#endif
    printf("Main: Compiled for %u auth %u transport %u DAA session slots\n",
	   TPM_MIN_AUTH_SESSIONS,
	   TPM_MIN_TRANS_SESSIONS,
	   TPM_MIN_DAA_SESSIONS);
    printf("Main: Compiled for %u key slots, %u owner evict slots\n",
	   TPM_KEY_HANDLES,
	   TPM_OWNER_EVICT_KEY_HANDLES);
    printf("Main: Compiled for %u counters, %u saved sessions\n",
	   TPM_MIN_COUNTERS,
	   TPM_MIN_SESSION_LIST);
    printf("Main: Compiled for %u family, %u delegate table entries\n",
	   TPM_NUM_FAMILY_TABLE_ENTRY_MIN,
	   TPM_NUM_DELEGATE_TABLE_ENTRY_MIN);
    printf("Main: Compiled for %u total NV, %u savestate, %u volatile space\n",
	   TPM_MAX_NV_SPACE,
	   TPM_MAX_SAVESTATE_SPACE,
	   TPM_MAX_VOLATILESTATE_SPACE);
    printf("Main: Compiled for %u NV defined space\n",
	   TPM_MAX_NV_DEFINED_SIZE);
    /* TPM_Init transitions the TPM from a power-off state to one where the TPM begins an
       initialization process.  TPM_Init could be the result of power being applied to the platform
       or a hard reset. */
    if (rc == 0) {
        rc = TPM_MainInit();
    }
    if (rc == 0) {
        mainLoop(NULL);
    }
    /* Fatal initialization errors cause the program to abort */
    if (rc == 0) {
        return EXIT_SUCCESS;
    }
    else {
        printf("main: TPM initialization failure %08x, exiting\n", rc);
        return EXIT_FAILURE;
    }
}

/* mainLoop() is the main server loop.

   It reads a TPM request, processes the ordinal, and writes the response
*/

#ifdef TPM_POSIX
static void *mainLoop(void *mainLoopArgs)
#endif
#ifdef TPM_WINDOWS
static void mainLoop(void *mainLoopArgs)
#endif
{
    TPM_RESULT          rc = 0;
    TPM_CONNECTION_FD   connection_fd;                          /* file descriptor for read/write */
    unsigned char       command[TPM_BUFFER_MAX];                /* command buffer */
    uint32_t		command_length;				/* actual length of command bytes */
    /* The response buffer is reused for each command. Thus it can grow but never shrink */
    unsigned char 	*rbuffer = NULL;                        /* actual response bytes */
    uint32_t            rlength = 0;				/* bytes in response buffer */
    uint32_t		rTotal = 0;				/* total allocated bytes */
#if TPM_THREADED
    unsigned long       threadId;

    TPM_Thread_Id(&threadId);
    printf("mainLoop: Thread number %u\n", *(int *)mainLoopArgs);
    printf("mainLoop: Thread ID %lu\n", threadId);
#else
    printf("mainLoop:\n");
#endif    
    while (TRUE) {
        /* connect to the client */
        if (rc == 0) {
            rc = TPM_IO_Connect(&connection_fd,
                                mainLoopArgs);
        }
        /* was connecting successful? */
        if (rc == 0) {
            /* Read the command.  The number of bytes is determined by 'paramSize' in the stream */
            if (rc == 0) {
                rc = TPM_IO_Read(&connection_fd, command, &command_length, sizeof(command),
                                 mainLoopArgs);
            }
            if (rc == 0) {
		rlength = 0;				/* clear the response buffer */
		rc = TPM_ProcessA(&rbuffer,
				  &rlength,
				  &rTotal,
				  command,		/* complete command array */
				  command_length);	/* actual bytes in command */
	    }
            /* write the results */
            if (rc == 0) {
                rc = TPM_IO_Write(&connection_fd, rbuffer, rlength);
            }
#ifdef TPM_VOLATILE_STORE
	    /* temporary code to test TPM_VOLATILE_STORE */
#ifdef TPM_VOLATILE_TEST
	    /* for test only, delete and reload the global state after every ordinal */
            if (rc == 0) {
		if (rc == 0) {
		    TPM_Global_Delete(tpm_instances[0]);
		    rc = TPM_Global_Init(tpm_instances[0]);
		}
		if (rc == 0) {
		    tpm_instances[0]->tpm_number = 0;
		    rc = TPM_Global_Load(tpm_instances[0]);
		}
	    }
#endif	/* temporary test code */
#endif	/* TPM_VOLATILE_STORE */
            /* disconnect from the client, do this even if the read or write fails */
            rc = TPM_IO_Disconnect(&connection_fd);
        }
        /* clear the response buffer, does not deallocate memory */
        rc = 0; /* A fatal TPM_Process() error should cause the TPM to enter shutdown.  IO errors
                   are outside the TPM, so the TPM does not shut down.  The main loop should
                   continue to function.*/
    }
#ifdef TPM_POSIX
    return NULL;
#endif
#ifdef TPM_WINDOWS
    return;
#endif
}
