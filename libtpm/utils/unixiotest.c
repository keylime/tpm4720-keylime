/********************************************************************************/
/*										*/
/*		     Test communication using UnixIO socket   			*/
/*			     Written by Stefan Berger				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*	      $Id: unixiotest.c 4702 2013-01-03 21:26:29Z kgoldman $		*/
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
#include <sys/un.h>
#include <sys/socket.h>

#include "tpm.h"
#include "tpmutil.h"
#include "tpmfunc.h"
#include "tpm_constants.h"
#include "tpm_structures.h"

static void usage(const char *name) {
	printf(
	"Usage: %s [-v] [--keep-alive] <instance number>\n"
	"-v           : enable verbose output\n"
	"--keep-alive : keep UnixIO connection alive\n"
	"-l <loops>   : the number of times to send a request; default is 10\n"
	"-?           : this help\n"
	"\n"
	"This program currently makes the TPM generate a key and then tries to migrate that key.\n"
	"\n"
	"\n"
	"Examples:\n"
	"%s 1\n",
	name, name);
}

int main(int argc, char * argv[]) {
	int i = 0;
	uint32_t instance;
	i = 1;
	TPM_BOOL keep_alive = FALSE;
	TPM_BOOL is_established = FALSE;
	int fd = -1;
	int loops;
	
	TPM_setlog(0);

	while (i < argc) {
		if (!strcmp("-v",argv[i])) {
		        TPM_setlog(1);
		} else
		if (!strcmp("--keep-alive",argv[i])) {
		        keep_alive = TRUE;
		} else
		if (!strcmp("-l",argv[i])) {
		        i++;
		        if (i >= argc) {
		                printf("Missing parameter to '-l'.\n");
		                usage(argv[0]);
		                exit(-1);
		        }
		        if (1 != sscanf(argv[i], "%d", &loops)) {
		                printf("Could not read integer parameter to '-l'\n");
		                usage(argv[0]);
		                exit(-1);
		        }
		} else
		if (!strcmp("-?",argv[i])) {
		        usage(argv[0]);
		        exit(0);
		} else {
		        break;
		}
		i++;
        }

        if (argc < (i+1)) {
                printf("Missing command line parameter.\n");
                usage(argv[0]);
                exit(-1);
        }

        if (1 != sscanf(argv[i],"%d",&instance)) {
                printf("Could not read instance parameter.\n");
                exit(-1);
        }
        
        for (i = 0; i < loops; i++) {
                if (fd < 0) {
                        fd = socket(PF_UNIX, SOCK_STREAM, 0);
#if 0
                        printf("socket fd: %d\n",fd);
                } else {
                        printf("NOT opening new socket.\n");
#endif
                }
                if (fd > 0) {
                        struct sockaddr_un addr;
                        uint32_t inst_no = htonl(instance);
                        unsigned char pcrread[] =  {
                                0x00, 0x00, 0x00, 0x00,  /* instance */
                                0x00, 0xc1,
                                0x00, 0x00, 0x00, 0x0e,  /* length code */
                                0x00, 0x00, 0x00, 0x15,  /* ordinal */
                                0x00, 0x00, 0x00, 0x0a   /* pcr 10 */
                        };
                        unsigned char buffer[1024];
                        int len, ctr;
                        if (FALSE == is_established) {
                                memset(&addr, 0x0, sizeof(addr));
                                addr.sun_family = AF_UNIX;
                                strcpy(addr.sun_path,
                                       "/var/vtpm/vtpm_all.socket");
                                if (connect(fd,
                                            (struct sockaddr *)&addr,
                                            sizeof(addr)) != 0) {
                                        close(fd);
                                        printf("Could not establish connection "
                                               "with vTPM.\n");
                                        return -1;
                                }
#if 0
                        } else {
                                printf("NOT connecting to server.\n");
#endif
                        }
                        memcpy(pcrread,
                               &inst_no,
                               sizeof(inst_no));
#if 0
                        printf("writing command.\n");
#endif
                        len = write(fd, pcrread, sizeof(pcrread));
                        if (len != sizeof(pcrread)) {
#if 0
                                printf("Could not write command.\n");
#endif
                                return -1;
                        }
#if 0
                        printf("wrote %d bytes. reading now.\n", len);
#endif
                        len = read(fd, buffer, sizeof(buffer));
                        if (len <= 0) {
                                printf("Could not read response.\n");
                                return -1;
                        }
                        printf("%02d. Response:\n",i);
                        for (ctr = 0; ctr < len; ctr++) {
                                printf("%02x ", buffer[ctr]);
                                if ((ctr & 0xf) == 0xf) {
                                        printf("\n");
                                }
                        }
                        if (FALSE == keep_alive) {
                                close(fd);
                                fd = -1;
                        } else {
                                is_established = TRUE;
                        }
                        printf("\n");
                } else {
                        printf("Could not create UnixIO socket.\n");
                        return -1;
                }
        }
        
        return 0;
}
