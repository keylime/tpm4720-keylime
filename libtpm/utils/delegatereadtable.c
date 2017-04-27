/********************************************************************************/
/*										*/
/*			     	TPM Delegate_ReadTable                        	*/
/*			     Written by S. Berger				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*	      $Id: delegatereadtable.c 4702 2013-01-03 21:26:29Z kgoldman $	*/
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
#ifdef TPM_POSIX
#include <netinet/in.h>
#endif
#ifdef TPM_WINDOWS
#include <winsock2.h>
#endif
#include "tpm.h"
#include "tpmutil.h"
#include <tpmfunc.h>


int main(int argc, char *argv[])
{
	int ret;
	unsigned char familyTable[256];
	uint32_t familyTableSize = sizeof(familyTable);
	unsigned char delegateTable[256];
	uint32_t delegateTableSize = sizeof(delegateTable);
	uint32_t i = 0;
	(void)argv;
	(void)argc;
	
	TPM_setlog(0);

	ret = TPM_Delegate_ReadTable(familyTable, &familyTableSize,
	                             delegateTable, &delegateTableSize);

	if (0 != ret) {
		printf("Delegate_ReadTable returned error '%s' (%d).\n",
		       TPM_GetErrMsg(ret),
		       ret);

	} else {
		STACK_TPM_BUFFER( buffer )
		i = 0;
		SET_TPM_BUFFER( &buffer, familyTable, familyTableSize)
		while (i < familyTableSize) {
			TPM_FAMILY_TABLE_ENTRY fte;
			ret = TPM_ReadFamilyTableEntry(&buffer, i, &fte);
			if (0 == (ret & ERR_MASK) && ret > 0) {
				printf("Family Table Entry:\n"
				       "familyLabel       : %d\n"
				       "familyID          : "OUT_FORMAT("%d","%d")"\n"
				       "verificationCount : "OUT_FORMAT("%d","%d")"\n"
				       "flags             : "OUT_FORMAT("0x%x","0x%x")"\n\n",
				       fte.familyLabel,
				       fte.familyID,
				       fte.verificationCount,
				       fte.flags);
			} else {
				printf("Error %s from TPM_ReadFamilyTableEntry.\n",
				       TPM_GetErrMsg(ret));
				return ret;
			}
			i += ret;
		}

		SET_TPM_BUFFER( &buffer, delegateTable, delegateTableSize);
		i = 0;
		while (i < delegateTableSize) {
			TPM_DELEGATE_PUBLIC dtp;
			TPM_DELEGATE_INDEX didx = LOAD32(buffer.buffer, i);
			i += 4;
			ret = TPM_ReadDelegatePublic(&buffer, i, &dtp);
			if (0 == (ret & ERR_MASK) && ret > 0) {
				printf("\n\nDelegate Table Entry:\n"
				       "index             : "OUT_FORMAT("%d","%d")"\n"
				       "rowLabel          : %d\n"
				       "permissions       : "OUT_FORMAT("0x%08x, 0x%08x","0x%08x, 0x%08x")"\n"
				       "familyID          : "OUT_FORMAT("%d","%d")"\n"
				       "verificationCount : "OUT_FORMAT("%d","%d")"\n",
				       didx,
				       dtp.rowLabel,
				       dtp.permissions.per1, dtp.permissions.per2,
				       dtp.familyID,
				       dtp.verificationCount);
			} else {
				printf("Error %s from TPM_ReadDelegatePublic.\n",
				       TPM_GetErrMsg(ret));
				exit(ret);
			}
			i += ret;
		}
		printf("\n");
		ret = 0;
	}

	exit(ret);
}
