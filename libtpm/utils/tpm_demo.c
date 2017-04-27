/********************************************************************************/
/*										*/
/*			     	TPM simple Demonstration Program		*/
/*			     Written by J. Kravitz 				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*	      $Id: tpm_demo.c 4702 2013-01-03 21:26:29Z kgoldman $		*/
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
#ifdef TPM_POSIX
#include <netinet/in.h>
#endif
#ifdef TPM_WINDOWS
#include <winsock2.h>
#endif
#include <tpmfunc.h>  /* using TPM_Transmit, TPM_reset, and TPM_setlog */


static
uint32_t TPM_GetCapability_Version_Val(int *major, int *minor, int *revMajor,
				       int *revMinor)
{
	STACK_TPM_BUFFER(blob)
	uint32_t ordinal_no = htonl(TPM_ORD_GetCapability);
	uint32_t cap = htonl(TPM_CAP_VERSION_VAL);
	uint32_t ret;	
	TSS_buildbuff("00 c1 T l l l", &blob,
		      ordinal_no,
		      cap, 
		      0);
	ret = TPM_Transmit(&blob, "TPM_GetCapability_Version_Val");
	if(ret) {
	    return(ret);
	}
	*major = (int)(blob.buffer[16]);
	*minor = (int)(blob.buffer[17]);
	*revMajor = (int)(blob.buffer[18]);
	*revMinor = (int)(blob.buffer[19]);
	return(ret);
}

static
uint32_t TPM_GetCapability_Slots(uint32_t *slots)
{
	STACK_TPM_BUFFER(blob)
	uint32_t ordinal_no = htonl(TPM_ORD_GetCapability);
	uint32_t cap = htonl(TPM_CAP_PROPERTY);
	unsigned char subcap[4];
	uint32_t subcap_size = sizeof(subcap);
	uint32_t ret;
	STORE32(subcap,0,TPM_CAP_PROP_KEYS);
	TSS_buildbuff("00 c1 T l l @", &blob,
	                       ordinal_no,
	                         cap,
	                           subcap_size, subcap);
	ret = TPM_Transmit(&blob, "TPM_GetCapability_Slots");
	if(ret)
		return(ret);
	*slots = ntohl(*(uint32_t *)(&blob.buffer[14]));
	return(ret);
}

static
uint32_t TPM_GetCapability_Pcrs(uint32_t *pcrs)
{
	STACK_TPM_BUFFER(blob)
	uint32_t ordinal_no = htonl(TPM_ORD_GetCapability);
	uint32_t cap = htonl(TPM_CAP_PROPERTY);
	unsigned char subcap[4];
	uint32_t subcap_size = sizeof(subcap);
	uint32_t ret;
	STORE32(subcap,0,TPM_CAP_PROP_PCR);
	TSS_buildbuff("00 c1 T l l @", &blob,
	                       ordinal_no,
	                         cap,
	                           subcap_size, subcap);
	ret = TPM_Transmit(&blob, "TPM_GetCapability_Pcrs");
	if(ret)
		return(ret);
	*pcrs = ntohl(*(uint32_t *)(&blob.buffer[14]));
	return(ret);
}

static
uint32_t TPM_GetCapability_Key_Handle(uint16_t *num, uint32_t keys[])
{
	STACK_TPM_BUFFER(blob)
	uint32_t ordinal_no = htonl(TPM_ORD_GetCapability);
	uint32_t cap = htonl(TPM_CAP_KEY_HANDLE);
 	uint32_t ret;
	int i;
	TSS_buildbuff("00 c1 T l l @", &blob,
	                       ordinal_no,
	                         cap,
	                           0, NULL);
	ret = TPM_Transmit(&blob, "TPM_GetCapability_Handle_List");
	if(ret)
		return(ret);
	*num = ntohs(*(uint16_t *)(&blob.buffer[14]));
	for(i=0;i<*num;i++)
		keys[i] = ntohl(*(uint32_t *)(&blob.buffer[16+4*i])); 
	return(ret);
}

int main(int argc, char *argv[])
{
    pubkeydata pubek;
    uint32_t slots;
    uint32_t pcrs;
    uint16_t num;
    uint32_t keys[256];
    unsigned char pcr_data[20];
    int major, minor, revMajor, revMinor, i, j;
    (void)argc;
    (void)argv;

#ifndef TPM_DEBUG
    /* by default, libtpm does verbose logging. This turns it off */
    TPM_setlog(0);
#endif

    if (TPM_Reset())
        exit(-1);
    printf("TPM successfully reset\n");

    if (TPM_GetCapability_Version_Val(&major,&minor,&revMajor,&revMinor))
        exit(-1);
    printf("TPM version %d.%d.%d.%d\n",major,minor,revMajor,revMinor);

    if(TPM_GetCapability_Pcrs(&pcrs))
        exit(-1);
    printf("%d PCR registers are available\n",pcrs);
    for(i=0;i<(int)pcrs;i++){
        if(TPM_PcrRead((uint32_t)i,pcr_data))
            exit(-1);
        printf("PCR-%02d: ",i);
        for(j=0;j<20;j++)
            printf("%02X ",pcr_data[j]);
        printf("\n");
    }

    if(TPM_GetCapability_Slots(&slots))
        exit(-1);
    printf("%d Key slots are available\n",slots);

    if(TPM_GetCapability_Key_Handle(&num, keys))
        exit(-1);
    if(num==0)
        printf("No keys are loaded\n");
    else 
        for(i=0;i<num;i++)
            printf("Key Handle %04X loaded\n",keys[i]);

    if (TPM_ReadPubek(&pubek))
        printf("Unable to read Pubek\n");
    else{
        printf("Pubek keylength %d\nModulus:",pubek.pubKey.keyLength);
        for(i=0;i<(int)pubek.pubKey.keyLength;i++){
            if(!(i%16))
                printf("\n");
            printf("%02X ",pubek.pubKey.modulus[i]);
        }
        printf("\n");
    }

    return (0);
}
