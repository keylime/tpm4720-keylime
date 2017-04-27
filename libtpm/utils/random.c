/********************************************************************************/
/*										*/
/*			     	TPM Test Random					*/
/*			     Written by S. Berger				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*	      $Id: random.c 4702 2013-01-03 21:26:29Z kgoldman $		*/
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

#include "tpm.h"
#include "tpmutil.h"
#include "tpmfunc.h"


static unsigned int
countOnes(unsigned char l)
{
	unsigned char mask = 0x1;
	unsigned int c = 0;
	while (mask) {
	        if (l & mask) {
	              c++;
	        }
	        mask <<= 1;
	}
	return c;
}

static unsigned int
matchPattern(unsigned char l, unsigned char pattern, unsigned char bits)
{
	int shifted = 0;
	unsigned char mask = 1;
	int c;
	unsigned int ctr = 0;
	for (c = 1; c < bits; c++) {
		mask <<= 1;
		mask |= 1;
	}
	while (shifted < 8) {
		if ((l & mask) == pattern) {
			ctr++;
		}
		l >>= bits;
		shifted += bits;
	}
	return ctr;
}

int main(void)
{
	unsigned char buffer[1024];
	unsigned int i = 0;
	unsigned int ones = 0, zeroes = 0;
	unsigned int pattern2[4] = {0,0,0,0};
	
	TPM_setlog(0);
	
	printf("Counting number of '1's and '0's of the random number generator.\n");
	while (i < 10) {
	        uint32_t bufferSize = sizeof(buffer);
	        unsigned int j = 0;
	        uint32_t ret;
	        ret = TPM_GetRandom(bufferSize,
	                            buffer, &bufferSize);
		if (0 != ret) {
			printf("Error %s from TPM_GetRandom.\n",
			       TPM_GetErrMsg(ret));
			exit (ret);
		}
                while (j < bufferSize) {
                        unsigned int c = countOnes(buffer[j]);
                        ones += c;
                        zeroes += (8-c);
                        pattern2[0] += matchPattern(buffer[j], 0x0, 2);
                        pattern2[1] += matchPattern(buffer[j], 0x1, 2);
                        pattern2[2] += matchPattern(buffer[j], 0x2, 2);
                        pattern2[3] += matchPattern(buffer[j], 0x3, 2);
                        j++;
                }
                ret = TPM_StirRandom(buffer, 10);
                if (0 != ret) {
                	printf("Error %s from TPM_StirRandom.\n",
                	       TPM_GetErrMsg(ret));
                	exit(ret);
                }
	        i++;
	}
	printf("Percentage of '1': %d percent.\n", (ones*100)/(ones+zeroes));
	printf("Percentage of '00' bits:  %d percent\n",
	       (pattern2[0]*200)/(ones+zeroes));
	printf("Percentage of '01' bits:  %d percent\n",
	       (pattern2[1]*200)/(ones+zeroes));
	printf("Percentage of '10' bits:  %d percent\n",
	       (pattern2[2]*200)/(ones+zeroes));
	printf("Percentage of '11' bits:  %d percent\n",
	       (pattern2[3]*200)/(ones+zeroes));
	return 0;
}

