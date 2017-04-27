/********************************************************************************/
/*										*/
/*			     	TPM Get Random					*/
/*			     Written by Nabil Schear			*/
/*										*/
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

static int printUsage()
{
    printf("Usage: getrandom\n"
	   "-size <number of bytes of randomness>\n"
	   "-out  <filename to write out randomness>\n");
    exit(-1);
    return -1;
}


int main(int argc, char *argv[])
{
    int ret;			/* general return value */
	unsigned char *buffer = NULL;
	int i = 0;
	uint32_t numbytes = 0;
	const char *output = NULL;
	FILE *fp = NULL;
	
	TPM_setlog(0);
	
    for (i=1 ; i<argc ; i++) {
	if (!strcmp(argv[i], "-size")) {
	    i++;
	    if (i < argc) {
		numbytes = atoi(argv[i]);
	    }
	    else {
		printf("Missing parameter to -size\n");
		printUsage();
	    }
	}
	else if (!strcmp(argv[i], "-out")) {
	    i++;
	    if (i < argc) {
		output = argv[i];
	    }
	    else {
		printf("Missing parameter to -out\n");
		printUsage();
	    }
	}
	else if (!strcmp(argv[i], "-h")) {
	    printUsage();
	}
	else if (!strcmp(argv[i], "-v")) {
	    TPM_setlog(1);
	}
	else {
	    printf("\n%s is not a valid option\n", argv[i]);
	    printUsage();
	}
    }

    if(output==NULL) {
    	printf("missing output filename\n");
    	return printUsage();
    }
    if(numbytes==0){
    	numbytes=32;
    }


    if((buffer=(unsigned char*)malloc(sizeof(unsigned char)*numbytes))==NULL) {
    printf("unable to allocate memory for random output.\n");
    exit(-1);
    }

    ret = TPM_GetRandom(numbytes,buffer,&numbytes);
	if (0 != ret) {
		printf("Error %s from TPM_GetRandom.\n",
		       TPM_GetErrMsg(ret));
		exit (ret);
	}

	// now write it out
    if((fp = fopen(output,"w"))==0) {
    printf("Error opening file %s\n",output);
    exit(-1);
    }
    if(fwrite(buffer,sizeof(unsigned char),numbytes,fp)<numbytes) {
    printf("Error writing randomness.\n");
    exit(-1);
    }

    fclose(fp);
    return 0;
}

