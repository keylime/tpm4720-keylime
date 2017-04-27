#################################################################################
#										#
#		Windows MinGW TPM Makefile - Test Suite TPM			#
#			     Written by Ken Goldman				#
#		       IBM Thomas J. Watson Research Center			#
#	      $Id: makefile-ts.mak 4716 2013-12-24 20:47:44Z kgoldman $		#
#										#
# (c) Copyright IBM Corporation 2006, 2010.					#
# 										#
# All rights reserved.								#
# 										#
# Redistribution and use in source and binary forms, with or without		#
# modification, are permitted provided that the following conditions are	#
# met:										#
# 										#
# Redistributions of source code must retain the above copyright notice,	#
# this list of conditions and the following disclaimer.				#
# 										#
# Redistributions in binary form must reproduce the above copyright		#
# notice, this list of conditions and the following disclaimer in the		#
# documentation and/or other materials provided with the distribution.		#
# 										#
# Neither the names of the IBM Corporation nor the names of its			#
# contributors may be used to endorse or promote products derived from		#
# this software without specific prior written permission.			#
# 										#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS		#
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT		#
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR		#
# A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT		#
# HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,	#
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT		#
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,		#
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY		#
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT		#
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE		#
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.		#
#										#
#################################################################################

CC = c:/progra~1/mingw/bin/gcc.exe

CCFLAGS = -Wall  			\
	-Wnested-externs -ggdb -O0 -c 	\
	-DTPM_WINDOWS 			\
	-DTPM_V12			\
	-DTPM_AES			\
	-DTPM_NV_DISK			\
	-DTPM_DEBUG   	\
	-DTPM_PCCLIENT 			\
	-DTPM_ENABLE_ACTIVATE		\
	-Ic:/progra~1/MinGW/include	\
	-Ic:/progra~1/openssl/include	\
	-I.

LNFLAGS = -ggdb 			\
	-DTPM_WINDOWS 			\
	-DTPM_V12			\
	-DTPM_AES			\
	-DTPM_NV_DISK			\
	-DTPM_DEBUG   	\
	-DTPM_PCCLIENT 			\
	-DTPM_ENABLE_ACTIVATE		\
	-Ic:/progra~1/MinGW/include	\
	-Ic:/progra~1/openssl/include	\
	-I.

LNLIBS = 	c:/progra~1/openssl/lib/mingw/libeay32.a \
		c:/progra~1/openssl/lib/mingw/ssleay32.a \
		c:/progra~1/MinGW/lib/libws2_32.a

all:	tpm_server.exe

CRYPTO_SUBSYSTEM = openssl
include makefile-common

.PHONY:		clean
.PRECIOUS:	%.o


OBJFILES += applink.o


tpm_server.exe:	$(OBJFILES)
		$(CC) $(OBJFILES) $(LNFLAGS) -o tpm_server.exe $(LNLIBS) 

clean:		
		rm *.o *.exe *~

# %.exe:		%.o applink.o
# 		$(CC) $(LNFLAGS) $< applink.o -o $@ $(LNLIBS)


%.o:		%.c
		$(CC) $(CCFLAGS) $< -o $@

