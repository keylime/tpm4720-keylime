#################################################################################
#										#	
#			Windows MinGW TPM Utilities Makefile			#
#			     Written by Ken Goldman				#
#		       IBM Thomas J. Watson Research Center			#
#	      $Id: makefile.mak 4702 2013-01-03 21:26:29Z kgoldman $		#
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

CCFLAGS = -Wall 			\
	-Wnested-externs -ggdb -O0 -c 	\
	-DTPM_WINDOWS 			\
	-DTPM_NV_DISK			\
	-DTPM_V12			\
	-DTPM_AES			\
	-DTPM_USE_TAG_IN_STRUCTURE	\
	-Ic:/progra~1/MinGW/include	\
	-Ic:/progra~1/openssl/include	\
	-I../lib			\
	-I.

LNFLAGS = -ggdb 			\
	-DTPM_WINDOWS 			\
	-DTPM_NV_DISK			\
	-DTPM_V12			\
	-DTPM_AES			\
	-DTPM_USE_TAG_IN_STRUCTURE	\
	-D_MT				\
	-Ic:/progra~1/MinGW/include	\
	-Ic:/progra~1/openssl/include	\
	-I.

LNLIBS = 	c:/progra~1/openssl/lib/mingw/libeay32.a \
		c:/progra~1/openssl/lib/mingw/ssleay32.a \
		c:/progra~1/MinGW/lib/libws2_32.a

LNDLLS = ../lib/libtpm.dll

.PHONY:		clean
.PRECIOUS:	%.o

all:				\
	bindfile.exe		\
	calcfuturepcr.exe	\
	certifykey.exe		\
	certifyselftest.exe	\
	chgauth.exe		\
	chgtpmauth.exe		\
	clearown.exe		\
	cmk_approvema.exe	\
	cmk_createkey.exe	\
	cmk_createticket.exe	\
	cmk_loadmigrationblob.exe	\
	cmk_migrate.exe		\
	cmk_setrestrictions.exe	\
	counter_calc_incr.exe	\
	counter_create.exe	\
	counter_increment.exe	\
	counter_read.exe	\
	counter_release.exe	\
	createek.exe		\
	createkey.exe		\
	createkeydelegation.exe	\
	createownerdelegation.exe	\
	createrevek.exe		\
	delegatemanage.exe	\
	delegatereadtable.exe	\
	dirread.exe		\
	dirwrite.exe		\
	disableforceclear.exe	\
	disableownerclear.exe	\
	disablepubek.exe	\
	dumpkey.exe		\
	enableaudit.exe		\
	evictkey.exe		\
	extend.exe		\
	flushspecific.exe	\
	forceclear.exe		\
	getauditdigest.exe	\
	getauditdigestsigned.exe	\
	getcapability.exe	\
	getcontextcount.exe	\
	getpubek.exe		\
	getticks.exe		\
	identity.exe		\
	keycontrol.exe		\
	killmaintenancefeature.exe	\
	libtpm-config.exe	\
	listkeys.exe		\
	loadauthcontext.exe	\
	loadcontext.exe		\
	loadkey.exe		\
	loadkeycontext.exe	\
	loadmanumaintpub.exe	\
	loadmigrationblob.exe	\
	loadownerdelegation.exe	\
	migrate.exe		\
	migratekey.exe		\
	nv.exe			\
	nv_definespace.exe	\
	nv_readvalue.exe	\
	nv_writevalue.exe	\
	ownerreadinternalpub.exe	\
	ownersetdisable.exe	\
	pcrread.exe		\
	pcrreset.exe		\
	physicaldisable.exe	\
	physicalenable.exe	\
	physicalpresence.exe	\
	physicalsetdeactivated.exe	\
	quote.exe		\
	quote2.exe		\
	random.exe		\
	readmanumaintpub.exe	\
	resetestbit.exe		\
	resetlockvalue.exe	\
	revtrust.exe		\
	saveauthcontext.exe	\
	savecontext.exe		\
	savekeycontext.exe	\
	savestate.exe		\
	sealfile.exe		\
	sealfile2.exe		\
	sealxfile.exe		\
	selftest.exe		\
	session.exe		\
	setcapability.exe	\
	setoperatorauth.exe	\
	setownerinstall.exe	\
	setownerpointer.exe	\
	settempdeactivated.exe	\
	sha.exe			\
	sha1parts.exe		\
	signfile.exe		\
	signmsg.exe		\
	takeown.exe		\
	tickstampblob.exe	\
	tpm_demo.exe		\
	tpmbios.exe		\
	tpminit.exe		\
	tpmreset.exe		\
	transport_test.exe	\
	unbindfile.exe		\
	unsealfile.exe		\
	unsealxfile.exe		\
	updateverification.exe	\
	verifydelegation.exe	\
	verifyfile.exe

clean:		
		rm *.o *.exe *~ *.dll *.a

%.exe:		%.o applink.o
		$(CC) $(LNFLAGS) $< applink.o -o $@ $(LNLIBS) $(LNDLLS)


%.o:		%.c
		$(CC) $(CCFLAGS) $< -o $@

