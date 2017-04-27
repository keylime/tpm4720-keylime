#!/bin/bash

#set -x

#################################################################################
# 										#
# Author: Stefan Berger, stefanb@us.ibm.com					#
# $Id: test_console.sh 4709 2013-10-15 16:47:00Z stefanb $			#
# 										#
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

havekeys=0
havekeys_cmk=0
havekeys_cmk_migration=0
havekeys_tpm2=0
havekeys_binding=0
havekeys_signing=0
end=0

KEYSIZE=2048
KEYSIZE_ST=2048
export TPM_SESSION=osap
export TPM_INSTANCE=0
TPM_VERSION=12
USE_TPMINIT=1
# For HW TPMs with physical presence locked, set to FALSE because owner clear requires
#       manual intervention before take ownership
USE_OWNERCLEAR="1"
# Indicates that one of the HW TPM options was specified
USE_HWTPM="0"
export TPM_SERVER_NAME
export TPM_SERVER_PORT
export TPM_TRANSPORT="0"
export TPM_TRANSPORT_EK
export TPM_TRANSPORT_EKP
export TPM_TRANSPORT_SK
export TPM_TRANSPORT_SKP
export TPM_TRANSPORT_PASS=pass
export TPM_TRANSPORT_HANDLE
export TPM_TRANSPORT_ENONCE
export TPM_TRANSPORT_ENC
export LOADKEY_VERSION=""
export TPM_AUDITING="0"
export TPM_IS_FIPS="0"
export TPM_ET_ENCRYPT_AES="0"
export NO_SRK_PASSWORD=0
export TPM_USE_LOCALITY=0
export TPM_DUMP_COMMANDS="0"
export TPM_REVOKE_EK="0"
# allow keys to be swapped
export TPM_NO_KEY_SWAP="0"
#Need to implement some special handling for the following ordinals
#first in the C-code: OIAP, OSAP, DSAP, ExcecuteTransport, TickStampBlob
#MakeIdentity, ActivateIdentity, LoadIdentity
#OIAP = 10
#OSAP = 11
#DSAP = 17
#GetPubKey = 33
#Terminate_Handle = 150
#ExecuteTransport = 231
#ReleaseTransportSigned = 232
#When testing transport the stack automatically 
# tries to open and close the transport session. This is bad
# for the 'GetAuditDigest' command since this changes
# the audit digest that is reported.
TPM_NON_AUDITED_ORDS="33 150 231 232"
CANNOT_AUDIT_WITH_TRANSPORT="10 11 33 150 231 232"

HWTPM_CHOICES="3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 20 23 25"

INTERACTIVE=1

PATH=$PWD:$PATH 

showMenu () 
{
	echo ""
	echo "Master TPM at $TPM_SERVER_NAME:$TPM_SERVER_PORT"
	echo "Slave TPM at $SLAVE_TPM_SERVER:$SLAVE_TPM_PORT"
	echo ""
	echo "Please select an item from the following test:"
	echo ""
	echo "1.  NVRAM, DIRs                    15. Context                       "
	echo "2.  Counters                       16. Chg. authority                "
	echo "3.  Sealing                        17. Maintenance                   "
	echo "4.  Binding                        18. Random Numbers                "
	echo "5.  Signing                        19. Ownership                     "
	echo "6.  Key migration, no CMK keys     20. Delegation                    "
	echo "7.  Key migration, CMK keys only   21. vTPM                          "
	echo "8.  Identity & key certification   22. TPM Migration                 "
	echo "9.  Sha1                           23. Transport                     "
	echo "10. Key eviction                   24. Misc. + S3 Suspend/Resume     "
	echo "11. Quoting and PCRs               25. Capabilities (visual verification)"
	echo "12. Self test                      26. Capabilities (may need TPM to reset)"
	echo "13. Auditing                       27. Re-cycle TPM                  "
	echo "14. Ticks                          28. Certificates                  "
	echo ""
	echo "all          Run tests 1-24,28            "
	echo "hwtpm        Tests without reset: $HWTPM_CHOICES"
	echo "hwtpm-owner  Tests without reset or owner clear: $HWTPM_CHOICES"
	echo "conf         configure global test parameters   "
	echo "quit         quit test program                  "
	echo ""
	echo "Current settings: TPM_SESSION=$TPM_SESSION, KEYSIZE=$KEYSIZE"
	echo "                  TPM_INSTANCE=$TPM_INSTANCE, KEYSIZE_ST=$KEYSIZE_ST, USE_TPMINIT=$USE_TPMINIT"
	echo "                  TPM_VERSION=$TPM_VERSION, TPM_TRANSPORT=$TPM_TRANSPORT ($TPM_TRANSPORT_ENC)"
	echo "                  TPM_AUDITING=$TPM_AUDITING, TPM_REVOKE_EK=$TPM_REVOKE_EK"
	read choices
	echo "Your choice: $choices"
	if [ "$choices" == "hwtpm" ]; then
		choices=$HWTPM_CHOICES
                USE_HWTPM="1"
	fi
	if [ "$choices" == "hwtpm-owner" ]; then
		choices=$HWTPM_CHOICES
                USE_HWTPM="1"
                USE_OWNERCLEAR="0"
	fi
}

test_tpm_init()
{
	if [ "$USE_TPMINIT" != "0" ]; then
		tpminit > run.out
		ERR=$?
		if [ $ERR -ne 0 ]; then
			USE_TPMINIT=0
		else
			havekeys=0
			havekeys_cmk=0
			havekeys_cmk_migration=0
			havekeys_binding=0
			havekeys_signing=0
			tpmbios > run.out
			ERR=$?
			if [ $ERR -ne 0 ]; then
				USE_TPMINIT=0
			fi
			TPM_TRANSPORT_EK=
			TPM_TRANSPORT_SK=
		fi
	fi
}

test_tpm_version()
{
	getcapability -cap 0xd > run.out
	if [ $? -ne 0 ]; then
		TPM_VERSION=11
	fi
	if [ "$TPM_VERSION" == "11" ]; then
		LOADKEY_VERSION="-v1"
		TPM_TRANSPORT="0"
	fi
}


disable_auditing_ords()
{
	if [ "$TPM_VERSION" != "11" -a "$TPM_AUDITING" == "1" ]; then
		while [ "$1" != "" ]; do
			enableaudit -o $1 -d -p $OWNER_PASSWORD > run.out
			shift
		done
	fi
}

enable_auditing_ords()
{
	if [ "$TPM_VERSION" != "11" -a "$TPM_AUDITING" == "1" ]; then
		while [ "$1" != "" ]; do
			enableaudit -o $1 -p $OWNER_PASSWORD > run.out
			shift
		done
	fi
}

# Expects the owner password as first parameter
enable_auditing() 
{
	if [ "$TPM_VERSION" != "11" -a "$TPM_AUDITING" == "1" ]; then
		#echo "ERROR: Owner password is $1."
		echo
		echo "Enabling auditing."
		AUDITED_ORDS=""
		rm -f .auditing-$TPM_INSTANCE
		let i=1
		while [ $i -le 255 ]; do
			let found=0
			for x in $TPM_NON_AUDITED_ORDS; do
				if [ $i == $x ]; then
					let found=1
					break
				fi
			done
			if [ $found -eq 0 ]; then
				enableaudit -o $i -p $1 > /dev/null
				RES=$?
				if [ $RES -eq 0 ]; then
					AUDITED_ORDS="$AUDITED_ORDS $i"
				else
					true
					#echo "ERROR: Could not enable auditing for ordinal $i"
				fi
			fi
			let i=i+1
		done
		echo " INFO: Enabled auditing."
		echo ""
		sync_auditing
	fi
}


sync_auditing ()
{
	if [ "$TPM_AUDITING" == "1" -a "$TPM_VERSION" != "11" ]; then
		echo "Synchronizing auditing data with TPM."
		rm -f .auditing-$TPM_INSTANCE
		if [ "$TPM_TRANSPORT" == "1" ]; then
			disable_auditing_ords $CANNOT_AUDIT_WITH_TRANSPORT
		fi
		getauditdigest -s 0 > run.out
		getauditdigest -s 0 > run.out
	fi
}

check_audit_digest ()
{
	if [ "$TPM_AUDITING" == "1" -a "$TPM_VERSION" != "11" ]; then
		#ls -l .auditing-0
		echo "Checking audit digest"
		if [ "$TPM_TRANSPORT" == "1" ]; then
			disable_auditing_ords $CANNOT_AUDIT_WITH_TRANSPORT
		fi
		getauditdigest -s 0 > run.out
		ERR=$?
		if [ $ERR -eq 0 ]; then
			if [ "$1" == "1" ]; then
				cat run.out
			fi
			RES=`cat run.out | grep "same digest"`
			if [ "$RES" != "" ]; then
				echo " INFO: Audit digest is the same"
			else
				echo " ERROR: Audit digest is different"
				ACTUAL=`cat run.out | grep "TPM Digest" | gawk '{ print $3}'`
				EXPECTED=`cat run.out | grep "different digest" | gawk '{ print $7 }'`
				echo "        Expected Digest: $EXPECTED"
				echo "        Actual Digest:   $ACTUAL"
				sync_auditing
			fi
		else
			if [ $ERR -eq 38 ]; then
				true
			else
				echo " WARN: Could not run 'getauditdigest'"
				dumpOutput
			fi
		fi
	fi
}

showConfigMenu () 
{
	end=0
	while [ "$end" == "0" ]; do
		echo ""
		echo ""
		echo "1. keysize (binding, signing, legacy) : $KEYSIZE"
		echo "2. keysize (storage,                ) : $KEYSIZE_ST"
		echo "3. preferred session (osap, oiap)     : $TPM_SESSION"
		echo "4. <reserved>"
		echo "5. TPM instance to test               : $TPM_INSTANCE"
		echo "6. Use 'tpminit' for resetting TPM    : $USE_TPMINIT"
		echo "7. Test for version (1.1=11,1.2=12)   : $TPM_VERSION ($LOADKEY_VERSION)"
		echo "8. Enable Transport Mode              : $TPM_TRANSPORT ($TPM_TRANSPORT_ENC)"
		echo "9. Enable auditing                    : $TPM_AUDITING"
		echo "10.Dump all requests and response     : $TPM_DUMP_COMMANDS"
		echo "11.Enable revoke EK interactive test  : $TPM_REVOKE_EK"
		echo ""
		echo "q  back to previous menu"
		read enter

		if [ "$enter" == "1" ]; then
			echo "Enter new key size for legacy, binding and signing keys:"
			read input
			input=`echo $input | tr -c -d "[:digit:]"`
			if [ $input -ge 16 ]; then
				KEYSIZE=$input
			fi
			havekeys=0
			havekeys_cmk=0
			havekeys_cmk_migration=0
			havekeys_binding=0
			havekeys_signing=0
		fi
		if [ "$enter" == "2" ]; then
			echo "Enter new key size for storage keys (>= 2048):"
			read input
			input=`echo $input | tr -c -d "[:digit:]"`
			if [ $input -ge 2048 ]; then
				KEYSIZE_ST=$input
			fi
			havekeys=0
			havekeys_cmk=0
			havekeys_cmk_migration=0
			havekeys_binding=0
			havekeys_signing=0
			if [ $KEYSIZE_ST -lt 2048 ]; then
				KEYSIZE_ST=2048
			fi
		fi
		if [ "$enter" == "3" ]; then
			echo "Enter the preferred session (osap or oiap):"
			read input
			input=`echo "${input}" | tr "[:lower:]" "[:upper:]"`
			case "$input" in
			OIAP)  TPM_SESSION="oiap";;
			OSAP)  TPM_SESSION="osap";;
			*) echo "Invalid session type. Press enter.";
			   read enter;;
			esac
		fi
		if [ "$enter" == "4" ]; then
			true
		fi
		if [ "$enter" == "5" ]; then
			echo "Enter the TPM instance number to run the tests against"
			read TPM_INSTANCE
		fi
		if [ "$enter" == "6" ]; then
			echo "Indicate whether to use 'tpminit' for resetting the TPM"
			echo "'0' means that 'tpminit' is not to be used."
			read USE_TPMINIT
			test_tpm_init
		fi
		if [ "$enter" == "7" ]; then
			echo "Indicate for which version of the TPM to test."
			echo "(1.1=11, 1.2=12)"
			read TPM_VERSION
			LOADKEY_VERSION=""
			if [ "$TPM_VERSION" != "11" ] &&
			   [ "$TPM_VERSION" != "12" ]; then
				TPM_VERSION="11"
			fi
			test_tpm_version
			
			if [ "$TPM_VERSION" == "11" ]; then
				LOADKEY_VERSION="-v1"
				TPM_TRANSPORT="0"
			fi
		fi
		if [ "$enter" == "8" ]; then
			#EstablishTransport implemented?
			checkOrdImplemented 0xe6
			rc=$?
			if [ $rc -eq 0 ]; then
				echo ""
				echo "Transport not supported by TPM."
				echo ""
			else
		
				if [ "$TPM_TRANSPORT" == "1" ]; then
					TPM_TRANSPORT="0"
					TPM_TRANSPORT_SK=""
					TPM_TRANSPORT_EK=""
				else
					TPM_TRANSPORT="1"
				fi
			
				if [ "$TPM_TRANSPORT" == "1" ]; then
					while [ 1 ]; do
						echo "Choose one of the following encryption algorithms:"
						echo "1. MGF1"
						echo "2. AES128-CTR"
						echo "3. AES128-OFB"
						echo ""
						read input
						if [ "$input" == "1" ]; then
							TPM_TRANSPORT_ENC="MGF1"
							break
						elif [ "$input" == "2" ]; then
							TPM_TRANSPORT_ENC="CTR"
							break
						elif [ "$input" == "3" ]; then
							TPM_TRANSPORT_ENC="OFB"
							break
						fi
					done
				fi
			fi
		fi
		if [ "$enter" == "9" ]; then
			clearown $OWNER_PASSWORD > run.out
			tpmbios -n > run.out
			
			#SetOrdinalAuditStatus implemented
			checkOrdImplemented 0x8d
			rc=$?
			if [ $rc -eq 0 ]; then
				echo ""
				echo "Auditing not supported by TPM."
				echo ""
			else
				if [ "$TPM_AUDITING" == "1" ]; then
					TPM_AUDITING="0"
				else
					TPM_AUDITING="1"
					echo "enabled auditing"
					getauditdigest -s 0 > run.out
					sync_auditing
					sync_auditing
				fi
			fi
		fi
		
		if [ "$enter" == "10" ]; then
			if [ "$TPM_DUMP_COMMANDS" == "0" ]; then
				echo "Enabling dumping of transactions."
				TPM_DUMP_COMMANDS="1"
			else
				echo "Disabling dumping of transactions."
				TPM_DUMP_COMMANDS="0"
			fi
		fi
		
		if [ "$enter" == "11" ]; then
		        echo "Indicate whether to run interactive revoke EK tests"
			if [ "$TPM_REVOKE_EK" == "0" ]; then 
			    echo "Enabling revoke EK tests"
			    TPM_REVOKE_EK="1"
			else
			    echo "Disabling revoke EK tests"
			    TPM_REVOKE_EK="0"
			fi
		fi

		if [ "$enter" == "q" ]; then
			if [ "$TPM_TRANSPORT" == "1" -a \
			     "$TPM_AUDITING"  == "1" ]; then
			    echo "Transport and auditing together are known to not correctly work in this"
			    echo "test environment. Some bug needs to be fixed. Press enter."
			    read
			fi
			end=1
		fi
	done
	end=0
}

needKeys ()
{
	if [ "$havekeys" == "0" ]; then
		if [ "$TPM_TRANSPORT" != "1" ]; then
			#Cannot remove the keys essential for the transport.
			evictkey all > run.out
			rm -rf /tmp/.key-*
			havekeys_tpm2=0
		fi
		echo "Need to create keys."
		takeTPM $OWNER_PASSWORD $SRK_PASSWORD $KEYSIZE_ST
		createAllKeys
		havekeys=1
	fi
}

needKeys_Binding()
{
	if [ "$havekeys_binding" == "0" ]; then
		echo "Need to create additional binding keys."
		createAdditionalBindingKeys
		havekeys_binding=1
	fi
}

needKeys_Signing()
{
	if [ "$havekeys_signing" == "0" ]; then
		echo "Need to create additional signing keys."
		createAdditionalSigningKeys
		havekeys_signing=1
	fi
}

needKeys_cmk ()
{
	needKeys
	if [ "$havekeys_cmk" == "0" -a "$TPM_VERSION" != "11" ]; then
		echo "Need to create CMK keys."
		createAllKeys_CMK
		ERR=$?
		if [ $ERR -eq 0 ]; then
			havekeys_cmk=1
		fi
	fi
}

needKeys_cmk_migration ()
{
	needKeys_tpm2
	if [ "$havekeys_cmk_migration" == "0" ]; then
		echo "Creating CMK keys for migration"
		createKeysCMKMigration
		ERR=$?
		if [ $ERR -eq 0 ]; then
			havekeys_cmk_migration=1
		fi
	fi
}

needKeys_tpm2 ()
{
	### Need to create some keys on 2nd tpm
	if [ "$havekeys_tpm2" == "0" ]; then
		TPM_SERVER_NAME=$SLAVE_TPM_SERVER
		TPM_SERVER_PORT=$SLAVE_TPM_PORT

		takeTPM $TPM2_OWNER_PASSWORD $TPM2_SRK_PASSWORD $KEYSIZE_ST
		echo "Need to create keys on TPM2"
		createKeys_tpm2
		ERR=$?
		if [ $ERR -eq 0 ]; then
			havekeys_tpm2=1
		fi

		TPM_SERVER_NAME=$MASTER_TPM_SERVER
		TPM_SERVER_PORT=$MASTER_TPM_PORT
	fi
}


title ()
{
	echo "------------------------------------------"
	echo "       Beginning test $1"
	echo ""
	echo ""
}

recycleTPM ()
{
	local ima_tcb=`grep ima_tcb /proc/cmdline  2>/dev/null`
	local num_msr=`wc /sys/kernel/security/ima/ascii_runtime_measurements \
	    2>/dev/null | \
	    gawk '{print $1}'`
	if [ "$num_msr" = "" ]; then
		num_msr=0
	fi

	if [ -n "$cmdline" -o $num_msr -gt 1 ]; then
		echo
		echo "IMA may be running and cause some of the tests to fail."
		echo "Consider rebooting with IMA inactive."
		echo "If you continue, then the tests may affect IMA's"
		echo "measurement log. Reboot after running the test."
		echo
		read enter
	fi

	if [ "$USE_TPMINIT" == "0" ]; then
		if [ $INTERACTIVE -ne 0 ]; then
			echo ""
			echo "Please stop the TPM at $TPM_SERVER_NAME:$TPM_SERVER_PORT and remove all"
			echo "permanent state. Then restart it."
			echo "Press enter to continue."
			read enter
		fi
	else
		tpminit > run.out
		if [ "$?" != "0" ]; then
			echo " ERROR: TPM_Init does not work on TPM at $TPM_SERVER_NAME:$TPM_SERVER_PORT."
			USE_TPMINIT=0
		fi
	fi
	TPM_TRANSPORT_EK=
	TPM_TRANSPORT_SK=
	tpmbios > run.out
	if [ "$USE_TPMINIT" == "0" ]; then
		echo ""
		echo "Please restart the TPM at $TPM_SERVER_NAME:$TPM_SERVER_PORT."
		echo "Press enter to continue."
		echo ""
	else
		tpminit > run.out
		if [ "$?" != "0" ]; then
			echo " ERROR: TPM_Init does not work."
			USE_TPMINIT=0
		fi
	fi
	tpmbios > run.out
	sync_auditing
}


suspendResumeTPM ()
{
	echo "Saving TPM state."
	savestate
	ERR=$?

	if [ $ERR -eq 0 ]; then
		echo " INFO: Successfully saved the TPM's state."
	else
		echo " ERROR: Could not save the TPM's state."
		dumpOutput
	fi
	
	if [ "$USE_TPMINIT" == "0" ]; then
		if [ $INTERACTIVE -ne 0 ]; then
			echo ""
			echo "Please stop the TPM at $TPM_SERVER_NAME:$TPM_SERVER_PORT"
			echo "Then restart it."
			echo "Press enter to continue."
			read enter
		fi
	else
		tpminit > run.out
		if [ "$?" != "0" ]; then
			echo " ERROR: TPM_Init does not work on TPM at $TPM_SERVER_NAME:$TPM_SERVER_PORT."
			USE_TPMINIT=0
		fi
	fi
	TPM_TRANSPORT_EK=
	TPM_TRANSPORT_SK=
	tpmbios -s -cs > run.out
	ERR=$?
	if [ $ERR -ne 0 ]; then
		echo " ERROR: Could not initialize communication with the TPM."
		echo "    *** Please re-cycle the TPM!! ***"
		dumpOutput
	fi
}


clean_tmp ()
{
	rm -rf /tmp/.key-*
	cd /tmp
	tmp=`ls .*transdigest* .*currentticks* 2>/dev/null`
	if [ "$tmp" != "" ]; then
		rm -rf ${tmp}
	fi
	cd - >/dev/null
}

usage()
{
	cat <<EOF
usage: $0 [options] tests

The following options are available:

--non-interactive : automatically run all tests without prompting the user
--help|-h         : display this test screen

The following test names are available:
nvram, counters, sealing, binding, signing, migration, identity, all, hwtpm

Otherwise the numbers of the tests can be used as well (1..27).

Multiple tests can be invoked by providing their names as parameter. The
tests 'all' and 'hwtpm' should only be passed without any other tests.

EOF
}

#
# Program Entry
#
main()
{
	choices=""

	# I need the constants to show the slave TPM's address
	. ./modules/test_constants

	while [ $# -ge 1 ]; do
		if [ "$1" == "nvram" ]; then
			choices="$choices 1"
		elif [ "$1" == "counters" ]; then
			choices="$choices 2"
		elif [ "$1" == "sealing" ]; then
			choices="$choices 3"
		elif [ "$1" == "binding" ]; then
			choices="$choices 4"
		elif [ "$1" == "signing" ]; then
			choices="$choices 5"
		elif [ "$1" == "migration" ]; then
			choices="$choices 6"
		elif [ "$1" == "identity" ]; then
			choices="$choices 8"
		elif [ "$1" == "all" ]; then
			choices=all
			echo "Master TPM at $TPM_SERVER_NAME:$TPM_SERVER_PORT"
			echo "Slave TPM at $SLAVE_TPM_SERVER:$SLAVE_TPM_PORT"
		elif [ "$1" == "--non-interactive" ]; then
			INTERACTIVE=0
		elif [ "$1" == "hwtpm" ]; then
			choices="$HWTPM_CHOICES"
	                USE_HWTPM="1"
		elif [ "$1" == "hwtpm-owner" ]; then
			choices="$HWTPM_CHOICES"
	                USE_HWTPM="1"
	                USE_OWNERCLEAR="0"
	        elif [ "$1" == "--help" -o "$1" == "-h" ]; then
	        	usage "$0"
	        	exit 0
		else
			choices="$1"
		fi
		shift 1
	done

	if [ -z "$choices" ]; then
		showMenu
	fi

	clean_tmp
	test_tpm_init
	test_tpm_version

	# create the test input file
	echo "input_to_test" > input

	while [ $end -eq 0 ]; do
		havekeys=0
		havekeys_cmk=0
		havekeys_cmk_migration=0
		havekeys_binding=0
		havekeys_signing=0

		. ./modules/test_auditing
		. ./modules/test_nvram
		. ./modules/test_basic
		. ./modules/test_constants
		. ./modules/test_counters
		. ./modules/test_migration
		. ./modules/test_identity
		. ./modules/test_binding
		. ./modules/test_quote
		. ./modules/test_seal
		. ./modules/test_signing
		. ./modules/test_selftest
		. ./modules/test_createkeys
		. ./modules/test_eviction
		. ./modules/test_sha
		. ./modules/test_pcr
		. ./modules/test_ticks
		. ./modules/test_context
		. ./modules/test_ownership
		. ./modules/test_capability
		. ./modules/test_maintenance
		. ./modules/test_misc
		. ./modules/test_changeauth
		. ./modules/test_delegation
		. ./modules/test_random
		. ./modules/test_vtpm
		. ./modules/test_transport
		. ./modules/test_certificates

		recycleTPM

		echo ""
		date
		echo ""
		echo "Vendor information for TPM being tested"
		getcapability -cap 0x1a
		echo ""

		for choice in $choices; do

		if [ "$choice" == "all" ]; then
			echo ""
			echo "Plese make sure that your TPM has been reset completely and all"
			echo "previous state has been removed. Some tests might otherwise fail."
			echo "Press enter to continue."
			read enter
		fi

		if [ "$TPM_AUDITING" == "1" -a "$choice" != "all" ]; then
			sync_auditing
		fi
	
		if [ "$choice" == "1" -o \
		     "$choice" == "all" ]; then
		     	#recycleTPM
		     	sync_auditing
			title "NVRAM"
			
			if [ "$TPM_VERSION" == "11" ]; then
				echo " This test does not work with 1.1 TPMs"
			else
				takeTPM $OWNER_PASSWORD $SRK_PASSWORD $KEYSIZE_ST
				doNVRAMTest

				check_audit_digest

				doNVRAMTest2_Part1

				if [ "$USE_TPMINIT" == "0" ]; then
					echo ""
					echo "Please restart the TPM at $TPM_SERVER_NAME:$TPM_SERVER_PORT for 2nd part of NV-RAM test."
					echo "Please press enter to continue."
					read enter
				else
					check_audit_digest
					tpminit > run.out
					if [ "$?" != "0" ]; then
						echo " ERROR: TPM_Init does not work."
						USE_TPMINIT=0
					fi
				fi
				TPM_TRANSPORT_EK=
				TPM_TRANSPORT_SK=
				tpmbios > run.out
				sync_auditing
				doNVRAMTest2_Part2

				if [ "$USE_TPMINIT" == "0" ]; then
					echo ""
					echo "Please restart the TPM at $TPM_SERVER_NAME:$TPM_SERVER_PORT."
					echo "Press enter to continue."
					read enter
				else
					check_audit_digest
					tpminit > run.out
					if [ "$?" != "0" ]; then
						echo " ERROR: TPM_Init does not work."
						USE_TPMINIT=0
					fi
				fi
				./tpmbios > run.out

				# need to re-create the transport keys (if needed)
				# after above reset
				createTransportKeys

				# NV index volatile flag interaction with ST_STATE and ST_CLEAR
				doNVSaveStateTest

				# NV index authorized by PCRs
				doNVPCRTest

				echo ""
				echo "Clearing owner"
				./clearown -pwdo $OWNER_PASSWORD > run.out
				ERR=$?
				if [ $ERR -ne 0 ]; then	
					echo " ERROR: Could not properly clear the owner."
				else
					echo " INFO: Successfully cleared ownership."
				fi

				./tpmbios -n > run.out
				sync_auditing
				check_audit_digest

				doNVRAMTest_noOwner_Part1
				check_audit_digest
				if [ $? -eq 0 ]; then
					doNVRAMTest_noOwner_Part2
					check_audit_digest
				fi

			#DirWriteAuth implemented
				checkOrdImplemented 0x19
				rc=$?
				if [ $rc -eq 0 ]; then
					echo "  Skipping DIR-related test since not implemented in TPM"
				else
					doDIRTest
				fi
				check_audit_digest
	
				if [ "$USE_TPMINIT" == "0" ]; then
					echo ""
					echo "Please restart the TPM at $TPM_SERVER_NAME:$TPM_SERVER_PORT."
					echo "Press enter to continue."
					read enter
				else
					check_audit_digest
					tpminit > run.out
					if [ "$?" != "0" ]; then
						echo " ERROR: TPM_Init does not work."
						USE_TPMINIT=0
					fi
				fi
				TPM_TRANSPORT_EK=
				TPM_TRANSPORT_SK=
				./tpmbios > run.out

				echo ""
				echo "Clearing owner"
				./clearown -pwdo $OWNER_PASSWORD > run.out
				ERR=$?
				if [ $ERR -ne 0 ]; then	
					echo " ERROR: Could not properly clear the owner."
				else
					echo " INFO: Successfully cleared ownership."
				fi

				./tpmbios -n > run.out
				sync_auditing
				check_audit_digest
				havekeys=0
				havekeys_cmk=0
				havekeys_cmk_migration=0
				havekeys_binding=0
				havekeys_signing=0
			fi
		fi


		if [ "$choice" == "2" -o \
		     "$choice" == "all" ]; then
			title "Counters"

			if [ "$TPM_VERSION" == "11" ]; then
				echo " This test does not work with 1.1 TPMs"
			else
				if [ "$USE_TPMINIT" == "0" ]; then
					echo ""
					echo "Please restart the TPM at $TPM_SERVER_NAME:$TPM_SERVER_PORT for counter test."
					echo "Please press enter to continue."
					read enter
				else
					check_audit_digest
					tpminit > run.out
					if [ "$?" != "0" ]; then
						echo " ERROR: TPM_Init does not work."
						USE_TPMINIT=0
					fi
					tpmbios > run.out
					sync_auditing

				fi
				TPM_TRANSPORT_EK=
				TPM_TRANSPORT_SK=
				# need to re-create the transport keys (if needed)
				# after above reset
				createTransportKeys

				takeTPM $OWNER_PASSWORD $SRK_PASSWORD $KEYSIZE_ST
	
				if [ $? -ne 0 ]; then
					echo "Check your TPM!"
				else
					doCounterTest
				fi
				havekeys=0
				havekeys_cmk=0
				havekeys_cmk_migration=0
				havekeys_binding=0
				havekeys_signing=0
			fi
		fi
	
		if [ "$choice" == "3" -o \
		     "$choice" == "all" ]; then
			title "Sealing"
			takeTPM $OWNER_PASSWORD $SRK_PASSWORD $KEYSIZE_ST
			needKeys
			echo ""
			doSealFileTest
			
			check_audit_digest
	
			doSealFileTest_PCRLocking
			check_audit_digest
			if [ "$TPM_VERSION" != "11" ]; then
				checkOrdImplemented 0x3d
				rc=$?
				if [ $rc -eq 0 ]; then
					echo ""
					echo "    Skipping SealX due to missing support in TPM"
					echo ""
				else
					doSealxFileTest_PCRLocking
					check_audit_digest
					doSealxFileTest_PCRLocking_AES_CTR
					check_audit_digest
				fi
			fi
	
			doSealFileTest_noPwd
			check_audit_digest
	
	                if [ $USE_OWNERCLEAR == "1" ]; then
	                    takeTPM_noSRKPwd $KEYSIZE_ST
	                    check_audit_digest
	
	                    if [ $? -eq 0 ]; then
				doSealFileTest_PCRLocking_noSRKPwd
				check_audit_digest
				if [ "$TPM_VERSION" != "11" ]; then
	                            checkOrdImplemented 0x3d
	                            rc=$?
	                            if [ $rc -eq 0 ]; then
	                                echo ""
	                                echo "    Skipping SealX due to missing support in TPM"
	                                echo ""
	                            else
	                                doSealxFileTest_PCRLocking_noSRKPwd
	                                check_audit_digest
	                            fi
				fi
	                    fi
	                    echo "Clearing owner"
	                    clearown -pwdo $OWNER_PASSWORD > run.out
	                    tpmbios -n > run.out
	                fi
	
			sync_auditing
			check_audit_digest
	
			havekeys=0
			havekeys_cmk=0
			havekeys_cmk_migration=0
			havekeys_binding=0
			havekeys_signing=0
		fi
	
		if [ "$choice" == "4" -o \
		     "$choice" == "all" ]; then
			title "Binding"
			takeTPM $OWNER_PASSWORD $SRK_PASSWORD $KEYSIZE_ST
			needKeys
			needKeys_Binding
			echo ""
			doBindingFileTest
			doBindingFileTestPKCSV15
			check_audit_digest
		fi
	
		if [ "$choice" == "5" -o \
		     "$choice" == "all" ]; then
			title "Signing"
			takeTPM $OWNER_PASSWORD $SRK_PASSWORD $KEYSIZE_ST
			needKeys
			needKeys_Signing
			echo ""
			doSignFileTest
			check_audit_digest
		fi
	
		if [ "$choice" == "6" -o \
		     "$choice" == "all" ]; then
			title "Migration - non-CMK keys"
			takeTPM $OWNER_PASSWORD $SRK_PASSWORD $KEYSIZE_ST
			needKeys
			echo ""
			
			doMigrationTest1TPM
			check_audit_digest
	
			doMigrationTest1TPM_2Steps
			check_audit_digest
	
	                if [ "$USE_HWTPM" == "0" ]; then 
	
	                    if [ "$TPM_TRANSPORT" != "0" ]; then
				echo ""
				echo " Turning TPM Transport usage off."
				echo ""
				TPM_TRANSPORT_REMEMBER=$TPM_TRANSPORT
				TPM_TRANSPORT="0"
	                    fi
			
	                    if [ "$TPM_AUDITING" != "0" ]; then
				echo ""
				echo " Turning auditing off."
				echo ""
				TPM_AUDITING_REMEMBER=$TPM_AUDITING
				TPM_AUDITING="0"
	                    fi
	
	
	                    MASTER_TPM_SERVER=$TPM_SERVER_NAME
	                    MASTER_TPM_PORT=$TPM_SERVER_PORT
	
	                    TPM_SERVER_NAME=$SLAVE_TPM_SERVER
	                    TPM_SERVER_PORT=$SLAVE_TPM_PORT
	
	                    pcrread -ix 0 > run.out
	                    ERR=$?
	                    if [ "$ERR" != "0" -a "$ERR" != "38" ]; then
				recycleTPM
	                    fi
			
	                    pcrread -ix 0 > run.out
	                    ERR=$?
	                    if [ "$ERR" != "0" -a "$ERR" != "38" ]; then
				echo ""
				echo "Please start the 2nd TPM now. Make sure that it is 'primed'."
				echo "Expecting 2nd TPM at $SLAVE_TPM_SERVER:$SLAVE_TPM_PORT."
				echo "Press 'enter' to continue."
				read enter
	                    fi
	                    echo "Performing some basic initilization on the 2nd TPM."
	
	                    sync_auditing
			    # Get the 2nd TPM.
	
	                    takeTPM $TPM2_OWNER_PASSWORD $TPM2_SRK_PASSWORD $KEYSIZE_ST
	
	
			    # Create keys on 2nd TPM.
	
	                    createKeys_tpm2
	                    check_audit_digest
	
	                    doMigrationTest2TPMs
	                    check_audit_digest
	
			    # Switch back to TPM 1
	                    TPM_SERVER_NAME=$MASTER_TPM_SERVER
	                    TPM_SERVER_PORT=$MASTER_TPM_PORT
			
	                    if [ "$TPM_AUDITING_REMEMBER" != "0" ]; then
				echo ""
				echo " Turning auditing on."
				TPM_AUDITING=$TPM_AUDITING_REMEMBER
				TPM_AUDITING_REMEMBER="0"
	                    fi
	
	                    if [ "$TPM_TRANSPORT_REMEMBER" != "0" ]; then
				echo ""
				echo " Turning TPM Transport usage on."
				echo ""
				TPM_TRANSPORT=$TPM_TRANSPORT_REMEMBER
				TPM_TRANSPORT_REMEMBER="0"
	                    fi
	                fi
			sync_auditing
	
			havekeys=0
			havekeys_cmk=0
			havekeys_cmk_migration=0
			havekeys_binding=0
			havekeys_signing=0
		fi
	
		if [ "$choice" == "7" -o \
		     "$choice" == "all" ]; then
			title "Migration CMK-keys"
			
			if [ "$TPM_VERSION" == "11" ]; then
				echo " This test does not work for 1.1 TPMs"
			else
				takeTPM $OWNER_PASSWORD $SRK_PASSWORD $KEYSIZE_ST
				needKeys
				needKeys_cmk
				echo ""
	
				doMigrationTest1TPM_CMK
				check_audit_digest
	
	                        if [ "$USE_HWTPM" == "0" ]; then 
	
	                            MASTER_TPM_SERVER=$TPM_SERVER_NAME
	                            MASTER_TPM_PORT=$TPM_SERVER_PORT
	
	                            if [ "$TPM_TRANSPORT" != "0" ]; then
					echo ""
					echo " Turning TPM Transport usage off."
					echo ""
					TPM_TRANSPORT_REMEMBER=$TPM_TRANSPORT
					TPM_TRANSPORT="0"
	                            fi
	
	                            if [ "$TPM_AUDITING" != "0" ]; then
					echo ""
					echo " Turning auditing off."
					echo ""
					TPM_AUDITING_REMEMBER=$TPM_AUDITING
					TPM_AUDITING="0"
	                            fi
	
	                            sync_auditing
	
	                            needKeys_tpm2
	                            needKeys_cmk_migration
	
				    ### Need to create a special key on 1st TPM for migration
	                            needKeys_cmk_migration
	
	                            doMigrationTest2TPMs_CMK
	
	                            if [ "$TPM_AUDITING_REMEMBER" != "0" ]; then
					echo ""
					echo " Turning auditing on."
					TPM_AUDITING=$TPM_AUDITING_REMEMBER
					TPM_AUDITING_REMEMBER="0"
	                            fi
				
	                            sync_auditing
				
	                            if [ "$TPM_TRANSPORT_REMEMBER" != "0" ]; then
					echo ""
					echo " Turning TPM Transport usage on."
					echo ""
					TPM_TRANSPORT=$TPM_TRANSPORT_REMEMBER
					TPM_TRANSPORT_REMEMBER="0"
	                            fi
	                        fi
	
				havekeys=0
				havekeys_cmk=0
				havekeys_cmk_migration=0
				havekeys_binding=0
				havekeys_signing=0
				havekeys_tpm2=0
			fi
		fi
	
		if [ "$choice" == "8" -o \
		     "$choice" == "all" ]; then
			title "Identity"
			needKeys
			needKeys_cmk
			needKeys_Signing
	
			echo ""
			doIdentityTest
			check_audit_digest
	
			doCertifyKeyTest
			check_audit_digest
	
			if [ "$TPM_VERSION" != "11" ]; then
				doCertifyKeyTest_CMK
				check_audit_digest
			fi
	
	                if [ $USE_OWNERCLEAR == "1" ]; then
	                    takeTPM_noSRKPwd $KEYSIZE_ST
	
	                    if [ $? -eq 0 ]; then
				### Identity test
				doIdentityTest_noSRKPwd
				check_audit_digest
	                    else
				echo " ERROR: Could not run test."
	                    fi
	
	                    check_audit_digest
	                    echo "Clearing owner"
	                    ./clearown -pwdo $OWNER_PASSWORD > run.out
	                    ./tpmbios -n > run.out
	                fi
			sync_auditing
			check_audit_digest
	
			havekeys=0
			havekeys_cmk=0
			havekeys_cmk_migration=0
			havekeys_binding=0
			havekeys_signing=0
		fi
	
		if [ "$choice" == "9" -o \
		     "$choice" == "all" ]; then
			title "Hashing"
			
			if [ "$TPM_TRANSPORT" != "0" ]; then
				echo ""
				echo " Turning TPM Transport usage off."
				echo ""
				TPM_TRANSPORT_REMEMBER=$TPM_TRANSPORT
				TPM_TRANSPORT="0"
			fi
			
			takeTPM $OWNER_PASSWORD $SRK_PASSWORD $KEYSIZE_ST
			doSha1Test
			check_audit_digest
	
			if [ "$TPM_TRANSPORT_REMEMBER" != "0" ]; then
				echo ""
				echo " Turning TPM Transport usage on."
				echo ""
				TPM_TRANSPORT=$TPM_TRANSPORT_REMEMBER
				TPM_TRANSPORT_REMEMBER="0"
			fi
		fi
	
		if [ "$choice" == "10" -o \
		     "$choice" == "all" ]; then
			title "Eviction"
			takeTPM $OWNER_PASSWORD $SRK_PASSWORD $KEYSIZE_ST
			needKeys
			echo ""
			doEvictionTest
			check_audit_digest
			havekeys=0
			havekeys_cmk=0
			havekeys_cmk_migration=0
			havekeys_binding=0
			havekeys_signing=0
		fi
	
		if [ "$choice" == "11" -o \
		     "$choice" == "all" ]; then
			title "PCRs and Quoting"
			takeTPM $OWNER_PASSWORD $SRK_PASSWORD $KEYSIZE_ST
			needKeys
			needKeys_cmk
			needKeys_Signing
			echo ""
			doQuoting
			check_audit_digest
			if [ "$TPM_VERSION" != "11" ]; then
				doQuoting2
				check_audit_digest
			fi
			doPCRTest
			check_audit_digest
		fi
	
		if [ "$choice" == "12" -o \
		     "$choice" == "all" ]; then
			title "Self Test"
			takeTPM $OWNER_PASSWORD $SRK_PASSWORD $KEYSIZE_ST
			doSelfTest
			check_audit_digest
		fi
	
		if [ "$choice" == "13" -o \
		     "$choice" == "all" ]; then
			title "Auditing"
			
			checkOrdImplemented 0x85
			rc=$?
			if [ $rc -eq 0 ]; then
				echo ""
				echo "Skipping test since auditing not implemented in TPM"
				echo ""
			else
				if [ "$TPM_VERSION" == "11" ]; then
					echo " This test does not work with 1.1 TPMs"
				else
					takeTPM $OWNER_PASSWORD $SRK_PASSWORD $KEYSIZE_ST
					needKeys
					needKeys_Signing
					doAuditTest
				fi
			fi
		fi
	
		if [ "$choice" == "14" -o \
		     "$choice" == "all" ]; then
			title "Ticks"
			if [ "$TPM_VERSION" == "11" ]; then
				echo " This test does not work with 1.1 TPMs"
			else
				takeTPM $OWNER_PASSWORD $SRK_PASSWORD $KEYSIZE_ST
				needKeys
				needKeys_Signing
				echo ""
				doTickTest
			fi
		fi
	
		if [ "$choice" == "15" -o \
	             "$choice" == "all" ]; then
			title "Key Context"
			if [ "$TPM_VERSION" == "11" ]; then
				echo " This test does not work with 1.1 TPMs"
			else
				takeTPM $OWNER_PASSWORD $SRK_PASSWORD $KEYSIZE_ST
				needKeys
				echo ""
				doKeyContextTest
				check_audit_digest
				doAuthContextTest
				check_audit_digest
				havekeys=0
				havekeys_cmk=0
				havekeys_cmk_migration=0
				havekeys_binding=0
				havekeys_signing=0
			fi
		fi
	
		if [ "$choice" == "16" -o \
	             "$choice" == "all" ]; then
			title "Changing authority/password"
			takeTPM $OWNER_PASSWORD $SRK_PASSWORD $KEYSIZE_ST
			needKeys
			echo ""
			doChangeAuthTest
			check_audit_digest
			doChangeKeyAuthTest
			check_audit_digest
			doChangeSealAuthTest
			check_audit_digest
		fi
	
		if [ "$choice" == "17" -o \
		     "$choice" == "all" ]; then
			title "Maintenance"
			
			checkOrdImplemented 0x2f
			rc=$?
			if [ $rc -eq 0 ]; then
				echo ""
				echo "    Skipping Maintenance test since not supported in TPM"
				echo ""
			else
				takeTPM $OWNER_PASSWORD $SRK_PASSWORD $KEYSIZE_ST
				needKeys
				echo ""
				doTestMaintenance
				check_audit_digest
			fi
		fi
	
		if [ "$choice" == "18" -o \
		     "$choice" == "all" ]; then
			title "RNG Test"
			echo ""
			takeTPM $OWNER_PASSWORD $SRK_PASSWORD $KEYSIZE_ST
			doTestRandom
			check_audit_digest
		fi
		
		if [ "$choice" == "19" -o \
		     "$choice" == "all" ]; then
			title "Ownership"
			takeTPM $OWNER_PASSWORD $SRK_PASSWORD $KEYSIZE_ST
			doTestOwnership
			doTestOwnershipFile
			if [ "$TPM_REVOKE_EK" == "1" ]; then 
			    doTestRevEK
			fi
			havekeys=0
			havekeys_cmk=0
			havekeys_cmk_migration=0
			havekeys_binding=0
			havekeys_signing=0
		fi
	
		if [ "$choice" == "20" -o \
		     "$choice" == "all" ]; then
		     	title "Delegation"
		     	
		     	if [ "$TPM_VERSION" == "11" ]; then
		     		echo " This test does not work with 1.1 TPMs"
		     	else
			     	takeTPM $OWNER_PASSWORD $SRK_PASSWORD $KEYSIZE_ST
				needKeys
				doDelegationTest
				check_audit_digest
				doDelegationTest_OwnerPointer
				check_audit_digest
			fi
		fi
	
		if [ "$choice" == "21" -o \
		     "$choice" == "all" ]; then
		     	title "virtual TPM"
		     	takeTPM $OWNER_PASSWORD $SRK_PASSWORD $KEYSIZE_ST
	
			# Since sync_auditing and enable_auditing take the global
			# onwer password OWNER_PASSWORD as parameter, I cannot run
			# the auditing when testing the vTPM instances with different
			# passwords than OWNER_PASSWORD. So I am disabling auditing for
			# this test...
		     	if [ "$TPM_AUDITING" == "1" ]; then
		     		echo 
		     		echo "Temporarily deactivating auditing."
		     		echo
		     		REMEMBER_TPM_AUDITING="1"
		     		TPM_AUDITING="0"
		     	fi
		     	
		     	checkVTPM
		     	RET=$?
		     	if [ "$RET" == "0" ]; then
		     		echo " WARN: Skipping test because this is not a VTPM."
		     	else
				takeTPM $OWNER_PASSWORD $SRK_PASSWORD $KEYSIZE_ST
				doTest_vTPM
				doTest_ExtendNotification
			fi
			
			if [ "$REMEMBER_TPM_AUDITING" == "1" ]; then
				TPM_AUDITING="1"
				REMEMBER_TPM_AUDITING="0"
			fi
		fi
	
		if [ "$choice" == "22" -o \
		     "$choice" == "all" ]; then
		     	title "TPM Migration"
	
		     	checkVTPM
		     	RET=$?
		     	if [ "$RET" == "0" ]; then
		     		echo " WARN: Skipping test because this is not a VTPM."
		     	else
				if [ "$TPM_TRANSPORT" != "0" ]; then
					echo ""
					echo " Turning (global) TPM Transport usage off."
					echo ""
					TPM_TRANSPORT_REMEMBER=$TPM_TRANSPORT
					TPM_TRANSPORT="0"
				fi
	
				echo "Recycling the master TPM"
				recycleTPM
				havekeys=0
				havekeys_cmk=0
				havekeys_cmk_migration=0
				havekeys_binding=0
				havekeys_signing=0
				takeTPM $OWNER_PASSWORD $SRK_PASSWORD $KEYSIZE_ST
	
				echo "Recycling the 2nd TPM."
				MASTER_TPM_SERVER=$TPM_SERVER_NAME
				MASTER_TPM_PORT=$TPM_SERVER_PORT
	
				TPM_SERVER_NAME=$SLAVE_TPM_SERVER
				TPM_SERVER_PORT=$SLAVE_TPM_PORT
				recycleTPM
				havekeys_tpm2=0
				sync_auditing
				takeTPM $TPM2_OWNER_PASSWORD $TPM2_SRK_PASSWORD $KEYSIZE_ST
	
				TPM_SERVER_NAME=$MASTER_TPM_SERVER
				TPM_SERVER_PORT=$MASTER_TPM_PORT
				doMigrate_MigrateVTPM
				havekeys=0
				havekeys_cmk=0
				havekeys_cmk_migration=0
				havekeys_binding=0
				havekeys_signing=0
				havekeys_tpm2=0
				TPM_SERVER_NAME=$MASTER_TPM_SERVER
				TPM_SERVER_PORT=$MASTER_TPM_PORT
				sync_auditing
	
				if [ "$TPM_TRANSPORT_REMEMBER" != "0" ]; then
					echo ""
					echo " Turning TPM Transport usage on."
					echo ""
					TPM_TRANSPORT=$TPM_TRANSPORT_REMEMBER
					TPM_TRANSPORT_REMEMBER="0"
				fi
	
			fi
		fi
		
		if [ "$choice" == "23" -o \
		     "$choice" == "all" ]; then
			title "Transport"
	
			if [ "$TPM_VERSION" == "11" ]; then
				echo " This test does not work with 1.1 TPMs"
			else
	
				if [ "$TPM_TRANSPORT" != "0" ]; then
					echo ""
					echo " Turning (global) TPM Transport usage off."
					echo ""
					TPM_TRANSPORT_REMEMBER=$TPM_TRANSPORT
					TPM_TRANSPORT="0"
				fi
	
				takeTPM $OWNER_PASSWORD $SRK_PASSWORD $KEYSIZE_ST
				doTransportTest
				check_audit_digest
	
				if [ "$TPM_TRANSPORT_REMEMBER" != "0" ]; then
					echo ""
					echo " Turning TPM Transport usage on."
					echo ""
					TPM_TRANSPORT=$TPM_TRANSPORT_REMEMBER
					TPM_TRANSPORT_REMEMBER="0"
					sync_auditing
				fi
			fi
		fi
	
		if [ "$choice" == "24" -o \
		     "$choice" == "all" ]; then
			title "Misc"
			if [ "$TPM_VERSION" == "11" ]; then
				echo " This test does not work with 1.1 TPMs"
			else
				takeTPM $OWNER_PASSWORD $SRK_PASSWORD $KEYSIZE_ST
				doMiscTest
				check_audit_digest
				
				echo "Clearing owner"
				./clearown -pwdo $OWNER_PASSWORD > run.out
				./tpmbios -n > run.out
				sync_auditing
				check_audit_digest
	
				takeTPM $OWNER_PASSWORD $SRK_PASSWORD $KEYSIZE_ST
				doPhysPresenceTest
				check_audit_digest
				
				echo "Clearing owner"
				./clearown -pwdo $OWNER_PASSWORD > run.out
				./tpmbios -n > run.out
				sync_auditing
				recycleTPM

				takeTPM $OWNER_PASSWORD $SRK_PASSWORD $KEYSIZE_ST
				doSuspendResumeTest
				recycleTPM
			fi
		fi
	
		if [ "$choice" == "25" -o \
		     "$choice" == "all" ]; then
			title "Capability"
			takeTPM $OWNER_PASSWORD $SRK_PASSWORD $KEYSIZE_ST
	
			if [ "$havekeys" == "1" -a \
			     "$choice" != "all" -a \
			     "$TPM_VERSION" == "11" ]; then
				doTestGetCapability "-hk $SIGNINGKEY_HANDLE -pwdk $SIGNINGKEY_PASSWORD"
				check_audit_digest
			else
				doTestGetCapability
				check_audit_digest
			fi
			check_audit_digest
			havekeys=0
		     	havekeys_cmk=0
		     	havekeys_cmk_migration=0
		     	havekeys_binding=0
			havekeys_signing=0
		fi
	
		if [ "$choice" == "26" ]; then
			title "Capability (needs reset of TPM afterwards)"
			takeTPM $OWNER_PASSWORD $SRK_PASSWORD $KEYSIZE_ST
	
			if [ "$havekeys" == "1" -a \
			     "$choice" != "all" -a \
			     "$TPM_VERSION" == "11" ]; then
				doTestGetCapability "-hk $SIGNINGKEY_HANDLE -pwdk $SIGNINGKEY_PASSWORD"
				check_audit_digest
				if [ "$TPM_VERSION" != "11" ]; then
					doTestSetCapability $OWNER_PASSWORD
					check_audit_digest
				fi
			else
				doTestGetCapability
				check_audit_digest
				if [ "$TPM_VERSION" != "11" ]; then
					doTestSetCapability $OWNER_PASSWORD
					check_audit_digest
				fi
			fi
			check_audit_digest
			if [ "$USE_TPMINIT" != "0" ]; then
				tpminit
				if [ "$?" != "0" ]; then
					echo " ERROR: TPM_Init does not work."
					USE_TPMINIT=0
				fi
				./tpmbios > run.out
				TPM_TRANSPORT_EK=
				TPM_TRANSPORT_SK=
			fi
			sync_auditing
			check_audit_digest
			havekeys=0
		     	havekeys_cmk=0
		     	havekeys_cmk_migration=0
		     	havekeys_binding=0
			havekeys_signing=0
		fi
	
	
		if [ "$choice" == "27" ]; then
		     	title "Recycling TPM"
		     	recycleTPM
		     	havekeys=0
		     	havekeys_cmk=0
		     	havekeys_cmk_migration=0
		     	havekeys_binding=0
			havekeys_signing=0
		fi
	
		if [ "$choice" == "28" -o \
		     "$choice" == "all" ]; then
			title "Certificates"
			if [ "$TPM_VERSION" == "11" ]; then
				echo " This test does not work with 1.1 TPMs"
			else
				echo ""
				doCertificatesTest
			fi
		fi
		if [ "$choice" == "conf" ]; then
			showConfigMenu
		fi
	
		if [ "$choice" == "quit" ]; then
			end=1
		fi
	
		done
		
		[ $INTERACTIVE -eq 0 ] && end=1
	
		choice=none
		if [ "$end" == "0" ]; then
			showMenu
		fi
	done
}
	
main "$@"
	
