# IBM TPM Emulator Fork
A fork of the IBM software TPM code from http://sourceforge.net/projects/ibmswtpm/

Specifically, this is a fork of revision 4720 https://sourceforge.net/projects/ibmswtpm/files/tpm4720.tar.gz/download

It includes patches and bug fixes required to use the libtpm utilities with keylime: https://github.com/mit-ll/python-keylime 

# Build for use with Keylime with a real TPM

To build the libtpm utilities for use with keylime.  First get prerequisites:

On Ubuntu: `apt-get -y install build-essential libssl-dev libtool automake`

On Centos: `yum install -y openssl-devel libtool gcc automake`

then build and install with:
```
cd tpm4720/libtpm
./comp-chardev.sh
sudo make install
```

# Build for use with keylime with the TPM emulator

Building on ubuntu/debian

`cd tpm4720/scripts`

`./install.sh`

Building on centos

`cd tpm4720/scripts`

`./install-centos.sh`


Building on a mac

you need brew installed prior to running this

`cd tpm4720/scripts`

`./install-mac.sh`

# Using the emulator

The above install scripts will also install some helpful scripts for starting and resetting the emulator.

To reset the TPM emulator, use:

`/usr/local/bin/init_tpm_server`

To start the TPM emulator use

`/usr/local/bin/tpm_serverd`

These scripts store state in in the user's home directory ~/.tpm0

# License for Updates to IBM Library


Copyright (c) 2015 Massachusetts Institute of Technology.

All rights reserved.

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.


DISTRIBUTION STATEMENT A. Approved for public release: distribution unlimited.

This material is based upon work supported by the Assistant Secretary of Defense for 
Research and Engineering under Air Force Contract No. FA8721-05-C-0002 and/or 
FA8702-15-D-0001. Any opinions, findings, conclusions or recommendations expressed in this
material are those of the author(s) and do not necessarily reflect the views of the 
Assistant Secretary of Defense for Research and Engineering.

Delivered to the US Government with Unlimited Rights, as defined in DFARS Part 
252.227-7013 or 7014 (Feb 2014). Notwithstanding any copyright notice, U.S. Government 
rights in this work are defined by DFARS 252.227-7013 or DFARS 252.227-7014 as detailed 
above. Use of this work other than as specifically authorized by the U.S. Government may 
violate any copyrights that exist in this work.

