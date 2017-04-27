# IBM TPM Emulator Fork
A fork of the IBM software TPM code from http://sourceforge.net/projects/ibmswtpm/

Specifically, this is a fork of revision 4720 https://sourceforge.net/projects/ibmswtpm/files/tpm4720.tar.gz/download

It includes patches and bug fixes required to use the libtpm utilities with keylime.

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

