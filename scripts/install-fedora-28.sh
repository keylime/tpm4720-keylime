#!/bin/bash

# Privilege verification
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root" 1>&2
   exit 1
fi

set -e 

dnf clean all
dnf install -y openssl-devel libtool gcc automake

cd ../tpm
make -f makefile-tpm

install -c tpm_server /usr/local/bin/tpm_server

cd ../libtpm
./comp-sockets.sh
make install

cd ../scripts
install -c tpm_serverd /usr/local/bin/tpm_serverd
install -c init_tpm_server /usr/local/bin/init_tpm_server

init_tpm_server

tpm_serverd

