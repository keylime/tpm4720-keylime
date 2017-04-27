#!/bin/bash

set -e

brew install libtool automake autoconf openssl
brew link openssl --force

cd ../tpm
make -f makefile-tpm

cd ../libtpm

echo "Compiling with socket support but NO virtual TPM support"
[ -r Makefile ] && make clean
./autogen-mac
# add --enable-chardev to not use sockets
./configure --includedir=/usr/local/opt/openssl/include --libdir=/usr/local/opt/openssl/lib

make 

echo "Please sudo to allow installation"
sudo make install

cd ../tpm
sudo install -c tpm_server /usr/local/bin/tpm_server


cd ../scripts
sudo install -c tpm_serverd /usr/local/bin/tpm_serverd
sudo install -c init_tpm_server /usr/local/bin/init_tpm_server

sudo init_tpm_server

sudo tpm_serverd
