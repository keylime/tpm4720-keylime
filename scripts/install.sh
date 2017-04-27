#!/bin/bash

set -e 

sudo -E apt-get update
sudo -E apt-get -y install build-essential libssl-dev libtool automake

cd ../tpm
make -f makefile-tpm

sudo install -c tpm_server /usr/local/bin/tpm_server

cd ../libtpm
./comp-sockets.sh
sudo make install

cd ../scripts
sudo install -c tpm_serverd /usr/local/bin/tpm_serverd
sudo install -c init_tpm_server /usr/local/bin/init_tpm_server

sudo init_tpm_server

sudo tpm_serverd
