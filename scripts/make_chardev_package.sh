#!/bin/bash

set -e 

# sudo -E apt-get update
# sudo -E apt-get -y install build-essential libssl-dev libtool automake ruby-dev gcc make
# gem install fpm

command -v fpm >/dev/null 2>&1 || { echo "I require fpm but it's not installed.  Aborting." >&2; exit 1; }

export DESTDIR=$(mktemp -d /tmp/blah.XXXX)

if [ ! -d $DESTDIR ]; then
	echo "aieeeee i have no temp dir"
	exit 1
fi


if [[ $# -eq 0 ]] ; then
    echo 'This should make a package. Specify a version (1.0), a revision (n)'
    exit 0
fi

if [ ! $1 ]; then
	echo "Specify a version number as the first argument"
	exit 1
fi

if [ ! $2 ]; then
	echo "specify a revision number as the second argument"
	exit 1
fi

DIRS="usr"

cd ../tpm
make -f makefile-tpm

mkdir -p $DESTDIR/usr/bin/
sudo install -c tpm_server $DESTDIR/usr/bin/tpm_server

cd ../libtpm
./autogen
./configure --prefix=/usr --enable-chardev
make install

cd ../scripts

fpm -t deb -s dir -C $DESTDIR -n tpmtools -v $1 --iteration $2 $DIRS

if [ $? == 0 ]; then
	rm -Rf $DESTDIR
	echo "Success"
else
	echo "It didn't work. I've left $DESTDIR intact."
	exit 1
fi
