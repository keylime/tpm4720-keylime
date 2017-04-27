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
    echo 'This should make a package. Specify a version (1.0), a revision (n), and init style (sysv)'
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

if [ ! $3 ]; then
	echo "Specify an init style - currently the only one supported is sysv"
	exit 1
fi


DIRS=""
AFTERINSTALL=""
case "$3" in
	"sysv")
		mkdir -p $DESTDIR/etc/init.d $DESTDIR/etc/default
		cp init-scripts/sysv/tpm_server-default $DESTDIR/etc/default/tpmserver
		cp init-scripts/sysv/tpm_server-init $DESTDIR/etc/init.d/tpmserver
		DIRS="usr etc"
		AFTERINSTALL="init-scripts/sysv/after-install"
	;;
	"systemd")
		mkdir -p $DESTDIR/lib/systemd/system $DESTDIR/etc/default $DESTDIR/usr/sbin
		cp init-scripts/systemd/tpmserver.service $DESTDIR/lib/systemd/system
		cp init-scripts/sysv/tpm_server-init $DESTDIR/usr/sbin/tpmctl
		cp init-scripts/sysv/tpm_server-default $DESTDIR/etc/default/tpmserver
		DIRS="usr etc lib"
		AFTERINSTALL="init-scripts/systemd/after-install"
	;;
	"upstart")
		mkdir -p $DESTDIR/etc/init $DESTDIR/usr/sbin
		cp init-scripts/upstart/tpmserver.conf $DESTDIR/etc/init
		cp init-scripts/upstart/tpmbios.conf $DESTDIR/etc/init
                cp init-scripts/upstart/tpmctl $DESTDIR/usr/sbin/tpmctl
		DIRS="usr etc"
		AFTERINSTALL="init-scripts/upstart/after-install"
	;;
	*) 
		echo "Did not specify valid init type" 
		exit 1
	;;
esac

cd ../tpm
make -f makefile-tpm

mkdir -p $DESTDIR/usr/bin/
sudo install -c tpm_server $DESTDIR/usr/bin/tpm_server

cd ../libtpm
./autogen
./configure --prefix=/usr
make install

cd ../scripts

fpm -t deb -s dir -C $DESTDIR -n tpmtools-emulate -v $1 --iteration $2 --after-install $AFTERINSTALL $DIRS

if [ $? == 0 ]; then
	rm -Rf $DESTDIR
	echo "Success"
else
	echo "It didn't work. I've left $DESTDIR intact."
	exit 1
fi
