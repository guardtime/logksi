#!/bin/bash

#
# Copyright 2013-2017 Guardtime, Inc.
#
# This file is part of the Guardtime client SDK.
#
# Licensed under the Apache License, Version 2.0 (the "License").
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#     http://www.apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES, CONDITIONS, OR OTHER LICENSES OF ANY KIND, either
# express or implied. See the License for the specific language governing
# permissions and limitations under the License.
# "Guardtime" and "KSI" are trademarks or registered trademarks of
# Guardtime, Inc., and no license to trademarks is granted; Guardtime
# reserves and retains all trademark rights.
#

set -e

conf_args="--enable-static-build"

if [ "$#" -eq 1 ]; then
	libksi_path="$1"
	export CPPFLAGS=-I$libksi_path/include
	export LDFLAGS=-L$libksi_path/lib
	export LD_LIBRARY_PATH=$libksi_path/lib
else
	conf_args="$conf_args --enable-use-installed-libksi"
fi

# Get version number.
VER=$(tr -d [:space:] < VERSION)
ARCH=$(dpkg --print-architecture)
RELEASE_VERSION="$(lsb_release -is)$(lsb_release -rs | grep -Po "[0-9]{1,3}" | head -1)"
PKG_VERSION=1
DEB_DIR=packaging/deb
PACKAGE_NAME=logksi

autoreconf -if
./configure $conf_args
make clean
make dist


# Rebuild debian changelog.
if command  -v dch > /dev/null; then
  echo "Generating debian changelog..."
  $DEB_DIR/rebuild_changelog.sh doc/ChangeLog $DEB_DIR/control $PACKAGE_NAME $DEB_DIR/changelog
else
  >&2 echo "Error: Unable to generate Debian changelog file as dch is not installed!"
  >&2 echo "Install devscripts 'apt-get install devscripts'"
  exit 1
fi

tar xvfz $PACKAGE_NAME-$VER.tar.gz
mv $PACKAGE_NAME-$VER.tar.gz $PACKAGE_NAME-$VER.orig.tar.gz
mkdir $PACKAGE_NAME-$VER/debian
cp $DEB_DIR/control $DEB_DIR/changelog $DEB_DIR/rules $DEB_DIR/copyright $PACKAGE_NAME-$VER/debian
chmod +x $PACKAGE_NAME-$VER/debian/rules
cd $PACKAGE_NAME-$VER
debuild -us -uc 
cd ..

suffix=${VER}-${PKG_VERSION}.${RELEASE_VERSION}_${ARCH}
mv ${PACKAGE_NAME}_${VER}_${ARCH}.changes ${PACKAGE_NAME}_$suffix.changes
mv ${PACKAGE_NAME}_${VER}_${ARCH}.deb ${PACKAGE_NAME}_$suffix.deb

rm -rf $PACKAGE_NAME-$VER

