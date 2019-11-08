#!/bin/sh

#
# Copyright 2013-2019 Guardtime, Inc.
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

set -e

libksi_git="https://github.com/guardtime/libksi.git"
libksi_version=v3.20.3025
libgtrfc3161_git="https://github.com/guardtime/libgtrfc3161.git"
libgtrfc3161_version=v1.1.78


tmp_build_dir_name="tmp_dep_build"
lib_out_dir="dependencies"
libksi_dir_name="libksi"
libgtrfc3161_dir_name="libgtrfc3161"

ignore_exit_code=false

while [ "$1" != "" ]; do
	case $1 in
		--ignore-build-error )	 echo "When building libksi and libgtrfc3161 result of the tests is ignored."
								 ignore_exit_code=true
								 ;;
		* )						 echo "Unknown token '$1' from command-line."
								 exit 1
	esac
	shift
done


rm -rf $tmp_build_dir_name
mkdir -p $tmp_build_dir_name
rm -rf $lib_out_dir

cd $tmp_build_dir_name
  git clone $libksi_git $libksi_dir_name 
  git clone $libgtrfc3161_git $libgtrfc3161_dir_name

  cd $libksi_dir_name
    git checkout $libksi_version
    ./rebuild.sh || $ignore_exit_code
  cd ..

  cd $libgtrfc3161_dir_name
    git checkout $libgtrfc3161_version
    ./rebuild.sh -l $(pwd)/../libksi/src/ksi/.libs/ -i $(pwd)/../libksi/src/ || $ignore_exit_code
  cd ..
cd ..


mkdir -p $lib_out_dir/include/ksi
mkdir -p $lib_out_dir/include/gtrfc3161
mkdir -p $lib_out_dir/lib

cp $tmp_build_dir_name/$libksi_dir_name/src/ksi/*.h $lib_out_dir/include/ksi/
cp $tmp_build_dir_name/$libksi_dir_name/src/ksi/.libs/libksi.* $lib_out_dir/lib/
cp $tmp_build_dir_name/$libgtrfc3161_dir_name/src/gtrfc3161/*.h $lib_out_dir/include/gtrfc3161/
cp $tmp_build_dir_name/$libgtrfc3161_dir_name/src/gtrfc3161/.libs/libgtrfc3161.* $lib_out_dir/lib/

rm -rf $tmp_build_dir_name
