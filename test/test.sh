#!/bin/bash

#
# Copyright 2013-2016 Guardtime, Inc.
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

# Remove test output directories.  
rm -rf test/out/integrate 2> /dev/null
rm -rf test/out/sign 2> /dev/null
rm -rf test/out/extend 2> /dev/null

# Create test output directories.
mkdir -p test/out/integrate
mkdir -p test/out/sign
mkdir -p test/out/extend

# Create some test files to output directory.
cp -r test/resource/signature/syslog.logsig.parts test/out/integrate/syslog.logsig.parts
cp test/resource/file/syslog test/out/integrate/syslog

# Define KSI_CONF for temporary testing.
export KSI_CONF=test/resource/conf/default-not-working-conf.cfg

# If ksi tool in project directory is available use that one, if not
# use the one installed in the machine.
if [ ! -f src/logksi ]; then
	tool=logksi
else
	tool=src/logksi
fi

if gttlvdump -h > /dev/null && gttlvgrep -h > /dev/null; then
	TEST_DEPENDING_ON_TLVUTIL="test/test_suites/sign-metadata.test test/test_suites/sign-masking.test"
	echo Info: Extra tests depending on gttlvutil added.
else
	TEST_DEPENDING_ON_TLVUTIL=""
	echo Warning: gttlvutil is not installed. Tests depending on gttlvutil are ignored.
fi

shelltest \
test/test_suites/integrate.test \
test/test_suites/sign.test \
--with=$tool -- -j1

exit_code=$?

exit $exit_code