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

# Remove test output directory.  
rm -rf test/out 2> /dev/null

# Create test output directory.
mkdir -p test/out

# Copy some test files to output directory.
cp -r test/resource/signature/syslog.logsig.parts test/out/syslog.logsig.parts
cp test/resource/file/syslog test/out/syslog
cp test/resource/file/syslog test/out/extended

# Define KSI_CONF for temporary testing.
export KSI_CONF=test/resource/conf/default-not-working-conf.cfg

# If ksi tool in project directory is available use that one, if not
# use the one installed in the machine.
if [ ! -f src/logksi ]; then
	tool=logksi
else
	tool=src/logksi
fi

shelltest \
test/test_suites/integrate.test \
test/test_suites/sign.test \
--with=$tool -- -j1

exit_code=$?

exit $exit_code