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

mem_test_dir=test/out/memory
test_suite_dir=test/test_suites

# Remove memory test directory.
rm -rf $mem_test_dir 2> /dev/null

# Create a temporary output directory for memory tests.
mkdir -p $mem_test_dir

# Create some test files to output directory.
cp -r test/resource/signature/syslog.logsig.parts $mem_test_dir/syslog.logsig.parts
cp test/resource/file/syslog $mem_test_dir/syslog
cp test/resource/file/syslog $mem_test_dir/extended

# Configure temporary KSI_CONF.
export KSI_CONF=test/resource/conf/default-not-working-conf.cfg

# A function to convert a test file to memory test.
function generate_test() {
test/convert-to-memory-test.sh $test_suite_dir/$1  $mem_test_dir/$1
}

# Convert test files to valgrind memory test files.
generate_test integrate.test
generate_test sign.test


# Run generated test scripts.

# If ksi tool in project directory is available use that one, if not
# use the one installed in the machine.
if [ ! -f src/logksi ]; then
	tool=logksi
else
	tool=src/logksi
fi

shelltest \
$mem_test_dir/integrate.test \
$mem_test_dir/sign.test \
--with="valgrind --leak-check=full $tool" -- -j1 -a
exit_code=$?

exit $exit_code