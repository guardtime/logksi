#!/bin/bash

#
# Copyright 2020 Guardtime, Inc.
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

mem_test_dir=test/memory_test_suite
test_suite_dir=test/test_suites

# Remove test out dir.
rm -rf test/out
mkdir -p test/out

# Remove memory test directory.
rm -rf $mem_test_dir 2> /dev/null

# Create a temporary output directory for memory tests.
mkdir -p $mem_test_dir


# A function to convert a test file to memory test.
function generate_test() {
test/convert-to-memory-test.sh $test_suite_dir/$1  $mem_test_dir/$1
}

if ksi -h > /dev/null; then
	TEST_DEPENDING_ON_KSI_TOOL="\
		$mem_test_dir/extract_ksig.bats"
	echo Info: Extra tests depending on KSI_TOOL added.
	
	generate_test extract_ksig.bats
else
	TEST_DEPENDING_ON_KSI_TOOL=""
	echo Warning: KSI tool is not installed. Tests depending on KSI tool are ignored.
fi



# Convert test files to valgrind memory test files.
generate_test integrate.bats
generate_test integrate_recover.bats
generate_test integrate_cmd.bats
generate_test integrate_debug_output.bats
generate_test verify_after_integrate.bats
generate_test sign.bats
generate_test sign_continue.bats
generate_test sign_debug_output.bats
generate_test sign_cmd.bats
generate_test verify_after_sign.bats
generate_test verify.bats
generate_test extend.bats
generate_test extend_debug_output.bats
generate_test extend_cmd.bats
generate_test verify_after_extend.bats
generate_test hash_check.bats
generate_test extract.bats
generate_test extract_debug_output.bats
generate_test extract_cmd.bats
generate_test treehash_check.bats
generate_test legacy.bats
generate_test verify_linking.bats
generate_test verify_continue.bats
generate_test verify_continue_debug_output.bats
generate_test verify_debug_output.bats
generate_test verify_cmd.bats
generate_test verify_log_rec_time.bats
generate_test verify_log_rec_time_debug_output.bats
generate_test verify_no_resource.bats
generate_test embedded_url.bats


bats \
$mem_test_dir/integrate.bats \
$mem_test_dir/integrate_recover.bats \
$mem_test_dir/integrate_cmd.bats \
$mem_test_dir/integrate_debug_output.bats \
$mem_test_dir/verify_after_integrate.bats \
$mem_test_dir/sign.bats \
$mem_test_dir/sign_continue.bats \
$mem_test_dir/sign_debug_output.bats \
$mem_test_dir/sign_cmd.bats \
$mem_test_dir/verify_after_sign.bats \
$mem_test_dir/verify.bats \
$mem_test_dir/extend.bats \
$mem_test_dir/extend_debug_output.bats \
$mem_test_dir/extend_cmd.bats \
$mem_test_dir/verify_after_extend.bats \
$mem_test_dir/hash_check.bats \
$mem_test_dir/extract.bats \
$mem_test_dir/extract_debug_output.bats \
$mem_test_dir/extract_cmd.bats \
$mem_test_dir/treehash_check.bats \
$mem_test_dir/legacy.bats \
$mem_test_dir/verify_linking.bats \
$mem_test_dir/verify_continue.bats \
$mem_test_dir/verify_continue_debug_output.bats \
$mem_test_dir/verify_debug_output.bats \
$mem_test_dir/verify_cmd.bats \
$mem_test_dir/verify_log_rec_time.bats \
$mem_test_dir/verify_log_rec_time_debug_output.bats \
$mem_test_dir/verify_no_resource.bats \
$mem_test_dir/embedded_url.bats \
$TEST_DEPENDING_ON_KSI_TOOL

exit_code=$?

exit $exit_code