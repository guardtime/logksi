#!/bin/bash

rm -rf test/out
mkdir -p test/out

if ksi -h > /dev/null; then
	TEST_DEPENDING_ON_KSI_TOOL="\
		test/test_suites/extract_ksig.bats"
	echo Info: Extra tests depending on KSI_TOOL added.
else
	TEST_DEPENDING_ON_KSI_TOOL=""
	echo Warning: KSI tool is not installed. Tests depending on KSI tool are ignored.
fi


bats \
test/test_suites/integrate.bats \
test/test_suites/integrate_recover.bats \
test/test_suites/integrate_cmd.bats \
test/test_suites/integrate_debug_output.bats \
test/test_suites/verify_after_integrate.bats \
test/test_suites/sign.bats \
test/test_suites/sign_continue.bats \
test/test_suites/sign_debug_output.bats \
test/test_suites/sign_cmd.bats \
test/test_suites/verify_after_sign.bats \
test/test_suites/verify.bats \
test/test_suites/extend.bats \
test/test_suites/extend_debug_output.bats \
test/test_suites/extend_cmd.bats \
test/test_suites/verify_after_extend.bats \
test/test_suites/hash_check.bats \
test/test_suites/extract.bats \
test/test_suites/extract_debug_output.bats \
test/test_suites/extract_cmd.bats \
test/test_suites/treehash_check.bats \
test/test_suites/legacy.bats \
test/test_suites/verify_linking.bats \
test/test_suites/verify_continue.bats \
test/test_suites/verify_continue_debug_output.bats \
test/test_suites/verify_debug_output.bats \
test/test_suites/verify_cmd.bats \
test/test_suites/verify_log_rec_time.bats \
test/test_suites/verify_log_rec_time_debug_output.bats \
test/test_suites/verify_no_resource.bats \
$TEST_DEPENDING_ON_KSI_TOOL

exit_code=$?

exit $exit_code
