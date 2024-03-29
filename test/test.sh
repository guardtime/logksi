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

if gttlvdump -h > /dev/null && gttlvgrep -h > /dev/null; then
	TEST_DEPENDING_ON_TLVUTIL="\
		test/test_suites/create-tlvutil.bats"
	echo Info: Extra tests depending on gttlvutil added.
else
	TEST_DEPENDING_ON_TLVUTIL=""
	echo Warning: gttlvutil is not installed. Tests depending on gttlvutil are ignored.
fi

if test -e /dev/urandom; then
	TEST_DEPENDING_ON_URANDOM="\
		test/test_suites/create-urandom.bats"
	echo Info: Extra tests depending on /dev/urandom added.
else
	TEST_DEPENDING_ON_URANDOM=""
	echo Warning: /dev/urandom does not exists. Tests depending on /dev/urandom are ignored.
fi

bats \
test/test_suites/conf_ok.bats \
test/test_suites/conf_invalid.bats \
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
test/test_suites/embedded_url.bats \
test/test_suites/create_cmd.bats \
test/test_suites/create_log_file_list_cmd.bats \
test/test_suites/create_static_file.bats \
test/test_suites/create_linking.bats \
test/test_suites/create_log_file_list.bats \
test/test_suites/create_rebuild.bats \
test/test_suites/create_state_file.bats \
test/test_suites/create_state_file_cmd.bats \
$TEST_DEPENDING_ON_KSI_TOOL \
$TEST_DEPENDING_ON_TLVUTIL \
$TEST_DEPENDING_ON_URANDOM

exit_code=$?

exit $exit_code
