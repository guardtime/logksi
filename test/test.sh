#!/bin/bash

rm -rf test/out
mkdir -p test/out

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
test/test_suites/verify_log_rec_time_debug_output.bats

exit_code=$?

exit $exit_code
