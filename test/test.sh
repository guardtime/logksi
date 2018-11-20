#!/bin/bash

rm -rf test/out
mkdir -p test/out

bats \
test/test_suites/integrate.bats \
test/test_suites/verify_after_integrate.bats \
test/test_suites/sign.bats \
test/test_suites/verify_after_sign.bats \
test/test_suites/verify.bats \
test/test_suites/extend.bats \
test/test_suites/verify_after_extend.bats \
test/test_suites/hash_check.bats \
test/test_suites/extract.bats \
test/test_suites/treehash_check.bats \
test/test_suites/legacy.bats \
test/test_suites/verify_linking.bats \
test/test_suites/verify_debug_output.bats

exit_code=$?

exit $exit_code
