#!/bin/bash

rm -rf test/out
mkdir test/out

bats \
test/test_suites/integrate.bats \
test/test_suites/verify_after_integrate.bats \
test/test_suites/sign.bats \
test/test_suites/verify_after_sign.bats \
test/test_suites/verify.bats \
test/test_suites/extend.bats
#test/test_suites/verify_after_extend.bats

exit_code=$?

exit $exit_code
